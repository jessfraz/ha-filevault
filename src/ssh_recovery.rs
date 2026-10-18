//! Manually calibrated phase identities. No automatic preboot signature.
use crate::{
    policy::State,
    secret::Secret,
    transport::{
        Connection, Failure, FutureResult, Observation, Session, Transport, connect_pinned,
    },
};
use russh::{client::AuthResult, keys::PublicKey};
use serde::Deserialize;

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub preboot_public_key: String,
    pub runtime_public_key: String,
    /// A trusted administrator's supervised phase-key calibration, not discovery.
    pub manual_enrollment_verified: bool,
}

pub struct SshRecovery {
    config: RecoveryConfig,
    preboot: PublicKey,
    runtime: PublicKey,
}
impl SshRecovery {
    pub fn new(config: RecoveryConfig) -> Result<Self, Failure> {
        if config.host.is_empty()
            || config.host.len() > 253
            || config.port == 0
            || config.host.chars().any(char::is_whitespace)
            || config.username.is_empty()
            || config.username.len() > 255
            || config
                .username
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Failure::Unverified);
        }
        let preboot =
            PublicKey::from_openssh(&config.preboot_public_key).map_err(|_| Failure::Identity)?;
        let runtime =
            PublicKey::from_openssh(&config.runtime_public_key).map_err(|_| Failure::Identity)?;
        // A shared key cannot distinguish the phases. There is no banner fallback.
        if preboot == runtime {
            return Err(Failure::Identity);
        }
        Ok(Self {
            config,
            preboot,
            runtime,
        })
    }
}

struct RecoverySession {
    connection: Connection,
    username: String,
    identity: String,
    verified: bool,
}
impl Session for RecoverySession {
    fn observation(&self) -> Observation {
        Observation {
            state: if self.verified {
                State::VerifiedPreboot
            } else {
                State::Unknown
            },
            identity: self.identity.clone(),
        }
    }
    fn recheck(&mut self) -> FutureResult<'_, Result<Observation, Failure>> {
        Box::pin(async {
            if !self.verified {
                return Err(Failure::Unverified);
            }
            // Fresh key exchange over this existing authenticated transport.
            // No auth-none, global requests, commands, or password probes.
            self.connection.recheck().await?;
            Ok(self.observation())
        })
    }
    fn submit(self: Box<Self>, password: Secret) -> FutureResult<'static, Result<(), Failure>> {
        Box::pin(async move {
            let mut session = *self;
            if !session.verified || session.connection.handle.is_closed() {
                return Err(Failure::Unverified);
            }
            // Exactly one SSH password method. russh zeroizes Method::Password.
            let result = session
                .connection
                .handle
                .authenticate_password(session.username, password.into_password())
                .await;
            let closed = session.connection.handle.is_closed();
            match result {
                Ok(AuthResult::Success) => Ok(()),
                Ok(AuthResult::Failure { .. }) if closed => Err(Failure::DeliveryUnknown),
                Ok(AuthResult::Failure { .. }) => Err(Failure::Rejected),
                Err(_) => Err(Failure::DeliveryUnknown),
            }
            // Connection drop closes the socket even when a task is cancelled.
        })
    }
}
impl Transport for SshRecovery {
    fn open(&self) -> FutureResult<'_, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            let connection =
                connect_pinned(&self.config.host, self.config.port, &self.preboot).await?;
            Ok(Box::new(RecoverySession {
                connection,
                username: self.config.username.clone(),
                identity: self
                    .preboot
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string(),
                verified: self.unlock_ready(),
            }) as Box<dyn Session>)
        })
    }
    fn runtime_ready(&self) -> FutureResult<'_, bool> {
        Box::pin(async move {
            if !self.unlock_ready() {
                return false;
            }
            // Independent fresh handshake, strictly pinned to the distinct normal
            // runtime identity enrolled under supervision. No password is reused.
            connect_pinned(&self.config.host, self.config.port, &self.runtime)
                .await
                .is_ok()
        })
    }
    fn unlock_ready(&self) -> bool {
        self.config.enabled && self.config.manual_enrollment_verified
    }
}
