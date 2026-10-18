//! Manually calibrated phase identities. No automatic preboot signature.
use crate::{
    policy::State,
    transport::{Failure, FutureResult, PasswordSession, Session, Transport, connect_pinned},
};
use russh::keys::PublicKey;
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

impl Transport for SshRecovery {
    fn open(&self) -> FutureResult<'_, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            let connection =
                connect_pinned(&self.config.host, self.config.port, &self.preboot).await?;
            Ok(Box::new(PasswordSession {
                connection,
                username: self.config.username.clone(),
                identity: self
                    .preboot
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string(),
                state: if self.unlock_ready() {
                    State::VerifiedPreboot
                } else {
                    State::Unknown
                },
                authorized: self.unlock_ready(),
                manual: false,
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
