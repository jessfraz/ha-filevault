use crate::{policy::State, secret::Secret};
use russh::{
    client,
    keys::{PublicKey, PublicKeyOrCertificate},
};
use serde::Deserialize;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub type FutureResult<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Unavailable,
    Identity,
    Unverified,
    Timeout,
    Rejected,
}

#[derive(Clone)]
pub struct Observation {
    pub state: State,
    /// Identity bound to a verified handshake, never a hostname/banner alone.
    pub identity: String,
}

pub trait Session: Send {
    fn observation(&self) -> Observation;
    fn recheck(&mut self) -> FutureResult<'_, Result<Observation, Failure>>;
    fn submit(self: Box<Self>, password: Secret) -> FutureResult<'static, Result<(), Failure>>;
}

pub trait Transport: Send + Sync {
    fn open(&self) -> FutureResult<'_, Result<Box<dyn Session>, Failure>>;
    fn runtime_ready(&self) -> FutureResult<'_, bool>;
    fn unlock_ready(&self) -> bool;
}

pub struct Disabled;
impl Transport for Disabled {
    fn open(&self) -> FutureResult<'_, Result<Box<dyn Session>, Failure>> {
        Box::pin(async { Err(Failure::Unverified) })
    }
    fn runtime_ready(&self) -> FutureResult<'_, bool> {
        Box::pin(async { false })
    }
    fn unlock_ready(&self) -> bool {
        false
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    pub host: String,
    pub port: u16,
    pub pinned_public_key: String,
}

/// Handshake only. No username, authentication method, agent, or password call.
pub struct SshProbe {
    config: ProbeConfig,
    key: PublicKey,
}
impl SshProbe {
    pub fn new(config: ProbeConfig) -> Result<Self, Failure> {
        if config.host.is_empty()
            || config.host.len() > 253
            || config.port == 0
            || config.host.chars().any(char::is_whitespace)
        {
            return Err(Failure::Unverified);
        }
        let key =
            PublicKey::from_openssh(&config.pinned_public_key).map_err(|_| Failure::Unverified)?;
        Ok(Self { config, key })
    }
}

struct PinnedKey {
    key: PublicKey,
}
impl client::Handler for PinnedKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        offered: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Certificates need their own review; comparing just their embedded key
        // would silently accept an unvalidated certificate envelope.
        Ok(offered.certificate().is_none() && offered.public_key() == self.key)
    }
}

struct ProbeSession {
    _handle: client::Handle<PinnedKey>,
    identity: String,
}
impl Session for ProbeSession {
    fn observation(&self) -> Observation {
        // A pinned host key identifies a peer, not whether FileVault is locked.
        Observation {
            state: State::Unknown,
            identity: self.identity.clone(),
        }
    }
    fn recheck(&mut self) -> FutureResult<'_, Result<Observation, Failure>> {
        Box::pin(async { Ok(self.observation()) })
    }
    fn submit(self: Box<Self>, _password: Secret) -> FutureResult<'static, Result<(), Failure>> {
        Box::pin(async { Err(Failure::Unverified) })
    }
}

impl Transport for SshProbe {
    fn open(&self) -> FutureResult<'_, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            let config = client::Config {
                inactivity_timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            };
            let handle = tokio::time::timeout(
                Duration::from_secs(5),
                client::connect(
                    Arc::new(config),
                    (self.config.host.as_str(), self.config.port),
                    PinnedKey {
                        key: self.key.clone(),
                    },
                ),
            )
            .await
            .map_err(|_| Failure::Timeout)?
            .map_err(|_| Failure::Identity)?;
            Ok(Box::new(ProbeSession {
                _handle: handle,
                identity: self
                    .key
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string(),
            }) as Box<dyn Session>)
        })
    }
    fn runtime_ready(&self) -> FutureResult<'_, bool> {
        Box::pin(async { false })
    }
    fn unlock_ready(&self) -> bool {
        false
    }
}
