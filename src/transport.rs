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
    DeliveryUnknown,
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

pub(crate) struct PinnedKey {
    key: PublicKey,
    epoch: tokio::sync::watch::Sender<u64>,
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

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // Observe completion only. Never retain or log KEX material.
        self.epoch.send_modify(|value| *value += 1);
        Ok(())
    }
}

struct ShutdownOnDrop(std::net::TcpStream);
impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

pub(crate) struct Connection {
    pub handle: client::Handle<PinnedKey>,
    epoch: tokio::sync::watch::Receiver<u64>,
    _shutdown: ShutdownOnDrop,
}
impl Connection {
    pub async fn recheck(&mut self) -> Result<(), Failure> {
        if self.handle.is_closed() {
            return Err(Failure::Unavailable);
        }
        self.epoch.borrow_and_update();
        self.handle
            .rekey_soon()
            .await
            .map_err(|_| Failure::Unavailable)?;
        self.epoch
            .changed()
            .await
            .map_err(|_| Failure::Unavailable)?;
        if self.handle.is_closed() {
            return Err(Failure::Unavailable);
        }
        Ok(())
    }
}

pub(crate) async fn connect_pinned(
    host: &str,
    port: u16,
    key: &PublicKey,
) -> Result<Connection, Failure> {
    let connection = async {
        let stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|_| Failure::Unavailable)?;
        let stream = stream.into_std().map_err(|_| Failure::Unavailable)?;
        let shutdown = ShutdownOnDrop(stream.try_clone().map_err(|_| Failure::Unavailable)?);
        let stream = tokio::net::TcpStream::from_std(stream).map_err(|_| Failure::Unavailable)?;
        let (epoch_tx, epoch) = tokio::sync::watch::channel(0);
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        };
        let handle = client::connect_stream(
            Arc::new(config),
            stream,
            PinnedKey {
                key: key.clone(),
                epoch: epoch_tx,
            },
        )
        .await
        .map_err(|_| Failure::Identity)?;
        Ok(Connection {
            handle,
            epoch,
            _shutdown: shutdown,
        })
    };
    tokio::time::timeout(Duration::from_secs(5), connection)
        .await
        .map_err(|_| Failure::Timeout)?
}

struct ProbeSession {
    _connection: Connection,
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
            let connection = connect_pinned(&self.config.host, self.config.port, &self.key).await?;
            Ok(Box::new(ProbeSession {
                _connection: connection,
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
