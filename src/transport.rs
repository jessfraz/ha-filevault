use crate::{policy::State, secret::Secret};
use russh::{
    client::{self, AuthResult},
    keys::{PublicKey, PublicKeyOrCertificate},
};
use serde::Deserialize;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub type FutureResult<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Busy,
    Cooldown,
    Unavailable,
    Resolution,
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
    fn confirm_manual_host(&mut self) -> Result<(), Failure> {
        Err(Failure::Unverified)
    }
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
    key: Option<PublicKey>,
    observed: Arc<std::sync::Mutex<Option<PublicKey>>>,
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
        if offered.certificate().is_some()
            || self
                .key
                .as_ref()
                .is_some_and(|key| offered.public_key() != *key)
        {
            return Ok(false);
        }
        let key = offered.public_key();
        self.key = Some(key.clone());
        *self.observed.lock().expect("host identity mutex") = Some(key);
        Ok(true)
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
    pub server_key: PublicKey,
    pub peer_addr: std::net::SocketAddr,
}

/// One password request on an already pinned connection. Phase is independent
/// of authorization: a manual user-confirmed connection can remain Unknown.
pub(crate) struct PasswordSession {
    pub connection: Connection,
    pub username: String,
    pub identity: String,
    pub state: State,
    pub authorized: bool,
    pub manual: bool,
}

impl Session for PasswordSession {
    fn observation(&self) -> Observation {
        Observation {
            state: self.state,
            identity: self.identity.clone(),
        }
    }

    fn recheck(&mut self) -> FutureResult<'_, Result<Observation, Failure>> {
        Box::pin(async {
            if !self.authorized && !self.manual {
                return Err(Failure::Unverified);
            }
            if self.manual {
                // The fresh candidate handshake and password use this same
                // cryptographic connection. Pin checks also cover any server
                // rekey. Do not require a nonstandard extra pre-auth rekey for
                // a normal manual password login or reconnect behind the user.
                if self.connection.handle.is_closed() {
                    return Err(Failure::Unavailable);
                }
                return Ok(self.observation());
            }
            self.connection.recheck().await?;
            Ok(self.observation())
        })
    }

    fn confirm_manual_host(&mut self) -> Result<(), Failure> {
        if !self.manual {
            return Err(Failure::Unverified);
        }
        self.authorized = true;
        Ok(())
    }

    fn submit(self: Box<Self>, password: Secret) -> FutureResult<'static, Result<(), Failure>> {
        Box::pin(async move {
            let mut session = *self;
            if !session.authorized || session.connection.handle.is_closed() {
                return Err(Failure::Unverified);
            }
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
            // Drop closes the socket; russh zeroizes its owned password method.
        })
    }
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
    connect_identity(host, port, Some(key.clone())).await
}

/// Discover a candidate identity without authenticating. The connection pins
/// that same key for rekey; user confirmation is required before any password.
pub(crate) async fn connect_candidate(host: &str, port: u16) -> Result<Connection, Failure> {
    connect_identity(host, port, None).await
}

async fn connect_identity(
    host: &str,
    port: u16,
    key: Option<PublicKey>,
) -> Result<Connection, Failure> {
    let connection = async {
        let stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|_| Failure::Unavailable)?;
        connect_stream_identity(stream, key).await
    };
    tokio::time::timeout(Duration::from_secs(5), connection)
        .await
        .map_err(|_| Failure::Timeout)?
}

/// Continue the exact TCP connection measured by the pre-authentication check.
/// The caller owns its timeout. No DNS lookup, reconnect, or login is performed.
pub(crate) async fn connect_stream_candidate(
    stream: tokio::net::TcpStream,
) -> Result<Connection, Failure> {
    connect_stream_identity(stream, None).await
}

async fn connect_stream_identity(
    stream: tokio::net::TcpStream,
    key: Option<PublicKey>,
) -> Result<Connection, Failure> {
    let peer_addr = stream.peer_addr().map_err(|_| Failure::Unavailable)?;
    let stream = stream.into_std().map_err(|_| Failure::Unavailable)?;
    let shutdown = ShutdownOnDrop(stream.try_clone().map_err(|_| Failure::Unavailable)?);
    let stream = tokio::net::TcpStream::from_std(stream).map_err(|_| Failure::Unavailable)?;
    let (epoch_tx, epoch) = tokio::sync::watch::channel(0);
    let observed = Arc::new(std::sync::Mutex::new(None));
    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(120)),
        ..Default::default()
    };
    let handle = client::connect_stream(
        Arc::new(config),
        stream,
        PinnedKey {
            key,
            observed: observed.clone(),
            epoch: epoch_tx,
        },
    )
    .await
    .map_err(|_| Failure::Identity)?;
    let server_key = observed
        .lock()
        .map_err(|_| Failure::Identity)?
        .clone()
        .ok_or(Failure::Identity)?;
    Ok(Connection {
        handle,
        epoch,
        _shutdown: shutdown,
        server_key,
        peer_addr,
    })
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
