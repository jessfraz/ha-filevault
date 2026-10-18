//! Permanent password SSH with explicit first-connection host verification.
use crate::{
    policy::State,
    transport::{Failure, FutureResult, PasswordSession, Session, connect_candidate},
};
use russh::keys::{
    HashAlg, PublicKey,
    known_hosts::{known_host_keys_path, learn_known_hosts_path},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManualConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Internal bootstrap from trusted local provisioning, never a UI requirement.
    #[serde(skip)]
    pub trusted_public_keys: Vec<String>,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct ManualTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_fingerprint: String,
    pub trust_status: &'static str,
    pub trusted: bool,
}

pub struct ManualConnection {
    pub session: Box<dyn Session>,
    pub target: ManualTarget,
    pub server_key: PublicKey,
}

pub trait ManualTransport: Send + Sync {
    fn open(&self) -> FutureResult<'_, Result<ManualConnection, Failure>>;
    fn trust(&self, key: &PublicKey) -> Result<(), Failure>;
}

enum Store {
    Memory(Mutex<Vec<PublicKey>>),
    File { path: PathBuf, lock: Mutex<()> },
}

pub struct SshManual {
    config: ManualConfig,
    store: Store,
}

impl SshManual {
    fn validate(config: &ManualConfig) -> Result<Vec<PublicKey>, Failure> {
        if !config.enabled
            || config.host.is_empty()
            || config.host.len() > 253
            || !config
                .host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_:%".contains(&c))
            || config.port == 0
            || config.username.is_empty()
            || config.username.len() > 255
            || config
                .username
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || config.trusted_public_keys.len() > 4
        {
            return Err(Failure::Unverified);
        }
        let mut keys = Vec::new();
        for value in &config.trusted_public_keys {
            let key = PublicKey::from_openssh(value).map_err(|_| Failure::Identity)?;
            if keys.contains(&key) {
                return Err(Failure::Identity);
            }
            keys.push(key);
        }
        Ok(keys)
    }

    /// In-memory trust is useful for synthetic peers and explicit library use.
    pub fn new(config: ManualConfig) -> Result<Self, Failure> {
        let keys = Self::validate(&config)?;
        Ok(Self {
            config,
            store: Store::Memory(Mutex::new(keys)),
        })
    }

    pub fn with_known_hosts(config: ManualConfig, path: PathBuf) -> Result<Self, Failure> {
        let keys = Self::validate(&config)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file.sync_all().map_err(|_| Failure::Unavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Failure::Unavailable),
        }
        Self::validate_file(&path)?;
        let result = Self {
            config,
            store: Store::File {
                path,
                lock: Mutex::new(()),
            },
        };
        for key in keys {
            result.trust(&key)?;
        }
        Ok(result)
    }

    fn validate_file(path: &Path) -> Result<(), Failure> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() > 1024 * 1024 {
            return Err(Failure::Unverified);
        }
        std::fs::File::open(path).map_err(|_| Failure::Unavailable)?;
        Ok(())
    }

    fn recorded(&self) -> Result<Vec<PublicKey>, Failure> {
        match &self.store {
            Store::Memory(keys) => Ok(keys.lock().map_err(|_| Failure::Unavailable)?.clone()),
            Store::File { path, lock } => {
                let _guard = lock.lock().map_err(|_| Failure::Unavailable)?;
                self.file_keys(path)
            }
        }
    }

    fn file_keys(&self, path: &Path) -> Result<Vec<PublicKey>, Failure> {
        Self::validate_file(path)?;
        Ok(
            known_host_keys_path(&self.config.host, self.config.port, path)
                .map_err(|_| Failure::Unverified)?
                .into_iter()
                .map(|(_, key)| key)
                .collect(),
        )
    }
}

impl ManualTransport for SshManual {
    fn open(&self) -> FutureResult<'_, Result<ManualConnection, Failure>> {
        Box::pin(async move {
            // A candidate handshake proves possession, not trust. No password
            // method is available until the retained identity is confirmed.
            let connection = connect_candidate(&self.config.host, self.config.port).await?;
            let key = connection.server_key.clone();
            let known = self.recorded()?;
            let trusted = known.contains(&key);
            let identity = key.fingerprint(HashAlg::Sha256).to_string();
            Ok(ManualConnection {
                target: ManualTarget {
                    host: self.config.host.clone(),
                    port: self.config.port,
                    username: self.config.username.clone(),
                    host_key_fingerprint: identity.clone(),
                    trust_status: if trusted {
                        "trusted"
                    } else if known.is_empty() {
                        "new"
                    } else {
                        "changed"
                    },
                    trusted,
                },
                server_key: key,
                session: Box::new(PasswordSession {
                    connection,
                    username: self.config.username.clone(),
                    identity,
                    state: State::Unknown,
                    authorized: trusted,
                    manual: true,
                }),
            })
        })
    }

    fn trust(&self, key: &PublicKey) -> Result<(), Failure> {
        match &self.store {
            Store::Memory(keys) => {
                let mut keys = keys.lock().map_err(|_| Failure::Unavailable)?;
                if !keys.contains(key) {
                    if keys.len() >= 4 {
                        return Err(Failure::Rejected);
                    }
                    keys.push(key.clone());
                }
            }
            Store::File { path, lock } => {
                let _guard = lock.lock().map_err(|_| Failure::Unavailable)?;
                let keys = self.file_keys(path)?;
                if !keys.contains(key) {
                    if keys.len() >= 4 {
                        return Err(Failure::Rejected);
                    }
                    learn_known_hosts_path(&self.config.host, self.config.port, key, path)
                        .map_err(|_| Failure::Unavailable)?;
                    if !self.file_keys(path)?.contains(key) {
                        return Err(Failure::Unavailable);
                    }
                    std::fs::File::open(path)
                        .and_then(|f| f.sync_all())
                        .map_err(|_| Failure::Unavailable)?;
                }
            }
        }
        Ok(())
    }
}
