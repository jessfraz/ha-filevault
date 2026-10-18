//! Persistent read-only pairing credential, never a Mac password.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub integration: String,
}
impl Credentials {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        use std::{
            fs::OpenOptions,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        if !path
            .try_exists()
            .map_err(|_| anyhow::anyhow!("check app credential"))?
        {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("generate app credential"))?;
            let value = Self {
                integration: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            };
            getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("generate temporary name"))?;
            let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let temporary = path.with_extension(format!("{suffix}.tmp"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| anyhow::anyhow!("create app credential"))?;
            let result = (|| -> Result<()> {
                file.write_all(
                    &serde_json::to_vec(&value)
                        .map_err(|_| anyhow::anyhow!("encode app credential"))?,
                )
                .map_err(|_| anyhow::anyhow!("write app credential"))?;
                file.sync_all()
                    .map_err(|_| anyhow::anyhow!("persist app credential"))?;
                match std::fs::hard_link(&temporary, path) {
                    Ok(()) => std::fs::File::open(
                        path.parent()
                            .ok_or_else(|| anyhow::anyhow!("credential directory"))?,
                    )?
                    .sync_all()
                    .map_err(|_| anyhow::anyhow!("persist credential directory"))?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(anyhow::anyhow!("publish app credential")),
                }
                Ok(())
            })();
            std::fs::remove_file(&temporary)
                .map_err(|_| anyhow::anyhow!("remove temporary credential"))?;
            result?;
        }
        let meta = std::fs::symlink_metadata(path)
            .map_err(|_| anyhow::anyhow!("read app credential permissions"))?;
        ensure!(
            meta.is_file() && meta.permissions().mode() & 0o077 == 0,
            "app credential must be an owner-only regular file"
        );
        let file = std::fs::File::open(path).map_err(|_| anyhow::anyhow!("open app credential"))?;
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("read app credential"))?;
        ensure!(bytes.len() <= 4096, "invalid app credential");
        let value: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid app credential"))?;
        ensure!(
            (32..=256).contains(&value.integration.len())
                && value.integration.bytes().all(|b| b.is_ascii_graphic()),
            "invalid app credential"
        );
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::Credentials;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn read_only_pairing_credential_is_private_stable_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let first = Credentials::load_or_create(&path).unwrap();
        let second = Credentials::load_or_create(&path).unwrap();
        assert!(first.integration == second.integration);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
        let data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(data.as_object().unwrap().len(), 1);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Credentials::load_or_create(&path).is_err());
    }
    #[test]
    fn concurrent_creation_preserves_one_complete_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("credentials.json"));
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || Credentials::load_or_create(&path).unwrap().integration)
            })
            .collect();
        let values: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(values.iter().all(|v| v == &values[0]));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
