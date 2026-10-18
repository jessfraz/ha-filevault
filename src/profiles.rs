//! Every transport is derived from the same canonical Mac connection.
use crate::{
    config::{MacConfig, Options},
    runtime::{RuntimeObserver, TailnetRuntime},
    ssh_manual::{ManualConfig, ManualTransport, SshManual},
    ssh_recovery::{RecoveryConfig, SshRecovery},
    transport::{Disabled, ProbeConfig, SshProbe, Transport},
};
use std::{path::Path, sync::Arc};

pub struct Profiles {
    pub transport: Arc<dyn Transport>,
    pub observer: Option<Arc<dyn Transport>>,
    pub manual: Option<Arc<dyn ManualTransport>>,
    pub runtime: Option<Arc<dyn RuntimeObserver>>,
    pub connection: Option<MacConfig>,
    pub errors: Vec<&'static str>,
    pub notes: Vec<&'static str>,
}

pub fn build(options: &Options, path: Option<&Path>) -> Profiles {
    let mut result = Profiles {
        transport: Arc::new(Disabled),
        observer: None,
        manual: None,
        runtime: None,
        connection: options.mac.clone(),
        errors: Vec::new(),
        notes: Vec::new(),
    };
    for kind in &options.invalid_profiles {
        result.errors.push(match *kind {
            "target_conflict" => "Connection settings disagree. Review the migration inputs and keep one Mac target before connecting. No target was selected.",
            "identity_conflict" => "Saved server identity settings disagree. Verify the Mac's server identity before connecting.",
            "automatic" => "Advanced FileVault detection settings could not be read. Manual SSH and the Tailscale running check remain independent.",
            _ => "Mac connection settings could not be read. Review the single Mac connection profile; never save an account password in settings.",
        });
    }
    if options.invalid_profiles.iter().any(|k| *k != "automatic") {
        result.connection = None;
        return result;
    }
    let Some(mac) = &options.mac else {
        return result;
    };
    if mac.host.is_empty() {
        result.notes.push("Set the Mac connection once in app settings. Manual SSH and automatic checks share it.");
        return result;
    }
    let mut trusted_public_keys = Vec::new();
    if let Some(automatic) = &options.automatic {
        if !automatic.runtime_public_key.is_empty() {
            match SshProbe::new(ProbeConfig { host: mac.host.clone(), port: mac.port,
                pinned_public_key: automatic.runtime_public_key.clone() }) {
                Ok(probe) => { result.observer = Some(Arc::new(probe));
                    trusted_public_keys.push(automatic.runtime_public_key.clone()); }
                Err(_) => result.errors.push("A saved Mac server identity could not be read. Verify its fingerprint in Connect with SSH; no client key or saved login password is needed."),
            }
        }
        if automatic.enabled {
            if automatic.preboot_public_key.is_empty()
                || automatic.runtime_public_key.is_empty()
                || !automatic.manual_enrollment_verified
            {
                result.notes.push("FileVault preboot detection has not been learned. This does not block manual SSH or the normal Tailscale running check.");
            } else {
                match SshRecovery::new(RecoveryConfig { enabled: true,
                    host: mac.host.clone(), port: mac.port, username: mac.username.clone(),
                    preboot_public_key: automatic.preboot_public_key.clone(),
                    runtime_public_key: automatic.runtime_public_key.clone(),
                    manual_enrollment_verified: automatic.manual_enrollment_verified }) {
                    Ok(profile) => result.transport = Arc::new(profile),
                    Err(_) => result.errors.push("Advanced FileVault identities need review. They cannot establish the current boot phase; manual SSH remains available."),
                }
            }
        }
    }
    let manual = path
        .map(|p| p.with_file_name("ssh_known_hosts"))
        .ok_or(crate::transport::Failure::Unverified)
        .and_then(|path| {
            SshManual::with_known_hosts(
                ManualConfig {
                    enabled: true,
                    host: mac.host.clone(),
                    port: mac.port,
                    username: mac.username.clone(),
                    trusted_public_keys,
                },
                path,
            )
        });
    match manual {
        Ok(manual) => {
            let identities: Arc<dyn ManualTransport> = Arc::new(manual);
            if !mac.tailscale_host.is_empty() {
                match TailnetRuntime::new(Arc::new(mac.clone()), identities.clone()) {
                    Ok(runtime) => result.runtime = Some(Arc::new(runtime)),
                    Err(_) => result.errors.push("Use this Mac's full Tailscale hostname or Tailscale IP address for its running check. The LAN password connection remains available."),
                }
            }
            if mac.manual_enabled { result.manual = Some(identities); }
        }
        Err(_) => result.errors.push("Check the Mac connection's LAN host, port and username. Server identity is verified in the app; no client key or saved password is required."),
    }
    if options
        .frontend_origin
        .as_ref()
        .is_none_or(|o| o.is_empty())
        && mac.manual_enabled
    {
        result
            .notes
            .push("Set the Home Assistant HTTPS origin before using the password dialog.");
    }
    result
}
