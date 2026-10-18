//! Invalid SSH options disable that action, not the authenticated dashboard.
use crate::{
    config::Options,
    ssh_manual::{ManualTransport, SshManual},
    ssh_recovery::SshRecovery,
    transport::{Disabled, ProbeConfig, SshProbe, Transport},
};
use std::{path::Path, sync::Arc};

pub struct Profiles {
    pub transport: Arc<dyn Transport>,
    pub observer: Option<Arc<dyn Transport>>,
    pub manual: Option<Arc<dyn ManualTransport>>,
    pub errors: Vec<&'static str>,
}

pub fn build(options: &Options, path: Option<&Path>) -> Profiles {
    let mut result = Profiles {
        transport: Arc::new(Disabled),
        observer: None,
        manual: None,
        errors: Vec::new(),
    };
    for kind in &options.invalid_profiles {
        result.errors.push(match *kind {
            "manual" => "Manual SSH options have invalid types or unsupported fields. The action is disabled; account passwords must be entered only in the app dialog.",
            "automatic" => "Automatic phase options have invalid types or unsupported fields. Automatic suggestions are disabled; no account password belongs in these options.",
            _ => "SSH observer options are invalid. Reachability is unverified.",
        });
    }
    if let Some(recovery) = &options.ssh_recovery {
        if recovery.enabled {
            match SshRecovery::new(recovery.clone()) {
                Ok(profile) => result.transport = Arc::new(profile),
                Err(_) => result.errors.push("Automatic phase detection is incomplete or invalid. The dashboard stays available; automatic unlock is disabled."),
            }
        }
        if !recovery.runtime_public_key.is_empty() {
            match SshProbe::new(ProbeConfig {
                host: recovery.host.clone(),
                port: recovery.port,
                pinned_public_key: recovery.runtime_public_key.clone(),
            }) {
                Ok(probe) => result.observer = Some(Arc::new(probe)),
                Err(_) => result.errors.push(
                    "The saved runtime server identity is invalid. SSH reachability is unverified.",
                ),
            }
        }
    }
    if let Some(probe) = &options.ssh_probe {
        match SshProbe::new(probe.clone()) {
            Ok(probe) => result.observer = Some(Arc::new(probe)),
            Err(_) => result
                .errors
                .push("The saved SSH observer is invalid. SSH reachability is unverified."),
        }
    }
    let mut manual = options.manual_ssh.clone();
    if manual
        .as_ref()
        .is_none_or(|m| m.enabled && m.host.is_empty() && m.username.is_empty())
        && !options.invalid_profiles.contains(&"manual")
        && let Some(recovery) = options
            .ssh_recovery
            .as_ref()
            .filter(|r| !r.host.is_empty() && !r.username.is_empty())
    {
        manual = Some(crate::ssh_manual::ManualConfig {
            enabled: true,
            host: recovery.host.clone(),
            port: recovery.port,
            username: recovery.username.clone(),
            trusted_public_keys: Vec::new(),
        });
    }
    if let Some(mut config) = manual.filter(|c| c.enabled) {
        if options
            .frontend_origin
            .as_ref()
            .is_none_or(|origin| origin.is_empty())
        {
            result.errors.push("Set the exact Home Assistant HTTPS origin before sending an SSH password. Host and username alone do not authorize browser requests.");
        }
        if let Some(recovery) = options.ssh_recovery.as_ref().filter(|r| !r.host.is_empty()) {
            if recovery.host != config.host
                || recovery.port != config.port
                || (!recovery.username.is_empty() && recovery.username != config.username)
            {
                result.errors.push(
                    "Manual SSH and the status profile must refer to the same configured target.",
                );
                return result;
            }
            // An explicitly provisioned runtime public key is a trusted local
            // bootstrap. It says nothing about a preboot identity or phase.
            if !recovery.runtime_public_key.is_empty()
                && russh::keys::PublicKey::from_openssh(&recovery.runtime_public_key).is_ok()
            {
                config
                    .trusted_public_keys
                    .push(recovery.runtime_public_key.clone());
            }
        }
        let manual = path
            .map(|path| path.with_file_name("ssh_known_hosts"))
            .ok_or(crate::transport::Failure::Unverified)
            .and_then(|path| SshManual::with_known_hosts(config, path));
        match manual {
            Ok(manual) => result.manual = Some(Arc::new(manual)),
            Err(_) => result.errors.push("Manual SSH configuration or its host identity store is unavailable. Check host, port, and username; no saved password or client key is required."),
        }
    }
    result
}
