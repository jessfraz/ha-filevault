//! One canonical Mac target. Legacy fields are input-only migration formats.
use crate::config::{AutomaticConfig, MacConfig, Options};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

fn host(value: &str) -> String {
    value.parse::<std::net::IpAddr>().map_or_else(
        |_| value.trim_end_matches('.').to_ascii_lowercase(),
        |ip| ip.to_string(),
    )
}

pub fn parse(bytes: &[u8]) -> Result<Options> {
    let mut raw: Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid app options JSON"))?;
    let object = raw
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("app options must be an object"))?;
    let mac = object.remove("mac").filter(|v| !v.is_null());
    let automatic = object.remove("automatic").filter(|v| !v.is_null());
    let recovery = object.remove("ssh_recovery").filter(|v| !v.is_null());
    let manual = object.remove("manual_ssh").filter(|v| !v.is_null());
    let probe = object.remove("ssh_probe").filter(|v| !v.is_null());
    let mut result: Options =
        serde_json::from_value(raw).map_err(|_| anyhow::anyhow!("invalid app access options"))?;
    result.migrated = recovery.is_some() || manual.is_some() || probe.is_some();
    let mut candidates = Vec::new();
    let mut connection = MacConfig::default();
    let new_manual_flag = mac
        .as_ref()
        .is_some_and(|v| v.get("manual_enabled").is_some());
    if let Some(value) = mac {
        match serde_json::from_value::<MacConfig>(value) {
            Ok(value) => {
                candidates.push(value.clone());
                connection = value;
            }
            Err(_) => result.invalid_profiles.push("connection"),
        }
    }
    if let Some(value) = automatic {
        match serde_json::from_value::<AutomaticConfig>(value) {
            Ok(value) => result.automatic = Some(value),
            Err(_) => result.invalid_profiles.push("automatic"),
        }
    }
    if let Some(mut value) = recovery {
        if value.get("port").is_none()
            && let Some(v) = value.as_object_mut()
        {
            v.insert("port".into(), Value::from(22));
        }
        match serde_json::from_value::<crate::ssh_recovery::RecoveryConfig>(value) {
            Ok(old) => {
                candidates.push(MacConfig {
                    host: old.host,
                    port: old.port,
                    username: old.username,
                    ..Default::default()
                });
                let old = AutomaticConfig {
                    enabled: old.enabled,
                    preboot_public_key: old.preboot_public_key,
                    runtime_public_key: old.runtime_public_key,
                    manual_enrollment_verified: old.manual_enrollment_verified,
                };
                if let Some(new) = &result.automatic {
                    if serde_json::to_value(new)? != serde_json::to_value(&old)? {
                        result.invalid_profiles.push("identity_conflict");
                    }
                } else {
                    result.automatic = Some(old);
                }
            }
            Err(_) => result.invalid_profiles.push("connection"),
        }
    }
    if let Some(mut value) = manual {
        if value.get("port").is_none()
            && let Some(v) = value.as_object_mut()
        {
            v.insert("port".into(), Value::from(22));
        }
        match serde_json::from_value::<crate::ssh_manual::ManualConfig>(value) {
            Ok(old) => {
                if !new_manual_flag {
                    connection.manual_enabled = old.enabled;
                }
                candidates.push(MacConfig {
                    host: old.host,
                    port: old.port,
                    username: old.username,
                    ..Default::default()
                });
            }
            Err(_) => result.invalid_profiles.push("connection"),
        }
    }
    if let Some(value) = probe {
        match serde_json::from_value::<crate::transport::ProbeConfig>(value) {
            Ok(old) => {
                candidates.push(MacConfig {
                    host: old.host,
                    port: old.port,
                    ..Default::default()
                });
                let automatic = result.automatic.get_or_insert_with(Default::default);
                if automatic.runtime_public_key.is_empty() {
                    automatic.runtime_public_key = old.pinned_public_key;
                } else if automatic.runtime_public_key != old.pinned_public_key {
                    result.invalid_profiles.push("identity_conflict");
                }
            }
            Err(_) => result.invalid_profiles.push("connection"),
        }
    }
    let mut selected_host = None;
    let mut selected_port = None;
    let mut selected_user = None;
    for candidate in candidates {
        if !candidate.host.is_empty() {
            let value = host(&candidate.host);
            if selected_host.as_ref().is_some_and(|old| old != &value)
                || selected_port.is_some_and(|old| old != candidate.port)
            {
                result.invalid_profiles.push("target_conflict");
            }
            selected_host = Some(value);
            selected_port = Some(candidate.port);
        } else if candidate.port != 0 && candidate.port != 22 {
            if selected_port.is_some_and(|old| old != candidate.port) {
                result.invalid_profiles.push("target_conflict");
            }
            selected_port = Some(candidate.port);
        }
        if !candidate.username.is_empty() {
            if selected_user
                .as_ref()
                .is_some_and(|old| old != &candidate.username)
            {
                result.invalid_profiles.push("target_conflict");
            }
            selected_user = Some(candidate.username);
        }
    }
    if let Some(value) = selected_host {
        connection.host = value;
    }
    if let Some(value) = selected_port {
        connection.port = value;
    }
    if let Some(value) = selected_user {
        connection.username = value;
    }
    result.invalid_profiles.sort_unstable();
    result.invalid_profiles.dedup();
    if !connection.tailscale_host.is_empty() {
        connection.tailscale_host = host(&connection.tailscale_host);
    }
    result.mac = Some(connection);
    result.automatic.get_or_insert_with(Default::default);
    result.frontend_origin.get_or_insert_with(String::new);
    result.status_token.get_or_insert_with(String::new);
    Ok(result)
}

/// Explicit migration creates one private output and never overwrites the input.
/// HA's owner applies it through Supervisor after the new schema is installed.
pub fn write(input: &Path, output: &Path) -> Result<()> {
    let bytes = std::fs::read(input).map_err(|_| anyhow::anyhow!("read original app options"))?;
    let options = parse(&bytes)?;
    ensure!(
        options.invalid_profiles.is_empty(),
        "migration needs review: conflicting targets, invalid fields, or identities; original options preserved"
    );
    if let Some(mac) = &options.mac {
        ensure!(
            mac.port != 0
                && mac.host.len() <= 253
                && mac
                    .host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_:%".contains(&c))
                && mac.username.len() <= 255
                && !mac
                    .username
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control()),
            "migration needs review: invalid Mac connection; original options preserved"
        );
    }
    let mut bytes = serde_json::to_vec_pretty(&options)?;
    bytes.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|_| anyhow::anyhow!("create new private migration output"))?;
    file.write_all(&bytes)
        .map_err(|_| anyhow::anyhow!("write private migration output"))?;
    file.sync_all()
        .map_err(|_| anyhow::anyhow!("sync private migration output"))?;
    Ok(())
}
