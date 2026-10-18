use anyhow::{Result, ensure};
use clap::Parser;
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

#[derive(Parser)]
#[command(version, about)]
pub struct Config {
    #[arg(long, env = "FILEVAULT_BIND", default_value = "127.0.0.1:8080")]
    pub bind: SocketAddr,
    #[arg(long, env = "FILEVAULT_STATUS_TOKEN", hide_env_values = true)]
    pub status_token: Option<String>,
    #[arg(long, env = "FILEVAULT_INGRESS_BIND")]
    pub ingress_bind: Option<SocketAddr>,
    #[arg(long, env = "FILEVAULT_INGRESS_PEER", default_value = "172.30.32.2")]
    pub ingress_peer: IpAddr,
    #[arg(long)]
    pub options: Option<PathBuf>,
    #[arg(long)]
    pub openapi: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub allowed_user_ids: Vec<String>,
    pub frontend_origin: Option<String>,
    pub ssh_probe: Option<crate::transport::ProbeConfig>,
    pub ssh_recovery: Option<crate::ssh_recovery::RecoveryConfig>,
    pub manual_ssh: Option<crate::ssh_manual::ManualConfig>,
    /// Separate read-only service credential, never a Mac password.
    pub status_token: Option<String>,
    #[serde(default)]
    pub auto_pairing: bool,
    #[serde(skip)]
    pub invalid_profiles: Vec<&'static str>,
}

impl Options {
    /// SSH sections may fail closed independently. Access-control options must
    /// remain valid; never invent an allowlist/origin from malformed input.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut raw: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid app options JSON"))?;
        let object = raw
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("app options must be an object"))?;
        let automatic = object.remove("ssh_recovery");
        let manual = object.remove("manual_ssh");
        let observer = object.remove("ssh_probe");
        let mut options: Self = serde_json::from_value(raw)
            .map_err(|_| anyhow::anyhow!("invalid app access options"))?;
        if let Some(value) = automatic {
            match serde_json::from_value(value) {
                Ok(profile) => options.ssh_recovery = profile,
                Err(_) => options.invalid_profiles.push("automatic"),
            }
        }
        if let Some(value) = manual {
            match serde_json::from_value(value) {
                Ok(profile) => options.manual_ssh = profile,
                Err(_) => options.invalid_profiles.push("manual"),
            }
        }
        if let Some(value) = observer {
            match serde_json::from_value(value) {
                Ok(profile) => options.ssh_probe = profile,
                Err(_) => options.invalid_profiles.push("observer"),
            }
        }
        Ok(options)
    }
}

impl Config {
    pub fn load() -> Result<(Self, Options)> {
        let mut config = Self::parse();
        let mut options: Options = if let Some(path) = &config.options {
            let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("read app options"))?;
            Options::parse(&bytes)?
        } else {
            Options::default()
        };
        options.frontend_origin = options.frontend_origin.filter(|origin| !origin.is_empty());
        if config.status_token.is_none() {
            config.status_token = options
                .status_token
                .take()
                .filter(|token| !token.is_empty());
        }
        if options.auto_pairing && config.openapi.is_none() {
            ensure!(
                std::env::var_os("SUPERVISOR_TOKEN").is_some_and(|v| !v.is_empty()),
                "automatic pairing requires Supervisor"
            );
            ensure!(
                config.status_token.is_none(),
                "choose automatic or explicit status credential"
            );
            let path = config
                .options
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("automatic pairing requires app options"))?;
            config.status_token = Some(
                crate::credentials::Credentials::load_or_create(
                    &path.with_file_name("credentials.json"),
                )?
                .integration,
            );
        }
        if let Some(origin) = &options.frontend_origin {
            let uri: http::Uri = origin
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid frontend origin"))?;
            ensure!(
                uri.scheme_str() == Some("https")
                    && uri.authority().is_some()
                    && !origin.contains('@')
                    && uri.path_and_query().is_none_or(|p| p.as_str() == "/")
                    && !origin.ends_with('/'),
                "HTTPS origin required without path"
            );
        }
        ensure!(
            config.status_token.as_ref().is_none_or(
                |s| (32..=256).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
            ),
            "invalid read-only status credential"
        );
        Ok((config, options))
    }
}
