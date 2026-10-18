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
    /// Separate read-only service credential, never a Mac password.
    pub status_token: Option<String>,
    #[serde(default)]
    pub auto_pairing: bool,
}

impl Config {
    pub fn load() -> Result<(Self, Options)> {
        let mut config = Self::parse();
        let mut options: Options = if let Some(path) = &config.options {
            let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("read app options"))?;
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid app options"))?
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
        ensure!(
            !(options.ssh_probe.is_some()
                && options.ssh_recovery.as_ref().is_some_and(|r| r.enabled)),
            "choose one SSH profile"
        );
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
