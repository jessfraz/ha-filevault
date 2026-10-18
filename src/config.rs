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
}

impl Config {
    pub fn load() -> Result<(Self, Options)> {
        let config = Self::parse();
        let options = if let Some(path) = &config.options {
            let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("read app options"))?;
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid app options"))?
        } else {
            Options::default()
        };
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
