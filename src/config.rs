use anyhow::{Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
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
    #[arg(long, env = "FILEVAULT_DATABASE", default_value = "filevault.sqlite3")]
    pub database: PathBuf,
    /// Background check cadence; failures back off up to five minutes.
    #[arg(long, env = "FILEVAULT_CHECK_INTERVAL_SECONDS", default_value = "60", value_parser = clap::value_parser!(u64).range(15..=300))]
    pub check_interval_seconds: u64,
    /// Applies only to observations created by this version.
    #[arg(long, env = "FILEVAULT_HISTORY_DAYS", default_value = "14", value_parser = clap::value_parser!(u32).range(1..=90))]
    pub history_days: u32,
    #[arg(long)]
    pub options: Option<PathBuf>,
    #[arg(long)]
    pub openapi: Option<PathBuf>,
    #[arg(long, requires = "migration_output", conflicts_with_all = ["options", "openapi"])]
    pub migrate_options: Option<PathBuf>,
    #[arg(long, requires = "migrate_options")]
    pub migration_output: Option<PathBuf>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MacConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub manual_enabled: bool,
    pub tailscale_host: String,
}
impl Default for MacConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: String::new(),
            manual_enabled: true,
            tailscale_host: String::new(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutomaticConfig {
    pub enabled: bool,
    pub preboot_public_key: String,
    pub runtime_public_key: String,
    pub manual_enrollment_verified: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub allowed_user_ids: Vec<String>,
    pub frontend_origin: Option<String>,
    pub mac: Option<MacConfig>,
    pub automatic: Option<AutomaticConfig>,
    /// Separate read-only service credential, never a Mac password.
    pub status_token: Option<String>,
    #[serde(default)]
    pub auto_pairing: bool,
    #[serde(skip)]
    pub invalid_profiles: Vec<&'static str>,
    #[serde(skip)]
    pub migrated: bool,
}

impl Options {
    /// Resolve every legacy target before constructing any transport. Malformed
    /// access controls remain fatal; connection conflicts disable all SSH paths.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        crate::migration::parse(bytes)
    }
}

impl Config {
    pub fn load() -> Result<(Self, Options)> {
        let mut config = Self::parse();
        if config.migrate_options.is_some() {
            return Ok((config, Options::default()));
        }
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
