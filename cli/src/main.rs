//! Native client. Integration reads and HA-authenticated recovery stay separate.
mod ha;
mod unlock;
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use reqwest::{Client, Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::PathBuf, process::ExitCode, time::Duration};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: usize = 65_536;

#[derive(Parser)]
#[command(version, about, disable_help_subcommand = true)]
struct Args {
    /// Read through the native API or the installed Home Assistant integration
    #[arg(long, value_enum, default_value_t = Transport::Native)]
    transport: Transport,
    /// Selected API origin; defaults to HA_FILEVAULT_URL or HOME_ASSISTANT_URL
    #[arg(long)]
    url: Option<String>,
    /// Owner-only token file; native defaults to HA_FILEVAULT_TOKEN_FILE, HA to HOME_ASSISTANT_TOKEN
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Transport {
    Native,
    HomeAssistant,
}

#[derive(Clone, Copy, Subcommand)]
enum Command {
    /// Read capabilities and verify the integration credential role
    System,
    /// Read status: native makes a fresh observation; HA reads its bounded cached snapshot
    Status,
    /// Unlock the configured Mac and wait for verified normal runtime
    Unlock(unlock::Args),
}

impl Command {
    fn path(self) -> Option<&'static str> {
        match self {
            Self::System => Some("/v1/system"),
            Self::Status => Some("/v1/status"),
            Self::Unlock(_) => None,
        }
    }
}

// Owned consumer DTOs mirror the external integration response, not ingress.
// Server DTOs contain &'static str fields and cannot deserialize client data.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Running,
    SshReachable,
    VerifiedPreboot,
    Unreachable,
    Unknown,
}

#[derive(Deserialize, Serialize)]
struct Decision {
    state: State,
    unlock_available: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeCheck {
    Unknown,
    NotConfigured,
    Verified,
    IdentityNeeded,
    Unavailable,
    NameUnavailable,
    TimedOut,
    Stale,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum IntegrationRole {
    Integration,
}

#[derive(Deserialize, Serialize)]
struct Configuration {
    version: String,
    manual_ready: bool,
    configuration_errors: Vec<String>,
    configuration_notes: Vec<String>,
    // An integration response must contain null, never owner connection details.
    connection: Option<()>,
}

#[derive(Deserialize, Serialize)]
struct SystemResponse {
    credential_role: IntegrationRole,
    #[serde(flatten)]
    configuration: Configuration,
}

#[derive(Deserialize, Serialize)]
struct StatusResponse {
    decision: Decision,
    transport_ready: bool,
    runtime_check: RuntimeCheck,
    #[serde(flatten)]
    configuration: Configuration,
}

#[derive(Deserialize, Serialize)]
struct HaHealth {
    available: bool,
    manual_ready: Option<bool>,
    advanced_detection_ready: Option<bool>,
    runtime_check: RuntimeCheck,
    configuration_error_count: Option<usize>,
    setup_note_count: Option<usize>,
}

#[derive(Deserialize, Serialize)]
struct HaStatus {
    state: State,
    observation_age_seconds: Option<u64>,
    #[serde(flatten)]
    health: HaHealth,
}

#[derive(Deserialize, Serialize)]
struct HaSystem {
    version: String,
    #[serde(flatten)]
    health: HaHealth,
}

fn endpoint(value: &str, command: Command) -> Result<Url, &'static str> {
    let invalid = "invalid external API origin";
    if value.contains('\\') || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid);
    }
    let mut url = Url::parse(value).map_err(|_| invalid)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        // Even empty userinfo is not an origin configuration.
        || value.split("://").nth(1).is_some_and(|s| s.contains('@'))
    {
        return Err(invalid);
    }
    url.set_path(command.path().ok_or(invalid)?);
    Ok(url)
}

fn credential(path: &std::path::Path, maximum: usize) -> Result<HeaderValue, &'static str> {
    use std::os::unix::fs::PermissionsExt;
    let error = "token file must be an owner-only regular file containing an integration token";
    let metadata = std::fs::symlink_metadata(path).map_err(|_| error)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(error);
    }
    let file = std::fs::File::open(path).map_err(|_| error)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((maximum + 3) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    // Accept a single line with an optional LF or CRLF, not arbitrary whitespace.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if !(32..=maximum).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_graphic) {
        return Err(error);
    }
    let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
    bearer.extend_from_slice(&bytes);
    let mut header = HeaderValue::from_bytes(&bearer).map_err(|_| error)?;
    header.set_sensitive(true);
    Ok(header)
}

fn ha_credential(path: Option<&std::path::Path>) -> Result<HeaderValue, &'static str> {
    if let Some(path) = path {
        return credential(path, 8192);
    }
    let token = Zeroizing::new(
        std::env::var("HOME_ASSISTANT_TOKEN").map_err(|_| "configure HOME_ASSISTANT_TOKEN")?,
    );
    if token.is_empty() || token.len() > 8192 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("HOME_ASSISTANT_TOKEN is invalid");
    }
    let bearer = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let mut header =
        HeaderValue::from_str(&bearer).map_err(|_| "HOME_ASSISTANT_TOKEN is invalid")?;
    header.set_sensitive(true);
    Ok(header)
}

enum Failure {
    Local(&'static str),
    Http { status: u16, message: &'static str },
}

impl From<&'static str> for Failure {
    fn from(message: &'static str) -> Self {
        Self::Local(message)
    }
}

async fn run(args: Args) -> Result<String, Failure> {
    if let Command::Unlock(options) = args.command {
        unlock::run(options).await?;
        return Ok("Mac is running (fresh runtime verified).".into());
    }
    let (url, token) = match args.transport {
        Transport::Native => {
            let configured = args.url.or_else(|| std::env::var("HA_FILEVAULT_URL").ok());
            let url = endpoint(
                configured
                    .as_deref()
                    .ok_or("configure HA_FILEVAULT_URL or --url")?,
                args.command,
            )?;
            let path = args
                .token_file
                .or_else(|| std::env::var_os("HA_FILEVAULT_TOKEN_FILE").map(PathBuf::from));
            let token = credential(
                path.as_deref()
                    .ok_or("configure HA_FILEVAULT_TOKEN_FILE or --token-file")?,
                256,
            )?;
            (url, token)
        }
        Transport::HomeAssistant => {
            let configured = args
                .url
                .or_else(|| std::env::var("HOME_ASSISTANT_URL").ok());
            let mut url = ha::origin(
                configured
                    .as_deref()
                    .ok_or("configure HOME_ASSISTANT_URL or --url")?,
            )?;
            url.set_path(match args.command {
                Command::System => "/api/filevault/v1/system",
                Command::Status => "/api/filevault/v1/status",
                Command::Unlock(_) => return Err("invalid integration command".into()),
            });
            (url, ha_credential(args.token_file.as_deref())?)
        }
    };
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        // No ambient credential-bearing proxy, cookie store, or HTTP/2 replay.
        .no_proxy()
        .http1_only()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "HTTP client unavailable")?;
    let mut response = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, token)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| "external API request failed")?;
    let status = response.status().as_u16();
    let message = match status {
        200 => None,
        401 | 403 => Some("integration credential rejected"),
        300..=399 => Some("external API redirect refused"),
        _ => Some("external API unavailable"),
    };
    if let Some(message) = message {
        // The two external routes define no application error codes. Preserve
        // HTTP status, never arbitrary Dropshot messages or redirect locations.
        return Err(Failure::Http { status, message });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "external API response failed")?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err("external API response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    let invalid = "invalid integration API response";
    match (args.transport, args.command) {
        (Transport::Native, Command::System) => {
            let report: SystemResponse = serde_json::from_slice(&body).map_err(|_| invalid)?;
            serde_json::to_string(&report)
        }
        (Transport::Native, Command::Status) => {
            let report: StatusResponse = serde_json::from_slice(&body).map_err(|_| invalid)?;
            serde_json::to_string(&report)
        }
        (Transport::HomeAssistant, Command::System) => {
            let report: HaSystem = serde_json::from_slice(&body).map_err(|_| invalid)?;
            serde_json::to_string(&report)
        }
        (Transport::HomeAssistant, Command::Status) => {
            let report: HaStatus = serde_json::from_slice(&body).map_err(|_| invalid)?;
            serde_json::to_string(&report)
        }
        (_, Command::Unlock(_)) => return Err("invalid integration command".into()),
    }
    .map_err(|_| Failure::from("JSON output unavailable"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Err(_) => {
            // Clap's normal diagnostics echo untrusted arguments and env values.
            eprintln!("ha-filevault: invalid arguments; run ha-filevault --help");
            return ExitCode::from(2);
        }
    };
    match run(args).await {
        Ok(json) => {
            use std::io::Write;
            match writeln!(std::io::stdout().lock(), "{json}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("ha-filevault: output failed");
                    ExitCode::FAILURE
                }
            }
        }
        Err(failure) => {
            match failure {
                Failure::Local(message) => eprintln!("ha-filevault: {message}"),
                Failure::Http { status, message } => {
                    eprintln!("ha-filevault: HTTP {status}: {message}");
                }
            }
            ExitCode::FAILURE
        }
    }
}
