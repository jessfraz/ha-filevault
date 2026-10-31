//! One password attempt, followed by independent fresh runtime verification.
use crate::{RuntimeCheck, State, ha};
use reqwest::{Client, Method, Response, header::HeaderValue};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    io::{BufRead, IsTerminal, Read, Write},
    time::Duration,
};
use tokio::time::{Instant, sleep};
use zeroize::Zeroizing;

#[derive(Clone, Copy, clap::Args)]
pub struct Args {
    /// Read the Mac password from stdin instead of the hidden terminal prompt
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Deserialize)]
struct Status {
    decision: crate::Decision,
    runtime_check: RuntimeCheck,
    manual_ready: bool,
}

impl Status {
    fn running(&self) -> bool {
        matches!(self.decision.state, State::Running)
            && matches!(self.runtime_check, RuntimeCheck::Verified)
    }
}

#[derive(Deserialize)]
struct Recovery {
    busy: bool,
    retry_after_ms: u64,
}

#[derive(Deserialize)]
struct Target {
    host: String,
    port: u16,
    username: String,
    host_key_fingerprint: String,
    trusted: bool,
}

#[derive(Deserialize)]
struct Challenge {
    nonce: String,
    target: Target,
}

#[derive(Deserialize)]
struct Trust {
    trusted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Running,
    Booting,
    Rejected,
    TimedOut,
    Authenticated,
    Unconfirmed,
}

#[derive(Deserialize)]
struct Attempt {
    outcome: Outcome,
}

#[derive(Deserialize)]
struct PreparationFailure {
    error_code: String,
}

struct Api {
    client: Client,
    ingress: ha::Ingress,
}

impl Api {
    fn request(&self, method: Method, path: &str) -> Result<reqwest::RequestBuilder, &'static str> {
        let url = self
            .ingress
            .base
            .join(path)
            .map_err(|_| "invalid FileVault endpoint")?;
        Ok(self
            .client
            .request(method, url)
            .timeout(Duration::from_secs(15))
            .header("cookie", self.ingress.cookie.clone())
            .header("x-filevault-client", "native-cli")
            .header("accept", "application/json"))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, &'static str> {
        let response = self
            .request(Method::GET, path)?
            .send()
            .await
            .map_err(|_| "FileVault observation failed")?;
        decode(response).await
    }
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, &'static str> {
    match response.status().as_u16() {
        200 => (),
        401 | 403 => return Err("FileVault access denied; allow this HA user in the app settings"),
        404 => return Err("FileVault app needs an update to support native unlock"),
        409 | 429 => return Err("FileVault recovery is busy or cooling down; no retry was sent"),
        300..=399 => return Err("FileVault redirect refused"),
        _ => return Err("FileVault request unavailable"),
    }
    read_json(response).await
}

async fn read_json<T: DeserializeOwned>(mut response: Response) -> Result<T, &'static str> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "FileVault response failed")?
    {
        if chunk.len() > crate::MAX_RESPONSE_BYTES - bytes.len() {
            return Err("FileVault response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid FileVault response")
}

fn cookie(response: &Response) -> Result<HeaderValue, &'static str> {
    let mut cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|header| header.to_str().ok())
        .filter_map(|line| line.split(';').next())
        .filter_map(|pair| pair.strip_prefix("fv_session="));
    let value = cookies.next().ok_or("FileVault request grant missing")?;
    if cookies.next().is_some()
        || value.len() != 64
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid FileVault request grant");
    }
    let mut header = HeaderValue::from_str(&format!("fv_session={value}"))
        .map_err(|_| "invalid FileVault request grant")?;
    header.set_sensitive(true);
    Ok(header)
}

fn safe_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.bytes().all(|b| b.is_ascii_graphic())
}

fn password(stdin: bool) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = if stdin {
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::stdin()
            .lock()
            .take(1027)
            .read_to_end(&mut bytes)
            .map_err(|_| "password input failed")?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        bytes
    } else {
        let mut value =
            Zeroizing::new(rpassword::prompt_password("Mac login password: ").map_err(
                |_| "hidden password prompt unavailable; use --password-stdin for automation",
            )?);
        Zeroizing::new(std::mem::take(&mut *value).into_bytes())
    };
    if bytes.is_empty()
        || bytes.len() > 1024
        || std::str::from_utf8(&bytes).is_err()
        || bytes.iter().any(|b| matches!(b, 0 | b'\r' | b'\n'))
    {
        bytes.clear();
        return Err("password must be one nonempty UTF-8 line, at most 1024 bytes");
    }
    Ok(bytes)
}

fn confirm_target(target: &Target, stdin: bool) -> Result<bool, &'static str> {
    if target.port == 0
        || !safe_label(&target.host)
        || !safe_label(&target.username)
        || !safe_label(&target.host_key_fingerprint)
        || !target.host_key_fingerprint.starts_with("SHA256:")
    {
        return Err("invalid FileVault SSH identity");
    }
    eprintln!(
        "Target: {}@{}:{}",
        target.username, target.host, target.port
    );
    eprintln!("SSH fingerprint: {}", target.host_key_fingerprint);
    if target.trusted {
        return Ok(false);
    }
    if stdin || !std::io::stdin().is_terminal() {
        return Err(
            "SSH identity needs approval; verify its fingerprint in the FileVault app first",
        );
    }
    eprint!("Verify this fingerprint independently. Trust this server? [y/N] ");
    std::io::stderr()
        .flush()
        .map_err(|_| "confirmation output failed")?;
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .take(16)
        .read_line(&mut answer)
        .map_err(|_| "confirmation input failed")?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        return Err("SSH identity was not approved; no password sent");
    }
    Ok(true)
}

pub async fn run(options: Args) -> Result<(), &'static str> {
    let base = ha::origin(
        &std::env::var("HOME_ASSISTANT_URL")
            .map_err(|_| "configure HOME_ASSISTANT_URL and HOME_ASSISTANT_TOKEN")?,
    )?;
    let token = Zeroizing::new(
        std::env::var("HOME_ASSISTANT_TOKEN")
            .map_err(|_| "configure HOME_ASSISTANT_URL and HOME_ASSISTANT_TOKEN")?,
    );
    eprintln!("Connecting to Home Assistant…");
    let ingress = ha::ingress(base, &token).await?;
    drop(token);
    let api = Api {
        client: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .http1_only()
            .timeout(Duration::from_secs(180))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "HTTP client unavailable")?,
        ingress,
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut wait_notice = false;
    let mut ssh_notice = false;
    let response = loop {
        if Instant::now() >= deadline {
            return Err("SSH recovery did not become available; no password sent");
        }
        let status: Status = api.get("v1/status").await?;
        if status.running() {
            return Ok(());
        }
        if matches!(status.runtime_check, RuntimeCheck::NotConfigured) {
            return Err("configure the app's normal-runtime Tailscale check before using unlock");
        }
        if !status.manual_ready {
            return Err("SSH recovery is not configured in the FileVault app");
        }
        let recovery: Recovery = api.get("v1/recovery").await?;
        if recovery.busy || recovery.retry_after_ms > 0 {
            if !wait_notice {
                eprintln!("Waiting for the current recovery or cooldown…");
                wait_notice = true;
            }
            sleep(Duration::from_millis(
                recovery.retry_after_ms.clamp(1000, 3000),
            ))
            .await;
            continue;
        }
        let response = api
            .request(Method::POST, "v1/cli/session")?
            .send()
            .await
            .map_err(|_| "SSH preparation failed; no password sent")?;
        if matches!(response.status().as_u16(), 502 | 504) {
            let failure: PreparationFailure = read_json(response).await?;
            if failure.error_code == "ssh_identity" {
                return Err("SSH identity verification failed; no password sent");
            }
            if !matches!(
                failure.error_code.as_str(),
                "ssh_unavailable" | "ssh_timeout" | "ssh_resolution"
            ) {
                return Err("SSH preparation failed; no password sent");
            }
            // These errors are issued before a grant exists or a password is
            // accepted. Retry preparation only, never credential submission.
            if !ssh_notice {
                eprintln!("Waiting for the Mac's SSH service to become available…");
                ssh_notice = true;
            }
            sleep(Duration::from_secs(2)).await;
            continue;
        }
        break response;
    };
    // Decode HTTP rejection before requiring the session cookie.
    if response.status().as_u16() != 200 {
        decode::<Challenge>(response).await?;
        return Err("SSH preparation failed");
    }
    let grant_cookie = cookie(&response)?;
    let challenge: Challenge = decode(response).await?;
    if challenge.nonce.len() != 64 || !challenge.nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid FileVault request grant");
    }
    let combined = Zeroizing::new(format!(
        "{}; {}",
        api.ingress
            .cookie
            .to_str()
            .map_err(|_| "invalid ingress session")?,
        grant_cookie.to_str().map_err(|_| "invalid request grant")?
    ));
    let mut cookies = HeaderValue::from_str(&combined).map_err(|_| "invalid request cookies")?;
    cookies.set_sensitive(true);
    let mut nonce = HeaderValue::from_str(&challenge.nonce).map_err(|_| "invalid request nonce")?;
    nonce.set_sensitive(true);
    if confirm_target(&challenge.target, options.password_stdin)? {
        let response = api
            .request(Method::POST, "v1/cli/trust")?
            .header("cookie", cookies.clone())
            .header("x-filevault-nonce", nonce.clone())
            .header("x-filevault-confirm", "verified_host_identity")
            .send()
            .await
            .map_err(|_| "SSH identity confirmation failed; no password sent")?;
        if !decode::<Trust>(response).await?.trusted {
            return Err("SSH identity confirmation failed; no password sent");
        }
    }
    let password = password(options.password_stdin)?;
    eprintln!("Sending one password attempt; waiting for verified normal runtime…");
    let attempt = api
        .request(Method::POST, "v1/cli/attempt")?
        .timeout(Duration::from_secs(180))
        .header("cookie", cookies)
        .header("x-filevault-nonce", nonce)
        .header("x-filevault-confirm", "manual_ssh")
        .header("content-type", "application/octet-stream")
        .body(password.to_vec())
        .send();
    drop(password);
    tokio::pin!(attempt);
    let outcome = loop {
        tokio::select! {
            response = &mut attempt => {
                break match response {
                    Ok(response) => Some(decode::<Attempt>(response).await?.outcome),
                    Err(_) => {
                        eprintln!("Attempt response lost. Checking runtime; the password will not be resent.");
                        None
                    }
                };
            }
            _ = sleep(Duration::from_secs(10)) => eprintln!("Waiting for the Mac to start…"),
        }
    };
    if matches!(outcome, Some(Outcome::Rejected)) {
        return Err("SSH attempt rejected; no retry was made");
    }
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if let Ok(status) = api.get::<Status>("v1/status").await
            && status.running()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "normal runtime could not be verified; unlock is unconfirmed, no retry was made",
            );
        }
        sleep(Duration::from_secs(2)).await;
    }
}
