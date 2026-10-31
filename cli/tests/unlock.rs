//! Real CLI process against an HA WebSocket broker and ingress HTTP boundary.
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{
    io::Write,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const TOKEN: &str = "DUMMY_HA_TOKEN";
const PASSWORD: &str = "DUMMY_MAC_PASSWORD";
const INGRESS: &str = "/api/hassio_ingress/dummy-ingress/";
const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GRANT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Copy)]
enum Mode {
    Startup,
    Running,
    Unlock,
    Reject,
    Untrusted,
    Stale,
    Redirect,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum WsRequest {
    #[serde(rename = "auth")]
    Auth { access_token: String },
    #[serde(rename = "get_panels")]
    Panels { id: u64 },
    #[serde(rename = "supervisor/api")]
    Supervisor {
        id: u64,
        endpoint: String,
        method: String,
    },
}

struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(mode: Mode) -> Self {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let record = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let listener = TcpListener::from_std(socket).unwrap();
                let attempted = Arc::new(AtomicBool::new(false));
                let starting = Arc::new(AtomicBool::new(matches!(mode, Mode::Startup)));
                while !stopped.load(Ordering::Relaxed) {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            tokio::spawn(serve(stream, mode, record.clone(), attempted.clone(), starting.clone()));
                        }
                        _ = tokio::time::sleep(Duration::from_millis(5)) => (),
                    }
                }
            });
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn invoke(&self, input: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ha-filevault"))
            .env_remove("HA_FILEVAULT_URL")
            .env_remove("HA_FILEVAULT_TOKEN_FILE")
            .env("HOME_ASSISTANT_URL", &self.url)
            .env("HOME_ASSISTANT_TOKEN", TOKEN)
            .args(["unlock", "--password-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn assert_no_password_post(&self) {
        assert!(
            !self
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.starts_with("POST /api/hassio_ingress/dummy-ingress/v1/cli/attempt"))
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

async fn serve(
    mut stream: TcpStream,
    mode: Mode,
    record: Arc<Mutex<Vec<String>>>,
    attempted: Arc<AtomicBool>,
    starting: Arc<AtomicBool>,
) {
    let mut prefix = [0; 64];
    let count = stream.peek(&mut prefix).await.unwrap();
    if prefix[..count].starts_with(b"GET /api/websocket ") {
        let mut socket = accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                r#"{"type":"auth_required","ha_version":"test"}"#.into(),
            ))
            .await
            .unwrap();
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let request: WsRequest = serde_json::from_str(&text).unwrap();
            let response = match request {
                WsRequest::Auth { access_token } => {
                    assert_eq!(access_token, TOKEN);
                    r#"{"type":"auth_ok"}"#.to_owned()
                }
                WsRequest::Panels { id } => format!(
                    r#"{{"id":{id},"type":"result","success":true,"result":{{"filevault":{{"config":{{"addon":"test_filevault"}}}}}}}}"#
                ),
                WsRequest::Supervisor {
                    id,
                    endpoint,
                    method,
                } => {
                    let result = match (endpoint.as_str(), method.as_str()) {
                        ("/addons/test_filevault/info", "get") => {
                            r#"{"slug":"test_filevault","state":"started","ingress_url":"/api/hassio_ingress/dummy-ingress"}"#
                        }
                        ("/ingress/session", "post") => r#"{"session":"dummy-session"}"#,
                        _ => panic!("unexpected HA operation"),
                    };
                    format!(r#"{{"id":{id},"type":"result","success":true,"result":{result}}}"#)
                }
            };
            socket.send(Message::Text(response.into())).await.unwrap();
        }
        return;
    }
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await.unwrap() == 0 {
            return;
        }
        bytes.push(byte[0]);
        assert!(bytes.len() < 16384);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains("cookie: ingress_session=dummy-session"));
    assert!(lower.contains("x-filevault-client: native-cli"));
    for forbidden in [
        "authorization:",
        "x-remote-user-id:",
        "origin:",
        "sec-fetch",
    ] {
        assert!(!lower.contains(forbidden));
    }
    let length: usize = lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .map_or(0, |n| n.parse().unwrap());
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    record.lock().unwrap().push(headers.clone());
    let request = headers.lines().next().unwrap();
    let path = request
        .split_whitespace()
        .nth(1)
        .unwrap()
        .strip_prefix(INGRESS)
        .unwrap();
    let (code, extra, response) = match path {
        "v1/status" => {
            let running =
                matches!(mode, Mode::Running | Mode::Stale) || attempted.load(Ordering::SeqCst);
            let state = if running { "running" } else { "unknown" };
            let runtime = if matches!(mode, Mode::Stale) {
                "stale"
            } else if running {
                "verified"
            } else {
                "unavailable"
            };
            let ready = !matches!(mode, Mode::Stale);
            (
                200,
                String::new(),
                format!(
                    r#"{{"decision":{{"state":"{state}","unlock_available":false}},"runtime_check":"{runtime}","manual_ready":{ready}}}"#
                ),
            )
        }
        "v1/recovery" => (
            200,
            String::new(),
            r#"{"busy":false,"retry_after_ms":0}"#.into(),
        ),
        "v1/cli/session" if starting.swap(false, Ordering::SeqCst) => (
            502,
            String::new(),
            r#"{"error_code":"ssh_unavailable","message":"DUMMY_SENSITIVE_BODY"}"#.into(),
        ),
        "v1/cli/session" if matches!(mode, Mode::Redirect) => (
            302,
            "Location: /DUMMY_SENSITIVE_REDIRECT\r\n".into(),
            "DUMMY_SENSITIVE_BODY".into(),
        ),
        "v1/cli/session" => (
            200,
            format!("Set-Cookie: fv_session={GRANT}; Secure; HttpOnly\r\n"),
            format!(
                r#"{{"nonce":"{NONCE}","target":{{"host":"mac.example.invalid","port":22,"username":"DUMMY_PRIVATE_SSH_ACCOUNT","host_key_fingerprint":"SHA256:dummy","trusted":{}}}}}"#,
                !matches!(mode, Mode::Untrusted)
            ),
        ),
        "v1/cli/attempt"
            if lower
                .lines()
                .filter(|line| line.starts_with("cookie:"))
                .count()
                != 1 =>
        {
            (
                403,
                String::new(),
                r#"{"message":"request grant required"}"#.into(),
            )
        }
        "v1/cli/attempt" => {
            assert!(lower.contains(&format!("; fv_session={GRANT}")));
            assert!(lower.contains(&format!("x-filevault-nonce: {NONCE}")));
            assert!(lower.contains("x-filevault-confirm: manual_ssh"));
            assert!(lower.contains("content-type: application/octet-stream"));
            assert_eq!(body, PASSWORD.as_bytes());
            assert!(!attempted.swap(true, Ordering::SeqCst), "password retried");
            let outcome = if matches!(mode, Mode::Reject) {
                "rejected"
            } else {
                "authenticated"
            };
            (200, String::new(), format!(r#"{{"outcome":"{outcome}"}}"#))
        }
        _ => panic!("unexpected ingress operation"),
    };
    let response = format!(
        "HTTP/1.1 {code} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{response}",
        response.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

#[test]
fn already_running_needs_fresh_runtime_and_does_not_consume_password() {
    let fixture = Fixture::new(Mode::Running);
    let output = fixture.invoke(b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("fresh runtime verified"));
    fixture.assert_no_password_post();
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    let fixture = Fixture::new(Mode::Stale);
    assert!(!fixture.invoke(b"").status.success());
    fixture.assert_no_password_post();
}

#[test]
fn one_password_attempt_then_independent_status_observation() {
    let fixture = Fixture::new(Mode::Unlock);
    let output = fixture.invoke(format!("{PASSWORD}\n").as_bytes());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST ") && r.contains("/cli/attempt "))
            .count(),
        1
    );
    assert!(requests.last().unwrap().contains("/v1/status "));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(PASSWORD));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(PASSWORD));
}

#[test]
fn untrusted_identity_invalid_password_redirect_and_rejection_are_not_retried() {
    for (mode, input, expected) in [
        (
            Mode::Untrusted,
            PASSWORD.as_bytes(),
            "identity needs approval",
        ),
        (Mode::Unlock, b"".as_slice(), "password must be"),
        (
            Mode::Unlock,
            b"first\nsecond\n".as_slice(),
            "password must be",
        ),
        (Mode::Redirect, PASSWORD.as_bytes(), "redirect refused"),
        (Mode::Reject, PASSWORD.as_bytes(), "SSH attempt rejected"),
    ] {
        let fixture = Fixture::new(mode);
        let output = fixture.invoke(input);
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains(PASSWORD));
        assert!(!error.contains("DUMMY_SENSITIVE"));
        if !matches!(mode, Mode::Reject) {
            fixture.assert_no_password_post();
        }
    }
}

#[test]
fn waits_for_ssh_startup_before_prompting_or_sending_a_password() {
    let fixture = Fixture::new(Mode::Startup);
    let output = fixture.invoke(format!("{PASSWORD}\n").as_bytes());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST ") && r.contains("/cli/session "))
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST ") && r.contains("/cli/attempt "))
            .count(),
        1
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DUMMY_SENSITIVE_BODY"));
}

#[test]
fn routine_unlock_output_does_not_disclose_the_configured_ssh_account() {
    let fixture = Fixture::new(Mode::Unlock);
    let output = fixture.invoke(format!("{PASSWORD}\n").as_bytes());
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DUMMY_PRIVATE_SSH_ACCOUNT"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DUMMY_PRIVATE_SSH_ACCOUNT"));
}

#[test]
fn recovery_grant_and_ingress_session_share_one_cookie_header() {
    let fixture = Fixture::new(Mode::Unlock);
    let output = fixture.invoke(format!("{PASSWORD}\n").as_bytes());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.requests.lock().unwrap();
    let attempt = requests
        .iter()
        .find(|r| r.starts_with("POST ") && r.contains("/cli/attempt "))
        .unwrap();
    let cookies: Vec<_> = attempt
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("cookie:"))
        .collect();
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].contains("ingress_session=dummy-session"));
    assert!(cookies[0].contains(&format!("fv_session={GRANT}")));
}
