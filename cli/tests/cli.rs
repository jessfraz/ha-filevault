//! Exercise the installed interface through the real process and loopback HTTP.
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

const TOKEN: &str = "DUMMY_INTEGRATION_TOKEN_0123456789abcdef";
const SENTINEL: &str = "DUMMY_SENSITIVE_SENTINEL";
const SYSTEM: &str = r#"{"version":"0.1.0-alpha.10","credential_role":"integration","manual_ready":false,"configuration_errors":[],"configuration_notes":["DUMMY_SENSITIVE_SENTINEL"],"connection":null,"future_secret":"DUMMY_SENSITIVE_SENTINEL"}"#;
const STATUS: &str = r#"{"version":"0.1.0-alpha.10","decision":{"state":"unknown","unlock_available":false},"transport_ready":false,"manual_ready":false,"configuration_errors":[],"configuration_notes":[],"runtime_check":"not_configured","connection":null}"#;

struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(status: &str, headers: &str, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Darwin can inherit O_NONBLOCK from the listening socket.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut byte = [0];
                        while !request.ends_with(b"\r\n\r\n") {
                            if stream.read(&mut byte).unwrap_or(0) == 0 {
                                break;
                            }
                            request.push(byte[0]);
                            assert!(request.len() < 8192);
                        }
                        recorded
                            .lock()
                            .unwrap()
                            .push(String::from_utf8(request).unwrap());
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("fixture listener failed: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn assert_request(&self, path: &str) {
        let requests = self.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "exactly one request, without a role preflight or retry"
        );
        let request = requests[0].to_ascii_lowercase();
        assert!(
            request.starts_with(&format!("get {path} http/1.1\r\n")),
            "unexpected fixture request: {request:?}"
        );
        assert!(request.contains(&format!(
            "authorization: bearer {}\r\n",
            TOKEN.to_ascii_lowercase()
        )));
        for forbidden in [
            "x-remote-user-id",
            "x-ingress",
            "origin:",
            "sec-fetch",
            "cookie:",
            "x-filevault",
            "content-length:",
        ] {
            assert!(!request.contains(forbidden));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ha-filevault"));
    // Tests never inherit real native or server credentials.
    command
        .env_remove("HA_FILEVAULT_URL")
        .env_remove("HA_FILEVAULT_TOKEN_FILE");
    command
}

fn token_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "{TOKEN}").unwrap();
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    file
}

fn invoke(fixture: &Fixture, subcommand: &str) -> Output {
    let token = token_file();
    command()
        .env("HA_FILEVAULT_URL", &fixture.url)
        .env("HA_FILEVAULT_TOKEN_FILE", token.path())
        .arg(subcommand)
        .output()
        .unwrap()
}

fn assert_safe_failure(output: &Output, message: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains(message),
        "unexpected fixed diagnostic: {error}"
    );
    assert!(!error.contains(SENTINEL));
    assert!(!error.contains(TOKEN));
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct SystemOutput {
    credential_role: String,
    manual_ready: bool,
    version: String,
    configuration_errors: Vec<String>,
    configuration_notes: Vec<String>,
    connection: Option<()>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    state: String,
    unlock_available: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusOutput {
    decision: Decision,
    transport_ready: bool,
    runtime_check: String,
    manual_ready: bool,
    version: String,
    configuration_errors: Vec<String>,
    configuration_notes: Vec<String>,
    connection: Option<()>,
}

#[test]
fn system_is_one_authenticated_get_preserving_all_integration_fields() {
    let fixture = Fixture::new("200 OK", "", SYSTEM);
    let output = invoke(&fixture, "system");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: SystemOutput = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report,
        SystemOutput {
            credential_role: "integration".into(),
            manual_ready: false,
            version: "0.1.0-alpha.10".into(),
            configuration_errors: vec![],
            configuration_notes: vec![SENTINEL.into()],
            connection: None,
        }
    );
    fixture.assert_request("/v1/system");
}

#[test]
fn status_uses_explicit_flags_without_an_extra_system_request() {
    let fixture = Fixture::new("200 OK", "", STATUS);
    let token = token_file();
    let output = command()
        .args(["--url", &fixture.url, "--token-file"])
        .arg(token.path())
        .arg("status")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: StatusOutput = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.decision.state, "unknown");
    assert!(!report.decision.unlock_available);
    assert!(!report.transport_ready);
    assert!(!report.manual_ready);
    assert_eq!(report.runtime_check, "not_configured");
    assert_eq!(report.version, "0.1.0-alpha.10");
    assert!(report.configuration_errors.is_empty());
    assert!(report.configuration_notes.is_empty());
    assert_eq!(report.connection, None);
    fixture.assert_request("/v1/status");
}

#[test]
fn failures_never_echo_server_bodies_or_retry() {
    for (status, message) in [
        ("401 Unauthorized", "credential rejected"),
        ("403 Forbidden", "credential rejected"),
        ("503 Service Unavailable", "API unavailable"),
    ] {
        let fixture = Fixture::new(status, "", SENTINEL);
        let output = invoke(&fixture, "system");
        assert_safe_failure(&output, message);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("HTTP {}:", &status[..3]))
        );
        fixture.assert_request("/v1/system");
    }
}

#[test]
fn redirects_never_forward_the_token_even_to_the_same_origin() {
    let sink = Fixture::new("200 OK", "", SYSTEM);
    for code in [301, 302, 303, 307, 308] {
        let fixture = Fixture::new(
            &format!("{code} Redirect"),
            &format!("Location: {}/{}\r\n", sink.url, SENTINEL),
            SENTINEL,
        );
        assert_safe_failure(&invoke(&fixture, "system"), "redirect refused");
        fixture.assert_request("/v1/system");
    }
    let fixture = Fixture::new("302 Redirect", "Location: /v1/status\r\n", "");
    assert_safe_failure(&invoke(&fixture, "system"), "redirect refused");
    fixture.assert_request("/v1/system");
    assert!(sink.requests.lock().unwrap().is_empty());
}

#[test]
fn invalid_owner_and_oversized_responses_are_not_dumped() {
    for body in [
        SENTINEL.to_owned(),
        SYSTEM.replace("integration", "ha_user"),
        SYSTEM.replace("null", r#"{"host":"DUMMY_SENSITIVE_SENTINEL"}"#),
        SYSTEM.replace("false", "null"),
        "x".repeat(65_537),
    ] {
        let fixture = Fixture::new("200 OK", "", &body);
        let message = if body.len() > 65_536 {
            "response too large"
        } else {
            "invalid integration API response"
        };
        assert_safe_failure(&invoke(&fixture, "system"), message);
        fixture.assert_request("/v1/system");
    }
    let fixture = Fixture::new("200 OK", "", &STATUS.replace("unknown", SENTINEL));
    assert_safe_failure(
        &invoke(&fixture, "status"),
        "invalid integration API response",
    );
}

#[test]
fn configuration_and_argument_failures_do_not_echo_sensitive_values() {
    let fixture = Fixture::new("200 OK", "", SYSTEM);
    let token = token_file();
    for suffix in [
        "/v1/manual/session",
        "/?DUMMY_SENSITIVE_SENTINEL",
        "/#DUMMY_SENSITIVE_SENTINEL",
        "/\\DUMMY_SENSITIVE_SENTINEL",
    ] {
        let output = command()
            .env("HA_FILEVAULT_URL", format!("{}{suffix}", fixture.url))
            .env("HA_FILEVAULT_TOKEN_FILE", token.path())
            .arg("system")
            .output()
            .unwrap();
        assert_safe_failure(&output, "invalid external API origin");
    }
    let output = command()
        .env("HA_FILEVAULT_URL", format!("http://{TOKEN}@127.0.0.1"))
        .env("HA_FILEVAULT_TOKEN_FILE", token.path())
        .arg("status")
        .output()
        .unwrap();
    assert_safe_failure(&output, "invalid external API origin");
    for operation in [
        "unlock",
        "manual",
        "connectivity",
        "history",
        "trust",
        "recovery",
        SENTINEL,
    ] {
        let output = command()
            .env("HA_FILEVAULT_URL", &fixture.url)
            .env("HA_FILEVAULT_TOKEN_FILE", token.path())
            .arg(operation)
            .output()
            .unwrap();
        assert_safe_failure(&output, "invalid arguments");
    }
    token
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    let output = command()
        .env("HA_FILEVAULT_URL", &fixture.url)
        .env("HA_FILEVAULT_TOKEN_FILE", token.path())
        .arg("system")
        .output()
        .unwrap();
    assert_safe_failure(&output, "owner-only regular file");
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn help_and_version_are_offline_and_hide_configured_values() {
    for args in [vec!["--help"], vec!["--version"], vec!["status", "--help"]] {
        let output = command()
            .env("HA_FILEVAULT_URL", SENTINEL)
            .env("HA_FILEVAULT_TOKEN_FILE", TOKEN)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("ha-filevault"));
        assert!(!text.contains(SENTINEL));
        assert!(!text.contains(TOKEN));
    }
    let output = command().arg("system").output().unwrap();
    assert_safe_failure(&output, "configure HA_FILEVAULT_URL");
}

#[test]
fn token_boundaries_and_symlinks_fail_before_network_access() {
    let fixture = Fixture::new("200 OK", "", SYSTEM);
    for token in [
        String::new(),
        "x".repeat(31),
        "x".repeat(257),
        format!("{TOKEN}\n\n"),
        format!("{TOKEN}\rheader"),
        format!("{TOKEN} "),
    ] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(token.as_bytes()).unwrap();
        let output = command()
            .env("HA_FILEVAULT_URL", &fixture.url)
            .env("HA_FILEVAULT_TOKEN_FILE", file.path())
            .arg("system")
            .output()
            .unwrap();
        assert_safe_failure(&output, "owner-only regular file");
    }
    let token = token_file();
    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("token-link");
    std::os::unix::fs::symlink(token.path(), &link).unwrap();
    let output = command()
        .env("HA_FILEVAULT_URL", &fixture.url)
        .env("HA_FILEVAULT_TOKEN_FILE", link)
        .arg("system")
        .output()
        .unwrap();
    assert_safe_failure(&output, "owner-only regular file");
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn valid_token_and_response_size_boundaries_succeed() {
    let mut body = SYSTEM.to_owned();
    body.push_str(&" ".repeat(65_536 - body.len()));
    let fixture = Fixture::new("200 OK", "", &body);
    for token in ["x".repeat(32), "x".repeat(256), format!("{TOKEN}\r\n")] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(token.as_bytes()).unwrap();
        let output = command()
            .env("HA_FILEVAULT_URL", &fixture.url)
            .env("HA_FILEVAULT_TOKEN_FILE", file.path())
            .arg("system")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: SystemOutput = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report.credential_role, "integration");
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
}

#[test]
fn ambient_proxy_and_server_configuration_are_not_native_authority() {
    let fixture = Fixture::new("200 OK", "", SYSTEM);
    let proxy = Fixture::new("200 OK", "", SENTINEL);
    let token = token_file();
    let output = command()
        .env("HA_FILEVAULT_URL", &fixture.url)
        .env("HA_FILEVAULT_TOKEN_FILE", token.path())
        .env("HTTP_PROXY", &proxy.url)
        .env("ALL_PROXY", &proxy.url)
        .env("http_proxy", &proxy.url)
        .env("all_proxy", &proxy.url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .arg("system")
        .output()
        .unwrap();
    assert!(output.status.success());
    fixture.assert_request("/v1/system");
    assert!(proxy.requests.lock().unwrap().is_empty());
    let output = command()
        .env("FILEVAULT_STATUS_TOKEN", TOKEN)
        .env("FILEVAULT_BIND", &fixture.url)
        .arg("status")
        .output()
        .unwrap();
    assert_safe_failure(&output, "configure HA_FILEVAULT_URL");
    let output = command()
        .args(["--token", TOKEN, "system"])
        .output()
        .unwrap();
    assert_safe_failure(&output, "invalid arguments");
}
