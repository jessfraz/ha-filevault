use filevault::{
    controller::{Controller, Outcome},
    policy::State,
    secret::Secret,
    ssh_manual::{ManualConfig, SshManual},
    ssh_recovery::{RecoveryConfig, SshRecovery},
    transport::{Disabled, Failure, Transport},
};
use russh::{
    keys::{Algorithm, PrivateKey},
    server,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct StateFixture {
    runtime: AtomicBool,
    passwords: AtomicUsize,
    closed: AtomicUsize,
    reject: bool,
    disconnect: bool,
    no_runtime: bool,
    hold_password: bool,
    password_received: tokio::sync::Notify,
    release_password: tokio::sync::Notify,
    peer_closed: tokio::sync::Notify,
}
struct Peer(Arc<StateFixture>);
impl Drop for Peer {
    fn drop(&mut self) {
        self.0.closed.fetch_add(1, Ordering::SeqCst);
        self.0.peer_closed.notify_one();
    }
}
impl server::Handler for Peer {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.0.passwords.fetch_add(1, Ordering::SeqCst);
        self.0.password_received.notify_one();
        if self.0.hold_password {
            self.0.release_password.notified().await;
        }
        if self.0.reject || user != "fixture-user" || password != "DUMMY_SENTINEL" {
            return Ok(server::Auth::reject());
        }
        self.0.runtime.store(!self.0.no_runtime, Ordering::SeqCst);
        if self.0.disconnect {
            return Err(russh::Error::Disconnect);
        }
        Ok(server::Auth::Accept)
    }
}
struct Fixture {
    state: Arc<StateFixture>,
    config: RecoveryConfig,
    accept: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.accept.abort();
    }
}
impl Fixture {
    async fn start(state: StateFixture) -> Self {
        let state = Arc::new(state);
        let preboot = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let runtime = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let config = RecoveryConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: address.port(),
            username: "fixture-user".into(),
            preboot_public_key: preboot.public_key().to_openssh().unwrap(),
            runtime_public_key: runtime.public_key().to_openssh().unwrap(),
            manual_enrollment_verified: true,
        };
        let serve = state.clone();
        let accept = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = socket.accept().await else {
                    break;
                };
                let key = if serve.runtime.load(Ordering::SeqCst) {
                    runtime.clone()
                } else {
                    preboot.clone()
                };
                let config = Arc::new(server::Config {
                    keys: vec![key],
                    auth_rejection_time: Duration::ZERO,
                    inactivity_timeout: Some(Duration::from_secs(5)),
                    ..Default::default()
                });
                let peer = Peer(serve.clone());
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, stream, peer).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self {
            state,
            config,
            accept,
        }
    }
    fn controller(&self) -> Controller {
        Controller::new(
            Arc::new(SshRecovery::new(self.config.clone()).unwrap()),
            "https://ha.example.invalid".into(),
            Instant::now() - Duration::from_secs(61),
        )
        .with_completion_limit(Duration::from_millis(100))
    }

    fn manual_profile(&self) -> SshManual {
        SshManual::new(ManualConfig {
            enabled: true,
            host: self.config.host.clone(),
            port: self.config.port,
            username: self.config.username.clone(),
            trusted_public_keys: vec![
                self.config.preboot_public_key.clone(),
                self.config.runtime_public_key.clone(),
            ],
        })
        .unwrap()
    }

    fn manual_controller(&self) -> Controller {
        Controller::new(
            Arc::new(Disabled),
            "https://ha.example.invalid".into(),
            Instant::now() - Duration::from_secs(61),
        )
        .with_manual(Arc::new(self.manual_profile()))
    }
}
fn dummy() -> Secret {
    Secret::from_bytes(b"DUMMY_SENTINEL".to_vec()).unwrap()
}

#[tokio::test]
async fn manual_password_attempt_waits_for_verified_runtime() {
    let fixture = Fixture::start(StateFixture {
        no_runtime: true,
        ..Default::default()
    })
    .await;
    let controller = Arc::new(
        fixture
            .controller()
            .with_manual(Arc::new(fixture.manual_profile()))
            .with_completion_limit(Duration::from_secs(3)),
    );
    let grant = controller.manual_challenge("user").await.unwrap();
    let worker = controller.clone();
    let attempt = tokio::spawn(async move {
        worker
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy(),
            )
            .await
    });
    fixture.state.password_received.notified().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !attempt.is_finished(),
        "password acceptance is not boot completion"
    );
    fixture.state.runtime.store(true, Ordering::SeqCst);
    assert_eq!(attempt.await.unwrap(), Outcome::Running);
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn manual_startup_cooldown_is_distinct_from_connection_failure() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let controller = Controller::new(
        Arc::new(Disabled),
        "https://ha.example.invalid".into(),
        Instant::now(),
    )
    .with_manual(Arc::new(fixture.manual_profile()));
    assert!(matches!(
        controller.manual_challenge("user").await,
        Err(Failure::Cooldown)
    ));
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cooldown_reports_remaining_time_and_expires_without_an_attempt() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let controller = Controller::new(
        Arc::new(Disabled),
        "https://ha.example.invalid".into(),
        Instant::now() - Duration::from_millis(59_900),
    )
    .with_manual(Arc::new(fixture.manual_profile()));
    let report = controller.recovery_status("user").await;
    assert!(!report.busy);
    assert!((1..=100).contains(&report.retry_after_ms));
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(controller.recovery_status("user").await.retry_after_ms, 0);
    assert!(controller.manual_challenge("user").await.is_ok());
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http_cooldown_and_failed_connection_have_distinct_codes() {
    use filevault::api::{self, Access, Context};
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        error_code: String,
    }
    let fixture = Fixture::start(StateFixture::default()).await;
    for cooling in [true, false] {
        let manual = if cooling {
            fixture.manual_profile()
        } else {
            let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            drop(socket);
            SshManual::new(ManualConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port,
                username: "fixture-user".into(),
                trusted_public_keys: vec![],
            })
            .unwrap()
        };
        let controller = Controller::new(
            Arc::new(Disabled),
            "https://ha.example.invalid".into(),
            Instant::now()
                - if cooling {
                    Duration::ZERO
                } else {
                    Duration::from_secs(61)
                },
        )
        .with_manual(Arc::new(manual));
        let server = api::start(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(Context::with_controller(
                Access::Ingress {
                    peer: "127.0.0.1".parse().unwrap(),
                    users: ["user".into()].into(),
                },
                Arc::new(controller),
            )),
        )
        .unwrap();
        let response = reqwest::Client::new()
            .post(format!("http://{}/v1/manual/session", server.local_addr()))
            .header("x-remote-user-id", "user")
            .header("origin", "https://ha.example.invalid")
            .header("sec-fetch-site", "same-origin")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), if cooling { 429 } else { 502 });
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers().contains_key("retry-after"), cooling);
        let body: ErrorBody = response.json().await.unwrap();
        assert_eq!(
            body.error_code,
            if cooling {
                "cooldown"
            } else {
                "ssh_unavailable"
            }
        );
        server.close().await.unwrap();
    }
}

#[tokio::test]
async fn live_ssh_progress_is_user_scoped_and_survives_http_disconnect() {
    use filevault::api::{self, Access, Context};
    #[derive(serde::Deserialize)]
    struct Event {
        message: String,
    }
    #[derive(serde::Deserialize)]
    struct Activity {
        active: bool,
        events: Vec<Event>,
        outcome: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Status {
        busy: bool,
        activity: Option<Activity>,
    }
    let fixture = Fixture::start(StateFixture {
        hold_password: true,
        ..Default::default()
    })
    .await;
    let controller = Arc::new(fixture.manual_controller());
    let grant = controller.manual_challenge("user").await.unwrap();
    let server = api::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Context::with_controller(
            Access::Ingress {
                peer: "127.0.0.1".parse().unwrap(),
                users: ["user".into(), "other".into()].into(),
            },
            controller.clone(),
        )),
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    let client = reqwest::Client::new();
    let attempt = client
        .post(format!("{base}/v1/manual/attempt"))
        .header("x-remote-user-id", "user")
        .header("origin", "https://ha.example.invalid")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/octet-stream")
        .header("x-filevault-nonce", grant.challenge.nonce)
        .header("cookie", format!("fv_session={}", grant.challenge.cookie))
        .header("x-filevault-confirm", "manual_ssh")
        .body("DUMMY_SENTINEL");
    let request = tokio::spawn(async move { attempt.send().await });
    fixture.state.password_received.notified().await;
    let response = client
        .get(format!("{base}/v1/recovery"))
        .header("x-remote-user-id", "user")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let report: Status = response.json().await.unwrap();
    assert!(report.busy);
    let activity = report.activity.unwrap();
    assert!(activity.active);
    assert!(
        activity
            .events
            .iter()
            .any(|e| e.message.contains("waiting for the server response"))
    );
    assert!(
        activity
            .events
            .iter()
            .all(|e| !e.message.contains("DUMMY_SENTINEL"))
    );
    let other: Status = client
        .get(format!("{base}/v1/recovery"))
        .header("x-remote-user-id", "other")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(other.busy);
    assert!(other.activity.is_none());
    request.abort();
    let _ = request.await;
    fixture.state.release_password.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !controller.recovery_status("user").await.busy {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let finished: Status = client
        .get(format!("{base}/v1/recovery"))
        .header("x-remote-user-id", "user")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let activity = finished.activity.unwrap();
    assert!(!activity.active);
    assert_eq!(activity.outcome.as_deref(), Some("authenticated"));
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    server.close().await.unwrap();
}

#[tokio::test]
async fn password_once_then_distinct_runtime_identity_confirms_running() {
    for disconnect in [false, true] {
        let fixture = Fixture::start(StateFixture {
            disconnect,
            ..Default::default()
        })
        .await;
        let controller = fixture.controller();
        let grant = controller.challenge("user").await.unwrap();
        assert_eq!(
            controller
                .submit(
                    &grant.nonce,
                    &grant.cookie,
                    "user",
                    "https://ha.example.invalid",
                    dummy()
                )
                .await,
            Outcome::Running
        );
        assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().await.state, State::Running);
        assert_eq!(
            controller
                .submit(
                    &grant.nonce,
                    &grant.cookie,
                    "user",
                    "https://ha.example.invalid",
                    dummy()
                )
                .await,
            Outcome::Rejected
        );
        assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn rejection_has_no_method_fallback_or_password_retry() {
    let fixture = Fixture::start(StateFixture {
        reject: true,
        ..Default::default()
    })
    .await;
    let controller = fixture.controller();
    let grant = controller.challenge("user").await.unwrap();
    assert_eq!(
        controller
            .submit(
                &grant.nonce,
                &grant.cookie,
                "user",
                "https://ha.example.invalid",
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ssh_success_or_disconnect_without_runtime_proof_is_only_booting() {
    for disconnect in [false, true] {
        let fixture = Fixture::start(StateFixture {
            disconnect,
            no_runtime: true,
            ..Default::default()
        })
        .await;
        let controller = fixture.controller();
        let grant = controller.challenge("user").await.unwrap();
        assert_eq!(
            controller
                .submit(
                    &grant.nonce,
                    &grant.cookie,
                    "user",
                    "https://ha.example.invalid",
                    dummy()
                )
                .await,
            Outcome::Booting
        );
        assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn unverified_or_shared_phase_identities_cannot_unlock() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let mut config = fixture.config.clone();
    config.manual_enrollment_verified = false;
    let transport = SshRecovery::new(config.clone()).unwrap();
    assert!(!transport.unlock_ready());
    assert!(!transport.runtime_ready().await);
    let mut session = transport.open().await.unwrap();
    assert_eq!(session.observation().state, State::Unknown);
    assert!(session.recheck().await.is_err());
    assert_eq!(session.submit(dummy()).await, Err(Failure::Unverified));
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
    config.runtime_public_key = config.preboot_public_key.clone();
    assert!(SshRecovery::new(config).is_err());
}

#[tokio::test]
async fn wrong_pin_or_runtime_phase_prevents_password_delivery() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let mut config = fixture.config.clone();
    config.preboot_public_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    assert!(SshRecovery::new(config).unwrap().open().await.is_err());
    let controller = fixture.controller();
    let grant = controller.challenge("user").await.unwrap();
    fixture.state.runtime.store(true, Ordering::SeqCst);
    assert_eq!(
        controller
            .submit(
                &grant.nonce,
                &grant.cookie,
                "user",
                "https://ha.example.invalid",
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_closes_socket_and_never_retries_password() {
    let fixture = Fixture::start(StateFixture {
        hold_password: true,
        ..Default::default()
    })
    .await;
    let transport = SshRecovery::new(fixture.config.clone()).unwrap();
    let mut session = transport.open().await.unwrap();
    session.recheck().await.unwrap();
    let mut attempt = session.submit(dummy());
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut attempt => panic!("held authentication completed before cancellation"),
            _ = fixture.state.password_received.notified() => {}
        }
    })
    .await
    .expect("synthetic server received the password");
    drop(attempt);
    fixture.state.release_password.notify_one();
    tokio::time::timeout(Duration::from_secs(5), fixture.state.peer_closed.notified())
        .await
        .expect("cancelled connection closed");
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn wrong_runtime_pin_never_confirms_a_successful_authentication() {
    let mut fixture = Fixture::start(StateFixture::default()).await;
    fixture.config.runtime_public_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    let controller = fixture.controller();
    let grant = controller.challenge("user").await.unwrap();
    assert_eq!(
        controller
            .submit(
                &grant.nonce,
                &grant.cookie,
                "user",
                "https://ha.example.invalid",
                dummy()
            )
            .await,
        Outcome::Booting
    );
    assert_eq!(controller.status().await.state, State::Unknown);
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn manual_unknown_phase_needs_confirmation_and_never_claims_unlock() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let controller = fixture.manual_controller();
    assert_eq!(controller.status().await.state, State::SshReachable);
    assert!(controller.manual_ready());
    assert!(!controller.ready());
    let grant = controller.manual_challenge("user").await.unwrap();
    assert_eq!(grant.target.username, "fixture-user");
    assert!(grant.target.host_key_fingerprint.starts_with("SHA256:"));
    assert_eq!(
        controller
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                false,
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
    let grant = controller.manual_challenge("user").await.unwrap();
    assert_eq!(
        controller
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Authenticated
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    assert_eq!(controller.status().await.state, State::SshReachable);
    assert_eq!(
        controller
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert!(controller.manual_challenge("user").await.is_err());
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn manual_action_is_available_even_when_running_is_detected() {
    let fixture = Fixture::start(StateFixture::default()).await;
    fixture.state.runtime.store(true, Ordering::SeqCst);
    let controller = fixture
        .controller()
        .with_manual(Arc::new(fixture.manual_profile()));
    assert_eq!(controller.status().await.state, State::Running);
    assert!(controller.challenge("user").await.is_err());
    let grant = controller.manual_challenge("user").await.unwrap();
    assert_eq!(
        controller
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Running
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn grants_cannot_change_between_manual_and_automatic_actions() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let controller = fixture
        .controller()
        .with_manual(Arc::new(fixture.manual_profile()));
    let grant = controller.manual_challenge("user").await.unwrap();
    assert_eq!(
        controller
            .submit(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    let grant = controller.challenge("user").await.unwrap();
    assert_eq!(
        controller
            .submit_manual(
                &grant.nonce,
                &grant.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn manual_rejection_and_disconnect_never_retry_or_claim_running() {
    for (state, expected) in [
        (
            StateFixture {
                reject: true,
                ..Default::default()
            },
            Outcome::Rejected,
        ),
        (
            StateFixture {
                disconnect: true,
                ..Default::default()
            },
            Outcome::Unconfirmed,
        ),
    ] {
        let fixture = Fixture::start(state).await;
        let controller = fixture.manual_controller();
        let grant = controller.manual_challenge("user").await.unwrap();
        assert_eq!(
            controller
                .submit_manual(
                    &grant.challenge.nonce,
                    &grant.challenge.cookie,
                    "user",
                    "https://ha.example.invalid",
                    true,
                    dummy()
                )
                .await,
            expected
        );
        assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().await.state, State::SshReachable);
    }
}

#[tokio::test]
async fn manual_wrong_host_pin_fails_before_any_password() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let mut config = ManualConfig {
        enabled: true,
        host: fixture.config.host.clone(),
        port: fixture.config.port,
        username: fixture.config.username.clone(),
        trusted_public_keys: vec![
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
        ],
    };
    let controller = Controller::new(
        Arc::new(Disabled),
        "https://ha.example.invalid".into(),
        Instant::now() - Duration::from_secs(61),
    )
    .with_manual(Arc::new(SshManual::new(config.clone()).unwrap()));
    let untrusted = controller.manual_challenge("user").await.unwrap();
    assert_eq!(untrusted.target.trust_status, "changed");
    assert!(!untrusted.target.trusted);
    assert_eq!(
        controller
            .submit_manual(
                &untrusted.challenge.nonce,
                &untrusted.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
    config.trusted_public_keys = vec![fixture.config.preboot_public_key.clone(); 2];
    assert!(SshManual::new(config.clone()).is_err());
    config.trusted_public_keys.clear();
    assert!(SshManual::new(config).is_ok());
}

#[tokio::test]
async fn manual_http_requires_ingress_origin_cookie_nonce_and_explicit_confirmation() {
    use filevault::api::{self, Access, Context};
    let fixture = Fixture::start(StateFixture::default()).await;
    let server = api::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Context::with_controller(
            Access::Ingress {
                peer: "127.0.0.1".parse().unwrap(),
                users: ["user".into()].into(),
            },
            Arc::new(fixture.manual_controller()),
        )),
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    let client = reqwest::Client::new();
    let request = |path: &str| {
        client
            .post(format!("{base}{path}"))
            .header("x-remote-user-id", "user")
            .header("origin", "https://ha.example.invalid")
            .header("sec-fetch-site", "same-origin")
    };
    assert_eq!(
        client
            .post(format!("{base}/v1/manual/session"))
            .header("x-remote-user-id", "user")
            .header("sec-fetch-site", "same-origin")
            .header("origin", "https://wrong.example.invalid")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for confirmed in [false, true] {
        let response = request("/v1/manual/session").send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let grant: serde_json::Value = response.json().await.unwrap();
        assert!(
            grant["target"]["host_key_fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("SHA256:")
        );
        let mut attempt = request("/v1/manual/attempt")
            .header("content-type", "application/octet-stream")
            .header("x-filevault-nonce", grant["nonce"].as_str().unwrap())
            .header("cookie", cookie)
            .body("DUMMY_SENTINEL");
        if confirmed {
            attempt = attempt.header("x-filevault-confirm", "manual_ssh");
        }
        let result: serde_json::Value = attempt.send().await.unwrap().json().await.unwrap();
        assert_eq!(
            result["outcome"],
            if confirmed {
                "authenticated"
            } else {
                "rejected"
            }
        );
        assert_eq!(
            fixture.state.passwords.load(Ordering::SeqCst),
            usize::from(confirmed)
        );
    }
    server.close().await.unwrap();
}

#[tokio::test]
async fn first_connection_remembers_only_explicitly_verified_server_identity() {
    use filevault::ssh_manual::ManualTransport;
    let fixture = Fixture::start(StateFixture::default()).await;
    let config = ManualConfig {
        enabled: true,
        host: fixture.config.host.clone(),
        port: fixture.config.port,
        username: fixture.config.username.clone(),
        trusted_public_keys: vec![],
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_known_hosts");
    let controller = Controller::new(
        Arc::new(Disabled),
        "https://ha.example.invalid".into(),
        Instant::now() - Duration::from_secs(61),
    )
    .with_manual(Arc::new(
        SshManual::with_known_hosts(config.clone(), path.clone()).unwrap(),
    ));
    let grant = controller.manual_challenge("user").await.unwrap();
    assert_eq!(grant.target.trust_status, "new");
    assert_eq!(
        controller
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
    let grant = controller.manual_challenge("user").await.unwrap();
    assert!(
        controller
            .trust_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "other-user",
                "https://ha.example.invalid"
            )
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    controller
        .trust_manual(
            &grant.challenge.nonce,
            &grant.challenge.cookie,
            "user",
            "https://ha.example.invalid",
        )
        .await
        .unwrap();
    let remembered = SshManual::with_known_hosts(config, path.clone()).unwrap();
    assert!(remembered.open().await.unwrap().target.trusted);
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(!content.contains("DUMMY_SENTINEL"));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
        0
    );
    assert_eq!(
        controller
            .submit_manual(
                &grant.challenge.nonce,
                &grant.challenge.cookie,
                "user",
                "https://ha.example.invalid",
                true,
                dummy()
            )
            .await,
        Outcome::Authenticated
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    let changed = remembered.open().await.unwrap();
    assert_eq!(changed.target.trust_status, "changed");
    assert!(!changed.target.trusted);
    assert_eq!(
        changed.session.submit(dummy()).await,
        Err(Failure::Unverified)
    );
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn runtime_public_identity_is_observed_without_enabling_phase_recovery() {
    let fixture = Fixture::start(StateFixture::default()).await;
    fixture.state.runtime.store(true, Ordering::SeqCst);
    let mut recovery = fixture.config.clone();
    recovery.enabled = false;
    recovery.manual_enrollment_verified = false;
    recovery.preboot_public_key.clear();
    let options = filevault::config::Options {
        mac: Some(filevault::config::MacConfig {
            host: recovery.host,
            port: recovery.port,
            username: recovery.username,
            ..Default::default()
        }),
        automatic: Some(filevault::config::AutomaticConfig {
            enabled: recovery.enabled,
            preboot_public_key: recovery.preboot_public_key,
            runtime_public_key: recovery.runtime_public_key,
            manual_enrollment_verified: recovery.manual_enrollment_verified,
        }),
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let profiles = filevault::profiles::build(&options, Some(&dir.path().join("options.json")));
    let controller = Controller::new(
        profiles.transport,
        "https://ha.example.invalid".into(),
        Instant::now(),
    )
    .with_observer(profiles.observer.unwrap());
    assert_eq!(controller.status().await.state, State::SshReachable);
    assert!(!controller.ready());
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn one_mac_profile_drives_both_manual_and_automatic_connections() {
    let fixture = Fixture::start(StateFixture::default()).await;
    let config = &fixture.config;
    let options = filevault::config::Options::parse(
        &serde_json::to_vec(&serde_json::json!({
            "mac":{"host":config.host,"port":config.port,"username":config.username},
            "automatic":{"enabled":true,"preboot_public_key":config.preboot_public_key,
                "runtime_public_key":config.runtime_public_key,"manual_enrollment_verified":true}
        }))
        .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profiles = filevault::profiles::build(&options, Some(&dir.path().join("options.json")));
    assert!(profiles.errors.is_empty());
    let controller = Controller::new(
        profiles.transport,
        "https://ha.example.invalid".into(),
        Instant::now() - Duration::from_secs(61),
    )
    .with_manual(profiles.manual.unwrap());
    assert_eq!(controller.status().await.state, State::VerifiedPreboot);
    let manual = controller.manual_challenge("user").await.unwrap();
    assert_eq!(
        (
            &*manual.target.host,
            manual.target.port,
            &*manual.target.username
        ),
        (&*config.host, config.port, &*config.username)
    );
    fixture.state.runtime.store(true, Ordering::SeqCst);
    assert_eq!(controller.status().await.state, State::Running);
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn shared_profile_http_flow_verifies_new_and_changed_servers_before_password() {
    use filevault::api::{self, Access, Context};
    let fixture = Fixture::start(StateFixture::default()).await;
    let options=filevault::config::Options::parse(&serde_json::to_vec(&serde_json::json!({
        "mac":{"host":fixture.config.host,"port":fixture.config.port,"username":fixture.config.username},
        "automatic":{"enabled":true}
    })).unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (index, trust_status) in ["new", "changed"].into_iter().enumerate() {
        let profiles = filevault::profiles::build(&options, Some(&dir.path().join("options.json")));
        assert!(profiles.errors.is_empty());
        let controller = Controller::new(
            profiles.transport,
            "https://ha.example.invalid".into(),
            Instant::now() - Duration::from_secs(61),
        )
        .with_manual(profiles.manual.unwrap())
        .with_connection(profiles.connection);
        assert_eq!(controller.status().await.state, State::Unknown);
        let server = api::start(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(Context::with_controller(
                Access::Ingress {
                    peer: "127.0.0.1".parse().unwrap(),
                    users: ["user".into()].into(),
                },
                Arc::new(controller),
            )),
        )
        .unwrap();
        let base = format!("http://{}", server.local_addr());
        let client = reqwest::Client::new();
        let request = |path: &str| {
            client
                .post(format!("{base}{path}"))
                .header("x-remote-user-id", "user")
                .header("origin", "https://ha.example.invalid")
                .header("sec-fetch-site", "same-origin")
        };
        let response = request("/v1/manual/session").send().await.unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let grant: serde_json::Value = response.json().await.unwrap();
        assert_eq!(grant["target"]["trust_status"], trust_status);
        assert_eq!(grant["target"]["host"], fixture.config.host);
        assert_eq!(grant["target"]["port"], fixture.config.port);
        assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), index);
        let denied = request("/v1/manual/trust")
            .header("cookie", &cookie)
            .header("x-filevault-nonce", grant["nonce"].as_str().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 400);
        let trusted = request("/v1/manual/trust")
            .header("cookie", &cookie)
            .header("x-filevault-nonce", grant["nonce"].as_str().unwrap())
            .header("x-filevault-confirm", "verified_host_identity")
            .send()
            .await
            .unwrap();
        assert_eq!(trusted.status(), 200);
        let response = request("/v1/manual/attempt")
            .header("cookie", cookie)
            .header("x-filevault-nonce", grant["nonce"].as_str().unwrap())
            .header("x-filevault-confirm", "manual_ssh")
            .header("content-type", "application/octet-stream")
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap();
        let result: serde_json::Value = response.json().await.unwrap();
        assert_eq!(result["outcome"], "authenticated");
        assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), index + 1);
        assert!(
            !std::fs::read_to_string(dir.path().join("ssh_known_hosts"))
                .unwrap()
                .contains("DUMMY_SENTINEL")
        );
        server.close().await.unwrap();
    }
}

#[tokio::test]
async fn native_http_uses_real_ssh_and_cannot_cross_browser_grants() {
    use filevault::api::{self, Access, Context};
    #[derive(serde::Deserialize)]
    struct Grant {
        nonce: String,
    }
    #[derive(serde::Deserialize)]
    struct ResultReport {
        outcome: String,
    }
    let fixture = Fixture::start(StateFixture::default()).await;
    let server = api::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Context::with_controller(
            Access::Ingress {
                peer: "127.0.0.1".parse().unwrap(),
                users: ["user".into()].into(),
            },
            Arc::new(fixture.manual_controller()),
        )),
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    let client = reqwest::Client::new();
    let native = |path: &str| {
        client
            .post(format!("{base}{path}"))
            .header("x-remote-user-id", "user")
            .header("x-filevault-client", "native-cli")
    };
    assert_eq!(
        client
            .post(format!("{base}/v1/cli/session"))
            .header("x-remote-user-id", "user")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for (header, value) in [
        ("origin", "https://ha.example.invalid"),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
    ] {
        assert_eq!(
            native("/v1/cli/session")
                .header(header, value)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    assert_eq!(
        native("/v1/cli/session?extra=1")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{base}/v1/cli/session"))
            .header("x-filevault-client", "native-cli")
            .header("x-remote-user-id", "other-user")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for cross_browser in [true, false] {
        let response = native("/v1/cli/session").send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let grant: Grant = response.json().await.unwrap();
        if !cross_browser {
            // Reproduce the native client's former duplicate-Cookie request.
            // The server reads the first Cookie header and rejects it before SSH.
            let rejected = native("/v1/cli/attempt")
                .header("cookie", "ingress_session=DUMMY")
                .header("cookie", &cookie)
                .header("x-filevault-nonce", &grant.nonce)
                .header("x-filevault-confirm", "manual_ssh")
                .header("content-type", "application/octet-stream")
                .body("DUMMY_SENTINEL")
                .send()
                .await
                .unwrap();
            assert_eq!(rejected.status(), 403);
            assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 0);
        }
        let cookie = format!("ingress_session=DUMMY; {cookie}");
        let request = if cross_browser {
            client
                .post(format!("{base}/v1/manual/attempt"))
                .header("x-remote-user-id", "user")
                .header("origin", "https://ha.example.invalid")
                .header("sec-fetch-site", "same-origin")
        } else {
            native("/v1/cli/attempt")
        };
        let result: ResultReport = request
            .header("cookie", &cookie)
            .header("x-filevault-nonce", &grant.nonce)
            .header("x-filevault-confirm", "manual_ssh")
            .header("content-type", "application/octet-stream")
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            result.outcome,
            if cross_browser {
                "rejected"
            } else {
                "authenticated"
            }
        );
        assert_eq!(
            fixture.state.passwords.load(Ordering::SeqCst),
            usize::from(!cross_browser)
        );
        let replay: ResultReport = native("/v1/cli/attempt")
            .header("cookie", cookie)
            .header("x-filevault-nonce", grant.nonce)
            .header("x-filevault-confirm", "manual_ssh")
            .header("content-type", "application/octet-stream")
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(replay.outcome, "rejected");
    }
    assert_eq!(fixture.state.passwords.load(Ordering::SeqCst), 1);
    assert_eq!(
        native("/v1/cli/session").send().await.unwrap().status(),
        429
    );
    server.close().await.unwrap();
}
