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
    delay: bool,
}
struct Peer(Arc<StateFixture>);
impl Drop for Peer {
    fn drop(&mut self) {
        self.0.closed.fetch_add(1, Ordering::SeqCst);
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
        if self.0.delay {
            tokio::time::sleep(Duration::from_millis(150)).await;
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
        delay: true,
        ..Default::default()
    })
    .await;
    let transport = SshRecovery::new(fixture.config.clone()).unwrap();
    let mut session = transport.open().await.unwrap();
    session.recheck().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(40), session.submit(dummy()))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
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
        Outcome::Authenticated
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
        ssh_recovery: Some(recovery),
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
