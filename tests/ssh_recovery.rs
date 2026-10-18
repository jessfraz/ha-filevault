use filevault::{
    controller::{Controller, Outcome},
    policy::State,
    secret::Secret,
    ssh_recovery::{RecoveryConfig, SshRecovery},
    transport::{Failure, Transport},
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
