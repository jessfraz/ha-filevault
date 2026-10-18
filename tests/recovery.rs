use filevault::{
    api::{self, Access, Context},
    controller::{Controller, Outcome},
    policy::State,
    secret::Secret,
    transport::{Failure, FutureResult, Observation, Session, Transport},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct Fixture {
    attempts: AtomicUsize,
    opens: AtomicUsize,
    closed: AtomicUsize,
    running: AtomicBool,
    changed: AtomicBool,
    confirm_running: bool,
    hold: bool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
struct FixtureSession(Arc<Fixture>);
impl Drop for FixtureSession {
    fn drop(&mut self) {
        self.0.closed.fetch_add(1, Ordering::SeqCst);
    }
}
impl Session for FixtureSession {
    fn observation(&self) -> Observation {
        Observation {
            state: State::VerifiedPreboot,
            identity: "synthetic-host-key".into(),
        }
    }
    fn recheck(&mut self) -> FutureResult<'_, Result<Observation, Failure>> {
        Box::pin(async {
            if self.0.changed.load(Ordering::SeqCst) {
                Err(Failure::Identity)
            } else {
                Ok(self.observation())
            }
        })
    }
    fn submit(self: Box<Self>, password: Secret) -> FutureResult<'static, Result<(), Failure>> {
        Box::pin(async move {
            self.0.attempts.fetch_add(1, Ordering::SeqCst);
            self.0.entered.notify_one();
            if self.0.hold {
                self.0.release.notified().await;
            }
            if !password.matches(b"DUMMY_SENTINEL") {
                return Err(Failure::Rejected);
            }
            self.0
                .running
                .store(self.0.confirm_running, Ordering::SeqCst);
            Ok(())
        })
    }
}
struct FixtureTransport(Arc<Fixture>);
impl Transport for FixtureTransport {
    fn open(&self) -> FutureResult<'_, Result<Box<dyn Session>, Failure>> {
        Box::pin(async {
            self.0.opens.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FixtureSession(self.0.clone())) as Box<dyn Session>)
        })
    }
    fn runtime_ready(&self) -> FutureResult<'_, bool> {
        Box::pin(async { self.0.running.load(Ordering::SeqCst) })
    }
    fn unlock_ready(&self) -> bool {
        true
    }
}
fn controller(fixture: Arc<Fixture>) -> Arc<Controller> {
    Arc::new(
        Controller::new(
            Arc::new(FixtureTransport(fixture)),
            "https://ha.example.invalid".into(),
            Instant::now() - Duration::from_secs(61),
        )
        .with_completion_limit(Duration::from_millis(5)),
    )
}
fn dummy() -> Secret {
    Secret::from_bytes(b"DUMMY_SENTINEL".to_vec()).unwrap()
}

#[tokio::test]
async fn one_attempt_and_positive_runtime_confirmation() {
    let fixture = Arc::new(Fixture {
        confirm_running: true,
        ..Default::default()
    });
    let controller = controller(fixture.clone());
    let grant = controller.challenge("user").await.unwrap();
    assert_eq!(fixture.opens.load(Ordering::SeqCst), 2);
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
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ssh_completion_alone_does_not_mean_running() {
    let fixture = Arc::new(Fixture::default());
    let controller = controller(fixture.clone());
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
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn authentication_timeout_does_not_retry() {
    let fixture = Arc::new(Fixture {
        hold: true,
        ..Default::default()
    });
    let controller = controller(fixture.clone());
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
        Outcome::TimedOut
    );
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn expired_grant_discards_retained_connection_without_submission() {
    let fixture = Arc::new(Fixture::default());
    let controller = controller(fixture.clone());
    let grant = controller.challenge("user").await.unwrap();
    assert_eq!(fixture.closed.load(Ordering::SeqCst), 1);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert_eq!(fixture.closed.load(Ordering::SeqCst), 2);
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
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn simultaneous_requests_and_cooldown_never_send_a_second_secret() {
    let fixture = Arc::new(Fixture {
        hold: true,
        ..Default::default()
    });
    let controller = controller(fixture.clone());
    let first = controller.challenge("user").await.unwrap();
    let second = controller.challenge("user").await.unwrap();
    let task_controller = controller.clone();
    let task = tokio::spawn(async move {
        task_controller
            .submit(
                &first.nonce,
                &first.cookie,
                "user",
                "https://ha.example.invalid",
                dummy(),
            )
            .await
    });
    fixture.entered.notified().await;
    assert_eq!(
        controller
            .submit(
                &second.nonce,
                &second.cookie,
                "user",
                "https://ha.example.invalid",
                dummy()
            )
            .await,
        Outcome::Rejected
    );
    assert!(!controller.status().await.unlock_available);
    fixture.release.notify_one();
    assert_eq!(task.await.unwrap(), Outcome::Booting);
    assert!(controller.challenge("user").await.is_err());
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn changed_identity_or_wrong_browser_context_never_sends_secret() {
    for wrong_context in [false, true] {
        let fixture = Arc::new(Fixture::default());
        let controller = controller(fixture.clone());
        let grant = controller.challenge("user").await.unwrap();
        fixture.changed.store(!wrong_context, Ordering::SeqCst);
        let origin = if wrong_context {
            "https://other.example.invalid"
        } else {
            "https://ha.example.invalid"
        };
        assert_eq!(
            controller
                .submit(&grant.nonce, &grant.cookie, "user", origin, dummy())
                .await,
            Outcome::Rejected
        );
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn contradictory_running_proof_blocks_preparation_and_submission() {
    let fixture = Arc::new(Fixture::default());
    let controller = controller(fixture.clone());
    fixture.running.store(true, Ordering::SeqCst);
    assert!(controller.challenge("user").await.is_err());
    fixture.running.store(false, Ordering::SeqCst);
    let grant = controller.challenge("user").await.unwrap();
    fixture.running.store(true, Ordering::SeqCst);
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
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ingress_api_uses_cookie_nonce_and_raw_ephemeral_body() {
    let fixture = Arc::new(Fixture {
        confirm_running: true,
        ..Default::default()
    });
    let context = Context::with_controller(
        Access::Ingress {
            peer: "127.0.0.1".parse().unwrap(),
            users: ["user".into()].into_iter().collect(),
        },
        controller(fixture.clone()),
    );
    let server = api::start("127.0.0.1:0".parse().unwrap(), Arc::new(context)).unwrap();
    let base = format!("http://{}", server.local_addr());
    let client = reqwest::Client::new();
    let browser = |path: &str| {
        client
            .post(format!("{base}{path}"))
            .header("x-remote-user-id", "user")
            .header("origin", "https://ha.example.invalid")
            .header("sec-fetch-site", "same-origin")
    };
    assert_eq!(
        client
            .post(format!("{base}/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for path in ["/v1/session?unexpected=1", "/v1/unlock?unexpected=1"] {
        assert_eq!(browser(path).send().await.unwrap().status(), 403);
    }
    assert_eq!(
        browser("/v1/session")
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(format!("{base}/v1/session"))
            .header("x-remote-user-id", "user")
            .header("origin", "https://other.example.invalid")
            .header("sec-fetch-site", "cross-site")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = browser("/v1/session").send().await.unwrap();
    assert_eq!(response.status(), 200);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict"));
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let grant: serde_json::Value = response.json().await.unwrap();
    let nonce = grant["nonce"].as_str().unwrap();
    assert_eq!(
        browser("/v1/unlock")
            .header("x-filevault-nonce", nonce)
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        browser("/v1/unlock")
            .header("x-filevault-nonce", nonce)
            .header("cookie", format!("{cookie}; {cookie}"))
            .header("content-type", "application/octet-stream")
            .body("DUMMY_SENTINEL")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        browser("/v1/unlock")
            .header("x-filevault-nonce", nonce)
            .header("cookie", &cookie)
            .header("content-type", "application/octet-stream")
            .body(vec![b'X'; 1025])
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let response = browser("/v1/unlock")
        .header("x-filevault-nonce", nonce)
        .header("cookie", &cookie)
        .header("content-type", "application/octet-stream")
        .body("DUMMY_SENTINEL")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let text = response.text().await.unwrap();
    assert_eq!(text, "{\"outcome\":\"running\"}");
    assert!(!text.contains("DUMMY_SENTINEL"));
    let response = browser("/v1/unlock")
        .header("x-filevault-nonce", nonce)
        .header("cookie", cookie)
        .header("content-type", "application/octet-stream")
        .body("DUMMY_SENTINEL")
        .send()
        .await
        .unwrap();
    assert!(response.text().await.unwrap().contains("rejected"));
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
    server.close().await.unwrap();
}
