use crate::{
    guard::AttemptGuard,
    policy::{Decision, Evidence, State, decide},
    secret::Secret,
    transport::{Failure, Session, Transport},
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

pub const CONNECT_LIMIT: Duration = Duration::from_secs(5);
pub const ATTEMPT_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Running,
    Booting,
    Rejected,
    TimedOut,
}

pub struct Challenge {
    pub nonce: String,
    pub cookie: String,
}
struct Pending {
    session: Box<dyn Session>,
    expires: Instant,
}
struct Inner {
    guard: AttemptGuard,
    pending: HashMap<String, Pending>,
}

pub struct Controller {
    transport: Arc<dyn Transport>,
    inner: Arc<Mutex<Inner>>,
    preparing: Semaphore,
    origin: String,
    completion_limit: Duration,
}

fn random_token() -> Result<String, Failure> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Failure::Unavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl Controller {
    pub fn new(transport: Arc<dyn Transport>, origin: String, started: Instant) -> Self {
        Self {
            transport,
            inner: Arc::new(Mutex::new(Inner {
                guard: AttemptGuard::new(origin.clone(), started),
                pending: HashMap::new(),
            })),
            preparing: Semaphore::new(1),
            origin,
            completion_limit: Duration::from_secs(120),
        }
    }

    /// Test-only tuning of non-secret confirmation time, not a production option.
    pub fn with_completion_limit(mut self, limit: Duration) -> Self {
        self.completion_limit = limit.min(Duration::from_secs(120));
        self
    }

    pub fn ready(&self) -> bool {
        self.transport.unlock_ready() && !self.origin.is_empty()
    }
    pub fn valid_origin(&self, origin: &str) -> bool {
        !self.origin.is_empty() && self.origin == origin
    }

    pub async fn status(&self) -> Decision {
        if tokio::time::timeout(CONNECT_LIMIT, self.transport.runtime_ready())
            .await
            .unwrap_or(false)
        {
            return decide(Evidence {
                age_seconds: Some(0.0),
                runtime_verified: true,
                ..Default::default()
            });
        }
        let result = tokio::time::timeout(CONNECT_LIMIT, self.transport.open()).await;
        let Ok(Ok(session)) = result else {
            return decide(Evidence::default());
        };
        let observation = session.observation();
        if observation.state != State::VerifiedPreboot || !self.ready() {
            return decide(Evidence::default());
        }
        drop(session);
        let repeated = tokio::time::timeout(CONNECT_LIMIT, self.transport.open()).await;
        let Ok(Ok(repeated)) = repeated else {
            return decide(Evidence::default());
        };
        let proof = repeated.observation();
        let inner = self.inner.lock().await;
        decide(Evidence {
            age_seconds: Some(0.0),
            preboot_verified: proof.state == State::VerifiedPreboot,
            host_key_pinned: proof.identity == observation.identity,
            prior_preboot_age_seconds: Some(0.0),
            busy: !inner.guard.available(Instant::now()),
            ..Default::default()
        })
    }

    pub async fn challenge(&self, user: &str) -> Result<Challenge, Failure> {
        let _preparing = self
            .preparing
            .try_acquire()
            .map_err(|_| Failure::Rejected)?;
        if !self.ready() || self.origin.is_empty() {
            return Err(Failure::Unverified);
        }
        if !self.inner.lock().await.guard.available(Instant::now()) {
            return Err(Failure::Rejected);
        }
        if !matches!(
            tokio::time::timeout(CONNECT_LIMIT, self.transport.runtime_ready()).await,
            Ok(false)
        ) {
            return Err(Failure::Unverified);
        }
        let first = tokio::time::timeout(CONNECT_LIMIT, self.transport.open())
            .await
            .map_err(|_| Failure::Timeout)??;
        let proof = first.observation();
        if proof.state != State::VerifiedPreboot {
            return Err(Failure::Unverified);
        }
        drop(first);
        let second = tokio::time::timeout(CONNECT_LIMIT, self.transport.open())
            .await
            .map_err(|_| Failure::Timeout)??;
        let proof2 = second.observation();
        if proof2.state != State::VerifiedPreboot || proof2.identity != proof.identity {
            return Err(Failure::Identity);
        }
        let nonce = random_token()?;
        let cookie = random_token()?;
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        inner.pending.retain(|_, pending| pending.expires > now);
        if !inner
            .guard
            .issue(nonce.clone(), user.into(), cookie.clone(), now)
        {
            return Err(Failure::Rejected);
        }
        inner.pending.insert(
            nonce.clone(),
            Pending {
                session: second,
                expires: now + Duration::from_secs(60),
            },
        );
        let state = self.inner.clone();
        let expiring = nonce.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut inner = state.lock().await;
            inner.pending.remove(&expiring);
            inner.guard.revoke(&expiring);
        });
        Ok(Challenge { nonce, cookie })
    }

    pub async fn submit(
        &self,
        nonce: &str,
        cookie: &str,
        user: &str,
        origin: &str,
        password: Secret,
    ) -> Outcome {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        let pending = inner.pending.remove(nonce);
        let accepted = inner
            .guard
            .begin(
                nonce,
                user,
                cookie,
                origin,
                pending.as_ref().is_some_and(|p| p.expires > now),
                now,
            )
            .is_ok();
        drop(inner);
        if !accepted {
            return Outcome::Rejected;
        }
        let mut session = pending
            .expect("accepted grant has a pending session")
            .session;
        if !matches!(
            tokio::time::timeout(CONNECT_LIMIT, self.transport.runtime_ready()).await,
            Ok(false)
        ) {
            self.inner.lock().await.guard.finish();
            return Outcome::Rejected;
        }
        let expected = session.observation();
        let checked = tokio::time::timeout(CONNECT_LIMIT, session.recheck()).await;
        if !matches!(checked, Ok(Ok(ref proof)) if proof.state == State::VerifiedPreboot
            && proof.identity == expected.identity)
        {
            self.inner.lock().await.guard.finish();
            return Outcome::Rejected;
        }
        let result = tokio::time::timeout(ATTEMPT_LIMIT, session.submit(password)).await;
        // The secret has been consumed and dropped before any runtime polling.
        let outcome = match result {
            Err(_) => Outcome::TimedOut,
            Ok(Err(Failure::DeliveryUnknown)) | Ok(Ok(())) => {
                let confirmation = async {
                    loop {
                        if self.transport.runtime_ready().await {
                            return Outcome::Running;
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                };
                tokio::time::timeout(self.completion_limit, confirmation)
                    .await
                    .unwrap_or(Outcome::Booting)
            }
            Ok(Err(_)) => Outcome::Rejected,
        };
        self.inner.lock().await.guard.finish();
        outcome
    }
}
