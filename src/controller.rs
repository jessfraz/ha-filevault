use crate::{
    config::MacConfig,
    connectivity::{ConnectionChecks, ConnectivityReport},
    guard::{AttemptGuard, Reject},
    policy::{Decision, Evidence, State, decide},
    runtime::{RuntimeCheck, RuntimeObserver},
    secret::Secret,
    ssh_manual::{ManualTarget, ManualTransport},
    store::HistoryPage,
    transport::{Failure, Session, Transport},
};
use schemars::JsonSchema;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

pub const CONNECT_LIMIT: Duration = Duration::from_secs(5);
pub const ATTEMPT_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Running,
    Booting,
    Rejected,
    TimedOut,
    Authenticated,
    Unconfirmed,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct RecoveryEvent {
    elapsed_ms: u64,
    message: &'static str,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct RecoveryActivity {
    pub events: Vec<RecoveryEvent>,
    pub outcome: Option<Outcome>,
    pub active: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct RecoveryStatus {
    pub busy: bool,
    pub retry_after_ms: u64,
    pub activity: Option<RecoveryActivity>,
}

struct Activity {
    user: String,
    started: Instant,
    report: RecoveryActivity,
}

pub struct Challenge {
    pub nonce: String,
    pub cookie: String,
}
pub struct ManualChallenge {
    pub challenge: Challenge,
    pub target: ManualTarget,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptMode {
    Automatic,
    Manual,
}
struct Pending {
    session: Box<dyn Session>,
    expires: Instant,
    mode: AttemptMode,
    trusted: bool,
    server_key: Option<russh::keys::PublicKey>,
}
struct Inner {
    guard: AttemptGuard,
    pending: HashMap<String, Pending>,
    activity: Option<Activity>,
}

pub struct Controller {
    transport: Arc<dyn Transport>,
    manual: Option<Arc<dyn ManualTransport>>,
    observer: Option<Arc<dyn Transport>>,
    configuration_errors: Vec<&'static str>,
    configuration_notes: Vec<&'static str>,
    connection: Option<MacConfig>,
    runtime: Option<Arc<dyn RuntimeObserver>>,
    connectivity: Option<Arc<ConnectionChecks>>,
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
    pub async fn recovery_status(&self, user: &str) -> RecoveryStatus {
        let inner = self.inner.lock().await;
        RecoveryStatus {
            busy: inner.guard.busy(),
            retry_after_ms: inner.guard.retry_after(Instant::now()).as_millis() as u64,
            activity: inner
                .activity
                .as_ref()
                .filter(|a| a.user == user)
                .map(|a| a.report.clone()),
        }
    }

    async fn available(&self) -> Result<(), Failure> {
        self.inner
            .lock()
            .await
            .guard
            .check(Instant::now())
            .map_err(|error| match error {
                Reject::Busy => Failure::Busy,
                Reject::Cooldown => Failure::Cooldown,
                _ => Failure::Rejected,
            })
    }

    async fn start_activity(&self, user: &str) {
        self.inner.lock().await.activity = Some(Activity {
            user: user.into(),
            started: Instant::now(),
            report: RecoveryActivity {
                events: Vec::new(),
                outcome: None,
                active: true,
            },
        });
        self.event(user, "SSH session prepared; retained connection ready.")
            .await;
    }

    async fn event(&self, user: &str, message: &'static str) {
        let mut inner = self.inner.lock().await;
        if let Some(activity) = inner.activity.as_mut().filter(|a| a.user == user) {
            // Fixed vocabulary only: no server text, credential bytes or errors.
            if activity.report.events.len() < 32 {
                activity.report.events.push(RecoveryEvent {
                    elapsed_ms: activity.started.elapsed().as_millis() as u64,
                    message,
                });
            }
        }
    }

    async fn finish_activity(&self, user: &str, outcome: Outcome) -> Outcome {
        self.event(user, match outcome {
            Outcome::Running => "Mac startup confirmed by a fresh, trusted runtime SSH response.",
            Outcome::Booting => "SSH attempt finished, but Mac startup was not confirmed before the wait ended.",
            Outcome::Authenticated => "SSH accepted the password. Mac startup remains unconfirmed.",
            Outcome::Unconfirmed => "SSH disconnected after password submission. Mac startup remains unconfirmed; no password retry was made.",
            Outcome::Rejected => "The SSH attempt was rejected. No password retry was made.",
            Outcome::TimedOut => "SSH password authentication timed out. Delivery and unlock are unconfirmed; no retry was made.",
        }).await;
        let mut inner = self.inner.lock().await;
        inner.guard.finish();
        if let Some(activity) = inner.activity.as_mut().filter(|a| a.user == user) {
            activity.report.active = false;
            activity.report.outcome = Some(outcome);
        }
        outcome
    }

    async fn runtime_verified(&self) -> bool {
        if let Some(runtime) = &self.runtime {
            return matches!(tokio::time::timeout(CONNECT_LIMIT, runtime.observe()).await,
                Ok(Ok(evidence)) if evidence.observed_at <= Instant::now()
                    && evidence.observed_at.elapsed() <= Duration::from_secs(10));
        }
        tokio::time::timeout(CONNECT_LIMIT, self.transport.runtime_ready())
            .await
            .unwrap_or(false)
    }

    pub fn new(transport: Arc<dyn Transport>, origin: String, started: Instant) -> Self {
        Self {
            transport,
            manual: None,
            observer: None,
            configuration_errors: Vec::new(),
            configuration_notes: Vec::new(),
            connection: None,
            runtime: None,
            connectivity: None,
            inner: Arc::new(Mutex::new(Inner {
                guard: AttemptGuard::new(origin.clone(), started),
                pending: HashMap::new(),
                activity: None,
            })),
            preparing: Semaphore::new(1),
            origin,
            completion_limit: Duration::from_secs(120),
        }
    }

    pub fn with_manual(mut self, manual: Arc<dyn ManualTransport>) -> Self {
        self.manual = Some(manual);
        self
    }

    pub fn manual_ready(&self) -> bool {
        self.manual.is_some() && !self.origin.is_empty()
    }

    pub fn with_observer(mut self, observer: Arc<dyn Transport>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn with_configuration_errors(mut self, errors: Vec<&'static str>) -> Self {
        self.configuration_errors = errors;
        self
    }

    pub fn configuration_errors(&self) -> Vec<&'static str> {
        self.configuration_errors.clone()
    }

    pub fn with_configuration_notes(mut self, notes: Vec<&'static str>) -> Self {
        self.configuration_notes = notes;
        self
    }
    pub fn configuration_notes(&self) -> Vec<&'static str> {
        self.configuration_notes.clone()
    }
    pub fn with_connection(mut self, connection: Option<MacConfig>) -> Self {
        self.connection = connection;
        self
    }
    pub fn connection(&self) -> Option<MacConfig> {
        self.connection.clone()
    }
    pub fn with_runtime(mut self, runtime: Arc<dyn RuntimeObserver>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn with_connectivity(mut self, connectivity: Arc<ConnectionChecks>) -> Self {
        self.connectivity = Some(connectivity);
        self
    }

    pub async fn check_connections(&self) -> Result<ConnectivityReport, Failure> {
        self.connectivity
            .as_ref()
            .ok_or(Failure::Unverified)?
            .check()
            .await
    }
    pub async fn connection_history(
        &self,
        before: Option<i64>,
        limit: u32,
    ) -> Result<HistoryPage, Failure> {
        self.connectivity
            .as_ref()
            .ok_or(Failure::Unavailable)?
            .history(before, limit)
            .await
    }
    pub async fn drain_connections(&self) {
        if let Some(checks) = &self.connectivity {
            checks.drain().await;
        }
    }

    pub async fn observe_status(&self) -> (Decision, RuntimeCheck) {
        let runtime_check = if let Some(runtime) = &self.runtime {
            match tokio::time::timeout(CONNECT_LIMIT, runtime.observe()).await {
                Ok(Ok(evidence)) => {
                    if evidence.observed_at.elapsed() <= Duration::from_secs(10)
                        && evidence.observed_at <= Instant::now()
                    {
                        RuntimeCheck::Verified
                    } else {
                        RuntimeCheck::Stale
                    }
                }
                Ok(Err(Failure::Identity)) => RuntimeCheck::IdentityNeeded,
                Ok(Err(Failure::Resolution)) => RuntimeCheck::NameUnavailable,
                Err(_) | Ok(Err(Failure::Timeout)) => RuntimeCheck::TimedOut,
                _ => RuntimeCheck::Unavailable,
            }
        } else {
            RuntimeCheck::NotConfigured
        };
        if runtime_check == RuntimeCheck::Verified {
            return (
                decide(Evidence {
                    age_seconds: Some(0.0),
                    runtime_verified: true,
                    ..Default::default()
                }),
                runtime_check,
            );
        }
        (self.phase_status().await, runtime_check)
    }

    async fn observed_ssh(&self) -> Decision {
        let pinned = if let Some(observer) = &self.observer {
            matches!(
                tokio::time::timeout(CONNECT_LIMIT, observer.open()).await,
                Ok(Ok(_))
            )
        } else {
            false
        };
        let trusted = if !pinned {
            if let Some(manual) = &self.manual {
                matches!(tokio::time::timeout(CONNECT_LIMIT, manual.open()).await,
                Ok(Ok(ref connection)) if connection.target.trusted)
            } else {
                false
            }
        } else {
            true
        };
        decide(Evidence {
            age_seconds: Some(0.0),
            ssh_identity_verified: trusted,
            ..Default::default()
        })
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
        self.observe_status().await.0
    }

    async fn phase_status(&self) -> Decision {
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
            return self.observed_ssh().await;
        };
        let observation = session.observation();
        if observation.state != State::VerifiedPreboot || !self.ready() {
            return self.observed_ssh().await;
        }
        drop(session);
        let repeated = tokio::time::timeout(CONNECT_LIMIT, self.transport.open()).await;
        let Ok(Ok(repeated)) = repeated else {
            return self.observed_ssh().await;
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
        let _preparing = self.preparing.try_acquire().map_err(|_| Failure::Busy)?;
        if !self.ready() || self.origin.is_empty() {
            return Err(Failure::Unverified);
        }
        self.available().await?;
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
        self.issue_session(user, second, AttemptMode::Automatic, true, None)
            .await
    }

    pub async fn manual_challenge(&self, user: &str) -> Result<ManualChallenge, Failure> {
        let _preparing = self.preparing.try_acquire().map_err(|_| Failure::Busy)?;
        if !self.manual_ready() {
            return Err(Failure::Unverified);
        }
        self.available().await?;
        let connection = tokio::time::timeout(
            CONNECT_LIMIT,
            self.manual.as_ref().ok_or(Failure::Unverified)?.open(),
        )
        .await
        .map_err(|_| Failure::Timeout)??;
        let challenge = self
            .issue_session(
                user,
                connection.session,
                AttemptMode::Manual,
                connection.target.trusted,
                Some(connection.server_key),
            )
            .await?;
        Ok(ManualChallenge {
            challenge,
            target: connection.target,
        })
    }

    async fn issue_session(
        &self,
        user: &str,
        session: Box<dyn Session>,
        mode: AttemptMode,
        trusted: bool,
        server_key: Option<russh::keys::PublicKey>,
    ) -> Result<Challenge, Failure> {
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
                session,
                expires: now + Duration::from_secs(60),
                mode,
                trusted,
                server_key,
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
        self.submit_mode(
            AttemptMode::Automatic,
            true,
            [nonce, cookie, user, origin],
            password,
        )
        .await
    }

    pub async fn trust_manual(
        &self,
        nonce: &str,
        cookie: &str,
        user: &str,
        origin: &str,
    ) -> Result<(), Failure> {
        let mut inner = self.inner.lock().await;
        if !inner
            .guard
            .owns(nonce, user, cookie, origin, Instant::now())
        {
            return Err(Failure::Rejected);
        }
        let pending = inner.pending.get_mut(nonce).ok_or(Failure::Rejected)?;
        if pending.mode != AttemptMode::Manual || pending.expires <= Instant::now() {
            return Err(Failure::Rejected);
        }
        let expected = pending.session.observation();
        let proof = tokio::time::timeout(CONNECT_LIMIT, pending.session.recheck())
            .await
            .map_err(|_| Failure::Timeout)??;
        if expected.identity != proof.identity {
            return Err(Failure::Identity);
        }
        self.manual
            .as_ref()
            .ok_or(Failure::Unverified)?
            .trust(pending.server_key.as_ref().ok_or(Failure::Identity)?)?;
        pending.session.confirm_manual_host()?;
        pending.trusted = true;
        Ok(())
    }

    pub async fn submit_manual(
        &self,
        nonce: &str,
        cookie: &str,
        user: &str,
        origin: &str,
        confirmed: bool,
        password: Secret,
    ) -> Outcome {
        self.submit_mode(
            AttemptMode::Manual,
            confirmed,
            [nonce, cookie, user, origin],
            password,
        )
        .await
    }

    async fn submit_mode(
        &self,
        mode: AttemptMode,
        confirmed: bool,
        request: [&str; 4],
        password: Secret,
    ) -> Outcome {
        let [nonce, cookie, user, origin] = request;
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
                confirmed
                    && pending
                        .as_ref()
                        .is_some_and(|p| p.expires > now && p.mode == mode && p.trusted),
                now,
            )
            .is_ok();
        drop(inner);
        if !accepted {
            return Outcome::Rejected;
        }
        self.start_activity(user).await;
        self.event(
            user,
            "Checking the retained SSH connection and server identity before authentication.",
        )
        .await;
        let mut session = pending
            .expect("accepted grant has a pending session")
            .session;
        if mode == AttemptMode::Automatic
            && !matches!(
                tokio::time::timeout(CONNECT_LIMIT, self.transport.runtime_ready()).await,
                Ok(false)
            )
        {
            return self.finish_activity(user, Outcome::Rejected).await;
        }
        let expected = session.observation();
        let checked = tokio::time::timeout(CONNECT_LIMIT, session.recheck()).await;
        if !matches!(checked, Ok(Ok(ref proof)) if proof.identity == expected.identity
            && (mode == AttemptMode::Manual || proof.state == State::VerifiedPreboot))
        {
            self.event(user, "The retained SSH connection expired, closed, or changed identity. No password was sent.").await;
            return self.finish_activity(user, Outcome::Rejected).await;
        }
        self.event(user, "Sending one SSH password authentication request; waiting for the server response (up to 30 seconds).").await;
        let result = tokio::time::timeout(ATTEMPT_LIMIT, session.submit(password)).await;
        // The secret has been consumed and dropped before any runtime polling.
        let outcome = match result {
            Err(_) | Ok(Err(Failure::DeliveryUnknown)) | Ok(Ok(())) => {
                let authenticated = matches!(result, Ok(Ok(())));
                let timed_out = result.is_err();
                if mode == AttemptMode::Manual
                    && self.runtime.is_none()
                    && !self.transport.unlock_ready()
                {
                    self.event(user, "No normal-runtime check is configured. SSH authentication cannot confirm Mac startup.").await;
                    return self
                        .finish_activity(
                            user,
                            if timed_out {
                                Outcome::TimedOut
                            } else if authenticated {
                                Outcome::Authenticated
                            } else {
                                Outcome::Unconfirmed
                            },
                        )
                        .await;
                }
                self.event(user, if timed_out {
                    "SSH authentication did not respond within 30 seconds. Checking whether macOS started; the password will not be resent."
                } else if authenticated {
                    "SSH accepted the password. Waiting up to 120 seconds for verified macOS startup."
                } else {
                    "SSH disconnected during authentication. FileVault may be starting macOS; checking runtime without resending the password."
                }).await;
                let confirmation = async {
                    loop {
                        if self.runtime_verified().await {
                            return Outcome::Running;
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                };
                tokio::time::timeout(self.completion_limit, confirmation)
                    .await
                    .unwrap_or(if mode == AttemptMode::Manual {
                        if timed_out {
                            Outcome::TimedOut
                        } else if authenticated {
                            Outcome::Authenticated
                        } else {
                            Outcome::Unconfirmed
                        }
                    } else if timed_out {
                        Outcome::TimedOut
                    } else {
                        Outcome::Booting
                    })
            }
            Ok(Err(_)) => {
                self.event(
                    user,
                    "The SSH server rejected authentication for the configured account.",
                )
                .await;
                Outcome::Rejected
            }
        };
        self.finish_activity(user, outcome).await
    }
}
