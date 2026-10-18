use filevault::{
    controller::Controller,
    policy::State,
    runtime::{RuntimeCheck, RuntimeEvidence, RuntimeObserver, is_tailnet_ip},
    transport::{Disabled, Failure, FutureResult},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

enum Sample {
    Fresh,
    Stale,
    Unavailable,
    NameUnavailable,
    IdentityNeeded,
    TimedOut,
}
impl RuntimeObserver for Sample {
    fn observe(&self) -> FutureResult<'_, Result<RuntimeEvidence, Failure>> {
        Box::pin(async {
            match self {
                Self::Fresh => Ok(RuntimeEvidence {
                    observed_at: Instant::now(),
                }),
                Self::Stale => Ok(RuntimeEvidence {
                    observed_at: Instant::now() - Duration::from_secs(20),
                }),
                Self::Unavailable => Err(Failure::Unavailable),
                Self::NameUnavailable => Err(Failure::Resolution),
                Self::IdentityNeeded => Err(Failure::Identity),
                Self::TimedOut => std::future::pending().await,
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn only_fresh_verified_tailnet_response_establishes_running() {
    for (sample, expected) in [
        (Sample::Fresh, RuntimeCheck::Verified),
        (Sample::Stale, RuntimeCheck::Stale),
        (Sample::Unavailable, RuntimeCheck::Unavailable),
        (Sample::NameUnavailable, RuntimeCheck::NameUnavailable),
        (Sample::IdentityNeeded, RuntimeCheck::IdentityNeeded),
        (Sample::TimedOut, RuntimeCheck::TimedOut),
    ] {
        let controller = Controller::new(
            Arc::new(Disabled),
            "https://ha.example.invalid".into(),
            Instant::now(),
        )
        .with_runtime(Arc::new(sample));
        let (decision, check) = controller.observe_status().await;
        assert_eq!(check, expected);
        assert_eq!(
            decision.state,
            if expected == RuntimeCheck::Verified {
                State::Running
            } else {
                State::Unknown
            }
        );
        assert!(!decision.unlock_available);
    }
}

#[test]
fn tailnet_network_ranges_do_not_accept_lan_or_public_addresses() {
    for value in ["100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1"] {
        assert!(is_tailnet_ip(value.parse().unwrap()));
    }
    for value in [
        "100.63.255.255",
        "100.128.0.1",
        "127.0.0.1",
        "192.0.2.1",
        "fd00::1",
        "::1",
    ] {
        assert!(!is_tailnet_ip(value.parse().unwrap()));
    }
}
