use filevault::{
    api::{Access, authorize},
    guard::{AttemptGuard, Reject},
    policy::{Evidence, State, decide},
};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

fn locked() -> Evidence {
    Evidence {
        age_seconds: Some(1.0),
        preboot_verified: true,
        host_key_pinned: true,
        prior_preboot_age_seconds: Some(5.0),
        ..Evidence::default()
    }
}

#[test]
fn only_fresh_repeated_pinned_preboot_offers_unlock() {
    assert!(decide(locked()).unlock_available);
    for evidence in [
        Evidence {
            host_key_pinned: false,
            ..locked()
        },
        Evidence {
            prior_preboot_age_seconds: None,
            ..locked()
        },
        Evidence {
            prior_preboot_age_seconds: Some(11.0),
            ..locked()
        },
        Evidence {
            identity_conflict: true,
            ..locked()
        },
        Evidence {
            busy: true,
            ..locked()
        },
        Evidence {
            age_seconds: Some(f64::NAN),
            ..locked()
        },
        Evidence {
            age_seconds: Some(f64::INFINITY),
            ..locked()
        },
        Evidence {
            age_seconds: Some(-1.0),
            ..locked()
        },
        Evidence {
            age_seconds: Some(11.0),
            ..locked()
        },
    ] {
        assert!(!decide(evidence).unlock_available);
    }
}

#[test]
fn missing_services_do_not_establish_filevault_state() {
    assert_eq!(decide(Evidence::default()).state, State::Unknown);
    assert_eq!(
        decide(Evidence {
            age_seconds: Some(1.0),
            host_key_pinned: true,
            ..Evidence::default()
        })
        .state,
        State::Unknown
    );
    assert_eq!(
        decide(Evidence {
            age_seconds: Some(1.0),
            unreachable: true,
            ..Evidence::default()
        })
        .state,
        State::Unknown
    );
    assert_eq!(
        decide(Evidence {
            age_seconds: Some(1.0),
            unreachable: true,
            route_healthy: true,
            ..Evidence::default()
        })
        .state,
        State::Unreachable
    );
}

#[test]
fn positive_runtime_hides_unlock_and_conflict_is_unknown() {
    let running = Evidence {
        age_seconds: Some(1.0),
        runtime_verified: true,
        ..Evidence::default()
    };
    assert_eq!(decide(running).state, State::Running);
    assert!(!decide(running).unlock_available);
    assert_eq!(
        decide(Evidence {
            preboot_verified: true,
            ..running
        })
        .state,
        State::Unknown
    );
}

#[test]
fn ingress_requires_both_trusted_peer_and_allowlisted_user() {
    let peer = "172.30.32.2".parse().unwrap();
    let access = Access::Ingress {
        peer,
        users: HashSet::from(["test-user".into()]),
    };
    assert!(authorize(&access, peer, Some("test-user"), None));
    assert!(!authorize(
        &access,
        "127.0.0.1".parse().unwrap(),
        Some("test-user"),
        None
    ));
    assert!(!authorize(&access, peer, None, None));
    assert!(!authorize(&access, peer, Some("another-user"), None));
}

fn nonce(number: u64) -> String {
    format!("{number:064x}")
}
fn issue(guard: &mut AttemptGuard, now: Instant, n: u64) {
    assert!(guard.issue(nonce(n), "user".into(), "session".into(), now));
}

#[test]
fn grants_are_user_session_origin_bound_and_consumed_on_failure() {
    let start = Instant::now();
    let now = start + Duration::from_secs(61);
    let mut guard = AttemptGuard::new("https://ha.example.invalid".into(), start);
    for (n, user, session, origin, locked, expected) in [
        (
            1,
            "wrong",
            "session",
            "https://ha.example.invalid",
            true,
            Reject::User,
        ),
        (
            2,
            "user",
            "wrong",
            "https://ha.example.invalid",
            true,
            Reject::User,
        ),
        (
            3,
            "user",
            "session",
            "https://other.example.invalid",
            true,
            Reject::Origin,
        ),
        (
            4,
            "user",
            "session",
            "https://ha.example.invalid",
            false,
            Reject::State,
        ),
    ] {
        issue(&mut guard, now, n);
        assert_eq!(
            guard.begin(&nonce(n), user, session, origin, locked, now),
            Err(expected)
        );
        assert_eq!(
            guard.begin(
                &nonce(n),
                "user",
                "session",
                "https://ha.example.invalid",
                true,
                now
            ),
            Err(Reject::Nonce)
        );
    }
}

#[test]
fn no_concurrent_attempt_or_automatic_retry_after_finish() {
    let start = Instant::now();
    let now = start + Duration::from_secs(61);
    let mut guard = AttemptGuard::new("https://ha.example.invalid".into(), start);
    issue(&mut guard, now, 1);
    issue(&mut guard, now, 2);
    issue(&mut guard, now, 3);
    assert_eq!(
        guard.begin(
            &nonce(1),
            "user",
            "session",
            "https://ha.example.invalid",
            true,
            now
        ),
        Ok(())
    );
    assert_eq!(
        guard.begin(
            &nonce(2),
            "user",
            "session",
            "https://ha.example.invalid",
            true,
            now
        ),
        Err(Reject::Busy)
    );
    guard.finish();
    assert_eq!(
        guard.begin(
            &nonce(3),
            "user",
            "session",
            "https://ha.example.invalid",
            true,
            now
        ),
        Err(Reject::Cooldown)
    );
}

#[test]
fn expiry_and_startup_cooldown_fail_closed() {
    let start = Instant::now();
    let mut guard = AttemptGuard::new("https://ha.example.invalid".into(), start);
    issue(&mut guard, start, 1);
    assert_eq!(
        guard.begin(
            &nonce(1),
            "user",
            "session",
            "https://ha.example.invalid",
            true,
            start
        ),
        Err(Reject::Cooldown)
    );
    issue(&mut guard, start, 2);
    assert_eq!(
        guard.begin(
            &nonce(2),
            "user",
            "session",
            "https://ha.example.invalid",
            true,
            start + Duration::from_secs(60)
        ),
        Err(Reject::Expired)
    );
}

#[test]
fn no_password_configuration_fields() {
    assert!(
        serde_json::from_str::<filevault::config::Options>(
            r#"{"allowed_user_ids":[],"password":"DUMMY_SENTINEL"}"#
        )
        .is_err()
    );
    for payload in [
        r#"{"manual_ssh":{"password":"DUMMY_SENTINEL"}}"#,
        r#"{"ssh_recovery":{"password":"DUMMY_SENTINEL"}}"#,
    ] {
        assert!(serde_json::from_str::<filevault::config::Options>(payload).is_err());
    }
}
