use schemars::JsonSchema;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Running,
    SshReachable,
    VerifiedPreboot,
    Unreachable,
    Unknown,
}

/// Trusted server evidence only. A port, SSH version, or client claim is not proof.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence {
    pub age_seconds: Option<f64>,
    pub runtime_verified: bool,
    pub ssh_identity_verified: bool,
    pub preboot_verified: bool,
    pub host_key_pinned: bool,
    pub prior_preboot_age_seconds: Option<f64>,
    pub route_healthy: bool,
    pub unreachable: bool,
    pub identity_conflict: bool,
    pub busy: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Decision {
    pub state: State,
    pub unlock_available: bool,
}

fn fresh(age: Option<f64>) -> bool {
    age.is_some_and(|age| age.is_finite() && (0.0..=10.0).contains(&age))
}

pub fn decide(e: Evidence) -> Decision {
    let state = if !fresh(e.age_seconds)
        || e.identity_conflict
        || (e.runtime_verified && (e.preboot_verified || e.unreachable))
    {
        State::Unknown
    } else if e.runtime_verified {
        State::Running
    } else if e.ssh_identity_verified {
        State::SshReachable
    } else if e.busy {
        State::Unknown
    } else if e.preboot_verified
        && e.host_key_pinned
        && fresh(e.prior_preboot_age_seconds)
        && !e.unreachable
    {
        State::VerifiedPreboot
    } else if e.route_healthy && e.unreachable {
        State::Unreachable
    } else {
        State::Unknown
    };
    Decision {
        state,
        unlock_available: state == State::VerifiedPreboot,
    }
}
