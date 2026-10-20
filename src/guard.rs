use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    User,
    Origin,
    Nonce,
    Expired,
    State,
    Busy,
    Cooldown,
}

struct Grant {
    user: String,
    session: String,
    expires: Instant,
}

/// Non-secret request policy, separate from credential bytes.
/// Callers supply CSPRNG tokens; passwords must never be passed to this type.
pub struct AttemptGuard {
    grants: HashMap<String, Grant>,
    origin: String,
    busy: bool,
    cooldown_until: Instant,
}

impl AttemptGuard {
    pub fn busy(&self) -> bool {
        self.busy
    }

    pub fn retry_after(&self, now: Instant) -> Duration {
        self.cooldown_until.saturating_duration_since(now)
    }

    pub fn check(&self, now: Instant) -> Result<(), Reject> {
        if self.busy {
            Err(Reject::Busy)
        } else if now < self.cooldown_until {
            Err(Reject::Cooldown)
        } else {
            Ok(())
        }
    }

    pub fn available(&self, now: Instant) -> bool {
        !self.busy && now >= self.cooldown_until
    }

    pub fn revoke(&mut self, nonce: &str) {
        self.grants.remove(nonce);
    }

    pub fn owns(&self, nonce: &str, user: &str, session: &str, origin: &str, now: Instant) -> bool {
        self.grants.get(nonce).is_some_and(|grant| {
            grant.expires > now
                && grant.user == user
                && grant.session == session
                && self.origin == origin
        })
    }

    pub fn new(origin: String, now: Instant) -> Self {
        Self {
            grants: HashMap::new(),
            origin,
            busy: false,
            cooldown_until: now + Duration::from_secs(60),
        }
    }

    pub fn issue(&mut self, nonce: String, user: String, session: String, now: Instant) -> bool {
        self.grants.retain(|_, grant| grant.expires > now);
        if nonce.len() != 64
            || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
            || user.is_empty()
            || session.is_empty()
            || self.grants.len() >= 64
            || self.grants.contains_key(&nonce)
        {
            return false;
        }
        self.grants.insert(
            nonce,
            Grant {
                user,
                session,
                expires: now + Duration::from_secs(60),
            },
        );
        true
    }

    pub fn begin(
        &mut self,
        nonce: &str,
        user: &str,
        session: &str,
        origin: &str,
        authorized_session: bool,
        now: Instant,
    ) -> Result<(), Reject> {
        // Caller holds the guard mutex throughout this operation. Consumption
        // precedes every decision, so failed requests cannot replay a grant.
        let grant = self.grants.remove(nonce).ok_or(Reject::Nonce)?;
        if grant.expires <= now {
            return Err(Reject::Expired);
        }
        if user != grant.user || session != grant.session {
            return Err(Reject::User);
        }
        if origin != self.origin {
            return Err(Reject::Origin);
        }
        if !authorized_session {
            return Err(Reject::State);
        }
        if self.busy {
            return Err(Reject::Busy);
        }
        if now < self.cooldown_until {
            return Err(Reject::Cooldown);
        }
        self.busy = true;
        self.cooldown_until = now + Duration::from_secs(60);
        Ok(())
    }

    pub fn finish(&mut self) {
        self.busy = false;
    }
}
