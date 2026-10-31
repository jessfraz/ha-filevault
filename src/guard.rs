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
    client: ClientKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientKind {
    Browser,
    NativeCli,
}

#[derive(Clone, Copy)]
pub(crate) enum RequestClient<'a> {
    Browser(&'a str),
    NativeCli,
}

impl RequestClient<'_> {
    pub(crate) fn kind(self) -> ClientKind {
        match self {
            Self::Browser(_) => ClientKind::Browser,
            Self::NativeCli => ClientKind::NativeCli,
        }
    }
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
        self.owns_for(nonce, user, session, RequestClient::Browser(origin), now)
    }

    pub(crate) fn owns_for(
        &self,
        nonce: &str,
        user: &str,
        session: &str,
        client: RequestClient<'_>,
        now: Instant,
    ) -> bool {
        self.grants.get(nonce).is_some_and(|grant| {
            grant.expires > now
                && grant.user == user
                && grant.session == session
                && self.accepts_client(grant, client)
        })
    }

    fn accepts_client(&self, grant: &Grant, client: RequestClient<'_>) -> bool {
        grant.client == client.kind()
            && match client {
                RequestClient::Browser(origin) => self.origin == origin,
                RequestClient::NativeCli => true,
            }
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
        self.issue_for(nonce, user, session, ClientKind::Browser, now)
    }

    pub(crate) fn issue_for(
        &mut self,
        nonce: String,
        user: String,
        session: String,
        client: ClientKind,
        now: Instant,
    ) -> bool {
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
                client,
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
        self.begin_for(
            nonce,
            user,
            session,
            RequestClient::Browser(origin),
            authorized_session,
            now,
        )
    }

    pub(crate) fn begin_for(
        &mut self,
        nonce: &str,
        user: &str,
        session: &str,
        client: RequestClient<'_>,
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
        if !self.accepts_client(&grant, client) {
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

#[cfg(test)]
mod tests {
    use super::{AttemptGuard, ClientKind, Reject, RequestClient};
    use std::time::{Duration, Instant};

    #[test]
    fn native_and_browser_grants_cannot_cross_request_channels() {
        let start = Instant::now();
        let now = start + Duration::from_secs(61);
        let mut guard = AttemptGuard::new("https://ha.example.invalid".into(), start);
        let browser = "a".repeat(64);
        assert!(guard.issue(browser.clone(), "user".into(), "cookie".into(), now));
        assert!(!guard.owns_for(&browser, "user", "cookie", RequestClient::NativeCli, now));
        assert_eq!(
            guard.begin_for(
                &browser,
                "user",
                "cookie",
                RequestClient::NativeCli,
                true,
                now
            ),
            Err(Reject::Origin)
        );
        assert_eq!(
            guard.begin(
                &browser,
                "user",
                "cookie",
                "https://ha.example.invalid",
                true,
                now
            ),
            Err(Reject::Nonce)
        );

        let native = "b".repeat(64);
        assert!(guard.issue_for(
            native.clone(),
            "user".into(),
            "cookie".into(),
            ClientKind::NativeCli,
            now
        ));
        assert!(!guard.owns(&native, "user", "cookie", "https://ha.example.invalid", now));
        assert_eq!(
            guard.begin(
                &native,
                "user",
                "cookie",
                "https://ha.example.invalid",
                true,
                now
            ),
            Err(Reject::Origin)
        );
        assert_eq!(
            guard.begin_for(
                &native,
                "user",
                "cookie",
                RequestClient::NativeCli,
                true,
                now
            ),
            Err(Reject::Nonce)
        );
    }

    #[test]
    fn native_grant_keeps_user_cookie_and_cooldown_binding() {
        let start = Instant::now();
        let now = start + Duration::from_secs(61);
        let mut guard = AttemptGuard::new("https://ha.example.invalid".into(), start);
        let nonce = "c".repeat(64);
        assert!(guard.issue_for(
            nonce.clone(),
            "user".into(),
            "cookie".into(),
            ClientKind::NativeCli,
            now
        ));
        assert!(guard.owns_for(&nonce, "user", "cookie", RequestClient::NativeCli, now));
        assert!(!guard.owns_for(
            &nonce,
            "another-user",
            "cookie",
            RequestClient::NativeCli,
            now
        ));
        assert!(!guard.owns_for(
            &nonce,
            "user",
            "another-cookie",
            RequestClient::NativeCli,
            now
        ));
        assert_eq!(
            guard.begin_for(
                &nonce,
                "user",
                "cookie",
                RequestClient::NativeCli,
                true,
                now
            ),
            Ok(())
        );
        assert!(guard.busy());
        guard.finish();
        assert_eq!(guard.check(now), Err(Reject::Cooldown));
    }
}
