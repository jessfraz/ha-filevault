//! Fresh tailnet transport evidence, never cached controller presence or login.
use crate::{
    config::MacConfig,
    ssh_manual::ManualTransport,
    transport::{Failure, FutureResult, connect_candidate},
};
use schemars::JsonSchema;
use serde::Serialize;
use std::{net::IpAddr, sync::Arc, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCheck {
    NotConfigured,
    Verified,
    IdentityNeeded,
    Unavailable,
    NameUnavailable,
    TimedOut,
    Stale,
}

pub struct RuntimeEvidence {
    pub observed_at: Instant,
}
pub trait RuntimeObserver: Send + Sync {
    fn observe(&self) -> FutureResult<'_, Result<RuntimeEvidence, Failure>>;
}

pub struct TailnetRuntime {
    mac: Arc<MacConfig>,
    identities: Arc<dyn ManualTransport>,
}

pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let v = ip.octets();
            v[0] == 100 && (64..=127).contains(&v[1])
        }
        IpAddr::V6(ip) => ip.octets()[..6] == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0],
    }
}

impl TailnetRuntime {
    pub fn new(mac: Arc<MacConfig>, identities: Arc<dyn ManualTransport>) -> Result<Self, Failure> {
        let host = &mac.tailscale_host;
        let valid_name = host.len() <= 253
            && host.ends_with(".ts.net")
            && host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c));
        if mac.port == 0 || !(host.parse().is_ok_and(is_tailnet_ip) || valid_name) {
            return Err(Failure::Unverified);
        }
        Ok(Self { mac, identities })
    }
}

impl RuntimeObserver for TailnetRuntime {
    fn observe(&self) -> FutureResult<'_, Result<RuntimeEvidence, Failure>> {
        Box::pin(async {
            let address =
                tokio::net::lookup_host((self.mac.tailscale_host.as_str(), self.mac.port))
                    .await
                    .map_err(|_| Failure::Resolution)?
                    .find(|address| is_tailnet_ip(address.ip()))
                    .ok_or(Failure::Unverified)?;
            let connection = connect_candidate(&address.ip().to_string(), self.mac.port).await?;
            // Resolve to a live tailnet peer, not a LAN alias or cached online flag.
            if !is_tailnet_ip(connection.peer_addr.ip()) {
                return Err(Failure::Unverified);
            }
            if !self.identities.trusts_key(&connection.server_key)? {
                return Err(Failure::Identity);
            }
            // SSH verifies possession; no username, auth method, password, command,
            // forwarding, controller API, or new Tailscale grant is used.
            Ok(RuntimeEvidence {
                observed_at: Instant::now(),
            })
        })
    }
}
