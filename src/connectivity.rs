//! Bounded checks of configured endpoints, without SSH authentication or trust.
use crate::{
    config::MacConfig,
    runtime::{is_tailnet_ip, valid_tailnet_host},
    ssh_manual::ManualTransport,
    store::{ConnectionRun, HistoryPage, Store, connection_fingerprint},
    transport::{Failure, FutureResult, connect_stream_candidate},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, sync::Semaphore, time::timeout};

const DNS_LIMIT: Duration = Duration::from_secs(2);
const TCP_LIMIT: Duration = Duration::from_secs(1);
const SSH_LIMIT: Duration = Duration::from_secs(3);
const MAX_ADDRESSES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsCheck {
    NotChecked,
    NotConfigured,
    Resolved,
    Failed,
    TimedOut,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TcpCheck {
    NotChecked,
    Connected,
    Unreachable,
    TimedOut,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SshCheck {
    NotChecked,
    Trusted,
    IdentityNeeded,
    Unavailable,
    TimedOut,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EndpointCheck {
    pub host: String,
    pub port: u16,
    pub dns: DnsCheck,
    pub tcp: TcpCheck,
    pub ssh: SshCheck,
}
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ConnectivityReport {
    pub lan: EndpointCheck,
    pub tailscale: EndpointCheck,
    /// IPs only, never search domains or the complete resolver configuration.
    pub nameservers: Vec<IpAddr>,
    pub run: Option<ConnectionRun>,
}

pub trait Resolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> FutureResult<'a, Result<Vec<SocketAddr>, Failure>>;
}
struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> FutureResult<'a, Result<Vec<SocketAddr>, Failure>> {
        Box::pin(async move {
            tokio::net::lookup_host((host, port))
                .await
                .map(|addresses| addresses.take(16).collect())
                .map_err(|_| Failure::Resolution)
        })
    }
}

#[derive(Clone)]
pub struct ConnectionChecks {
    mac: Arc<MacConfig>,
    identities: Option<Arc<dyn ManualTransport>>,
    resolver: Arc<dyn Resolver>,
    in_flight: Arc<Semaphore>,
    store: Option<Store>,
}
impl ConnectionChecks {
    pub fn new(mac: Arc<MacConfig>, identities: Option<Arc<dyn ManualTransport>>) -> Self {
        Self::with_resolver(mac, identities, Arc::new(SystemResolver))
    }
    pub fn with_resolver(
        mac: Arc<MacConfig>,
        identities: Option<Arc<dyn ManualTransport>>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            mac,
            identities,
            resolver,
            in_flight: Arc::new(Semaphore::new(1)),
            store: None,
        }
    }
    pub fn with_store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }
    /// Runs without a browser. Shares the manual check semaphore, never queues
    /// overlapping probes, and uses completion-relative sleeps (no catch-up).
    pub async fn monitor(&self, interval: Duration, mut stop: tokio::sync::watch::Receiver<bool>) {
        let interval = interval.clamp(Duration::from_secs(15), Duration::from_secs(300));
        let mut delay = interval;
        loop {
            if *stop.borrow() {
                break;
            }
            let healthy = match self.check().await {
                Ok(report) => [report.lan.ssh, report.tailscale.ssh].contains(&SshCheck::Trusted),
                Err(_) => false,
            };
            delay = if healthy {
                interval
            } else {
                (delay * 2).min(Duration::from_secs(300))
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                _ = stop.changed() => break,
            }
        }
    }

    pub async fn history(&self, before: Option<i64>, limit: u32) -> Result<HistoryPage, Failure> {
        self.store
            .as_ref()
            .ok_or(Failure::Unavailable)?
            .history(&connection_fingerprint(&self.mac), before, limit)
            .await
            .map_err(|_| Failure::Unavailable)
    }
    pub async fn drain(&self) {
        // Listeners have stopped admitting requests before shutdown reaches us.
        let _permit = self.in_flight.acquire().await;
    }
    pub async fn check(&self) -> Result<ConnectivityReport, Failure> {
        // No queued probes or shared recovery locks. An accepted check finishes
        // and records its bounded probes even if the browser stops waiting.
        let permit = self
            .in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let checks = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            checks.run().await
        })
        .await
        .map_err(|_| Failure::Unavailable)?
    }
    async fn run(&self) -> Result<ConnectivityReport, Failure> {
        let sequence = match &self.store {
            Some(store) => Some(
                store
                    .begin(&self.mac)
                    .await
                    .map_err(|_| Failure::Unavailable)?,
            ),
            None => None,
        };
        let (lan, tailscale) = tokio::join!(
            self.endpoint(&self.mac.host, false),
            self.endpoint(&self.mac.tailscale_host, true),
        );
        let run = match (&self.store, sequence) {
            (Some(store), Some(sequence)) => Some(
                store
                    .finish(sequence, &lan, &tailscale)
                    .await
                    .map_err(|_| Failure::Unavailable)?,
            ),
            _ => None,
        };
        Ok(ConnectivityReport {
            lan,
            tailscale,
            nameservers: resolver_nameservers(),
            run,
        })
    }
    async fn endpoint(&self, host: &str, tailnet: bool) -> EndpointCheck {
        let mut report = EndpointCheck {
            host: host.into(),
            port: self.mac.port,
            dns: DnsCheck::NotConfigured,
            tcp: TcpCheck::NotChecked,
            ssh: SshCheck::NotChecked,
        };
        if host.is_empty() {
            return report;
        }
        if self.mac.port == 0
            || host.len() > 253
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_:%".contains(&c))
            || (tailnet && !valid_tailnet_host(host))
        {
            report.dns = DnsCheck::Rejected;
            return report;
        }
        let resolved = match timeout(DNS_LIMIT, self.resolver.resolve(host, self.mac.port)).await {
            Ok(Ok(addresses)) if !addresses.is_empty() => addresses,
            Err(_) => {
                report.dns = DnsCheck::TimedOut;
                return report;
            }
            _ => {
                report.dns = DnsCheck::Failed;
                return report;
            }
        };
        let mut addresses = Vec::new();
        for address in resolved.into_iter().take(16) {
            if address.port() == self.mac.port
                && (!tailnet || is_tailnet_ip(address.ip()))
                && !addresses.contains(&address)
            {
                addresses.push(address);
                if addresses.len() == MAX_ADDRESSES {
                    break;
                }
            }
        }
        if addresses.is_empty() {
            report.dns = DnsCheck::Rejected;
            return report;
        }
        report.dns = DnsCheck::Resolved;
        let mut timed_out = false;
        let mut connected = None;
        for address in addresses {
            match timeout(TCP_LIMIT, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => timed_out = true,
                _ => {}
            }
        }
        let Some(stream) = connected else {
            report.tcp = if timed_out {
                TcpCheck::TimedOut
            } else {
                TcpCheck::Unreachable
            };
            return report;
        };
        report.tcp = TcpCheck::Connected;
        if tailnet
            && !stream
                .peer_addr()
                .is_ok_and(|address| is_tailnet_ip(address.ip()))
        {
            report.ssh = SshCheck::Unavailable;
            return report;
        }
        report.ssh = match timeout(SSH_LIMIT, connect_stream_candidate(stream)).await {
            Ok(Ok(connection)) => match &self.identities {
                Some(identities) => match identities.trusts_key(&connection.server_key) {
                    Ok(true) => SshCheck::Trusted,
                    Ok(false) => SshCheck::IdentityNeeded,
                    Err(_) => SshCheck::Unavailable,
                },
                None => SshCheck::IdentityNeeded,
            },
            Err(_) => SshCheck::TimedOut,
            _ => SshCheck::Unavailable,
        };
        report
    }
}

fn resolver_nameservers() -> Vec<IpAddr> {
    let Ok(file) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    if file.len() > 4096 {
        return Vec::new();
    }
    file.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next()?.parse().ok())
                .flatten()
        })
        .take(3)
        .collect()
}
