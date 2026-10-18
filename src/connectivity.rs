//! Bounded checks of configured endpoints, without SSH authentication or trust.
use crate::{
    config::MacConfig,
    runtime::{is_tailnet_ip, valid_tailnet_host},
    ssh_manual::ManualTransport,
    transport::{Failure, FutureResult, connect_stream_candidate},
};
use schemars::JsonSchema;
use serde::Serialize;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsCheck {
    NotConfigured,
    Resolved,
    Failed,
    TimedOut,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TcpCheck {
    NotChecked,
    Connected,
    Unreachable,
    TimedOut,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
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

pub struct ConnectionChecks {
    mac: Arc<MacConfig>,
    identities: Option<Arc<dyn ManualTransport>>,
    resolver: Arc<dyn Resolver>,
    in_flight: Semaphore,
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
            in_flight: Semaphore::new(1),
        }
    }
    pub async fn check(&self) -> Result<ConnectivityReport, Failure> {
        // No queued probes or shared recovery locks. Dropping a request cancels
        // its probes and closes any in-progress SSH socket.
        let _permit = self
            .in_flight
            .try_acquire()
            .map_err(|_| Failure::Unavailable)?;
        let (lan, tailscale) = tokio::join!(
            self.endpoint(&self.mac.host, false),
            self.endpoint(&self.mac.tailscale_host, true),
        );
        Ok(ConnectivityReport {
            lan,
            tailscale,
            nameservers: resolver_nameservers(),
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
