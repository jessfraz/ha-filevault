use filevault::{
    api::{self, Access, Context},
    config::MacConfig,
    connectivity::{ConnectionChecks, DnsCheck, Resolver, SshCheck, TcpCheck},
    controller::Controller,
    ssh_manual::{ManualConfig, ManualTransport, SshManual},
    transport::{Disabled, Failure, FutureResult},
};
use russh::{
    keys::{Algorithm, PrivateKey},
    server,
};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

struct FixedResolver {
    addresses: Vec<SocketAddr>,
    calls: AtomicUsize,
}
impl Resolver for FixedResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        _: u16,
    ) -> FutureResult<'a, Result<Vec<SocketAddr>, Failure>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if host.ends_with(".ts.net") {
                Err(Failure::Resolution)
            } else {
                Ok(self.addresses.clone())
            }
        })
    }
}
fn mac(port: u16) -> Arc<MacConfig> {
    Arc::new(MacConfig {
        host: "mac.example.invalid".into(),
        port,
        username: "fixture-user".into(),
        manual_enabled: true,
        tailscale_host: concat!("mac.example", ".ts.net").into(),
    })
}
struct Peer(Arc<AtomicUsize>);
impl server::Handler for Peer {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(server::Auth::reject())
    }
    async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(server::Auth::reject())
    }
    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(server::Auth::reject())
    }
}

#[tokio::test]
async fn real_handshake_distinguishes_identity_without_authentication_or_trust_writes() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let auth = Arc::new(AtomicUsize::new(0));
    let counter = auth.clone();
    let public = key.public_key().clone();
    let serve = tokio::spawn(async move {
        while let Ok((stream, _)) = socket.accept().await {
            let config = Arc::new(server::Config {
                keys: vec![key.clone()],
                inactivity_timeout: Some(Duration::from_secs(4)),
                ..Default::default()
            });
            let peer = Peer(counter.clone());
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, peer).await {
                    let _ = session.await;
                }
            });
        }
    });
    let config = mac(address.port());
    let identities = Arc::new(
        SshManual::new(ManualConfig {
            enabled: true,
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            trusted_public_keys: vec![],
        })
        .unwrap(),
    );
    let checks = ConnectionChecks::with_resolver(
        config.clone(),
        Some(identities.clone()),
        Arc::new(FixedResolver {
            addresses: vec![address],
            calls: AtomicUsize::new(0),
        }),
    );
    let report = checks.check().await.unwrap();
    assert_eq!(
        (report.lan.dns, report.lan.tcp, report.lan.ssh),
        (
            DnsCheck::Resolved,
            TcpCheck::Connected,
            SshCheck::IdentityNeeded
        )
    );
    assert_eq!(
        (
            report.tailscale.dns,
            report.tailscale.tcp,
            report.tailscale.ssh
        ),
        (DnsCheck::Failed, TcpCheck::NotChecked, SshCheck::NotChecked)
    );
    assert!(!identities.trusts_key(&public).unwrap());
    identities.trust(&public).unwrap(); // Explicit synthetic fixture provisioning only.
    assert_eq!(checks.check().await.unwrap().lan.ssh, SshCheck::Trusted);
    assert_eq!(auth.load(Ordering::SeqCst), 0);
    serve.abort();
}

#[tokio::test]
async fn dns_success_with_closed_port_is_not_an_identity_failure() {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let checks = ConnectionChecks::with_resolver(
        mac(address.port()),
        None,
        Arc::new(FixedResolver {
            addresses: vec![address],
            calls: AtomicUsize::new(0),
        }),
    );
    let report = checks.check().await.unwrap();
    assert_eq!(
        (report.lan.dns, report.lan.tcp, report.lan.ssh),
        (
            DnsCheck::Resolved,
            TcpCheck::Unreachable,
            SshCheck::NotChecked
        )
    );
}

struct PendingResolver;
impl Resolver for PendingResolver {
    fn resolve<'a>(
        &'a self,
        _: &'a str,
        _: u16,
    ) -> FutureResult<'a, Result<Vec<SocketAddr>, Failure>> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test(start_paused = true)]
async fn dns_timeout_and_concurrent_requests_are_bounded_after_browser_cancellation() {
    let checks = Arc::new(ConnectionChecks::with_resolver(
        mac(22),
        None,
        Arc::new(PendingResolver),
    ));
    let sample = checks.clone();
    let running = tokio::spawn(async move { sample.check().await });
    tokio::task::yield_now().await;
    assert!(checks.check().await.is_err());
    running.abort();
    let _ = running.await;
    assert!(checks.check().await.is_err());
    checks.drain().await;
    let report = checks.check().await.unwrap();
    assert_eq!(report.lan.dns, DnsCheck::TimedOut);
    assert_eq!(report.tailscale.dns, DnsCheck::TimedOut);
    assert_eq!(report.lan.tcp, TcpCheck::NotChecked);
}

struct TailnetResolver(SocketAddr);
impl Resolver for TailnetResolver {
    fn resolve<'a>(
        &'a self,
        _: &'a str,
        _: u16,
    ) -> FutureResult<'a, Result<Vec<SocketAddr>, Failure>> {
        Box::pin(async { Ok(vec![self.0]) })
    }
}
#[tokio::test]
async fn tailnet_name_cannot_dial_a_lan_answer_and_detached_check_closes_its_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let checks = Arc::new(ConnectionChecks::with_resolver(
        mac(address.port()),
        None,
        Arc::new(TailnetResolver(address)),
    ));
    let copy = checks.clone();
    let running = tokio::spawn(async move { copy.check().await });
    let (mut stream, _) = listener.accept().await.unwrap();
    running.abort();
    let _ = running.await;
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    // Only the LAN check connected; the Tailscale answer is rejected pre-TCP.
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let mut only_tailnet = (*mac(address.port())).clone();
    only_tailnet.host.clear();
    let report = ConnectionChecks::with_resolver(
        Arc::new(only_tailnet),
        None,
        Arc::new(TailnetResolver(address)),
    )
    .check()
    .await
    .unwrap();
    assert_eq!(report.lan.dns, DnsCheck::NotConfigured);
    assert_eq!(report.tailscale.dns, DnsCheck::Rejected);
    assert_eq!(report.tailscale.tcp, TcpCheck::NotChecked);
}

#[tokio::test]
async fn non_ssh_listener_reports_tcp_success_and_handshake_timeout_without_login() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let checks = ConnectionChecks::with_resolver(
        mac(address.port()),
        None,
        Arc::new(TailnetResolver(address)),
    );
    let (report, peer) = tokio::join!(checks.check(), listener.accept());
    drop(peer);
    let report = report.unwrap();
    assert_eq!(report.lan.tcp, TcpCheck::Connected);
    assert_eq!(report.lan.ssh, SshCheck::TimedOut);
}

#[tokio::test]
async fn endpoint_requires_ingress_origin_and_fixed_config_and_does_not_change_state() {
    let resolver = Arc::new(FixedResolver {
        addresses: vec![],
        calls: AtomicUsize::new(0),
    });
    let dir = tempfile::tempdir().unwrap();
    let store = filevault::store::Store::open(&dir.path().join("history.sqlite3"))
        .await
        .unwrap();
    let controller = Arc::new(
        Controller::new(
            Arc::new(Disabled),
            "https://ha.example.invalid".into(),
            Instant::now(),
        )
        .with_connection(Some((*mac(22)).clone()))
        .with_connectivity(Arc::new(
            ConnectionChecks::with_resolver(mac(22), None, resolver.clone())
                .with_store(store.clone()),
        )),
    );
    let integration = api::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Context::with_controller(
            Access::Status {
                token_hash: Sha256::digest("fixture-status").into(),
            },
            controller.clone(),
        )),
    )
    .unwrap();
    let ingress = api::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Context::with_controller(
            Access::Ingress {
                peer: "127.0.0.1".parse().unwrap(),
                users: ["fixture-user".into()].into(),
            },
            controller.clone(),
        )),
    )
    .unwrap();
    let client = reqwest::Client::new();
    let request = |url: String, origin: &str| {
        client
            .post(url)
            .header("x-remote-user-id", "fixture-user")
            .header("origin", origin)
            .header("sec-fetch-site", "same-origin")
    };
    assert_eq!(
        request(
            format!("http://{}/v1/connectivity", integration.local_addr()),
            "https://ha.example.invalid"
        )
        .bearer_auth("fixture-status")
        .send()
        .await
        .unwrap()
        .status(),
        403
    );
    for (query, origin) in [
        ("?host=other.example.invalid", "https://ha.example.invalid"),
        ("", "https://other.example.invalid"),
    ] {
        assert_eq!(
            request(
                format!("http://{}/v1/connectivity{query}", ingress.local_addr()),
                origin
            )
            .send()
            .await
            .unwrap()
            .status(),
            403
        );
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    let history_url = format!("http://{}/v1/connectivity/history", ingress.local_addr());
    assert_eq!(client.get(&history_url).send().await.unwrap().status(), 403);
    assert_eq!(
        client
            .get(format!(
                "http://{}/v1/connectivity/history",
                integration.local_addr()
            ))
            .bearer_auth("fixture-status")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let before = client
        .get(&history_url)
        .header("x-remote-user-id", "fixture-user")
        .send()
        .await
        .unwrap();
    assert!(
        before.json::<serde_json::Value>().await.unwrap()["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let response = request(
        format!("http://{}/v1/connectivity", ingress.local_addr()),
        "https://ha.example.invalid",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["lan"]["dns"], "failed");
    assert_eq!(body["tailscale"]["dns"], "failed");
    assert!(!body.to_string().contains("fixture-user"));
    let history = client
        .get(&history_url)
        .header("x-remote-user-id", "fixture-user")
        .send()
        .await
        .unwrap();
    assert_eq!(history.headers()["cache-control"], "no-store");
    let history: serde_json::Value = history.json().await.unwrap();
    assert_eq!(history["results"].as_array().unwrap().len(), 1);
    assert_eq!(history["results"][0]["lan"]["error"], "dns_failed");
    assert!(history["results"][0]["lan"].get("host").is_none());
    assert_eq!(
        controller.status().await.state,
        filevault::policy::State::Unknown
    );
    integration.close().await.unwrap();
    ingress.close().await.unwrap();
    controller.drain_connections().await;
    store.close().await.unwrap();
}

#[tokio::test]
async fn accepted_check_is_saved_after_the_http_waiter_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let store = filevault::store::Store::open(&dir.path().join("history.sqlite3"))
        .await
        .unwrap();
    let checks = Arc::new(
        ConnectionChecks::with_resolver(mac(22), None, Arc::new(PendingResolver))
            .with_store(store.clone()),
    );
    let sample = checks.clone();
    let waiting = tokio::spawn(async move { sample.check().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !checks.history(None, 20).await.unwrap().results.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    waiting.abort();
    let _ = waiting.await;
    tokio::time::timeout(Duration::from_secs(3), checks.drain())
        .await
        .unwrap();
    let history = checks.history(None, 20).await.unwrap();
    assert_eq!(history.results.len(), 1);
    assert!(matches!(
        history.results[0].state,
        filevault::store::RunState::Complete
    ));
    assert_eq!(history.results[0].lan.dns, DnsCheck::TimedOut);
    store.close().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn background_monitor_starts_without_ui_backs_off_and_stops() {
    let resolver = Arc::new(FixedResolver {
        addresses: vec![],
        calls: AtomicUsize::new(0),
    });
    let checks = ConnectionChecks::with_resolver(mac(22), None, resolver.clone());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { checks.monitor(Duration::from_secs(60), stopped).await });
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(119)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
    tokio::time::advance(Duration::from_secs(240)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 6);
    tokio::time::advance(Duration::from_secs(300)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 8);
    stop.send(true).unwrap();
    task.await.unwrap();
    tokio::time::advance(Duration::from_secs(1000)).await;
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 8);
}

#[tokio::test(start_paused = true)]
async fn monitor_and_manual_probes_share_nonqueueing_lock() {
    let checks = ConnectionChecks::with_resolver(mac(22), None, Arc::new(PendingResolver));
    let background = checks.clone();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task =
        tokio::spawn(async move { background.monitor(Duration::from_secs(60), stopped).await });
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(checks.check().await.is_err());
    stop.send(true).unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    task.await.unwrap();
    checks.drain().await;
}

#[tokio::test]
async fn background_observation_persists_without_an_http_client() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("background.sqlite3");
    let store = filevault::store::Store::open(&path).await.unwrap();
    let checks = ConnectionChecks::with_resolver(
        mac(22),
        None,
        Arc::new(FixedResolver {
            addresses: vec![],
            calls: AtomicUsize::new(0),
        }),
    )
    .with_store(store.clone());
    let background = checks.clone();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task =
        tokio::spawn(async move { background.monitor(Duration::from_secs(60), stopped).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let page = checks.history(None, 20).await.unwrap();
            if page
                .latest
                .is_some_and(|run| matches!(run.state, filevault::store::RunState::Complete))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    task.await.unwrap();
    checks.drain().await;
    store.close().await.unwrap();
    let store = filevault::store::Store::open(&path).await.unwrap();
    let checks = ConnectionChecks::new(mac(22), None).with_store(store.clone());
    let page = checks.history(None, 20).await.unwrap();
    assert_eq!(page.results.len(), 1);
    assert_eq!(page.latest.unwrap().lan.dns, DnsCheck::Failed);
    assert!(page.last_success.tailscale.verified_at.is_none());
    assert!(!page.stale);
    store.close().await.unwrap();
}
