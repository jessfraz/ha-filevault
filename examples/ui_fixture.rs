//! Loopback-only browser fixture. Accepts only DUMMY_SENTINEL, never real logins.
use filevault::{
    api::{self, Access, Context},
    config::Options,
    connectivity::{ConnectionChecks, Resolver},
    controller::Controller,
    profiles,
    runtime::{RuntimeEvidence, RuntimeObserver},
    transport::{Failure, FutureResult},
};
use russh::{
    keys::{Algorithm, HashAlg, PrivateKey},
    server,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

struct Peer(Arc<AtomicUsize>);
impl server::Handler for Peer {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        if user == "fixture-user" && password == "DUMMY_SENTINEL" {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }
}
struct Unavailable;
struct FixtureResolver(std::net::SocketAddr);
impl Resolver for FixtureResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        _: u16,
    ) -> FutureResult<'a, Result<Vec<std::net::SocketAddr>, Failure>> {
        Box::pin(async move {
            if host == "127.0.0.1" {
                Ok(vec![self.0])
            } else {
                Err(Failure::Resolution)
            }
        })
    }
}
impl RuntimeObserver for Unavailable {
    fn observe(&self) -> FutureResult<'_, Result<RuntimeEvidence, Failure>> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keys = [
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?,
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?,
    ];
    let fingerprints = keys
        .iter()
        .map(|k| k.public_key().fingerprint(HashAlg::Sha256).to_string())
        .collect::<Vec<_>>();
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let count = Arc::new(AtomicUsize::new(0));
    let passwords = count.clone();
    let listener = tokio::spawn(async move {
        while let Ok((stream, _)) = socket.accept().await {
            let index = usize::from(count.load(Ordering::SeqCst) > 0);
            let config = Arc::new(server::Config {
                keys: vec![keys[index].clone()],
                auth_rejection_time: Duration::ZERO,
                inactivity_timeout: Some(Duration::from_secs(90)),
                ..Default::default()
            });
            let peer = Peer(count.clone());
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, peer).await {
                    let _ = session.await;
                }
            });
        }
    });
    let options = Options::parse(&serde_json::to_vec(&serde_json::json!({
        "frontend_origin":"https://ha.example.invalid",
        "mac":{"host":"127.0.0.1","port":address.port(),"username":"fixture-user","tailscale_host":"100.64.0.2"},
        "automatic":{"enabled":true}
    }))?)?;
    let dir = tempfile::tempdir()?;
    let profiles = profiles::build(&options, Some(&dir.path().join("options.json")));
    let checks = ConnectionChecks::with_resolver(
        Arc::new(options.mac.as_ref().unwrap().clone()),
        profiles.manual.clone(),
        Arc::new(FixtureResolver(address)),
    );
    let controller = Controller::new(
        profiles.transport,
        "https://ha.example.invalid".into(),
        Instant::now() - Duration::from_secs(61),
    )
    .with_manual(profiles.manual.unwrap())
    .with_runtime(Arc::new(Unavailable))
    .with_connectivity(Arc::new(checks))
    .with_connection(profiles.connection)
    .with_configuration_errors(profiles.errors)
    .with_configuration_notes(profiles.notes);
    let server = api::start(
        "127.0.0.1:0".parse()?,
        Arc::new(Context::with_controller(
            Access::Ingress {
                peer: "127.0.0.1".parse()?,
                users: ["fixture-user".into()].into(),
            },
            Arc::new(controller),
        )),
    )?;
    println!(
        "{}",
        serde_json::json!({"backend":format!("http://{}",server.local_addr()),"ssh_port":address.port(),"fingerprints":fingerprints,"fixture_only":true})
    );
    tokio::signal::ctrl_c().await?;
    listener.abort();
    server.close().await.map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        serde_json::json!({"synthetic_password_attempts":passwords.load(Ordering::SeqCst)})
    );
    Ok(())
}
