use filevault::{
    policy::State,
    transport::{ProbeConfig, SshProbe, Transport},
};
use russh::{
    keys::{Algorithm, PrivateKey},
    server::{self, Server as _},
};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct FixtureServer;
impl server::Server for FixtureServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Self
    }
    fn handle_session_error(&mut self, _: <Self as server::Handler>::Error) {}
}
impl server::Handler for FixtureServer {
    type Error = russh::Error;
}

#[tokio::test]
async fn pinned_ssh_handshake_is_unknown_and_never_unlock_ready() {
    // Ephemeral fixture key, generated in memory and never written to disk.
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let pin = key.public_key().to_openssh().unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        inactivity_timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    });
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut fixture = FixtureServer;
    let running = fixture.run_on_socket(config, &socket);
    let stop = running.handle();
    let checks = async {
        let probe = SshProbe::new(ProbeConfig {
            host: "127.0.0.1".into(),
            port: address.port(),
            pinned_public_key: pin,
        })
        .unwrap();
        let connection = probe.open().await.unwrap();
        assert_eq!(connection.observation().state, State::Unknown);
        assert!(!probe.unlock_ready());
        let wrong = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mismatch = SshProbe::new(ProbeConfig {
            host: "127.0.0.1".into(),
            port: address.port(),
            pinned_public_key: wrong.public_key().to_openssh().unwrap(),
        })
        .unwrap();
        assert!(mismatch.open().await.is_err());
        drop(connection);
        stop.shutdown("fixture complete".into());
    };
    let (result, ()) = tokio::join!(running, checks);
    result.unwrap();
}
