use filevault::{config::Options, controller::Controller, profiles};
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn incomplete_phase_profile_keeps_the_real_app_and_manual_ui_available() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("options.json");
    std::fs::write(&path, serde_json::to_vec(&serde_json::json!({
        "allowed_user_ids": ["fixture-ha-user"], "frontend_origin": "https://ha.example.invalid",
        "ssh_recovery": {"enabled": true, "host":"127.0.0.1", "port":22,
            "username":"fixture-user", "preboot_public_key":"", "runtime_public_key":"",
            "manual_enrollment_verified": false}
    })).unwrap()).unwrap();
    let original_options = std::fs::read(&path).unwrap();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_filevault"))
            .current_dir(dir.path())
            .args([
                "--options",
                path.to_str().unwrap(),
                "--ingress-bind",
                &address.to_string(),
                "--ingress-peer",
                "127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "app exited on incomplete automatic options"
        );
        if let Ok(response) = client
            .get(format!("http://{address}/v1/system"))
            .header("x-remote-user-id", "fixture-ha-user")
            .send()
            .await
        {
            break response;
        }
        assert!(Instant::now() < deadline, "app did not start");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(response.status(), 200);
    let report: serde_json::Value = response.json().await.unwrap();
    assert_eq!(report["manual_ready"], true);
    assert!(
        report["configuration_notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("preboot detection"))
    );
    let html = client
        .get(format!("http://{address}/"))
        .header("x-remote-user-id", "fixture-ha-user")
        .send()
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    assert!(html.text().await.unwrap().contains("Manual SSH unlock"));
    assert!(dir.path().join("ssh_known_hosts").is_file());
    assert_eq!(std::fs::read(&path).unwrap(), original_options);
}

#[test]
fn invalid_manual_options_disable_the_action_without_exposing_input() {
    let options =
        Options::parse(br#"{"mac":{"host":"bad host","port":22,"username":"fixture-user"}}"#)
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = profiles::build(&options, Some(&dir.path().join("options.json")));
    assert!(result.manual.is_none());
    assert!(!result.errors.is_empty());
    assert!(!result.errors.join(" ").contains("bad host"));
    let controller = Controller::new(
        result.transport,
        "https://ha.example.invalid".into(),
        Instant::now(),
    )
    .with_configuration_errors(result.errors);
    assert!(!controller.manual_ready());
    assert!(!controller.ready());
}

#[test]
fn malformed_ssh_sections_fail_closed_without_discarding_access_configuration() {
    let options = Options::parse(br#"{
        "allowed_user_ids":["fixture-ha-user"],
        "frontend_origin":"https://ha.example.invalid",
        "ssh_recovery":{"enabled":"wrong-type"},
        "manual_ssh":{"enabled":true,"host":"127.0.0.1","port":"wrong-type","username":"fixture-user"}
    }"#).unwrap();
    assert_eq!(options.allowed_user_ids, ["fixture-ha-user"]);
    assert!(options.invalid_profiles.contains(&"connection"));
    let dir = tempfile::tempdir().unwrap();
    let profiles = profiles::build(&options, Some(&dir.path().join("options.json")));
    assert!(profiles.manual.is_none());
    assert!(!profiles.errors.join(" ").contains("wrong-type"));
    assert!(!profiles.transport.unlock_ready());
}

#[test]
fn malformed_access_options_never_create_default_authority() {
    assert!(Options::parse(br#"{"allowed_user_ids":"wrong-type"}"#).is_err());
    assert!(Options::parse(br#"{"frontend_origin":42}"#).is_err());
    assert!(Options::parse(br#"{"allowed_user_ids":["fixture-user"]"#).is_err());
    let options = Options::parse(
        br#"{
        "allowed_user_ids":["fixture-user"],
        "manual_ssh":{"password":"DUMMY_SENTINEL"}
    }"#,
    )
    .unwrap();
    assert_eq!(options.invalid_profiles, ["connection"]);
}

#[test]
fn invalid_optional_runtime_key_does_not_disable_manual_host_verification() {
    let options = Options::parse(
        br#"{
        "allowed_user_ids":["fixture-user"],
        "frontend_origin":"https://ha.example.invalid",
        "ssh_recovery":{"enabled":true,"host":"127.0.0.1","port":22,
            "username":"fixture-user","runtime_public_key":"invalid-public-identity"}
    }"#,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let profiles = profiles::build(&options, Some(&dir.path().join("options.json")));
    assert!(profiles.manual.is_some());
    assert!(profiles.observer.is_none());
    assert!(!profiles.transport.unlock_ready());
    assert!(
        !profiles
            .errors
            .join(" ")
            .contains("invalid-public-identity")
    );
}
