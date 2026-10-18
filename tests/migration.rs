use filevault::{config::Options, migration, profiles};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, process::Command};

fn parse(value: serde_json::Value) -> Options {
    Options::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

#[test]
fn matching_legacy_targets_collapse_to_one_profile_and_keep_access_controls() {
    let value = json!({"allowed_user_ids":["fixture-user"],
        "frontend_origin":"https://ha.example.invalid","auto_pairing":true,
        "status_token":"fixture-read-only-service-credential",
        "ssh_recovery":{"enabled":true,"host":"MAC.EXAMPLE.INVALID.","port":2222,"username":"fixture-user"},
        "manual_ssh":{"enabled":true,"host":"mac.example.invalid","port":2222,"username":"fixture-user"}});
    let options = parse(value);
    assert!(options.invalid_profiles.is_empty());
    let mac = options.mac.as_ref().unwrap();
    assert_eq!(
        (&*mac.host, mac.port, &*mac.username),
        ("mac.example.invalid", 2222, "fixture-user")
    );
    assert!(options.automatic.as_ref().unwrap().enabled);
    let canonical = serde_json::to_value(&options).unwrap();
    for key in ["manual_ssh", "ssh_recovery", "ssh_probe"] {
        assert!(canonical.get(key).is_none());
    }
    assert_eq!(canonical["allowed_user_ids"], json!(["fixture-user"]));
    assert_eq!(
        canonical["status_token"],
        "fixture-read-only-service-credential"
    );
    let again = parse(canonical.clone());
    assert!(!again.migrated);
    assert_eq!(serde_json::to_value(again).unwrap(), canonical);
}

#[test]
fn manual_only_and_probe_only_options_migrate_without_inventing_authority() {
    let options = parse(
        json!({"manual_ssh":{"enabled":false,"host":"mac.example.invalid","port":22,"username":"fixture-user"}}),
    );
    assert!(!options.mac.unwrap().manual_enabled);
    assert!(options.allowed_user_ids.is_empty());
    let options = parse(
        json!({"ssh_probe":{"host":"mac.example.invalid","port":2222,"pinned_public_key":"public-identity-fixture"}}),
    );
    let mac = options.mac.unwrap();
    assert_eq!(mac.username, "");
    assert_eq!(mac.port, 2222);
    assert!(!options.automatic.unwrap().enabled);
}

#[test]
fn blank_defaults_do_not_override_an_existing_target() {
    let options = parse(json!({"mac":{"host":"","port":22,"username":""},
        "manual_ssh":{"enabled":true,"host":"","port":22,"username":""},
        "ssh_recovery":{"enabled":true,"host":"mac.example.invalid","port":2222,"username":"fixture-user"}}));
    assert!(options.invalid_profiles.is_empty());
    assert_eq!(options.mac.unwrap().port, 2222);
}

#[test]
fn divergent_targets_disable_every_transport_even_with_a_canonical_target() {
    for changed in [
        json!({"host":"other.example.invalid","port":22,"username":"fixture-user"}),
        json!({"host":"mac.example.invalid","port":2222,"username":"fixture-user"}),
        json!({"host":"mac.example.invalid","port":22,"username":"other-user"}),
    ] {
        let options = parse(
            json!({"mac":{"host":"mac.example.invalid","port":22,"username":"fixture-user"},
            "ssh_recovery":changed,"manual_ssh":{"enabled":true,"host":"mac.example.invalid","port":22,"username":"fixture-user"}}),
        );
        assert!(options.invalid_profiles.contains(&"target_conflict"));
        let dir = tempfile::tempdir().unwrap();
        let profiles = profiles::build(&options, Some(&dir.path().join("options.json")));
        assert!(
            profiles.manual.is_none() && profiles.observer.is_none() && profiles.runtime.is_none()
        );
        assert!(profiles.connection.is_none());
        assert!(!profiles.transport.unlock_ready());
        assert!(!profiles.errors.join(" ").contains("other.example.invalid"));
    }
}

#[test]
fn migration_command_is_private_idempotent_and_preserves_original_options() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("original.json");
    let output = dir.path().join("canonical.json");
    let original = br#"{"allowed_user_ids":["fixture-user"],"manual_ssh":{"enabled":true,"host":"mac.example.invalid","port":22,"username":"fixture-user"}}"#;
    std::fs::write(&input, original).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_filevault"))
        .current_dir(dir.path())
        .args([
            "--migrate-options",
            input.to_str().unwrap(),
            "--migration-output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!dir.path().join("filevault.sqlite3").exists());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("mac.example.invalid"));
    assert_eq!(std::fs::read(&input).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let canonical: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(canonical["mac"]["host"], "mac.example.invalid");
    assert!(canonical.get("manual_ssh").is_none());
    assert_eq!(canonical["frontend_origin"], "");
    assert_eq!(canonical["status_token"], "");
    assert!(canonical["automatic"].is_object());
    assert!(migration::write(&input, &output).is_err());
}

#[test]
fn conflict_or_password_field_never_creates_migration_output() {
    for value in [
        json!({"mac":{"host":"mac.example.invalid"},"manual_ssh":{"host":"other.example.invalid"}}),
        json!({"mac":{"host":"mac.example.invalid","password":"DUMMY_SENTINEL"}}),
        json!({"automatic":{"password":"DUMMY_SENTINEL"}}),
        json!({"mac":{"host":"mac.example.invalid","port":0}}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("original.json");
        let output = dir.path().join("canonical.json");
        let original = serde_json::to_vec(&value).unwrap();
        std::fs::write(&input, &original).unwrap();
        assert!(migration::write(&input, &output).is_err());
        assert!(!output.exists());
        assert_eq!(std::fs::read(input).unwrap(), original);
    }
}

#[test]
fn incomplete_preboot_is_a_setup_note_and_not_an_invalid_normal_profile() {
    let options = parse(
        json!({"mac":{"host":"127.0.0.1","port":22,"username":"fixture-user"},
        "automatic":{"enabled":true}}),
    );
    let dir = tempfile::tempdir().unwrap();
    let p = profiles::build(&options, Some(&dir.path().join("options.json")));
    assert!(p.errors.is_empty());
    assert!(p.manual.is_some());
    assert!(p.notes.join(" ").contains("has not been learned"));
}

#[test]
fn malformed_profile_and_identity_conflicts_are_not_silently_discarded() {
    let options =
        parse(json!({"mac":{"host":"mac.example.invalid"},"manual_ssh":{"port":"wrong-type"}}));
    assert!(options.invalid_profiles.contains(&"connection"));
    let options = parse(json!({"automatic":{"runtime_public_key":"one"},
        "ssh_probe":{"host":"mac.example.invalid","port":22,"pinned_public_key":"two"}}));
    assert!(options.invalid_profiles.contains(&"identity_conflict"));
}
