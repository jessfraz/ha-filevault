"""The HA-generated editor must expose exactly one Mac connection target."""

from pathlib import Path

import yaml


def test_one_shared_mac_target_and_no_password_or_client_key_requirement() -> None:
    config = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "filevault/config.yaml").read_text()
    )
    schema = config["schema"]
    assert not {"manual_ssh", "ssh_recovery", "ssh_probe"} & schema.keys()
    assert schema["mac"] == {
        "host": "str",
        "tailscale_host": "str",
        "port": "port",
        "username": "str",
        "manual_enabled": "bool",
    }
    for group, fields in schema.items():
        if group != "mac" and isinstance(fields, dict):
            assert not {"host", "hostname", "port", "username"} & fields.keys()
    assert "password" not in schema["mac"]
    assert "private_key" not in schema["mac"]
    assert "0.1.0-alpha.3" in config["breaking_versions"]
