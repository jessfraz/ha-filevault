"""Standalone status-boundary tests; full HA loading remains a release gate."""

import importlib.util
import sys
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "custom_components/filevault/models.py"
spec = importlib.util.spec_from_file_location("status_models", path)
assert spec is not None and spec.loader is not None
models = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = models
spec.loader.exec_module(models)


class StatusBoundaryTests(unittest.TestCase):
    def test_unknown_fields_do_not_enter_ha_state(self) -> None:
        data = {
            "decision": {"state": "unknown", "unlock_available": False},
            "transport_ready": False,
            "transcript": "DUMMY_SENTINEL",
        }
        status = models.parse_status(data)
        self.assertNotIn("DUMMY_SENTINEL", repr(status))

    def test_malformed_or_conflicting_status_is_rejected(self) -> None:
        for decision in (
            {"state": "unexpected", "unlock_available": False},
            {"state": "running", "unlock_available": True},
            {"state": "unknown", "unlock_available": "false"},
        ):
            with self.assertRaises(ValueError):
                models.parse_status({"decision": decision, "transport_ready": False})

    def test_unready_transport_cannot_offer_unlock(self) -> None:
        result = models.parse_status(
            {
                "decision": {"state": "verified_preboot", "unlock_available": True},
                "transport_ready": False,
            }
        )
        self.assertFalse(result.unlock_available)

    def test_ssh_reachability_is_status_only_without_phase_enrollment(self) -> None:
        result = models.parse_status(
            {
                "decision": {"state": "ssh_reachable", "unlock_available": False},
                "transport_ready": False,
                "manual_ready": True,
                "configuration_errors": ["Automatic phase detection is incomplete."],
            }
        )
        self.assertEqual(result.state, "ssh_reachable")
        self.assertFalse(result.unlock_available)
        self.assertNotIn("configuration_errors", repr(result))
