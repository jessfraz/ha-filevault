"""Fixed safe projections shared by queries and native diagnostics."""

from homeassistant.util import dt as dt_util
from homeassistant.util.json import JsonObjectType

from .coordinator import FileVaultCoordinator

FRESH_SECONDS = 30


def status_snapshot(coordinator: FileVaultCoordinator | None) -> JsonObjectType:
    """Never replay stale running evidence or expose a backend error body."""
    age = None
    if coordinator is not None and coordinator.last_success_at is not None:
        age = (dt_util.utcnow() - coordinator.last_success_at).total_seconds()
    fresh = bool(
        coordinator is not None
        and coordinator.last_update_success
        and age is not None
        and 0 <= age <= FRESH_SECONDS
    )
    data = coordinator.data if fresh and coordinator is not None else None
    return {
        "available": fresh,
        "state": data.state if data is not None else "unknown",
        "runtime_check": data.runtime_check if data is not None else "unknown",
        "observation_age_seconds": int(age)
        if age is not None and 0 <= age <= 86400
        else None,
        "manual_ready": data.manual_ready if data is not None else None,
        "advanced_detection_ready": data.transport_ready if data is not None else None,
    }


def configuration_health(coordinator: FileVaultCoordinator | None) -> JsonObjectType:
    """Only capability flags and counts, never connection or message contents."""
    result = status_snapshot(coordinator)
    data = coordinator.data if result["available"] and coordinator is not None else None
    return {
        "available": result["available"],
        "manual_ready": result["manual_ready"],
        "advanced_detection_ready": result["advanced_detection_ready"],
        "runtime_check": result["runtime_check"],
        "configuration_error_count": data.error_count if data is not None else None,
        "setup_note_count": data.note_count if data is not None else None,
    }
