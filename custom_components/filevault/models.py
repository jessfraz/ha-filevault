"""Keep HA state limited to a fixed non-secret status vocabulary."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Status:
    state: str
    unlock_available: bool
    transport_ready: bool
    manual_ready: bool | None = None
    runtime_check: str = "unknown"
    error_count: int | None = None
    note_count: int | None = None


def _message_count(data: dict[str, object], key: str) -> int | None:
    """Count bounded messages without retaining their potentially private text."""
    if key not in data:
        return None
    messages = data[key]
    if (
        not isinstance(messages, list)
        or len(messages) > 32
        or any(not isinstance(item, str) for item in messages)
    ):
        raise ValueError("Invalid configuration health")
    return len(messages)


def parse_status(data: object) -> Status:
    """Reject malformed replies; never retain unknown fields as attributes."""
    if not isinstance(data, dict):
        raise ValueError("Invalid status response")
    decision = data.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("Invalid status decision")
    state = decision.get("state")
    available = decision.get("unlock_available")
    ready = data.get("transport_ready")
    if (
        not isinstance(state, str)
        or state
        not in {
            "running",
            "ssh_reachable",
            "verified_preboot",
            "unreachable",
            "unknown",
        }
        or type(available) is not bool
        or type(ready) is not bool
        or available != (state == "verified_preboot")
    ):
        raise ValueError("Invalid status decision")
    manual = data.get("manual_ready")
    runtime = data.get("runtime_check", "unknown")
    if (
        (manual is not None and type(manual) is not bool)
        or not isinstance(runtime, str)
        or runtime
        not in {
            "unknown",
            "not_configured",
            "verified",
            "identity_needed",
            "unavailable",
            "name_unavailable",
            "timed_out",
            "stale",
        }
    ):
        raise ValueError("Invalid status health")
    return Status(
        state,
        available and ready,
        ready,
        manual,
        runtime,
        _message_count(data, "configuration_errors"),
        _message_count(data, "configuration_notes"),
    )
