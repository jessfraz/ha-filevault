"""Keep HA state limited to a fixed non-secret status vocabulary."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Status:
    state: str
    unlock_available: bool
    transport_ready: bool


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
        state
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
    return Status(state, available and ready, ready)
