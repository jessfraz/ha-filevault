"""Native HA diagnostics use an allowlist, including for unknown future fields."""

from homeassistant.components.diagnostics import REDACTED
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.util.json import JsonObjectType

from . import FileVaultConfigEntry
from .const import DOMAIN
from .health import configuration_health, status_snapshot


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: FileVaultConfigEntry
) -> JsonObjectType:
    """Return useful support data without copying config, IDs or exceptions."""
    coordinator = entry.runtime_data if entry.state is ConfigEntryState.LOADED else None
    return {
        "integration": DOMAIN,
        "entry_state": entry.state.value,
        "connection": REDACTED,
        "credentials": REDACTED,
        "status": status_snapshot(coordinator),
        "configuration_health": configuration_health(coordinator),
    }
