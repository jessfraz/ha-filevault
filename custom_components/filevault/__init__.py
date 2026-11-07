"""Read-only HA adapter. Passwords and unlock requests never enter Core."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType
from homeassistant.loader import async_get_integration

from .client import FileVaultClient
from .const import CONF_BACKEND_URL, CONF_TOKEN
from .coordinator import FileVaultCoordinator
from .http import FileVaultView

CONFIG_SCHEMA = cv.config_entry_only_config_schema("filevault")
PLATFORMS = [Platform.SENSOR]
type FileVaultConfigEntry = ConfigEntry[FileVaultCoordinator]


async def async_setup(hass: HomeAssistant, _config: ConfigType) -> bool:
    """Register fixed, authenticated read routes once, across entry reloads."""
    integration = await async_get_integration(hass, "filevault")
    hass.http.register_view(FileVaultView(hass, integration.version or "unknown"))
    return True


async def async_setup_entry(hass: HomeAssistant, entry: FileVaultConfigEntry) -> bool:
    client = FileVaultClient(
        async_get_clientsession(hass),
        entry.data[CONF_BACKEND_URL],
        entry.data[CONF_TOKEN],
    )
    coordinator = FileVaultCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: FileVaultConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
