"""Read-only HA adapter. Passwords and unlock requests never enter Core."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from ._app_kit.repairs import VersionRepairs, async_check_startup_version
from ._app_kit.version import LOADED_VERSION
from .client import FileVaultClient
from .const import CONF_BACKEND_URL, CONF_TOKEN
from .coordinator import FileVaultCoordinator
from .http import FileVaultView
from .repairs import VERSION_REPAIR

CONFIG_SCHEMA = cv.config_entry_only_config_schema("filevault")
PLATFORMS = [Platform.SENSOR]
type FileVaultConfigEntry = ConfigEntry[FileVaultCoordinator]


async def async_setup(hass: HomeAssistant, _config: ConfigType) -> bool:
    """Register fixed, authenticated read routes once, across entry reloads."""
    hass.http.register_view(FileVaultView(hass, LOADED_VERSION))
    return True


async def async_setup_entry(hass: HomeAssistant, entry: FileVaultConfigEntry) -> bool:
    client = FileVaultClient(
        async_get_clientsession(hass),
        entry.data[CONF_BACKEND_URL],
        entry.data[CONF_TOKEN],
    )
    coordinator = FileVaultCoordinator(hass, entry, client)
    try:
        await coordinator.async_config_entry_first_refresh()
    except ConfigEntryNotReady:
        await async_check_startup_version(hass, entry, VERSION_REPAIR)
        raise
    entry.runtime_data = coordinator
    coordinator.version_repairs = VersionRepairs(hass, entry, VERSION_REPAIR)
    coordinator.version_repairs.async_start()
    coordinator.repairs.async_start()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: FileVaultConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
