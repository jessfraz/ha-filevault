"""Poll non-secret backend status using HA's shared client session."""

import logging
from datetime import timedelta

from aiohttp import ClientError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import FileVaultClient
from .const import DOMAIN
from .models import Status


class FileVaultCoordinator(DataUpdateCoordinator[Status]):
    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: FileVaultClient
    ) -> None:
        super().__init__(
            hass,
            logging.getLogger(__name__),
            name=DOMAIN,
            config_entry=entry,
            update_interval=timedelta(seconds=10),
            always_update=False,
        )
        self.client = client

    async def _async_update_data(self) -> Status:
        try:
            return await self.client.status()
        except (ClientError, TimeoutError, ValueError) as err:
            raise UpdateFailed("Cannot read FileVault status") from err
