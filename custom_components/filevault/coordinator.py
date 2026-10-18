"""Poll non-secret backend status using HA's shared client session."""

import logging
from datetime import datetime, timedelta

from aiohttp import ClientError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .client import FileVaultClient, InvalidAuth
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
        self.last_success_at: datetime | None = None

    async def _async_update_data(self) -> Status:
        try:
            result = await self.client.status()
            self.last_success_at = dt_util.utcnow()
            return result
        except InvalidAuth as err:
            raise ConfigEntryAuthFailed("Status credential rejected") from err
        except (ClientError, TimeoutError, ValueError) as err:
            raise UpdateFailed("Cannot read FileVault status") from err
