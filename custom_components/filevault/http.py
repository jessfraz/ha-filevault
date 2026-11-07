"""Authenticated cached health reads for native HA clients."""

from aiohttp import web
from homeassistant.auth.permissions.const import POLICY_READ
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.http import HomeAssistantView

from .const import DOMAIN
from .health import configuration_health, status_snapshot


class FileVaultView(HomeAssistantView):
    """No proxy, unlock path, credential access or backend refresh."""

    url = "/api/filevault/v1/status"
    extra_urls = ["/api/filevault/v1/system"]
    name = "api:filevault:v1"
    requires_auth = True

    def __init__(self, hass: HomeAssistant, version: str) -> None:
        self._hass = hass
        self._version = version

    async def get(self, request: web.Request) -> web.Response:
        """Authorize the sensor, then read only the currently loaded owner."""
        entity_id = er.async_get(self._hass).async_get_entity_id(
            "sensor", DOMAIN, "filevault_status"
        )
        user = request["hass_user"]
        if not user.is_active or (
            entity_id is not None
            and not user.permissions.check_entity(entity_id, POLICY_READ)
        ):
            raise web.HTTPForbidden
        if entity_id is None or self._hass.states.get(entity_id) is None:
            raise web.HTTPServiceUnavailable
        for entry in self._hass.config_entries.async_loaded_entries(DOMAIN):
            coordinator = entry.runtime_data
            health = configuration_health(coordinator)
            data = (
                {"version": self._version} | health
                if request.path.endswith("/system")
                else status_snapshot(coordinator) | health
            )
            return self.json(data)
        raise web.HTTPServiceUnavailable
