"""Explicit read-only status pairing; no Mac password or auto-generated key."""

import probatio as vol
from aiohttp import ClientError
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .client import FileVaultClient
from .const import CONF_BACKEND_URL, CONF_TOKEN, DOMAIN


class FileVaultConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ) -> ConfigFlowResult:
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        errors = {}
        if user_input is not None:
            try:
                await FileVaultClient(
                    async_get_clientsession(self.hass),
                    user_input[CONF_BACKEND_URL],
                    user_input[CONF_TOKEN],
                ).status()
            except ValueError, ClientError, TimeoutError:
                errors["base"] = "cannot_connect"
            else:
                return self.async_create_entry(title="FileVault", data=user_input)
        return self.async_show_form(
            step_id="user",
            errors=errors,
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_BACKEND_URL): str,
                    vol.Required(CONF_TOKEN): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                }
            ),
        )
