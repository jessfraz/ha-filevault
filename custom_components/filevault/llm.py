"""Contribute only bounded, exposed, read-only FileVault queries to Assist."""

from typing import Literal, override

import probatio as vol
from homeassistant.auth.permissions.const import POLICY_READ
from homeassistant.components import llm
from homeassistant.components.homeassistant.exposed_entities import async_should_expose
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.llm import (
    LLMContext,
    Tool,
    ToolAnnotations,
    ToolInput,
    ToolResult,
)

from . import FileVaultConfigEntry
from .const import DOMAIN
from .health import configuration_health, status_snapshot


def _entity_id(hass: HomeAssistant) -> str | None:
    return er.async_get(hass).async_get_entity_id("sensor", DOMAIN, "filevault_status")


@callback
def async_get_tools(
    hass: HomeAssistant, llm_context: LLMContext, api_id: str
) -> llm.LLMTools | None:
    """Core discovers these only for a loaded, explicitly exposed status entity."""
    if api_id != "assist":
        return None
    entity_id = _entity_id(hass)
    if entity_id is None or not async_should_expose(
        hass, llm_context.assistant, entity_id
    ):
        return None
    for entry in hass.config_entries.async_loaded_entries(DOMAIN):
        return llm.LLMTools(
            tools=[
                FileVaultQuery(entry, "status"),
                FileVaultQuery(entry, "configuration_health"),
            ],
            prompt=(
                "Use filevault__status for the last bounded FileVault observation and "
                "filevault__configuration_health for safe capability flags and counts. "
                "Unavailable, unknown and failed observations never prove locked or "
                "powered off. Running does not prove desktop login or app health. "
                "Setup notes are not configuration errors. These tools cannot unlock, "
                "use a password, restart, or power-cycle anything. Direct manual "
                "recovery to the FileVault app; never request a password in chat."
            ),
        )
    return None


class FileVaultQuery(Tool):
    """A zero-argument cached query, with authorization rechecked at every call."""

    integration = DOMAIN
    parameters = vol.Schema({})
    annotations = ToolAnnotations(
        read_only=True, destructive=False, idempotent=True, open_world=False
    )

    def __init__(
        self,
        entry: FileVaultConfigEntry,
        view: Literal["status", "configuration_health"],
    ) -> None:
        self.entry = entry
        self.coordinator = entry.runtime_data
        self.view = view
        self.name = f"filevault__{view}"
        self.title = (
            "Read FileVault status" if view == "status" else "Read FileVault health"
        )
        self.description = (
            "Read the latest FileVault status, no older than 30 seconds. "
            "Unknown or unavailable never proves the Mac is locked."
            if view == "status"
            else "Read FileVault capability flags and error/setup-note counts. "
            "No connection identifiers, message text or credentials are returned."
        )

    @override
    async def async_call(
        self, hass: HomeAssistant, tool_input: ToolInput, llm_context: LLMContext
    ) -> ToolResult:
        """No HTTP, service calls, free-form queries, history or credential reads."""
        try:
            self.parameters(tool_input.tool_args)
        except vol.Invalid:
            return ToolResult(data={"error": "invalid_arguments"}, error=True)
        if (
            self.entry.state is not ConfigEntryState.LOADED
            or self.entry.runtime_data is not self.coordinator
        ):
            return ToolResult(data={"error": "unavailable"}, error=True)
        entity_id = _entity_id(hass)
        if (
            entity_id is None
            or hass.states.get(entity_id) is None
            or not async_should_expose(hass, llm_context.assistant, entity_id)
        ):
            return ToolResult(data={"error": "not_exposed"}, error=True)
        context = llm_context.context
        user = (
            await hass.auth.async_get_user(context.user_id)
            if context and context.user_id
            else None
        )
        if (
            user is None
            or not user.is_active
            or not user.permissions.check_entity(entity_id, POLICY_READ)
        ):
            return ToolResult(data={"error": "permission_denied"}, error=True)
        # The auth lookup yielded; exposure and entry ownership can change meanwhile.
        if (
            self.entry.state is not ConfigEntryState.LOADED
            or self.entry.runtime_data is not self.coordinator
            or not async_should_expose(hass, llm_context.assistant, entity_id)
        ):
            return ToolResult(data={"error": "unavailable"}, error=True)
        projection = status_snapshot if self.view == "status" else configuration_health
        return ToolResult(data=projection(self.coordinator))
