"""Native Assist discovery and diagnostics with hostile fictional backend data."""

import json
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.auth.models import User
from homeassistant.components import llm
from homeassistant.components.homeassistant.exposed_entities import async_expose_entity
from homeassistant.core import Context, HomeAssistant
from homeassistant.helpers.llm import LLMContext, ToolInput
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.components.diagnostics import (
    get_diagnostics_for_config_entry,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

from custom_components.filevault import FileVaultConfigEntry
from custom_components.filevault.diagnostics import async_get_config_entry_diagnostics
from custom_components.filevault.health import configuration_health, status_snapshot
from custom_components.filevault.llm import FileVaultQuery, async_get_tools
from custom_components.filevault.models import parse_status

PRIVATE = "PRIVATE_SENTINEL_NEVER_EXPORT"
REPORT = {
    "decision": {"state": "running", "unlock_available": False},
    "transport_ready": False,
    "manual_ready": True,
    "runtime_check": "verified",
    "configuration_errors": [],
    "configuration_notes": [PRIVATE],
    "connection": {"host": PRIVATE, "username": PRIVATE, "tailscale_host": PRIVATE},
    "password": PRIVATE,
    "token": PRIVATE,
    "host_key": PRIVATE,
    "future_unrecognized_field": {"nested_secret": PRIVATE},
}


@pytest.fixture
async def loaded(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
) -> FileVaultConfigEntry:
    """Use actual HA setup so platform discovery and entry lifetime are exercised."""
    assert await async_setup_component(hass, "homeassistant", {})
    aioclient_mock.get("http://service.example.invalid/v1/status", json=REPORT)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    async_expose_entity(hass, "conversation", "sensor.filevault_status", True)
    return entry


def context(user: User | None) -> LLMContext:
    return LLMContext(
        platform="conversation",
        context=Context(user_id=user.id) if user else None,
        language="en",
        assistant="conversation",
        device_id=None,
    )


async def test_native_core_discovers_only_two_exposed_read_only_tools(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_admin_user: User,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    assert await async_setup_component(hass, "llm", {})
    ctx = context(hass_admin_user)
    bundle = await llm.async_get_tools(hass, ctx, "assist")
    tools = [t for t in bundle.tools if t.integration == "filevault"]
    assert {t.name for t in tools} == {
        "filevault__status",
        "filevault__configuration_health",
    }
    calls = len(aioclient_mock.mock_calls)
    for tool in tools:
        assert isinstance(tool, FileVaultQuery)
        assert tool.annotations.read_only and tool.annotations.idempotent
        assert not tool.annotations.destructive and not tool.annotations.open_world
        result = await tool.async_call(hass, ToolInput(tool.name, {}), ctx)
        assert not result.error
        assert result.data["available"] is True
        assert PRIVATE not in json.dumps(result.data)
        assert len(json.dumps(result.data)) < 1024
        rejected = await tool.async_call(
            hass, ToolInput(tool.name, {"password": PRIVATE}), ctx
        )
        assert rejected.error and rejected.data == {"error": "invalid_arguments"}
    assert (
        len(aioclient_mock.mock_calls) == calls
    )  # Queries never issue network requests.
    assert not hass.services.has_service("filevault", "unlock")
    assert async_get_tools(hass, ctx, "homeassistant") is None


async def test_cached_tools_recheck_exposure_user_and_entry_lifetime(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_admin_user: User,
) -> None:
    ctx = context(hass_admin_user)
    bundle = async_get_tools(hass, ctx, "assist")
    assert bundle is not None
    tool = bundle.tools[0]
    assert isinstance(tool, FileVaultQuery)
    no_user = await tool.async_call(hass, ToolInput(tool.name, {}), context(None))
    assert no_user.error and no_user.data == {"error": "permission_denied"}
    async_expose_entity(hass, "conversation", "sensor.filevault_status", False)
    assert async_get_tools(hass, ctx, "assist") is None
    denied = await tool.async_call(hass, ToolInput(tool.name, {}), ctx)
    assert denied.error and denied.data == {"error": "not_exposed"}
    async_expose_entity(hass, "conversation", "sensor.filevault_status", True)
    with patch.object(hass.auth, "async_get_user", return_value=None):
        denied = await tool.async_call(hass, ToolInput(tool.name, {}), ctx)
        assert denied.error and denied.data == {"error": "permission_denied"}
    assert await hass.config_entries.async_unload(loaded.entry_id)
    denied = await tool.async_call(hass, ToolInput(tool.name, {}), ctx)
    assert denied.error and denied.data == {"error": "unavailable"}


async def test_exposure_revoked_during_user_lookup_blocks_cached_query(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_admin_user: User,
) -> None:
    ctx = context(hass_admin_user)
    bundle = async_get_tools(hass, ctx, "assist")
    assert bundle is not None
    tool = bundle.tools[0]
    assert isinstance(tool, FileVaultQuery)

    async def revoke(user_id: str) -> User:
        async_expose_entity(hass, "conversation", "sensor.filevault_status", False)
        return hass_admin_user

    with patch.object(hass.auth, "async_get_user", side_effect=revoke):
        result = await tool.async_call(hass, ToolInput(tool.name, {}), ctx)
    assert result.error and result.data == {"error": "unavailable"}


@pytest.mark.parametrize("restriction", ["no_read_permission", "inactive"])
async def test_user_must_be_active_and_permitted_to_read_the_sensor(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_admin_user: User,
    restriction: str,
) -> None:
    user = hass_admin_user
    if restriction == "no_read_permission":
        user = await hass.auth.async_create_user("Restricted fixture", group_ids=[])
    else:
        await hass.auth.async_update_user(user, is_active=False)
    bundle = async_get_tools(hass, context(user), "assist")
    assert bundle is not None
    tool = bundle.tools[0]
    assert isinstance(tool, FileVaultQuery)
    result = await tool.async_call(hass, ToolInput(tool.name, {}), context(user))
    assert result.error and result.data == {"error": "permission_denied"}


async def test_old_tool_cannot_read_a_reloaded_installation(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_admin_user: User,
) -> None:
    ctx = context(hass_admin_user)
    bundle = async_get_tools(hass, ctx, "assist")
    assert bundle is not None
    tool = bundle.tools[0]
    assert isinstance(tool, FileVaultQuery)
    assert await hass.config_entries.async_reload(loaded.entry_id)
    result = await tool.async_call(hass, ToolInput(tool.name, {}), ctx)
    assert result.error and result.data == {"error": "unavailable"}


async def test_stale_future_and_failed_poll_never_replay_running(
    loaded: FileVaultConfigEntry,
) -> None:
    coordinator = loaded.runtime_data
    assert status_snapshot(coordinator)["state"] == "running"
    for observed in [
        dt_util.utcnow() - timedelta(seconds=31),
        dt_util.utcnow() + timedelta(seconds=5),
    ]:
        coordinator.last_success_at = observed
        result = status_snapshot(coordinator)
        assert result["state"] == "unknown" and not result["available"]
        assert configuration_health(coordinator)["manual_ready"] is None
    coordinator.last_success_at = dt_util.utcnow()
    coordinator.last_update_success = False
    coordinator.last_exception = ValueError(PRIVATE)
    assert status_snapshot(coordinator)["state"] == "unknown"


async def test_native_diagnostic_download_redacts_every_connection_and_secret(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_client: ClientSessionGenerator,
) -> None:
    hass.config_entries.async_update_entry(
        loaded, data={**loaded.data, "future_secret": PRIVATE}, title=PRIVATE
    )
    loaded.runtime_data.last_exception = ValueError(PRIVATE)
    before = dict(loaded.data)
    with patch.object(
        loaded.runtime_data.client,
        "status",
        new=AsyncMock(side_effect=AssertionError("no network")),
    ):
        result = await get_diagnostics_for_config_entry(hass, hass_client, loaded)
    encoded = json.dumps(result)
    for value in [
        PRIVATE,
        "service.example.invalid",
        "test-only-status-token",
        loaded.entry_id,
    ]:
        assert value not in encoded
    status = result["status"]
    health = result["configuration_health"]
    assert isinstance(status, dict) and isinstance(health, dict)
    assert status["state"] == "running"
    assert health["setup_note_count"] == 1
    assert dict(loaded.data) == before
    assert await hass.config_entries.async_unload(loaded.entry_id)
    result = await async_get_config_entry_diagnostics(hass, loaded)
    status = result["status"]
    assert isinstance(status, dict)
    assert status["state"] == "unknown"


@pytest.mark.parametrize(
    "extra",
    [
        {"manual_ready": "true"},
        {"runtime_check": []},
        {"runtime_check": PRIVATE},
        {"configuration_errors": [PRIVATE] * 33},
        {"configuration_notes": {"token": PRIVATE}},
    ],
)
def test_malformed_health_is_rejected_without_preserving_raw_text(
    extra: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="Invalid"):
        parse_status({**REPORT, **extra})
