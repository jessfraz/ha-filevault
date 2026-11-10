"""Exercise the authenticated cached status API, without backend actions."""

import json
from datetime import timedelta

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker
from pytest_homeassistant.typing import ClientSessionGenerator

from custom_components.filevault import FileVaultConfigEntry

PRIVATE = "PRIVATE_SENTINEL_NEVER_EXPORT"


@pytest.fixture
async def loaded(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
) -> FileVaultConfigEntry:
    aioclient_mock.get(
        "http://service.example.invalid/v1/status",
        json={
            "decision": {"state": "running", "unlock_available": False},
            "transport_ready": False,
            "manual_ready": True,
            "runtime_check": "verified",
            "configuration_errors": [],
            "configuration_notes": [PRIVATE],
            "connection": {"host": PRIVATE},
        },
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def test_authenticated_reads_are_cached_safe_and_expire(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    client = await hass_client()
    calls = len(aioclient_mock.mock_calls)
    response = await client.get("/api/filevault/v1/status")
    assert response.status == 200
    data = await response.json()
    assert data["state"] == "running"
    assert data["available"] is True
    assert data["configuration_error_count"] == 0
    assert data["setup_note_count"] == 1
    assert PRIVATE not in json.dumps(data)
    response = await client.get("/api/filevault/v1/system")
    assert response.status == 200
    assert (await response.json())["version"] == "0.1.8"
    assert len(aioclient_mock.mock_calls) == calls

    await loaded.runtime_data.async_shutdown()
    loaded.runtime_data.last_success_at = dt_util.utcnow() - timedelta(seconds=60)
    response = await client.get("/api/filevault/v1/status")
    assert response.status == 200
    data = await response.json()
    assert data["state"] == "unknown" and data["available"] is False
    assert data["configuration_error_count"] is None
    assert await hass.config_entries.async_unload(loaded.entry_id)
    assert (await client.get("/api/filevault/v1/status")).status == 503
    assert len(aioclient_mock.mock_calls) == calls


async def test_auth_read_permission_and_fixed_routes(
    hass: HomeAssistant,
    loaded: FileVaultConfigEntry,
    hass_client: ClientSessionGenerator,
) -> None:
    anonymous = await hass_client(None)
    assert (await anonymous.get("/api/filevault/v1/status")).status == 401
    user = await hass.auth.async_create_user("Restricted fixture", group_ids=[])
    refresh = await hass.auth.async_create_refresh_token(
        user, client_id="https://example.invalid"
    )
    restricted = await hass_client(hass.auth.async_create_access_token(refresh))
    assert (await restricted.get("/api/filevault/v1/status")).status == 403
    client = await hass_client()
    assert (await client.post("/api/filevault/v1/status")).status == 405
    assert (await client.get("/api/filevault/v1/unlock")).status == 404
