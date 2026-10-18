"""HA setup/unload and credential boundary checks with fictional fixtures."""

import pytest
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.filevault import FileVaultConfigEntry


@pytest.mark.usefixtures("enable_custom_integrations")
async def test_status_only_setup_and_unload(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    entry: FileVaultConfigEntry,
) -> None:
    aioclient_mock.get(
        "http://service.example.invalid/v1/status",
        json={
            "version": "0.0.0",
            "decision": {"state": "unknown", "unlock_available": False},
            "transport_ready": False,
        },
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    sensor = hass.states.get("sensor.filevault_status")
    assert sensor is not None
    assert sensor.state == "unknown"
    assert not hass.services.has_service("filevault", "unlock")
    assert "token" not in sensor.attributes
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.usefixtures("enable_custom_integrations")
async def test_unavailable_backend_does_not_claim_locked(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    entry: FileVaultConfigEntry,
) -> None:
    aioclient_mock.get("http://service.example.invalid/v1/status", status=503)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    sensor = hass.states.get("sensor.filevault_status")
    assert sensor is None or sensor.state != "verified_preboot"
