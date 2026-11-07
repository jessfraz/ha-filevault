"""HA setup/unload and credential boundary checks with fictional fixtures."""

from datetime import timedelta

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed
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


async def test_running_observation_expires_without_another_poll(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    entry: FileVaultConfigEntry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """The dashboard cannot retain a green state after polling stops."""
    aioclient_mock.get(
        "http://service.example.invalid/v1/status",
        json={
            "decision": {"state": "running", "unlock_available": False},
            "transport_ready": False,
        },
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    running = hass.states.get("sensor.filevault_status")
    assert running is not None and running.state == "running"

    # Stop the poller while leaving its entity installed, then age its evidence.
    await entry.runtime_data.async_shutdown()
    entry.runtime_data.last_success_at = dt_util.utcnow() - timedelta(seconds=45)
    freezer.tick(timedelta(seconds=15))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()

    state = hass.states.get("sensor.filevault_status")
    assert state is not None
    assert state.state == "unknown"
    assert state.attributes["available"] is False
    assert state.attributes["observation_age_seconds"] >= 45
    assert await hass.config_entries.async_unload(entry.entry_id)
