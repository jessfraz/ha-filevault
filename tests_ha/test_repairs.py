"""Repairs follow verified observations and remain owned by their config entry."""

import asyncio
from datetime import timedelta

import pytest
from aiohttp import web
from freezegun.api import FrozenDateTimeFactory
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.util import dt as dt_util
from pytest_aiohttp.plugin import AiohttpServer
from pytest_homeassistant.common import async_fire_time_changed
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker

from custom_components.filevault import FileVaultConfigEntry

URL = "http://service.example.invalid/v1/status"


def report(state: str, *, errors: list[str] | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "decision": {"state": state, "unlock_available": state == "verified_preboot"},
        "transport_ready": True,
    }
    if errors is not None:
        result["configuration_errors"] = errors
    return result


def issue(
    hass: HomeAssistant, entry: FileVaultConfigEntry, kind: str
) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue("filevault", f"{entry.entry_id}_{kind}")


def core_auth_key(entry: FileVaultConfigEntry) -> tuple[str, str]:
    return ("homeassistant", f"config_entry_reauth_filevault_{entry.entry_id}")


def owned_issues(
    hass: HomeAssistant, entry: FileVaultConfigEntry
) -> set[tuple[str, str]]:
    return {
        (item.domain, item.issue_id)
        for item in ir.async_get(hass).issues.values()
        if item.config_entry_id == entry.entry_id
    }


async def test_verified_preboot_configuration_and_transport_recovery(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    aioclient_mock.get(
        URL, json=report("verified_preboot", errors=["private host detail"])
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    locked = issue(hass, entry, "status")
    assert locked is not None and locked.translation_key == "unlock_required"
    assert locked.config_entry_id == entry.entry_id
    assert (
        locked.learn_more_url
        == "homeassistant://config/integrations/integration/filevault"
    )
    configuration = issue(hass, entry, "configuration")
    assert configuration is not None
    assert configuration.translation_placeholders == {"count": "1"}
    assert "private host detail" not in str(configuration)
    assert not hass.services.has_service("filevault", "unlock")

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, status=503)
    await entry.runtime_data.async_refresh()
    failed = issue(hass, entry, "availability")
    assert failed is not None and failed.translation_key == "status_unavailable"
    assert issue(hass, entry, "status") is locked
    assert issue(hass, entry, "configuration") is not None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, json=report("unknown"))
    await entry.runtime_data.async_refresh()
    assert issue(hass, entry, "availability") is None
    assert issue(hass, entry, "status") is locked
    assert issue(hass, entry, "configuration") is not None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, json=report("running", errors=[]))
    await entry.runtime_data.async_refresh()
    assert issue(hass, entry, "status") is None
    assert issue(hass, entry, "configuration") is None


@pytest.mark.parametrize("status", [503, 401])
async def test_initial_backend_failure_creates_owned_repair(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    status: int,
) -> None:
    aioclient_mock.get(URL, status=status)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    if status == 401:
        assert owned_issues(hass, entry) == {core_auth_key(entry)}
    else:
        failed = issue(hass, entry, "availability")
        assert failed is not None and failed.translation_key == "status_unavailable"
        assert failed.config_entry_id == entry.entry_id
    await hass.config_entries.async_remove(entry.entry_id)
    assert not owned_issues(hass, entry)


async def test_freshness_timer_and_unload_cleanup(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
) -> None:
    aioclient_mock.get(URL, json=report("running", errors=[]))
    assert await hass.config_entries.async_setup(entry.entry_id)
    # Pause scheduled polling while the installed entry still owns its timers.
    entry.runtime_data._unschedule_refresh()
    entry.runtime_data.last_success_at = dt_util.utcnow() - timedelta(seconds=31)
    freezer.tick(timedelta(seconds=15))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()
    stale = issue(hass, entry, "availability")
    assert stale is not None and stale.translation_key == "status_unavailable"
    assert await hass.config_entries.async_unload(entry.entry_id)
    ir.async_delete_issue(hass, "filevault", f"{entry.entry_id}_availability")
    freezer.tick(timedelta(minutes=1))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()
    assert issue(hass, entry, "status") is None


@pytest.mark.parametrize("remove", [False, True])
async def test_late_failed_http_response_cannot_publish_after_unload(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aiohttp_server: AiohttpServer,
    socket_enabled: None,
    remove: bool,
) -> None:
    received = asyncio.Event()
    release = asyncio.Event()
    blocked = False

    async def status(_request: web.Request) -> web.Response:
        if blocked:
            received.set()
            await release.wait()
            return web.Response(status=503)
        return web.json_response(report("running", errors=[]))

    app = web.Application()
    app.router.add_get("/v1/status", status)
    server = await aiohttp_server(app)
    hass.config_entries.async_update_entry(
        entry,
        data={
            "backend_url": str(server.make_url("")).rstrip("/"),
            "token": "test-only-token",
        },
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    coordinator = entry.runtime_data
    blocked = True
    refresh = hass.async_create_background_task(
        coordinator.async_refresh(), "late status fixture"
    )
    try:
        async with asyncio.timeout(2):
            await received.wait()
            if remove:
                assert await hass.config_entries.async_remove(entry.entry_id)
            else:
                assert await hass.config_entries.async_unload(entry.entry_id)
    finally:
        release.set()
        await refresh
    assert not owned_issues(hass, entry)
    assert isinstance(coordinator.last_exception, UpdateFailed)


async def test_credential_failure_replaces_only_generic_availability(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
) -> None:
    aioclient_mock.get(URL, json=report("running", errors=[]))
    assert await hass.config_entries.async_setup(entry.entry_id)
    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, status=503)
    await entry.runtime_data.async_refresh()
    assert any(
        item.domain == "filevault" and item.translation_key == "status_unavailable"
        for item in ir.async_get(hass).issues.values()
    )
    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, status=401)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert owned_issues(hass, entry) == {core_auth_key(entry)}
    freezer.tick(timedelta(seconds=30))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()
    assert owned_issues(hass, entry) == {core_auth_key(entry)}


async def test_credential_failure_retains_confirmed_preboot_and_configuration(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
) -> None:
    aioclient_mock.get(URL, json=report("verified_preboot", errors=["private detail"]))
    assert await hass.config_entries.async_setup(entry.entry_id)
    locked = issue(hass, entry, "status")
    configuration = issue(hass, entry, "configuration")
    assert locked is not None and configuration is not None
    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, status=401)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    freezer.tick(timedelta(seconds=30))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()
    assert issue(hass, entry, "status") is locked
    assert issue(hass, entry, "configuration") is configuration
    assert owned_issues(hass, entry) == {
        core_auth_key(entry),
        ("filevault", f"{entry.entry_id}_status"),
        ("filevault", f"{entry.entry_id}_configuration"),
    }


async def test_version_repair_uses_loaded_release_and_fresh_status(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    aioclient_mock.get(URL, json=report("running"))
    aioclient_mock.get(
        "http://service.example.invalid/v1/system",
        json={"credential_role": "integration", "version": "9.8.7"},
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    mismatch = issue(hass, entry, "version_mismatch")
    assert mismatch is not None and mismatch.is_fixable
    assert mismatch.translation_placeholders is not None
    assert mismatch.translation_placeholders["app_version"] == "9.8.7"

    aioclient_mock.clear_requests()
    aioclient_mock.get(
        URL,
        json=report("running")
        | {"version": mismatch.translation_placeholders["integration_version"]},
    )
    await entry.runtime_data.async_refresh()
    assert issue(hass, entry, "version_mismatch") is None
    assert not hass.services.has_service("filevault", "unlock")
