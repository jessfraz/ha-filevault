"""Execute shipped notifications through HA's actual blueprint/automation engine."""

import shutil
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.components.automation.helpers import async_get_blueprints
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

BLUEPRINTS = Path(__file__).resolve().parents[1] / "blueprints/automation/filevault"
ENTITY = "sensor.fixture_filevault_status"


@pytest.fixture
def hass_config_dir(hass_tmp_config_dir: str) -> str:
    return hass_tmp_config_dir


@pytest.fixture(autouse=True)
async def stop_automation(hass: HomeAssistant) -> AsyncIterator[None]:
    yield
    if hass.services.has_service("automation", "turn_off"):
        await hass.services.async_call(
            "automation",
            "turn_off",
            {"entity_id": "automation.filevault_notification"},
            blocking=True,
        )
        await hass.async_block_till_done()


@pytest.fixture
def notifications(hass: HomeAssistant) -> list[dict[str, object]]:
    received: list[dict[str, object]] = []

    @callback
    def record(call: ServiceCall) -> None:
        received.append(dict(call.data))

    hass.services.async_register("notify", "record_filevault", record)
    return received


async def setup(
    hass: HomeAssistant,
    filename: str,
    inputs: dict[str, object],
    initial: str,
) -> None:
    def install() -> None:
        destination = Path(hass.config.path("blueprints/automation/filevault"))
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BLUEPRINTS / filename, destination / filename)

    await hass.async_add_executor_job(install)
    hass.states.async_set(ENTITY, initial)
    config = {
        "id": "filevault_notification",
        "alias": "FileVault notification",
        "use_blueprint": {
            "path": f"filevault/{filename}",
            "input": {
                "status_entity": ENTITY,
                **inputs,
                "notify_actions": [
                    {
                        "action": "notify.record_filevault",
                        "data": {
                            "title": "{{ title }}",
                            "message": "{{ message }}",
                            "status": "{{ status }}",
                        },
                    }
                ],
            },
        },
    }
    loaded = await async_get_blueprints(hass).async_inputs_from_config(config)
    assert loaded.blueprint.validate() is None
    assert await async_setup_component(hass, "automation", {"automation": [config]})
    await hass.async_start()
    await hass.async_block_till_done()
    state = hass.states.get("automation.filevault_notification")
    assert state is not None and state.state == "on"


async def advance(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    seconds: float,
) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()


async def state(
    hass: HomeAssistant, value: str, attributes: dict[str, object] | None = None
) -> None:
    hass.states.async_set(ENTITY, value, attributes)
    await hass.async_block_till_done()


@pytest.mark.freeze_time("2026-10-20T12:00:00Z")
async def test_attention_debounces_flaps_ignores_attributes_and_limits_repeats(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    notifications: list[dict[str, object]],
) -> None:
    await setup(
        hass,
        "needs_attention.yaml",
        {"debounce": {"seconds": 2}, "cooldown_minutes": 1},
        "running",
    )
    assert notifications == []
    await state(hass, "unknown")
    await advance(hass, freezer, 1)
    await state(hass, "running")
    await advance(hass, freezer, 3)
    assert notifications == []
    await state(hass, "unknown")
    await advance(hass, freezer, 3)
    assert len(notifications) == 1
    assert "may need unlocking" in " ".join(str(notifications[0]["message"]).split())
    assert "networking may be unavailable" in str(notifications[0]["message"])
    await state(hass, "unknown", {"changed": True})
    await advance(hass, freezer, 3)
    await state(hass, "unreachable")
    await advance(hass, freezer, 3)
    assert len(notifications) == 1
    await advance(hass, freezer, 65)
    assert len(notifications) == 1  # Suppressed triggers are not queued for later.
    await state(hass, "running")
    await state(hass, "unavailable")
    await advance(hass, freezer, 3)
    assert len(notifications) == 2
    assert "power and lock state are unknown" in " ".join(
        str(notifications[1]["message"]).split()
    )


@pytest.mark.freeze_time("2026-10-20T12:00:00Z")
async def test_running_again_requires_stable_real_transition_and_cooldown(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    notifications: list[dict[str, object]],
) -> None:
    await setup(
        hass,
        "running_again.yaml",
        {"debounce": {"seconds": 2}, "cooldown_minutes": 1},
        "running",
    )
    await advance(hass, freezer, 3)
    assert notifications == []
    await state(hass, "unknown")
    await state(hass, "running")
    await advance(hass, freezer, 1)
    await state(hass, "unknown")
    await advance(hass, freezer, 3)
    assert notifications == []
    await state(hass, "running")
    await advance(hass, freezer, 3)
    assert len(notifications) == 1
    assert notifications[0]["status"] == "running"
    assert "have not been checked" in str(notifications[0]["message"])
    await state(hass, "unavailable")
    await state(hass, "running")
    await advance(hass, freezer, 3)
    assert len(notifications) == 1


@pytest.mark.parametrize(
    ("initial", "include_running", "expected"),
    [
        ("running", False, 0),
        ("running", True, 1),
        ("unknown", False, 1),
        ("unavailable", False, 1),
        ("verified_preboot", False, 1),
    ],
)
@pytest.mark.freeze_time("2026-10-20T07:59:58Z")
async def test_daily_digest_is_configurable_and_quiet_for_running_by_default(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    notifications: list[dict[str, object]],
    initial: str,
    include_running: bool,
    expected: int,
) -> None:
    await hass.config.async_set_time_zone("UTC")
    await setup(
        hass, "daily_status.yaml", {"include_running": include_running}, initial
    )
    await advance(hass, freezer, 3)
    assert len(notifications) == expected
    if expected:
        assert notifications[0]["status"] == initial
    await state(hass, "unknown", {"ignored": True})
    await advance(hass, freezer, 5)
    assert len(notifications) == expected


@pytest.mark.freeze_time("2026-11-01T05:29:58Z")
async def test_daily_digest_does_not_repeat_in_dst_fallback_hour(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    notifications: list[dict[str, object]],
) -> None:
    await hass.config.async_set_time_zone("America/New_York")
    await setup(hass, "daily_status.yaml", {"notification_time": "01:30:00"}, "unknown")
    await advance(hass, freezer, 3)
    assert len(notifications) == 1
    await advance(hass, freezer, 3600)
    assert len(notifications) == 1
