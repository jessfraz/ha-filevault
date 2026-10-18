"""Actual HA config-flow boundaries, with fictional authenticated discovery."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.service_info.hassio import HassioServiceInfo
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.filevault import FileVaultConfigEntry

ORIGIN = "http://fixture-filevault:8080"
TOKEN = "integration-only-dummy-token"
UUID_TEXT = "39f3f4c04b8246eb8cf38e7278f57428"


def discovery() -> HassioServiceInfo:
    return HassioServiceInfo(
        config={"backend_url": ORIGIN, "token": TOKEN},
        name="FileVault",
        slug="fixture_filevault",
        uuid=UUID_TEXT,
    )


async def test_discovery_waits_for_confirmation_before_credential_probe_or_storage(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    result = await hass.config_entries.flow.async_init(
        "filevault", context={"source": "hassio"}, data=discovery()
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "hassio_confirm"
    assert not aioclient_mock.mock_calls
    assert not hass.config_entries.async_entries("filevault")
    aioclient_mock.get(ORIGIN + "/v1/system", json={"credential_role": "integration"})
    with patch("custom_components.filevault.async_setup_entry", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        "backend_url": ORIGIN,
        "token": TOKEN,
        "addon_slug": "fixture_filevault",
    }
    assert aioclient_mock.mock_calls[0][3]["Authorization"] == "Bearer " + TOKEN


async def test_app_menu_uses_supervisor_discovery_without_manual_token_entry(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    found = SimpleNamespace(
        service="filevault",
        addon="fixture_filevault",
        uuid=UUID(UUID_TEXT),
        config=discovery().config,
    )
    service = SimpleNamespace(
        discovery=SimpleNamespace(list=AsyncMock(return_value=[found]))
    )
    result = await hass.config_entries.flow.async_init(
        "filevault", context={"source": "user"}
    )
    assert result["type"] is FlowResultType.MENU
    with (
        patch("custom_components.filevault.config_flow.is_hassio", return_value=True),
        patch(
            "homeassistant.components.hassio.get_supervisor_client",
            return_value=service,
        ),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "app"}
        )
    assert result["step_id"] == "hassio_confirm"
    assert not aioclient_mock.mock_calls
    assert not hass.config_entries.async_entries("filevault")


async def test_non_integration_credential_is_rejected_after_confirmation(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    result = await hass.config_entries.flow.async_init(
        "filevault", context={"source": "hassio"}, data=discovery()
    )
    aioclient_mock.get(ORIGIN + "/v1/system", json={"credential_role": "owner"})
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "integration_required"}
    assert not hass.config_entries.async_entries("filevault")


async def test_reauth_rediscovery_requires_confirmation_before_replacement(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    entry: FileVaultConfigEntry,
) -> None:
    hass.config_entries.async_update_entry(
        entry,
        unique_id=UUID_TEXT,
        data={
            "backend_url": ORIGIN,
            "token": "old-dummy-token",
            "addon_slug": "fixture_filevault",
        },
    )
    fresh = discovery()
    fresh.config["token"] = TOKEN
    found = SimpleNamespace(
        service="filevault",
        addon="fixture_filevault",
        uuid=UUID(UUID_TEXT),
        config=fresh.config,
    )
    service = SimpleNamespace(
        discovery=SimpleNamespace(list=AsyncMock(return_value=[found]))
    )
    with (
        patch("custom_components.filevault.config_flow.is_hassio", return_value=True),
        patch(
            "homeassistant.components.hassio.get_supervisor_client",
            return_value=service,
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            "filevault",
            context={
                "source": config_entries.SOURCE_REAUTH,
                "entry_id": entry.entry_id,
            },
            data=entry.data,
        )
    assert result["step_id"] == "hassio_confirm"
    assert entry.data["token"] == "old-dummy-token"
    assert not aioclient_mock.mock_calls
    aioclient_mock.get(ORIGIN + "/v1/system", json={"credential_role": "integration"})
    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["token"] == TOKEN
