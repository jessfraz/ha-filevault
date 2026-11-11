"""A failed status projection retains a usable native version Repair."""

from aiohttp import web
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component
from pytest_aiohttp.plugin import AiohttpServer
from pytest_homeassistant.common import MockConfigEntry
from pytest_homeassistant.typing import ClientSessionGenerator

from custom_components.filevault._app_kit.version import LOADED_VERSION
from custom_components.filevault.const import CONF_BACKEND_URL, CONF_TOKEN, DOMAIN


async def test_failed_startup_version_repair_opens_in_native_repairs(
    hass: HomeAssistant,
    aiohttp_server: AiohttpServer,
    socket_enabled: None,
    hass_client: ClientSessionGenerator,
) -> None:
    recovered = False
    methods: list[str] = []

    async def handle(request: web.Request) -> web.Response:
        methods.append(request.method)
        assert request.headers["Authorization"] == "Bearer test-integration-token"
        if request.path == "/v1/system":
            return web.json_response(
                {
                    "credential_role": "integration",
                    "version": LOADED_VERSION if recovered else "0.0.1",
                }
            )
        if not recovered:
            return web.json_response({}, status=404)
        return web.json_response(
            {
                "decision": {"state": "running", "unlock_available": False},
                "transport_ready": True,
                "version": LOADED_VERSION,
            }
        )

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handle)
    server = await aiohttp_server(app)
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_BACKEND_URL: str(server.make_url("")).rstrip("/"),
            CONF_TOKEN: "test-integration-token",
        },
    )
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    issue_id = f"{entry.entry_id}_version_mismatch"
    issue = ir.async_get(hass).async_get_issue(DOMAIN, issue_id)
    assert issue is not None and issue.is_fixable and issue.is_persistent
    assert issue.config_entry_id == entry.entry_id

    assert await async_setup_component(hass, "repairs", {})
    client = await hass_client()
    response = await client.post(
        "/api/repairs/issues/fix", json={"handler": DOMAIN, "issue_id": issue_id}
    )
    assert response.status == 200
    flow = await response.json()
    assert flow["type"] == "form" and flow["step_id"] == "retry"
    assert flow["errors"] == {"base": "managed_update_unavailable"}
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is issue
    assert all(method == "GET" for method in methods)
    assert not hass.services.has_service(DOMAIN, "unlock")

    recovered = True
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.state is ConfigEntryState.LOADED
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is None
