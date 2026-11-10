"""Entry-owned Repairs use confirmed observations, never an unlock action."""

import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from homeassistant.components.repairs import RepairsFlow
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.event import async_track_time_interval

from ._app_kit.repairs import VersionRepairSpec, create_version_fix_flow
from ._app_kit.version import LOADED_VERSION
from ._app_kit.versions import ReleaseVersion
from .const import CONF_ADDON_SLUG, DOMAIN
from .health import status_snapshot

if TYPE_CHECKING:
    from .coordinator import FileVaultCoordinator


class FileVaultRepairs:
    """Keep status and configuration incidents separate across transport gaps."""

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, coordinator: FileVaultCoordinator
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.coordinator = coordinator
        slug = entry.data.get(CONF_ADDON_SLUG)
        self._link = (
            f"homeassistant://config/app/{slug}/logs"
            if isinstance(slug, str) and re.fullmatch(r"[a-z0-9_]+", slug)
            else f"homeassistant://config/integrations/integration/{DOMAIN}"
        )

    @callback
    def async_start(self) -> None:
        """Repairs also consume polling when all entity consumers are disabled."""
        self.entry.async_on_unload(
            self.coordinator.async_add_listener(self.async_reconcile)
        )
        self.entry.async_on_unload(
            async_track_time_interval(
                self.hass, self._async_tick, timedelta(seconds=15)
            )
        )
        self.async_reconcile()

    @callback
    def _async_tick(self, _now: datetime) -> None:
        self.async_reconcile()

    @callback
    def _async_issue(self, kind: str, key: str, count: int | None = None) -> None:
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"{self.entry.entry_id}_{kind}",
            config_entry_id=self.entry.entry_id,
            is_fixable=False,
            is_persistent=True,
            severity=ir.IssueSeverity.WARNING,
            translation_key=key,
            translation_placeholders={"count": str(count)}
            if count is not None
            else None,
            learn_more_url=self._link,
        )

    @callback
    def async_connection_failed(self) -> None:
        """Initial setup and transport failures also need a native Repair."""
        if not self.coordinator._shutdown_requested:
            self._async_issue("availability", "status_unavailable")

    @callback
    def async_auth_failed(self) -> None:
        """Core owns rejected credentials; retain distinct confirmed boot faults."""
        if not self.coordinator._shutdown_requested:
            ir.async_delete_issue(
                self.hass, DOMAIN, f"{self.entry.entry_id}_availability"
            )

    @callback
    def async_reconcile(self) -> None:
        # Shutdown unsubscribes future polls without cancelling an in-flight read.
        if self.coordinator._shutdown_requested:
            return
        if not self.coordinator.last_update_success and isinstance(
            self.coordinator.last_exception, ConfigEntryAuthFailed
        ):
            self.async_auth_failed()
            return
        snapshot = status_snapshot(self.coordinator)
        if not snapshot["available"]:
            self.async_connection_failed()
            return
        ir.async_delete_issue(self.hass, DOMAIN, f"{self.entry.entry_id}_availability")
        data = self.coordinator.data
        status = ir.async_get(self.hass).async_get_issue(
            DOMAIN, f"{self.entry.entry_id}_status"
        )
        if data.state == "running":
            ir.async_delete_issue(self.hass, DOMAIN, f"{self.entry.entry_id}_status")
        elif (
            data.state == "verified_preboot"
            or status is None
            or status.translation_key != "unlock_required"
        ):
            self._async_issue(
                "status",
                "unlock_required"
                if data.state == "verified_preboot"
                else "status_unknown",
            )
        if data.error_count is not None:
            if data.error_count:
                self._async_issue(
                    "configuration", "configuration_errors", data.error_count
                )
            else:
                ir.async_delete_issue(
                    self.hass, DOMAIN, f"{self.entry.entry_id}_configuration"
                )


async def _async_probe_version(
    _hass: HomeAssistant, entry: ConfigEntry
) -> ReleaseVersion:
    runtime: FileVaultCoordinator = entry.runtime_data
    value = await runtime.client.system()
    if value.get("credential_role") != "integration":
        raise ValueError("Cannot verify the FileVault version")
    return ReleaseVersion.parse(value.get("version"))


def _app_slug(entry: ConfigEntry) -> str | None:
    slug = entry.data.get(CONF_ADDON_SLUG)
    return slug if isinstance(slug, str) else None


VERSION_REPAIR = VersionRepairSpec(
    DOMAIN,
    "FileVault",
    "1423923660",
    ReleaseVersion.parse(LOADED_VERSION),
    _async_probe_version,
    _app_slug,
)


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    _data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Resolve the issue against its current loaded configuration entry."""
    return create_version_fix_flow(hass, issue_id, VERSION_REPAIR)
