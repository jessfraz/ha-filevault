"""Expose status without a password field, unlock service, or transcript."""

from datetime import datetime, timedelta
from typing import override

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import FileVaultConfigEntry
from .coordinator import FileVaultCoordinator
from .health import configuration_health, status_snapshot


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FileVaultConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([FileVaultStatusSensor(entry.runtime_data)])


class FileVaultStatusSensor(CoordinatorEntity[FileVaultCoordinator], SensorEntity):
    _attr_name = "FileVault status"
    _attr_translation_key = "status"
    _attr_unique_id = "filevault_status"
    _attr_device_class = SensorDeviceClass.ENUM
    _unrecorded_attributes = frozenset({"observation_age_seconds"})
    _attr_options = [
        "running",
        "ssh_reachable",
        "verified_preboot",
        "unreachable",
        "unknown",
    ]

    def __init__(self, coordinator: FileVaultCoordinator) -> None:
        super().__init__(coordinator)
        self._update_status()

    def _update_status(self) -> None:
        """Expire stale observations even when the last value was running."""
        report = status_snapshot(self.coordinator)
        state = report["state"]
        self._attr_native_value = state if isinstance(state, str) else "unknown"
        self._attr_extra_state_attributes = report | configuration_health(
            self.coordinator
        )

    @override
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_track_time_interval(
                self.hass, self._refresh_freshness, timedelta(seconds=15)
            )
        )

    @callback
    def _refresh_freshness(self, _now: datetime) -> None:
        self._update_status()
        self.async_write_ha_state()

    @callback
    @override
    def _handle_coordinator_update(self) -> None:
        self._update_status()
        super()._handle_coordinator_update()
