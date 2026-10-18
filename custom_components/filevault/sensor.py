"""Expose status without a password field, unlock service, or transcript."""

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import FileVaultConfigEntry
from .coordinator import FileVaultCoordinator


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
    _attr_options = ["running", "verified_preboot", "unreachable", "unknown"]

    def __init__(self, coordinator: FileVaultCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_native_value = coordinator.data.state

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_native_value = self.coordinator.data.state
        super()._handle_coordinator_update()
