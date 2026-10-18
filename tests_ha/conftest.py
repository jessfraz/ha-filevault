"""Enable the checkout's adapter using the reference app fixture pattern."""

import pytest
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.filevault import FileVaultConfigEntry


@pytest.fixture(autouse=True)
def custom_integrations(enable_custom_integrations: None) -> None:
    """Load custom components from this checkout."""


@pytest.fixture
def entry(hass: HomeAssistant) -> FileVaultConfigEntry:
    """Register a fictional read-only service, as in the reference tests."""
    result = MockConfigEntry(
        domain="filevault",
        data={
            "backend_url": "http://service.example.invalid",
            "token": "test-only-status-token",
        },
    )
    result.add_to_hass(hass)
    return result
