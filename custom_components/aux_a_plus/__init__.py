"""AUX A+ Air Conditioner custom component."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN

PLATFORMS: list[Platform] = [Platform.CLIMATE, Platform.SWITCH]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the AUX A+ integration."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AUX A+ from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload an AUX A+ config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
