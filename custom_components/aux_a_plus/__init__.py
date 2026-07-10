"""AUX A+ Air Conditioner custom component."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .api import AuxAPlusApi
from .const import (
    CONF_CONFIG_ID,
    CONF_DEVICE_ID,
    CONF_PUBLIC_KEY,
    DEFAULT_CONFIG_ID,
    DEFAULT_PUBLIC_KEY_BASE64,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.CLIMATE, Platform.SENSOR, Platform.SWITCH]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the AUX A+ integration."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AUX A+ from a config entry."""
    data = entry.data
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = AuxAPlusApi(
        account=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        device_id=data[CONF_DEVICE_ID],
        config_id=data.get(CONF_CONFIG_ID, DEFAULT_CONFIG_ID),
        public_key_base64=data.get(CONF_PUBLIC_KEY, DEFAULT_PUBLIC_KEY_BASE64),
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate existing entities to concise AUX entity IDs."""
    if entry.version < 2:
        device_id = entry.data[CONF_DEVICE_ID]
        registry = er.async_get(hass)
        entity_ids = {
            ("climate", f"aux_a_plus_{device_id}"): "climate.aux",
            ("sensor", f"aux_a_plus_{device_id}_indoor_temperature"): "sensor.aux_temperature",
            ("sensor", f"aux_a_plus_{device_id}_indoor_humidity"): "sensor.aux_humidity",
            ("switch", f"aux_a_plus_{device_id}_left_right_swing"): "switch.aux_left_right_swing",
        }

        for (platform, unique_id), target_entity_id in entity_ids.items():
            current_entity_id = registry.async_get_entity_id(platform, DOMAIN, unique_id)
            if current_entity_id is None or current_entity_id == target_entity_id:
                continue
            if registry.async_get(target_entity_id) is not None:
                _LOGGER.warning(
                    "Cannot rename %s to %s because the target entity ID already exists",
                    current_entity_id,
                    target_entity_id,
                )
                continue
            registry.async_update_entity(current_entity_id, new_entity_id=target_entity_id)

        hass.config_entries.async_update_entry(entry, version=2)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload an AUX A+ config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
