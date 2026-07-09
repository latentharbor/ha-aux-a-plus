"""Switch platform for AUX A+ Air Conditioner."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME

from .api import AuxAPlusApi, AuxAPlusApiError
from .const import (
    CONF_CONFIG_ID,
    CONF_DEVICE_ID,
    CONF_PUBLIC_KEY,
    DEFAULT_CONFIG_ID,
    DEFAULT_NAME,
    DEFAULT_PUBLIC_KEY_BASE64,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up AUX A+ switches from a config entry."""
    data = entry.data
    name = entry.options.get(CONF_NAME, data.get(CONF_NAME, DEFAULT_NAME))
    api = AuxAPlusApi(
        account=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        device_id=data[CONF_DEVICE_ID],
        config_id=data.get(CONF_CONFIG_ID, DEFAULT_CONFIG_ID),
        public_key_base64=data.get(CONF_PUBLIC_KEY, DEFAULT_PUBLIC_KEY_BASE64),
    )
    async_add_entities([AuxAPlusLeftRightSwingSwitch(api, name, data[CONF_DEVICE_ID])], True)


class AuxAPlusLeftRightSwingSwitch(SwitchEntity):
    """Control left/right swing separately from Home Assistant's climate swing mode."""

    _attr_has_entity_name = True
    _attr_translation_key = "left_right_swing"

    def __init__(self, api: AuxAPlusApi, name: str, device_id: str) -> None:
        self.api = api
        self._device_id = device_id
        self._attr_name = "Left/right swing"
        self._attr_unique_id = f"aux_a_plus_{device_id}_left_right_swing"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"aux_a_plus_{device_id}")},
            "name": name,
            "manufacturer": "AUX / 奥克斯",
        }
        self._available = False
        self._is_on: bool | None = None
        self._raw_value: Any = None

    @property
    def available(self) -> bool:
        return self._available

    @property
    def is_on(self) -> bool | None:
        return self._is_on

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"left_right_swing": self._raw_value}

    def update(self) -> None:
        try:
            device = self.api.get_device()
            state = device.get("data") or {}
            self._raw_value = state.get("left_right_swing")
            self._is_on = str(self._raw_value) != "7" if self._raw_value is not None else None
            self._available = bool(device.get("online", True))
        except AuxAPlusApiError as err:
            self._available = False
            _LOGGER.warning("AUX A+ left/right swing update failed: %s", err)
        except Exception as err:  # noqa: BLE001
            self._available = False
            _LOGGER.exception("Unexpected AUX A+ left/right swing update error: %s", err)

    def turn_on(self, **kwargs: Any) -> None:
        self.api.control({"left_right_swing": 0}, v2=False)
        self.update()

    def turn_off(self, **kwargs: Any) -> None:
        self.api.control({"left_right_swing": 7}, v2=False)
        self.update()
