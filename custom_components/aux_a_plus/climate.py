"""Climate platform for AUX A+ Air Conditioner."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.climate import ClimateEntity, PLATFORM_SCHEMA
try:
    from homeassistant.components.climate import ClimateEntityFeature, HVACMode
except ImportError:  # Older/newer HA compatibility
    from homeassistant.components.climate.const import ClimateEntityFeature, HVACMode
from homeassistant.const import (
    ATTR_TEMPERATURE,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_USERNAME,
    UnitOfTemperature,
)
import homeassistant.helpers.config_validation as cv

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

MODE_TO_HVAC = {
    0: HVACMode.AUTO,
    1: HVACMode.COOL,
    2: HVACMode.DRY,
    4: HVACMode.HEAT,
    6: HVACMode.FAN_ONLY,
}
HVAC_TO_MODE = {value: key for key, value in MODE_TO_HVAC.items()}

FAN_TO_CODE = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "quiet": 3,
    "auto": 4,
    "turbo": 5,
    "medium low": 6,
    "medium high": 7,
}
CODE_TO_FAN = {value: key for key, value in FAN_TO_CODE.items()}

SWING_TO_CODE = {
    "auto up/down": 0,
    "position 1": 1,
    "position 2": 2,
    "position 3": 3,
    "position 4": 4,
    "position 5": 5,
    "position 6": 6,
    "off": 7,
}
CODE_TO_SWING = {value: key for key, value in SWING_TO_CODE.items()}

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_DEVICE_ID): cv.string,
        vol.Optional(CONF_CONFIG_ID, default=DEFAULT_CONFIG_ID): cv.string,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
        vol.Optional(CONF_PUBLIC_KEY, default=DEFAULT_PUBLIC_KEY_BASE64): cv.string,
    }
)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the AUX A+ climate platform from YAML."""
    api = AuxAPlusApi(
        account=config[CONF_USERNAME],
        password=config[CONF_PASSWORD],
        device_id=config[CONF_DEVICE_ID],
        config_id=config[CONF_CONFIG_ID],
        public_key_base64=config[CONF_PUBLIC_KEY],
    )
    add_entities([AuxAPlusClimate(api, config[CONF_NAME], config[CONF_DEVICE_ID])], True)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up the AUX A+ climate entity from a config entry."""
    data = entry.data
    name = entry.options.get(CONF_NAME, data.get(CONF_NAME, DEFAULT_NAME))
    api = AuxAPlusApi(
        account=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        device_id=data[CONF_DEVICE_ID],
        config_id=data.get(CONF_CONFIG_ID, DEFAULT_CONFIG_ID),
        public_key_base64=data.get(CONF_PUBLIC_KEY, DEFAULT_PUBLIC_KEY_BASE64),
    )
    async_add_entities([AuxAPlusClimate(api, name, data[CONF_DEVICE_ID])], True)


class AuxAPlusClimate(ClimateEntity):
    """Representation of one AUX A+ air conditioner."""

    _attr_has_entity_name = False
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_min_temp = 16
    _attr_max_temp = 30
    _attr_target_temperature_step = 1
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.SWING_MODE
        | ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
    )
    _attr_hvac_modes = [
        HVACMode.OFF,
        HVACMode.AUTO,
        HVACMode.COOL,
        HVACMode.DRY,
        HVACMode.HEAT,
        HVACMode.FAN_ONLY,
    ]
    _attr_fan_modes = list(FAN_TO_CODE.keys())
    _attr_swing_modes = list(SWING_TO_CODE.keys())

    def __init__(self, api: AuxAPlusApi, name: str, device_id: str) -> None:
        self.api = api
        self._attr_name = name
        self._attr_unique_id = f"aux_a_plus_{device_id}"
        self._available = False
        self._device: dict[str, Any] = {}
        self._state: dict[str, Any] = {}

    @property
    def available(self) -> bool:
        return self._available

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "online": self._device.get("online"),
            "device_id": self._device.get("deviceId"),
            "alias": self._device.get("alias"),
            "electric_heating": self._state.get("electric_heating"),
            "sleep_mode": self._state.get("sleep_mode"),
            "left_right_swing": self._state.get("left_right_swing"),
            "screen_on_off": self._state.get("screen_on_off"),
            "raw_state": self._state,
        }

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._attr_unique_id)},
            "name": self._device.get("alias") or self._attr_name,
            "manufacturer": "AUX / 奥克斯",
            "model": self._device.get("modelId") or "AUX A+ AC",
            "sw_version": self._device.get("wifi_soft_version"),
            "hw_version": self._device.get("wifi_hard_version"),
        }

    @property
    def hvac_mode(self) -> HVACMode:
        if int(self._state.get("on_off", 0) or 0) == 0:
            return HVACMode.OFF
        return MODE_TO_HVAC.get(int(self._state.get("air_con_func", 1) or 1), HVACMode.COOL)

    @property
    def target_temperature(self) -> float | None:
        temp = self._state.get("temperature")
        if temp is None:
            return None
        try:
            # Status uses whole Celsius degrees; control uses Celsius * 10.
            return float(temp) + float(self._state.get("temperature_decimal", 0) or 0) / 10.0
        except (TypeError, ValueError):
            return None

    @property
    def current_temperature(self) -> float | None:
        for key in ("room_temperature", "indoor_temperature", "indoor_temp", "room_temp"):
            temp = self._state.get(key)
            if temp is not None:
                return self._as_float(temp)
        # Captured AUX A+ traffic exposes room temperature as top-level dataOne
        # when feature.roomTempDisplay is enabled.
        return self._as_float(self._device.get("dataOne"))

    @property
    def fan_mode(self) -> str | None:
        # Captured status uses wind_speed_1; captured control sends wind_speed.
        code = self._state.get("wind_speed_1", self._state.get("wind_speed"))
        try:
            return CODE_TO_FAN.get(int(code))
        except (TypeError, ValueError):
            return None

    @property
    def swing_mode(self) -> str | None:
        code = self._state.get("up_down_swing")
        try:
            return CODE_TO_SWING.get(int(code))
        except (TypeError, ValueError):
            return None

    def update(self) -> None:
        try:
            device = self.api.get_device()
            self._device = device
            self._state = device.get("data") or {}
            self._available = bool(device.get("online", True))
            _LOGGER.debug("AUX A+ state updated: %s", self._state)
        except AuxAPlusApiError as err:
            self._available = False
            _LOGGER.warning("AUX A+ update failed: %s", err)
        except Exception as err:  # noqa: BLE001 - keep entity alive and log useful info.
            self._available = False
            _LOGGER.exception("Unexpected AUX A+ update error: %s", err)

    def turn_on(self) -> None:
        self.api.control({"on_off": 1}, v2=True)
        self.update()

    def turn_off(self) -> None:
        self.api.control({"on_off": 0}, v2=True)
        self.update()

    def set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        if hvac_mode == HVACMode.OFF:
            self.turn_off()
            return
        if self.hvac_mode == HVACMode.OFF:
            self.api.control({"on_off": 1}, v2=True)
        mode = HVAC_TO_MODE.get(hvac_mode)
        if mode is not None:
            self.api.control({"air_con_func": mode}, v2=False)
        self.update()

    def set_temperature(self, **kwargs: Any) -> None:
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            return
        self.api.control({"temperature": int(round(float(temperature) * 10))}, v2=False)
        self.update()

    def set_fan_mode(self, fan_mode: str) -> None:
        code = FAN_TO_CODE.get(fan_mode)
        if code is None:
            raise ValueError(f"Unsupported AUX A+ fan mode: {fan_mode}")
        self.api.control({"wind_speed": code}, v2=False)
        self.update()

    def set_swing_mode(self, swing_mode: str) -> None:
        code = SWING_TO_CODE.get(swing_mode)
        if code is None:
            raise ValueError(f"Unsupported AUX A+ swing mode: {swing_mode}")
        self.api.control({"up_down_swing": code}, v2=False)
        self.update()

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
