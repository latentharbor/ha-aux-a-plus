"""Sensor platform for AUX A+ Air Conditioner."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity
try:
    from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
except ImportError:  # Older HA compatibility
    from homeassistant.components.sensor.const import SensorDeviceClass, SensorStateClass
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME, PERCENTAGE, UnitOfTemperature

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
    """Set up AUX A+ sensors from a config entry."""
    data = entry.data
    name = entry.options.get(CONF_NAME, data.get(CONF_NAME, DEFAULT_NAME))
    api = AuxAPlusApi(
        account=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        device_id=data[CONF_DEVICE_ID],
        config_id=data.get(CONF_CONFIG_ID, DEFAULT_CONFIG_ID),
        public_key_base64=data.get(CONF_PUBLIC_KEY, DEFAULT_PUBLIC_KEY_BASE64),
    )
    async_add_entities(
        [
            AuxAPlusValueSensor(api, name, data[CONF_DEVICE_ID], "indoor_temperature"),
            AuxAPlusValueSensor(api, name, data[CONF_DEVICE_ID], "indoor_humidity"),
        ],
        True,
    )


class AuxAPlusValueSensor(SensorEntity):
    """Expose measured AUX A+ values as separate Home Assistant sensors."""

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, api: AuxAPlusApi, name: str, device_id: str, kind: str) -> None:
        self.api = api
        self.kind = kind
        self._device_id = device_id
        self._attr_unique_id = f"aux_a_plus_{device_id}_{kind}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"aux_a_plus_{device_id}")},
            "name": name,
            "manufacturer": "AUX / 奥克斯",
        }
        if kind == "indoor_temperature":
            self._attr_name = "室内温度"
            self._attr_device_class = SensorDeviceClass.TEMPERATURE
            self._attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
        else:
            self._attr_name = "室内湿度"
            self._attr_device_class = SensorDeviceClass.HUMIDITY
            self._attr_native_unit_of_measurement = PERCENTAGE
        self._available = False
        self._value: float | None = None
        self._raw: Any = None

    @property
    def available(self) -> bool:
        return self._available and self._value is not None

    @property
    def native_value(self) -> float | None:
        return self._value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"raw_value": self._raw}

    def update(self) -> None:
        try:
            device = self.api.get_device()
            state = device.get("data") or {}
            self._raw = self._extract_raw_value(device, state)
            self._value = self._as_float(self._raw)
            self._available = bool(device.get("online", True))
        except AuxAPlusApiError as err:
            self._available = False
            _LOGGER.warning("AUX A+ %s sensor update failed: %s", self.kind, err)
        except Exception as err:  # noqa: BLE001
            self._available = False
            _LOGGER.exception("Unexpected AUX A+ %s sensor update error: %s", self.kind, err)

    def _extract_raw_value(self, device: dict[str, Any], state: dict[str, Any]) -> Any:
        if self.kind == "indoor_temperature":
            return self._first_present(
                state,
                device,
                (
                    "room_temperature",
                    "indoor_temperature",
                    "indoor_temp",
                    "room_temp",
                    "dataOne",
                ),
            )
        return self._first_present(
            state,
            device,
            (
                "room_humidity",
                "indoor_humidity",
                "indoorHumidity",
                "humidity",
                "relative_humidity",
            ),
        )

    @staticmethod
    def _first_present(state: dict[str, Any], device: dict[str, Any], keys: tuple[str, ...]) -> Any:
        for key in keys:
            if key in state and state[key] not in (None, ""):
                return state[key]
            if key in device and device[key] not in (None, ""):
                return device[key]
        return None

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
