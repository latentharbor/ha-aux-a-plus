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
from homeassistant.const import CONF_NAME, UnitOfEnergy, UnitOfTime

from .api import AuxAPlusApi, AuxAPlusApiError
from .const import (
    CONF_DEVICE_ID,
    DEFAULT_NAME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=60)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up AUX A+ sensors from a config entry."""
    data = entry.data
    name = entry.options.get(CONF_NAME, data.get(CONF_NAME, DEFAULT_NAME))
    api = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            AuxAPlusDailySensor(api, name, data[CONF_DEVICE_ID], "today_runtime"),
            AuxAPlusDailySensor(api, name, data[CONF_DEVICE_ID], "today_energy"),
        ],
        True,
    )


class AuxAPlusDailySensor(SensorEntity):
    """Expose daily AUX A+ usage values."""

    _attr_has_entity_name = True

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
        if kind == "today_runtime":
            self._attr_name = "今日运行时间"
            self._attr_suggested_object_id = "aux_today_runtime"
            self._attr_device_class = SensorDeviceClass.DURATION
            self._attr_native_unit_of_measurement = UnitOfTime.HOURS
            self._attr_state_class = SensorStateClass.MEASUREMENT
            self._api_key = "todayUseTime"
        else:
            self._attr_name = "今日耗电量"
            self._attr_suggested_object_id = "aux_today_energy"
            self._attr_device_class = SensorDeviceClass.ENERGY
            self._attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
            self._attr_state_class = SensorStateClass.TOTAL_INCREASING
            self._api_key = "todayElectricityConsumption"
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
            daily = self.api.get_daily_electricity()
            self._raw = daily.get(self._api_key)
            self._value = self._as_float(self._raw)
            self._available = True
        except AuxAPlusApiError as err:
            self._available = False
            _LOGGER.warning("AUX A+ %s sensor update failed: %s", self.kind, err)
        except Exception as err:  # noqa: BLE001
            self._available = False
            _LOGGER.exception("Unexpected AUX A+ %s sensor update error: %s", self.kind, err)

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
