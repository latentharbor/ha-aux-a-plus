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
from homeassistant.const import (
    CONF_NAME,
    UnitOfEnergy,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

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
            AuxAPlusTemperatureSensor(api, name, data[CONF_DEVICE_ID]),
            AuxAPlusDailySensor(api, name, data[CONF_DEVICE_ID], "today_runtime"),
            AuxAPlusDailySensor(api, name, data[CONF_DEVICE_ID], "today_energy"),
            AuxAPlusTotalEnergySensor(api, name, data[CONF_DEVICE_ID]),
        ],
        True,
    )


class AuxAPlusTemperatureSensor(SensorEntity):
    """Expose the indoor temperature reported by the air conditioner."""

    _attr_has_entity_name = True
    _attr_name = "室内温度"
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_object_id = "aux_indoor_temperature"

    def __init__(self, api: AuxAPlusApi, name: str, device_id: str) -> None:
        self.api = api
        self._attr_unique_id = f"aux_a_plus_{device_id}_indoor_temperature"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"aux_a_plus_{device_id}")},
            "name": name,
            "manufacturer": "AUX / 奥克斯",
        }
        self._available = False
        self._value: float | None = None

    async def async_added_to_hass(self) -> None:
        """Subscribe to live temperature updates."""
        await super().async_added_to_hass()
        self.async_on_remove(self.api.add_state_listener(self._state_updated))

    def _state_updated(self) -> None:
        self.hass.loop.call_soon_threadsafe(self._schedule_update)

    @callback
    def _schedule_update(self) -> None:
        self.schedule_update_ha_state(force_refresh=True)

    @property
    def available(self) -> bool:
        return self._available and self._value is not None

    @property
    def native_value(self) -> float | None:
        return self._value

    def update(self) -> None:
        try:
            temperatures = self.api.get_realtime_temperatures()
            self._value = self._as_float(temperatures.get("indoor_temperature"))
            self._available = self._value is not None
        except AuxAPlusApiError as err:
            self._available = False
            _LOGGER.warning("AUX A+ indoor temperature update failed: %s", err)
        except Exception as err:  # noqa: BLE001
            self._available = False
            _LOGGER.exception(
                "Unexpected AUX A+ indoor temperature update error: %s", err
            )

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None


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


class AuxAPlusTotalEnergySensor(SensorEntity, RestoreEntity):
    """Accumulate the daily energy counter into a persistent total."""

    _attr_has_entity_name = True
    _attr_name = "累计耗电量"
    _attr_suggested_object_id = "aux_total_energy"
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    def __init__(self, api: AuxAPlusApi, name: str, device_id: str) -> None:
        self.api = api
        self._attr_unique_id = f"aux_a_plus_{device_id}_total_energy"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"aux_a_plus_{device_id}")},
            "name": name,
            "manufacturer": "AUX / 奥克斯",
        }
        self._available = False
        self._value: float | None = None
        self._last_daily_energy: float | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the accumulated total and the last daily counter."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is None:
            return

        self._value = self._as_float(
            last_state.attributes.get("accumulated_energy", last_state.state)
        )
        self._last_daily_energy = self._as_float(
            last_state.attributes.get("source_daily_energy")
        )

    @property
    def available(self) -> bool:
        return self._available and self._value is not None

    @property
    def native_value(self) -> float | None:
        return self._value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "accumulated_energy": self._value,
            "source_daily_energy": self._last_daily_energy,
        }

    def update(self) -> None:
        try:
            daily = self.api.get_daily_electricity()
            current_daily = self._as_float(daily.get("todayElectricityConsumption"))
            if current_daily is None:
                self._available = False
                return

            self._value, self._last_daily_energy = self._accumulate(
                self._value,
                self._last_daily_energy,
                current_daily,
            )
            self._available = True
        except AuxAPlusApiError as err:
            self._available = False
            _LOGGER.warning("AUX A+ total energy sensor update failed: %s", err)
        except Exception as err:  # noqa: BLE001
            self._available = False
            _LOGGER.exception(
                "Unexpected AUX A+ total energy sensor update error: %s", err
            )

    @staticmethod
    def _accumulate(
        total: float | None,
        previous_daily: float | None,
        current_daily: float,
    ) -> tuple[float, float]:
        """Return a cumulative total from the API's daily-resetting counter."""
        if total is None or previous_daily is None:
            return current_daily, current_daily

        if current_daily >= previous_daily:
            return round(total + (current_daily - previous_daily), 6), current_daily

        # The daily counter reset at midnight. Include today's current value.
        return round(total + current_daily, 6), current_daily

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value in (None, "", "unknown", "unavailable"):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
