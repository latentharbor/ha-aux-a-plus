"""Config flow for AUX A+ Air Conditioner."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback

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


class AuxAPlusConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle an AUX A+ config flow."""

    VERSION = 2

    def __init__(self) -> None:
        self._account_data: dict[str, Any] = {}
        self._devices: list[dict[str, Any]] = []

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Ask for AUX A+ account credentials and config id."""
        errors: dict[str, str] = {}

        if user_input is not None:
            account = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]
            config_id = user_input.get(CONF_CONFIG_ID, DEFAULT_CONFIG_ID)
            public_key = user_input.get(CONF_PUBLIC_KEY, DEFAULT_PUBLIC_KEY_BASE64)

            api = AuxAPlusApi(
                account=account,
                password=password,
                device_id="",
                config_id=config_id,
                public_key_base64=public_key,
            )

            try:
                devices = await self.hass.async_add_executor_job(api.list_devices)
            except AuxAPlusApiError as err:
                _LOGGER.warning("AUX A+ setup failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception as err:  # noqa: BLE001
                _LOGGER.exception("Unexpected AUX A+ setup error: %s", err)
                errors["base"] = "unknown"
            else:
                devices = [d for d in devices if d.get("deviceId") or d.get("did")]
                if not devices:
                    errors["base"] = "no_devices"
                else:
                    self._account_data = {
                        CONF_USERNAME: account,
                        CONF_PASSWORD: password,
                        CONF_CONFIG_ID: config_id,
                        CONF_PUBLIC_KEY: public_key,
                    }
                    self._devices = devices
                    if len(devices) == 1:
                        return await self._create_entry_from_device(devices[0])
                    return await self.async_step_select_device()

        schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_CONFIG_ID, default=DEFAULT_CONFIG_ID): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_select_device(self, user_input: dict[str, Any] | None = None):
        """Ask which bound AUX A+ device should be added."""
        errors: dict[str, str] = {}
        device_options = {
            self._device_id(device): self._device_label(device)
            for device in self._devices
            if self._device_id(device)
        }

        if user_input is not None:
            selected_device_id = user_input[CONF_DEVICE_ID]
            for device in self._devices:
                if self._device_id(device) == selected_device_id:
                    return await self._create_entry_from_device(device)
            errors["base"] = "device_not_found"

        schema = vol.Schema({vol.Required(CONF_DEVICE_ID): vol.In(device_options)})
        return self.async_show_form(step_id="select_device", data_schema=schema, errors=errors)

    async def _create_entry_from_device(self, device: dict[str, Any]):
        device_id = self._device_id(device)
        await self.async_set_unique_id(device_id)
        self._abort_if_unique_id_configured()

        alias = device.get("alias") or device.get("deviceName") or DEFAULT_NAME
        data = {
            **self._account_data,
            CONF_DEVICE_ID: device_id,
            CONF_NAME: alias,
        }
        return self.async_create_entry(title=alias, data=data)

    @staticmethod
    def _device_id(device: dict[str, Any]) -> str:
        return str(device.get("deviceId") or device.get("did") or "")

    @staticmethod
    def _device_label(device: dict[str, Any]) -> str:
        alias = device.get("alias") or device.get("deviceName") or DEFAULT_NAME
        device_id = AuxAPlusConfigFlow._device_id(device)
        online = "在线" if device.get("online") else "离线"
        return f"{alias} ({online}) - {device_id}"

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return AuxAPlusOptionsFlow(config_entry)


class AuxAPlusOptionsFlow(config_entries.OptionsFlow):
    """Options flow for AUX A+."""

    def __init__(self, config_entry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Allow adjusting display name."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        name = self.config_entry.options.get(CONF_NAME, self.config_entry.data.get(CONF_NAME, DEFAULT_NAME))
        schema = vol.Schema({vol.Optional(CONF_NAME, default=name): str})
        return self.async_show_form(step_id="init", data_schema=schema)
