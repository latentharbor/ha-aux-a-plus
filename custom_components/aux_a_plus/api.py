"""Small AUX A+ cloud API client for the newer smarthome.aux-home.com API."""
from __future__ import annotations

import base64
import logging
import threading
import time
from typing import Any

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from .const import APP_VERSION, BASE_URL, DEFAULT_PUBLIC_KEY_BASE64, OS_VERSION, USER_AGENT
from .mqtt import AuxMqttAuthError, AuxMqttError, control_device, query_temperatures

_LOGGER = logging.getLogger(__name__)

CONTROL_STATE_GRACE_SECONDS = 90
CONTROL_DEDUP_SECONDS = 3


class AuxAPlusApiError(Exception):
    """Raised when AUX A+ API returns an error."""


class AuxAPlusApi:
    """A minimal client for the newer AUX A+ API."""

    def __init__(
        self,
        account: str,
        password: str,
        device_id: str,
        config_id: str,
        public_key_base64: str = DEFAULT_PUBLIC_KEY_BASE64,
        timeout: int = 12,
    ) -> None:
        self.account = account
        self.password = password
        self.device_id = device_id
        self.config_id = config_id
        self.public_key_base64 = public_key_base64
        self.timeout = timeout
        self.session = requests.Session()
        self.token: str | None = None
        self.token_expire_at: int = 0
        self.uid: str | None = None
        self.nickname: str | None = None
        self._request_lock = threading.RLock()
        self._cached_device: dict[str, Any] | None = None
        self._device_cache_at = 0.0
        self._device_last_attempt_at = 0.0
        self._force_device_refresh = False
        self._cached_daily_electricity: dict[str, Any] | None = None
        self._daily_electricity_cache_at = 0.0
        self._cached_temperatures: dict[str, float] | None = None
        self._temperature_cache_at = 0.0
        self._mqtt_sequence = 0
        self._pending_control_state: dict[str, Any] = {}
        self._pending_control_until = 0.0
        self._last_control_intent: dict[str, Any] | None = None
        self._last_control_at = 0.0

    def _now_ms(self) -> str:
        return str(int(time.time() * 1000))

    def _headers(self, *, auth: bool = True, json_content: bool = False) -> dict[str, str]:
        headers = {
            "timestamp": self._now_ms(),
            "AppVersion": APP_VERSION,
            "Accept": "*/*",
            "Accept-Language": "zh-Hans-CN;q=1, en;q=0.9",
            "User-Agent": USER_AGENT,
            "os_version": OS_VERSION,
        }
        if json_content:
            headers["Content-Type"] = "application/json"
        if auth and self.token:
            headers["Authorization"] = f"bearer {self.token}"
        return headers

    def _encrypt_password(self, ts: str) -> str:
        # The captured app request sends password, account, ts and publicKeyBase64.
        # In AUX A+ 7.2.4 the password field is RSA/PKCS#1 v1.5 encrypted with this public key.
        public_key = RSA.import_key(base64.b64decode(self.public_key_base64))
        cipher = PKCS1_v1_5.new(public_key)
        encrypted = cipher.encrypt(self.password.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")

    def get_public_key(self) -> str:
        """Fetch the current login public key.

        AUX expires login public keys, so using a key captured from old traffic can
        fail with code 64033 ("public key expired").
        """
        url = f"{BASE_URL}/app/auth/getPubkey"
        _LOGGER.debug("AUX A+ get public key: %s", url)
        resp = self.session.get(url, headers=self._headers(auth=False), timeout=self.timeout)
        data = self._json_or_raise(resp)
        if not self._is_success(data):
            raise AuxAPlusApiError(f"Get public key failed: {self._summarize_response(data)}")
        public_key = data.get("data")
        if not isinstance(public_key, str) or not public_key:
            raise AuxAPlusApiError(f"Get public key returned unexpected payload: {self._summarize_response(data)}")
        return public_key

    def login(self) -> None:
        ts = self._now_ms()
        self.public_key_base64 = self.get_public_key()
        payload = {
            "password": self._encrypt_password(ts),
            "account": self.account,
            "ts": ts,
            "publicKeyBase64": self.public_key_base64,
        }
        url = f"{BASE_URL}/app/auth/login/pwd"
        _LOGGER.debug("AUX A+ login: %s", url)
        resp = self.session.post(url, json=payload, headers=self._headers(auth=False, json_content=True), timeout=self.timeout)
        data = self._json_or_raise(resp)
        if not self._is_success(data):
            raise AuxAPlusApiError(f"Login failed: {self._summarize_response(data)}")
        root = data.get("data") or {}
        user = root.get("appUser") or {}
        token_info = root.get("openApiToken") or {}
        token = token_info.get("token") or root.get("token") or data.get("token")
        if not token:
            raise AuxAPlusApiError(f"Login succeeded but token missing: {self._summarize_response(data)}")
        self.token = token
        self.token_expire_at = int(token_info.get("expireAt") or 0)
        self.uid = user.get("uid")
        self.nickname = user.get("realName") or user.get("phone") or self.account
        _LOGGER.debug("AUX A+ login ok; expireAt=%s", self.token_expire_at)

    def ensure_login(self) -> None:
        # Refresh a little before expiry. expireAt is seconds-since-epoch in captured traffic.
        if not self.token or (self.token_expire_at and time.time() > self.token_expire_at - 3600):
            self.login()

    def list_devices(self) -> list[dict[str, Any]]:
        """Return bound devices with current status."""
        self.ensure_login()
        url = f"{BASE_URL}/app/device_bindings"
        params = {"configId": self.config_id, "getStatus": "1"}
        resp = self.session.get(url, params=params, headers=self._headers(auth=True), timeout=self.timeout)
        data = self._json_or_raise(resp)
        if not self._is_success(data):
            # Token may have been invalidated by another login.
            _LOGGER.debug("AUX A+ device list failed once, retrying login: %s", self._summarize_response(data))
            self.login()
            resp = self.session.get(url, params=params, headers=self._headers(auth=True), timeout=self.timeout)
            data = self._json_or_raise(resp)
        if not self._is_success(data):
            raise AuxAPlusApiError(f"Device list failed: {self._summarize_response(data)}")
        devices = self._extract_device_list(data)
        if not isinstance(devices, list):
            raise AuxAPlusApiError(f"Device list returned unexpected payload: {self._summarize_response(data)}")
        return devices

    def get_device(self) -> dict[str, Any]:
        """Return the configured device from the device bindings endpoint."""
        with self._request_lock:
            now = time.monotonic()
            if (
                self._cached_device is not None
                and not self._force_device_refresh
                and now - self._device_last_attempt_at < 20
            ):
                return self._cached_device

            self._device_last_attempt_at = now
            try:
                for device in self.list_devices():
                    if device.get("deviceId") == self.device_id or device.get("did") == self.device_id:
                        self._merge_pending_control_state(device, now)
                        self._cached_device = device
                        self._device_cache_at = now
                        self._force_device_refresh = False
                        return device
                raise AuxAPlusApiError(f"Device {self.device_id} not found in device_bindings")
            except AuxAPlusApiError:
                # Keep entities stable through brief AUX cloud/token failures.
                if self._cached_device is not None and now - self._device_cache_at < 300:
                    self._force_device_refresh = False
                    _LOGGER.warning("AUX A+ refresh failed; using the last successful device state")
                    return self._cached_device
                raise

    def control(self, intent: dict[str, Any], *, v2: bool = False) -> dict[str, Any]:
        with self._request_lock:
            now = time.monotonic()
            if self._intent_matches_cached_state(intent):
                return {"code": 200, "message": "Control state already applied"}
            if (
                self._last_control_intent == intent
                and now - self._last_control_at < CONTROL_DEDUP_SECONDS
            ):
                self._record_control_state(intent, now)
                self._last_control_at = now
                return {"code": 200, "message": "Duplicate control suppressed"}

            try:
                result = self._control_mqtt(intent)
            except AuxMqttError as err:
                _LOGGER.warning(
                    "AUX MQTT control failed; falling back to HTTP control: %s", err
                )
                if "on_off" in intent and len(intent) > 1:
                    self._control({"on_off": intent["on_off"]}, v2=True)
                    remaining = {
                        key: value
                        for key, value in intent.items()
                        if key != "on_off"
                    }
                    result = self._control(remaining, v2=False)
                else:
                    result = self._control(intent, v2=v2)
            self._record_control_state(intent, now)
            self._last_control_intent = dict(intent)
            self._last_control_at = now
            return result

    def _record_control_state(self, intent: dict[str, Any], now: float) -> None:
        state = self._state_from_intent(intent)
        self._pending_control_state.update(state)
        self._pending_control_until = now + CONTROL_STATE_GRACE_SECONDS
        self._force_device_refresh = False
        self._device_last_attempt_at = now

        if self._cached_device is not None:
            cached_state = self._cached_device.get("data")
            if not isinstance(cached_state, dict):
                cached_state = {}
            self._cached_device["data"] = cached_state
            cached_state.update(state)
            self._device_cache_at = now

    def _intent_matches_cached_state(self, intent: dict[str, Any]) -> bool:
        if self._cached_device is None:
            return False
        state = self._cached_device.get("data")
        if not isinstance(state, dict):
            return False

        for key in ("on_off", "air_con_func", "up_down_swing", "left_right_swing"):
            if key in intent and not self._state_values_equal(
                state.get(key), intent[key]
            ):
                return False

        if "wind_speed" in intent:
            current_fan = state.get("wind_speed_1", state.get("wind_speed"))
            if not self._state_values_equal(current_fan, intent["wind_speed"]):
                return False

        if "temperature" in intent:
            whole = state.get("temperature")
            if whole in (None, ""):
                return False
            try:
                fraction = 0.5 if int(state.get("half", 0) or 0) == 1 else 0.0
                if not fraction:
                    fraction = float(state.get("temperature_decimal", 0) or 0) / 10.0
                current_target = float(whole) + fraction
                requested_target = float(intent["temperature"]) / 10.0
            except (TypeError, ValueError):
                return False
            if current_target != requested_target:
                return False

        return True

    def _merge_pending_control_state(
        self, device: dict[str, Any], now: float
    ) -> None:
        if not self._pending_control_state:
            return
        if now >= self._pending_control_until:
            self._pending_control_state.clear()
            return

        state = device.get("data")
        if not isinstance(state, dict):
            state = {}
            device["data"] = state

        confirmed: list[str] = []
        for key, expected in self._pending_control_state.items():
            if self._state_values_equal(state.get(key), expected):
                confirmed.append(key)
            else:
                state[key] = expected
        for key in confirmed:
            self._pending_control_state.pop(key, None)
        if not self._pending_control_state:
            self._pending_control_until = 0.0

    @staticmethod
    def _state_from_intent(intent: dict[str, Any]) -> dict[str, Any]:
        state: dict[str, Any] = {}
        for key in ("on_off", "air_con_func", "up_down_swing", "left_right_swing"):
            if key in intent:
                state[key] = int(intent[key])

        if "wind_speed" in intent:
            state["wind_speed"] = int(intent["wind_speed"])
            state["wind_speed_1"] = int(intent["wind_speed"])

        if "temperature" in intent:
            target = float(intent["temperature"]) / 10.0
            whole = int(target)
            fraction = int(round((target - whole) * 10))
            state["temperature"] = whole
            state["half"] = 1 if fraction == 5 else 0
            state["temperature_decimal"] = fraction
        return state

    @staticmethod
    def _state_values_equal(actual: Any, expected: Any) -> bool:
        if actual in (None, ""):
            return False
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return actual == expected

    def _control_mqtt(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.ensure_login()
        if not self.uid or not self.token:
            raise AuxAPlusApiError("Login succeeded but MQTT credentials are missing")

        self._mqtt_sequence = (self._mqtt_sequence + 2) & 0xFFFF
        try:
            control_device(
                uid=str(self.uid),
                token=self.token,
                device_id=self.device_id,
                app_id=self.config_id,
                sequence=self._mqtt_sequence,
                intent=intent,
                timeout=self.timeout,
            )
        except AuxMqttAuthError:
            self.login()
            if not self.uid or not self.token:
                raise AuxAPlusApiError(
                    "Login succeeded but MQTT credentials are missing"
                )
            control_device(
                uid=str(self.uid),
                token=self.token,
                device_id=self.device_id,
                app_id=self.config_id,
                sequence=self._mqtt_sequence,
                intent=intent,
                timeout=self.timeout,
            )
        return {"code": 200, "message": "MQTT control acknowledged"}

    def get_daily_electricity(self) -> dict[str, Any]:
        """Return today's runtime and electricity consumption."""
        with self._request_lock:
            now = time.monotonic()
            if (
                self._cached_daily_electricity is not None
                and now - self._daily_electricity_cache_at < 50
            ):
                return self._cached_daily_electricity

            try:
                self.ensure_login()
                url = f"{BASE_URL}/app/daily/electricity"
                params = {"deviceId": self.device_id}
                resp = self.session.get(
                    url,
                    params=params,
                    headers=self._headers(auth=True),
                    timeout=self.timeout,
                )
                data = self._json_or_raise(resp)
                if not self._is_success(data):
                    self.login()
                    resp = self.session.get(
                        url,
                        params=params,
                        headers=self._headers(auth=True),
                        timeout=self.timeout,
                    )
                    data = self._json_or_raise(resp)
                if not self._is_success(data):
                    raise AuxAPlusApiError(
                        f"Daily electricity failed: {self._summarize_response(data)}"
                    )
                result = data.get("data")
                if not isinstance(result, dict):
                    raise AuxAPlusApiError(
                        "Daily electricity returned unexpected payload: "
                        f"{self._summarize_response(data)}"
                    )
                self._cached_daily_electricity = result
                self._daily_electricity_cache_at = now
                return result
            except AuxAPlusApiError:
                if (
                    self._cached_daily_electricity is not None
                    and now - self._daily_electricity_cache_at < 300
                ):
                    _LOGGER.warning(
                        "AUX A+ daily electricity refresh failed; using the last successful data"
                    )
                    return self._cached_daily_electricity
                raise

    def get_realtime_temperatures(self) -> dict[str, float]:
        """Return indoor-unit temperatures from the AUX MQTT status channel."""
        with self._request_lock:
            now = time.monotonic()
            if (
                self._cached_temperatures is not None
                and now - self._temperature_cache_at < 25
            ):
                return self._cached_temperatures

            try:
                self.ensure_login()
                if not self.uid or not self.token:
                    raise AuxAPlusApiError("Login succeeded but MQTT credentials are missing")

                self._mqtt_sequence = (self._mqtt_sequence + 1) & 0xFFFF
                try:
                    result = query_temperatures(
                        uid=str(self.uid),
                        token=self.token,
                        device_id=self.device_id,
                        app_id=self.config_id,
                        sequence=self._mqtt_sequence,
                        timeout=self.timeout,
                    )
                except AuxMqttAuthError:
                    self.login()
                    if not self.uid or not self.token:
                        raise AuxAPlusApiError(
                            "Login succeeded but MQTT credentials are missing"
                        )
                    result = query_temperatures(
                        uid=str(self.uid),
                        token=self.token,
                        device_id=self.device_id,
                        app_id=self.config_id,
                        sequence=self._mqtt_sequence,
                        timeout=self.timeout,
                    )

                self._cached_temperatures = result
                self._temperature_cache_at = now
                return result
            except AuxMqttError as err:
                if (
                    self._cached_temperatures is not None
                    and now - self._temperature_cache_at < 300
                ):
                    _LOGGER.warning(
                        "AUX MQTT temperature refresh failed; using the last successful data"
                    )
                    return self._cached_temperatures
                raise AuxAPlusApiError(str(err)) from err

    def _control(self, intent: dict[str, Any], *, v2: bool = False) -> dict[str, Any]:
        """Send a control command while the caller holds the request lock."""
        self.ensure_login()
        path = "/app/device/v2/control" if v2 else "/app/device/control"
        payload: dict[str, Any] = {
            "intent": intent,
            "dst": 1,
            "type": "app",
            "deviceId": self.device_id,
            "did": self.device_id,
        }
        if v2:
            payload["needControl"] = True
        else:
            payload["needControl"] = False
        if self.uid:
            payload["uid"] = self.uid
        if self.nickname:
            payload["nickName"] = self.nickname
        url = f"{BASE_URL}{path}"
        _LOGGER.debug("AUX A+ control %s payload=%s", path, payload)
        resp = self.session.post(
            url,
            json=payload,
            headers=self._headers(auth=True, json_content=True),
            timeout=self.timeout,
        )
        data = self._json_or_raise(resp)
        if not self._is_success(data, allow_missing_code=True):
            self.login()
            resp = self.session.post(
                url,
                json=payload,
                headers=self._headers(auth=True, json_content=True),
                timeout=self.timeout,
            )
            data = self._json_or_raise(resp)
        if not self._is_success(data, allow_missing_code=True):
            raise AuxAPlusApiError(
                f"Control failed: {self._summarize_response(data)}"
            )
        return data

    @staticmethod
    def _json_or_raise(resp: requests.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except Exception as err:
            raise AuxAPlusApiError(f"HTTP {resp.status_code}: non-JSON response: {resp.text[:300]}") from err
        if resp.status_code >= 400:
            raise AuxAPlusApiError(f"HTTP {resp.status_code}: {data}")
        return data

    @staticmethod
    def _is_success(data: dict[str, Any], *, allow_missing_code: bool = False) -> bool:
        code = data.get("code")
        if code is None:
            return allow_missing_code
        return str(code) in {"0", "200"}

    @staticmethod
    def _extract_device_list(data: dict[str, Any]) -> Any:
        root = data.get("data") or []
        if isinstance(root, list):
            return root
        if isinstance(root, dict):
            for key in ("list", "records", "rows", "devices", "deviceBindings"):
                value = root.get(key)
                if isinstance(value, list):
                    return value
        return root

    @staticmethod
    def _summarize_response(data: dict[str, Any]) -> dict[str, Any]:
        """Return enough response detail for logs without leaking tokens."""
        summary: dict[str, Any] = {}
        for key in ("code", "msg", "message", "error", "error_description"):
            if key in data:
                summary[key] = data[key]
        root = data.get("data")
        if isinstance(root, dict):
            summary["data_keys"] = sorted(root.keys())
        elif isinstance(root, list):
            summary["data_len"] = len(root)
        return summary or {"keys": sorted(data.keys())}
