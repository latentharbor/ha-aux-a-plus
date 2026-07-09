"""Small AUX A+ cloud API client for the newer smarthome.aux-home.com API."""
from __future__ import annotations

import base64
import logging
import time
from typing import Any

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from .const import APP_VERSION, BASE_URL, DEFAULT_PUBLIC_KEY_BASE64, OS_VERSION, USER_AGENT

_LOGGER = logging.getLogger(__name__)


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
        for device in self.list_devices():
            if device.get("deviceId") == self.device_id or device.get("did") == self.device_id:
                return device
        raise AuxAPlusApiError(f"Device {self.device_id} not found in device_bindings")

    def control(self, intent: dict[str, Any], *, v2: bool = False) -> dict[str, Any]:
        self.ensure_login()
        path = "/app/device/v2/control" if v2 else "/app/device/control"
        payload: dict[str, Any] = {
            "intent": intent,
            "dst": 1,
            "type": "app",
            "deviceId": self.device_id,
        }
        if v2:
            payload["needControl"] = True
        if self.uid:
            payload["uid"] = self.uid
        if self.nickname:
            payload["nickName"] = self.nickname
        url = f"{BASE_URL}{path}"
        _LOGGER.debug("AUX A+ control %s payload=%s", path, payload)
        resp = self.session.post(url, json=payload, headers=self._headers(auth=True, json_content=True), timeout=self.timeout)
        data = self._json_or_raise(resp)
        if not self._is_success(data, allow_missing_code=True):
            # Some AUX control endpoints return code/message, some may return empty-ish success.
            _LOGGER.warning("AUX A+ control returned non-200 response: %s", self._summarize_response(data))
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
