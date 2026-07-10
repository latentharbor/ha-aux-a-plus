"""Persistent local AUXLink client for AUX A+ air conditioners."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
import secrets
import socket
import struct
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .mqtt import (
    AuxMqttError,
    _BIG_STATUS_QUERY,
    _SMALL_STATUS_QUERY_BODY,
    _apply_control_intent,
    _decode_big_body,
    _decode_small_state,
    _inner_command,
)


LAN_PORT = 12416
DISCOVERY_PORT = 12414
DISCOVERY_REPLY_PORT = 2415
DISCOVERY_QUERY = bytes.fromhex("a5a50a000200000028ab")
PASSCODE_QUERY = bytes.fromhex("a5a50a00050000007986")
HEARTBEAT_SECONDS = 4.0
STATUS_REFRESH_SECONDS = 10.0

_LOGGER = logging.getLogger(__name__)


class AuxLanError(Exception):
    """Raised when an AUXLink LAN operation fails."""


class AuxLanClient:
    """Maintain one authenticated local connection to an AUX device."""

    def __init__(
        self,
        *,
        device_id: str,
        host: str | None = None,
        timeout: float = 12,
        on_update: Callable[[dict[str, object], dict[str, float]], None] | None = None,
    ) -> None:
        self.device_id = device_id
        self.host = host
        self.timeout = timeout
        self.on_update = on_update

        self._condition = threading.Condition(threading.RLock())
        self._send_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._connected_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None
        self._session_key: bytes | None = None
        self._mac: bytes | None = None
        self._passcode: bytes | None = None
        self._sequence = 0
        self._small_body: bytes | None = None
        self._state: dict[str, object] = {}
        self._temperatures: dict[str, float] = {}
        self._small_generation = 0
        self._big_generation = 0
        self._ack_generation = 0
        self._last_state_at = 0.0
        self._last_error: AuxLanError | None = None

    @property
    def connected(self) -> bool:
        return self._connected_event.is_set()

    @property
    def last_state_at(self) -> float:
        with self._condition:
            return self._last_state_at

    def start(self) -> None:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._last_error = None
            self._thread = threading.Thread(
                target=self._run,
                name=f"aux-lan-{self.device_id[-6:]}",
                daemon=True,
            )
            self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        with self._condition:
            sock = self._socket
            self._socket = None
            self._condition.notify_all()
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3)
        self._connected_event.clear()

    def snapshot(self) -> tuple[dict[str, object], dict[str, float]]:
        with self._condition:
            return dict(self._state), dict(self._temperatures)

    def configure_credentials(self, mac: str | bytes, passcode: str | bytes) -> None:
        """Set fixed local credentials returned by AUX cloud metadata."""
        try:
            mac_bytes = bytes.fromhex(mac) if isinstance(mac, str) else bytes(mac)
        except ValueError as err:
            raise AuxLanError("AUX cloud metadata returned an invalid MAC") from err
        passcode_bytes = passcode.encode("ascii") if isinstance(passcode, str) else bytes(passcode)
        if len(mac_bytes) != 6 or not passcode_bytes:
            raise AuxLanError("AUX cloud metadata returned invalid local credentials")
        with self._condition:
            self._mac = mac_bytes
            self._passcode = passcode_bytes

    def request_status(
        self, *, wait: bool = True
    ) -> tuple[dict[str, object], dict[str, float]]:
        self.start()
        self._wait_connected()
        with self._condition:
            small_generation = self._small_generation
        self._send_uart(_inner_command(_SMALL_STATUS_QUERY_BODY))
        self._send_uart(_BIG_STATUS_QUERY)
        if wait:
            deadline = time.monotonic() + self.timeout
            with self._condition:
                while self._small_generation == small_generation:
                    self._raise_if_unavailable()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AuxLanError("AUX LAN status query timed out")
                    self._condition.wait(remaining)
        return self.snapshot()

    def control(self, intent: dict[str, object]) -> dict[str, object]:
        self.start()
        self._wait_connected()
        if self._small_body is None or time.monotonic() - self.last_state_at > 10:
            self.request_status(wait=True)

        with self._condition:
            current = self._small_body
            ack_generation = self._ack_generation
        if current is None:
            raise AuxLanError("AUX LAN has no small status state")

        try:
            control_body = _apply_control_intent(current, intent)
        except AuxMqttError as err:
            raise AuxLanError(str(err)) from err
        if control_body[2:] == current[2:]:
            return dict(self._state)

        self._send_uart(_inner_command(control_body))
        deadline = time.monotonic() + self.timeout
        with self._condition:
            while self._ack_generation == ack_generation:
                self._raise_if_unavailable()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AuxLanError("AUX LAN control acknowledgement timed out")
                self._condition.wait(remaining)

            confirmed = bytearray(control_body)
            confirmed[1] = 0x11
            self._small_body = bytes(confirmed)
            self._state = _decode_small_state(self._small_body)
            self._last_state_at = time.monotonic()
            state = dict(self._state)
            temperatures = dict(self._temperatures)
        self._notify_update(state, temperatures)
        return state

    def _run(self) -> None:
        delay = 1.0
        while not self._stop_event.is_set():
            try:
                self._listen_once()
                delay = 1.0
            except (AuxLanError, OSError, TimeoutError, ValueError) as err:
                lan_error = err if isinstance(err, AuxLanError) else AuxLanError(str(err))
                with self._condition:
                    self._last_error = lan_error
                    self._condition.notify_all()
                _LOGGER.debug("AUX LAN connection unavailable: %s", err)
            finally:
                self._connected_event.clear()
                with self._condition:
                    sock = self._socket
                    self._socket = None
                    self._session_key = None
                    self._condition.notify_all()
                if sock is not None:
                    sock.close()
            self._stop_event.wait(delay)
            delay = min(delay * 2, 30.0)

    def _listen_once(self) -> None:
        with self._condition:
            mac = self._mac
        if mac is None:
            try:
                mac = bytes.fromhex(self.device_id[-12:])
            except ValueError as err:
                raise AuxLanError("AUX device ID does not contain a valid MAC") from err
            if len(mac) != 6:
                raise AuxLanError("AUX device ID does not contain a valid MAC")

        if self.host:
            host = _find_host_in_arp(mac) or self.host
            self.host = host
            _send_discovery_probe(host)
        else:
            host, discovered_mac = discover_device(
                self.device_id, timeout=min(self.timeout, 5)
            )
            if discovered_mac != mac:
                raise AuxLanError("AUX LAN discovery returned an unexpected MAC")
            self.host = host
        sock = socket.create_connection((host, LAN_PORT), timeout=self.timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.settimeout(self.timeout)
            session_key = self._authenticate(sock, mac)
        except Exception:
            sock.close()
            raise

        with self._condition:
            self._socket = sock
            self._session_key = session_key
            self._last_error = None
            self._connected_event.set()
            self._condition.notify_all()

        self._send_uart(_inner_command(_SMALL_STATUS_QUERY_BODY))
        self._send_uart(_BIG_STATUS_QUERY)
        last_heartbeat_at = time.monotonic()
        last_status_at = last_heartbeat_at
        sock.settimeout(1.0)
        while not self._stop_event.is_set():
            try:
                frame_type, _sequence, payload = _receive_frame(sock)
            except socket.timeout:
                now = time.monotonic()
                if now - last_heartbeat_at >= HEARTBEAT_SECONDS:
                    self._send_frame(0x0009, b"")
                    last_heartbeat_at = now
                if now - last_status_at >= STATUS_REFRESH_SECONDS:
                    self._send_uart(_inner_command(_SMALL_STATUS_QUERY_BODY))
                    self._send_uart(_BIG_STATUS_QUERY)
                    last_status_at = now
                continue
            if frame_type == 0x100B:
                self._process_uart(_decrypt(session_key, payload))
            elif frame_type == 0x1009:
                last_heartbeat_at = time.monotonic()
            elif frame_type == 0x1007:
                if _decrypt(session_key, payload) != b"ok":
                    raise AuxLanError("AUX LAN login was rejected")

    def _authenticate(self, sock: socket.socket, mac: bytes) -> bytes:
        with self._condition:
            passcode = self._passcode
        if passcode is None:
            sock.sendall(PASSCODE_QUERY)
            frame_type, _sequence, payload = _receive_frame(sock)
            if frame_type != 0x1005 or not payload:
                raise AuxLanError("AUX LAN returned an invalid passcode response")
            passcode_length = payload[0]
            if passcode_length == 0 or len(payload) < passcode_length + 1:
                raise AuxLanError("AUX LAN returned a truncated passcode")
            passcode = payload[1 : passcode_length + 1]
            with self._condition:
                self._passcode = passcode

        auth_key = hashlib.md5(passcode + mac).digest()
        session_key = secrets.token_bytes(16)
        auth_payload = _encrypt(auth_key, session_key) + hashlib.md5(session_key).digest()
        sock.sendall(_build_frame(0x0007, 0, auth_payload))

        # This AC firmware accepts authentication but omits the documented
        # 0x1007 "ok" response. Waiting briefly also preserves compatibility
        # with modules which do send the acknowledgement.
        sock.settimeout(2.0)
        try:
            frame_type, _sequence, payload = _receive_frame(sock)
        except socket.timeout:
            return session_key
        if frame_type != 0x1007 or _decrypt(session_key, payload) != b"ok":
            raise AuxLanError("AUX LAN login was rejected")
        return session_key

    def _process_uart(self, inner: bytes) -> None:
        if len(inner) < 10 or inner[0] != 0xBB:
            return
        body_length = inner[6]
        body = inner[8 : 8 + body_length]
        if len(body) < 2:
            return

        notify = False
        with self._condition:
            command = body[1]
            if command == 0x11 and len(body) >= 15:
                self._small_body = body[:15]
                state = _decode_small_state(self._small_body)
                notify = state != self._state
                self._state = state
                self._small_generation += 1
                self._last_state_at = time.monotonic()
            elif command in (0x21, 0x2C) and len(body) >= 24:
                temperatures = _decode_big_body(body)
                notify = temperatures != self._temperatures
                self._temperatures = temperatures
                self._big_generation += 1
            elif command == 0x01:
                self._ack_generation += 1
            state = dict(self._state)
            temperatures = dict(self._temperatures)
            self._condition.notify_all()
        if notify:
            self._notify_update(state, temperatures)

    def _send_uart(self, inner: bytes) -> None:
        with self._condition:
            session_key = self._session_key
        if session_key is None:
            raise AuxLanError("AUX LAN is not authenticated")
        self._send_frame(0x000B, _encrypt(session_key, inner))

    def _send_frame(self, frame_type: int, payload: bytes) -> None:
        with self._condition:
            sock = self._socket
            if frame_type == 0x0009:
                sequence = 0
            else:
                self._sequence = (self._sequence + 1) & 0xFFFF
                sequence = self._sequence
        if sock is None:
            raise AuxLanError("AUX LAN is disconnected")
        with self._send_lock:
            sock.sendall(_build_frame(frame_type, sequence, payload))

    def _wait_connected(self) -> None:
        deadline = time.monotonic() + self.timeout
        while not self._connected_event.wait(0.2):
            with self._condition:
                self._raise_if_unavailable()
            if time.monotonic() >= deadline:
                raise AuxLanError("AUX LAN connection timed out")

    def _raise_if_unavailable(self) -> None:
        if self._stop_event.is_set():
            raise AuxLanError("AUX LAN client is stopped")
        if self._last_error is not None and not self._connected_event.is_set():
            raise self._last_error

    def _notify_update(
        self, state: dict[str, object], temperatures: dict[str, float]
    ) -> None:
        if self.on_update is None:
            return
        try:
            self.on_update(state, temperatures)
        except Exception:  # noqa: BLE001 - callbacks must not stop the LAN thread.
            _LOGGER.exception("Unexpected AUX LAN update callback error")


def discover_device(device_id: str, *, timeout: float = 5) -> tuple[str, bytes]:
    """Discover an AUXLink device by DID and return its IP and MAC."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver.bind(("", DISCOVERY_REPLY_PORT))
        receiver.settimeout(timeout)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sender.sendto(DISCOVERY_QUERY, ("255.255.255.255", DISCOVERY_PORT))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            receiver.settimeout(max(0.1, deadline - time.monotonic()))
            data, address = receiver.recvfrom(512)
            parsed = _parse_discovery(data)
            if parsed is None:
                continue
            discovered_id, mac, secure_type = parsed
            if discovered_id == device_id and secure_type == 1:
                return address[0], mac
    except socket.timeout as err:
        raise AuxLanError(f"AUX LAN device {device_id} was not discovered") from err
    finally:
        receiver.close()
        sender.close()
    raise AuxLanError(f"AUX LAN device {device_id} was not discovered")


def _send_discovery_probe(host: str) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for target in (host, "255.255.255.255"):
            sender.sendto(DISCOVERY_QUERY, (target, DISCOVERY_PORT))
    finally:
        sender.close()
    time.sleep(0.2)


def _find_host_in_arp(mac: bytes) -> str | None:
    """Return a Linux ARP-cache address matching the device MAC."""
    arp_path = Path("/proc/net/arp")
    try:
        lines = arp_path.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return None
    expected = ":".join(f"{value:02x}" for value in mac)
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[3].lower() == expected:
            return fields[0]
    return None


def _parse_discovery(data: bytes) -> tuple[str, bytes, int] | None:
    try:
        frame_type, _sequence, payload = _parse_frame(data)
    except AuxLanError:
        return None
    if frame_type != 0x0003 or len(payload) < 9:
        return None
    secure_type = payload[0]
    mac_length = payload[7]
    mac_start = 8
    mac_end = mac_start + mac_length
    if mac_length != 6 or mac_end >= len(payload):
        return None
    did_length = payload[mac_end]
    did_start = mac_end + 1
    did_end = did_start + did_length
    if did_length == 0 or did_end > len(payload):
        return None
    try:
        device_id = payload[did_start:did_end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return device_id, payload[mac_start:mac_end], secure_type


def _encrypt(key: bytes, payload: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _decrypt(key: bytes, payload: bytes) -> bytes:
    if not payload or len(payload) % 16:
        raise AuxLanError("AUX LAN returned invalid encrypted data")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(payload) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as err:
        raise AuxLanError("AUX LAN returned invalid encrypted padding") from err


def _build_frame(frame_type: int, sequence: int, payload: bytes) -> bytes:
    prefix = (
        b"\xA5\xA5"
        + struct.pack("<H", len(payload) + 10)
        + struct.pack("<H", frame_type)
        + struct.pack("<H", sequence & 0xFFFF)
        + payload
    )
    return prefix + struct.pack("!H", _crc16_ccitt(prefix))


def _receive_frame(sock: socket.socket) -> tuple[int, int, bytes]:
    header = _read_exact(sock, 8)
    if header[:2] != b"\xA5\xA5":
        raise AuxLanError("AUX LAN returned invalid frame magic")
    total_length = struct.unpack("<H", header[2:4])[0]
    if total_length < 10 or total_length > 4096:
        raise AuxLanError("AUX LAN returned invalid frame length")
    return _parse_frame(header + _read_exact(sock, total_length - 8))


def _parse_frame(data: bytes) -> tuple[int, int, bytes]:
    if len(data) < 10 or data[:2] != b"\xA5\xA5":
        raise AuxLanError("AUX LAN frame is truncated")
    total_length, frame_type, sequence = struct.unpack("<HHH", data[2:8])
    if total_length != len(data):
        raise AuxLanError("AUX LAN frame length does not match")
    expected_crc = struct.unpack("!H", data[-2:])[0]
    if _crc16_ccitt(data[:-2]) != expected_crc:
        raise AuxLanError("AUX LAN frame checksum is invalid")
    return frame_type, sequence, data[8:-2]


def _read_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise AuxLanError("AUX LAN connection closed")
        result.extend(chunk)
    return bytes(result)


def _crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc
