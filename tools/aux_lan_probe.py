#!/usr/bin/env python3
"""Read AUX air-conditioner state through the local AUXLink protocol."""

from __future__ import annotations

import argparse
import hashlib
import secrets
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


MAGIC = b"\xA5\xA5"
PASSCODE_REQUEST = bytes.fromhex("a5a50a00050000007986")
SMALL_STATUS_QUERY = b"\x11\x01"

MODE_NAMES = {
    0: "auto",
    1: "cool",
    2: "dry",
    4: "heat",
    6: "fan_only",
}
FAN_NAMES = {
    0: "silent",
    1: "low",
    2: "medium",
    3: "high",
    4: "high",
    5: "turbo",
}
AUX_TO_MODE = {
    0x00: 0,
    0x20: 1,
    0x40: 2,
    0x80: 4,
    0xC0: 6,
}
AUX_TO_FAN = {
    0x20: 4,
    0x40: 2,
    0x60: 1,
    0xA0: 4,
}


class AuxLanError(Exception):
    """Raised when the local AUXLink exchange is invalid."""


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def inner_crc(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    checksum = sum(
        (data[index] << 8) | data[index + 1]
        for index in range(0, len(data), 2)
    )
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return (~checksum) & 0xFFFF


def build_frame(frame_type: int, sequence: int, payload: bytes) -> bytes:
    prefix = (
        MAGIC
        + struct.pack("<H", len(payload) + 10)
        + struct.pack("<H", frame_type)
        + struct.pack("<H", sequence & 0xFFFF)
        + payload
    )
    return prefix + struct.pack("!H", crc16_ccitt(prefix))


def build_inner_command(body: bytes) -> bytes:
    prefix = b"\xBB\x00\x06\x80\x00\x00" + bytes((len(body), 0)) + body
    return prefix + struct.pack("!H", inner_crc(prefix))


def encrypt(key: bytes, payload: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt(key: bytes, payload: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(payload) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as err:
        raise AuxLanError("device returned invalid encrypted data") from err


def read_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise AuxLanError("device closed the local connection")
        result.extend(chunk)
    return bytes(result)


def receive_frame(sock: socket.socket) -> tuple[int, int, bytes]:
    header = read_exact(sock, 8)
    if header[:2] != MAGIC:
        raise AuxLanError("device returned invalid frame magic")
    total_length, frame_type, sequence = struct.unpack("<HHH", header[2:8])
    if total_length < 10 or total_length > 4096:
        raise AuxLanError(f"device returned invalid frame length {total_length}")
    frame = header + read_exact(sock, total_length - len(header))
    expected_crc = struct.unpack("!H", frame[-2:])[0]
    if crc16_ccitt(frame[:-2]) != expected_crc:
        raise AuxLanError("device returned a frame with an invalid checksum")
    return frame_type, sequence, frame[8:-2]


def parse_mac(value: str) -> bytes:
    compact = value.replace(":", "").replace("-", "")
    if len(compact) != 12:
        raise argparse.ArgumentTypeError("MAC must contain six bytes")
    try:
        return bytes.fromhex(compact)
    except ValueError as err:
        raise argparse.ArgumentTypeError("MAC is not hexadecimal") from err


def parse_passcode(payload: bytes) -> bytes:
    if not payload:
        raise AuxLanError("passcode response is empty")
    length = payload[0]
    if length == 0 or len(payload) < length + 1:
        raise AuxLanError("passcode response has an invalid length")
    return payload[1 : length + 1]


def decode_small_state(payload: bytes) -> dict[str, object]:
    if len(payload) < 10 or payload[0] != 0xBB:
        raise AuxLanError("status response does not contain a UART packet")
    body_length = payload[6]
    body = payload[8 : 8 + body_length]
    if len(body) < 15 or body[1] != 0x11:
        raise AuxLanError("status response is not a small-status packet")

    fraction = body[14] if body[14] <= 9 else 0
    if fraction == 0 and body[4] & 0x80:
        fraction = 5
    fan_flags = body[6] & 0xC0
    if fan_flags & 0x80:
        fan = 0
    elif fan_flags & 0x40:
        fan = 5
    else:
        fan = AUX_TO_FAN.get(body[5] & 0xE0, 4)
    mode = AUX_TO_MODE.get(body[7] & 0xE0, 1)

    return {
        "power": "on" if body[10] & 0x20 else "off",
        "mode": MODE_NAMES[mode],
        "target_temperature": 8 + (body[2] >> 3) + fraction / 10.0,
        "fan": FAN_NAMES[fan],
        "vertical_swing": body[2] & 0x07,
        "horizontal_swing": 0 if body[3] & 0xE0 == 0 else 7,
    }


def query_state(
    host: str, mac: bytes, timeout: float, passcode: bytes | None = None
) -> dict[str, object]:
    with socket.create_connection((host, 12416), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(PASSCODE_REQUEST)
        try:
            frame_type, _, payload = receive_frame(sock)
        except socket.timeout as err:
            raise AuxLanError("passcode response timed out") from err
        if frame_type != 0x1005:
            raise AuxLanError(
                f"expected passcode response, got 0x{frame_type:04x}"
            )
        device_passcode = parse_passcode(payload)
        if passcode is not None and passcode != device_passcode:
            raise AuxLanError("stored passcode does not match the device response")
        passcode = device_passcode

        auth_key = hashlib.md5(passcode + mac).digest()
        session_key = secrets.token_bytes(16)
        auth_payload = encrypt(auth_key, session_key) + hashlib.md5(session_key).digest()
        sock.sendall(build_frame(0x0007, 0, auth_payload))

        sock.settimeout(2.0)
        try:
            frame_type, _, payload = receive_frame(sock)
        except socket.timeout:
            frame_type = 0
        if frame_type:
            if frame_type != 0x1007:
                raise AuxLanError(
                    f"expected login response, got 0x{frame_type:04x}"
                )
            if decrypt(session_key, payload) != b"ok":
                raise AuxLanError("device rejected local authentication")

        query = build_inner_command(SMALL_STATUS_QUERY)
        sock.settimeout(timeout)
        sock.sendall(build_frame(0x000B, 1, encrypt(session_key, query)))
        try:
            frame_type, _, payload = receive_frame(sock)
        except socket.timeout as err:
            raise AuxLanError("status response timed out after authentication") from err
        if frame_type != 0x100B:
            raise AuxLanError(f"expected UART response, got 0x{frame_type:04x}")
        return decode_small_state(decrypt(session_key, payload))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read AUX A+ state over LAN without sending control commands."
    )
    parser.add_argument("host", help="air-conditioner IPv4 address")
    parser.add_argument("mac", type=parse_mac, help="air-conditioner Wi-Fi MAC")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--passcode-stdin",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="silently retry until the device responds or this deadline expires",
    )
    args = parser.parse_args()
    passcode = None
    if args.passcode_stdin:
        passcode = sys.stdin.buffer.readline().strip()
        if not passcode:
            parser.exit(2, "AUX LAN probe failed: passcode input is empty\n")

    deadline = time.monotonic() + args.wait
    while True:
        try:
            state = query_state(args.host, args.mac, args.timeout, passcode)
            break
        except (AuxLanError, OSError) as err:
            if time.monotonic() >= deadline:
                parser.exit(1, f"AUX LAN probe failed: {err}\n")
            time.sleep(1)

    print("AUX LAN authentication succeeded")
    for key, value in state.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
