"""One-shot AUXLink MQTT status queries."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import socket
import ssl
import struct
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding


MQTT_HOST = "smthomem2m.aux-home.com"
MQTT_PORT = 8883
MQTT_KEEP_ALIVE = 120
MQTT_INTERMEDIATE_CERT = Path(__file__).with_name("geotrust_g2_cn_2022_ca1.pem")

_BIG_STATUS_QUERY = bytes.fromhex("bb0006800000020021011b7e")
_SMALL_STATUS_QUERY_BODY = b"\x11\x01"

_MODE_TO_AUX = {
    0: 0x00,
    1: 0x20,
    2: 0x40,
    4: 0x80,
    6: 0xC0,
}
_FAN_TO_AUX = {
    1: 0x60,
    2: 0x40,
    3: 0x20,
    4: 0x20,
}


class AuxMqttError(Exception):
    """Raised when an AUX MQTT query fails."""


class AuxMqttAuthError(AuxMqttError):
    """Raised when the AUX MQTT broker rejects the login token."""


def query_temperatures(
    *,
    uid: str,
    token: str,
    device_id: str,
    app_id: str,
    sequence: int,
    timeout: float = 12,
) -> dict[str, float]:
    """Query the indoor unit's large status packet over AUXLink MQTT."""
    context = _mqtt_ssl_context()

    for attempt in range(2):
        try:
            return _query_temperatures_once(
                context=context,
                uid=uid,
                token=token,
                device_id=device_id,
                app_id=app_id,
                sequence=sequence,
                timeout=timeout,
            )
        except AuxMqttError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as err:
            if attempt == 1:
                raise AuxMqttError(f"AUX MQTT connection failed: {err}") from err
            time.sleep(0.5)

    raise AuxMqttError("AUX MQTT connection failed")


def control_device(
    *,
    uid: str,
    token: str,
    device_id: str,
    app_id: str,
    sequence: int,
    intent: dict[str, object],
    timeout: float = 12,
) -> None:
    """Apply a control intent through the AUXLink MQTT channel."""
    context = _mqtt_ssl_context()
    for attempt in range(2):
        try:
            _control_device_once(
                context=context,
                uid=uid,
                token=token,
                device_id=device_id,
                app_id=app_id,
                sequence=sequence,
                intent=intent,
                timeout=timeout,
            )
            return
        except AuxMqttError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as err:
            if attempt == 1:
                raise AuxMqttError(f"AUX MQTT connection failed: {err}") from err
            time.sleep(0.5)

    raise AuxMqttError("AUX MQTT control failed")


def _mqtt_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    return context


def _query_temperatures_once(
    *,
    context: ssl.SSLContext,
    uid: str,
    token: str,
    device_id: str,
    app_id: str,
    sequence: int,
    timeout: float,
) -> dict[str, float]:
    with socket.create_connection(
        (MQTT_HOST, MQTT_PORT), timeout=timeout
    ) as raw_socket:
        with context.wrap_socket(
            raw_socket, server_hostname=MQTT_HOST
        ) as mqtt_socket:
            _verify_server_certificate(mqtt_socket)
            mqtt_socket.settimeout(timeout)
            _mqtt_connect(mqtt_socket, uid=uid, token=token, app_id=app_id)
            _mqtt_subscribe(mqtt_socket, f"dev2app/{uid}/#")

            # AUX's native SDK publishes to this literal topic, including '#'.
            # General MQTT libraries reject it, so this small client writes the
            # MQTT 3.1 packet directly for protocol compatibility.
            query = _auxlink_frame(_BIG_STATUS_QUERY, sequence)
            publish_body = _mqtt_utf8(f"app2dev/{device_id}/#") + query
            mqtt_socket.sendall(_mqtt_packet(0x30, publish_body))

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                mqtt_socket.settimeout(max(0.1, deadline - time.monotonic()))
                packet_type, flags, data = _mqtt_receive(mqtt_socket)
                if packet_type != 3:
                    continue
                payload = _mqtt_publish_payload(flags, data)
                temperatures = _decode_temperatures(payload)
                if temperatures is not None:
                    return temperatures

    raise AuxMqttError("AUX MQTT status query timed out")


def _control_device_once(
    *,
    context: ssl.SSLContext,
    uid: str,
    token: str,
    device_id: str,
    app_id: str,
    sequence: int,
    intent: dict[str, object],
    timeout: float,
) -> None:
    with socket.create_connection(
        (MQTT_HOST, MQTT_PORT), timeout=timeout
    ) as raw_socket:
        with context.wrap_socket(
            raw_socket, server_hostname=MQTT_HOST
        ) as mqtt_socket:
            _verify_server_certificate(mqtt_socket)
            mqtt_socket.settimeout(timeout)
            _mqtt_connect(mqtt_socket, uid=uid, token=token, app_id=app_id)
            _mqtt_subscribe(mqtt_socket, f"dev2app/{uid}/#")

            small_query = _inner_command(_SMALL_STATUS_QUERY_BODY)
            _publish_aux(mqtt_socket, device_id, sequence, small_query)
            current = _receive_aux_body(mqtt_socket, {0x11}, timeout)
            control_body = _apply_control_intent(current, intent)

            command = _inner_command(control_body)
            _publish_aux(mqtt_socket, device_id, sequence + 1, command)
            _receive_aux_body(mqtt_socket, {0x01}, timeout)


def _publish_aux(
    sock: ssl.SSLSocket, device_id: str, sequence: int, inner: bytes
) -> None:
    outer = _auxlink_frame(inner, sequence)
    body = _mqtt_utf8(f"app2dev/{device_id}/#") + outer
    sock.sendall(_mqtt_packet(0x30, body))


def _receive_aux_body(
    sock: ssl.SSLSocket, accepted_commands: set[int], timeout: float
) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        packet_type, flags, data = _mqtt_receive(sock)
        if packet_type != 3:
            continue
        payload = _mqtt_publish_payload(flags, data)
        inner = _auxlink_inner(payload)
        if inner is None:
            continue
        body_length = inner[6]
        body = inner[8:8 + body_length]
        if len(body) >= 2 and body[1] in accepted_commands:
            return body
    raise AuxMqttError("AUX MQTT command response timed out")


def _apply_control_intent(current: bytes, intent: dict[str, object]) -> bytes:
    if len(current) < 15 or current[1] != 0x11:
        raise AuxMqttError("AUX small status packet is invalid")
    body = bytearray(current[:15])
    body[0] = 0x01
    body[1] = 0x01

    if "temperature" in intent:
        target = max(16.0, min(30.0, float(intent["temperature"]) / 10.0))
        whole = int(target)
        body[2] = (body[2] & 0x07) | ((whole - 8) << 3)
        body[4] = (body[4] & 0x7F) | (0x80 if target - whole >= 0.5 else 0)
        body[14] = int(round(target * 10)) % 10

    if "air_con_func" in intent:
        mode = int(intent["air_con_func"])
        if mode not in _MODE_TO_AUX:
            raise AuxMqttError(f"Unsupported AUX mode code: {mode}")
        body[7] = (body[7] & 0x1F) | _MODE_TO_AUX[mode]

    if "on_off" in intent:
        body[10] = (body[10] & ~0x20) | (0x20 if int(intent["on_off"]) else 0)

    if "wind_speed" in intent:
        fan = int(intent["wind_speed"])
        body[6] &= ~0xC0
        if fan == 0:
            body[6] |= 0x80
        elif fan == 5:
            body[6] |= 0x40
        elif fan in _FAN_TO_AUX:
            body[5] = (body[5] & 0x1F) | _FAN_TO_AUX[fan]
        else:
            raise AuxMqttError(f"Unsupported AUX fan code: {fan}")

    if "up_down_swing" in intent:
        vertical = 0x00 if int(intent["up_down_swing"]) != 7 else 0x07
        body[2] = (body[2] & 0xF8) | vertical

    if "left_right_swing" in intent:
        horizontal = 0x00 if int(intent["left_right_swing"]) != 7 else 0xE0
        body[3] = (body[3] & 0x1F) | horizontal

    return bytes(body)


def _verify_server_certificate(sock: ssl.SSLSocket) -> None:
    """Verify AUX's leaf cert against its omitted intermediate before login."""
    leaf_der = sock.getpeercert(binary_form=True)
    if not leaf_der:
        raise AuxMqttError("AUX MQTT server did not provide a certificate")

    leaf = x509.load_der_x509_certificate(leaf_der)
    intermediate = x509.load_pem_x509_certificate(MQTT_INTERMEDIATE_CERT.read_bytes())
    if leaf.issuer != intermediate.subject:
        raise AuxMqttError("AUX MQTT certificate has an unexpected issuer")

    try:
        intermediate.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
    except InvalidSignature as err:
        raise AuxMqttError("AUX MQTT certificate signature is invalid") from err

    valid_from = getattr(leaf, "not_valid_before_utc", None)
    valid_until = getattr(leaf, "not_valid_after_utc", None)
    if valid_from is None:
        valid_from = leaf.not_valid_before.replace(tzinfo=timezone.utc)
        valid_until = leaf.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if not valid_from <= now <= valid_until:
        raise AuxMqttError("AUX MQTT certificate is expired or not yet valid")

    try:
        names = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound as err:
        raise AuxMqttError("AUX MQTT certificate has no DNS names") from err
    if not any(_dns_name_matches(name, MQTT_HOST) for name in names):
        raise AuxMqttError("AUX MQTT certificate hostname does not match")


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if not pattern.startswith("*."):
        return pattern == hostname
    suffix = pattern[1:]
    return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")


def _mqtt_connect(sock: ssl.SSLSocket, *, uid: str, token: str, app_id: str) -> None:
    connect_body = (
        _mqtt_utf8("MQIsdp")
        + bytes((3, 0xC2))
        + struct.pack("!H", MQTT_KEEP_ALIVE)
        + _mqtt_utf8(f"usr{uid}")
        + _mqtt_utf8(f"2${app_id}${uid}")
        + _mqtt_utf8(token)
    )
    sock.sendall(_mqtt_packet(0x10, connect_body))
    packet_type, _flags, data = _mqtt_receive(sock)
    if packet_type != 2 or len(data) != 2:
        raise AuxMqttError("Unexpected AUX MQTT CONNACK")
    if data[1] != 0:
        raise AuxMqttAuthError(f"AUX MQTT login rejected with code {data[1]}")


def _mqtt_subscribe(sock: ssl.SSLSocket, topic: str) -> None:
    body = struct.pack("!H", 1) + _mqtt_utf8(topic) + b"\x00"
    sock.sendall(_mqtt_packet(0x82, body))
    while True:
        packet_type, _flags, data = _mqtt_receive(sock)
        if packet_type != 9:
            continue
        if len(data) < 3 or data[2] == 0x80:
            raise AuxMqttError("AUX MQTT subscription rejected")
        return


def _mqtt_receive(sock: ssl.SSLSocket) -> tuple[int, int, bytes]:
    first = _receive_exact(sock, 1)[0]
    remaining = 0
    multiplier = 1
    while True:
        digit = _receive_exact(sock, 1)[0]
        remaining += (digit & 0x7F) * multiplier
        if not digit & 0x80:
            break
        multiplier *= 128
        if multiplier > 128**3:
            raise AuxMqttError("Invalid MQTT remaining length")
    return first >> 4, first & 0x0F, _receive_exact(sock, remaining)


def _receive_exact(sock: ssl.SSLSocket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise AuxMqttError("AUX MQTT connection closed")
        result.extend(chunk)
    return bytes(result)


def _mqtt_publish_payload(flags: int, data: bytes) -> bytes:
    if len(data) < 2:
        raise AuxMqttError("Truncated MQTT PUBLISH packet")
    topic_length = struct.unpack("!H", data[:2])[0]
    position = 2 + topic_length
    if position > len(data):
        raise AuxMqttError("Truncated MQTT PUBLISH topic")
    if (flags >> 1) & 0x03:
        position += 2
    return data[position:]


def _mqtt_utf8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("!H", len(encoded)) + encoded


def _mqtt_packet(packet_type_and_flags: int, body: bytes) -> bytes:
    return bytes((packet_type_and_flags,)) + _mqtt_remaining_length(len(body)) + body


def _mqtt_remaining_length(length: int) -> bytes:
    result = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length:
            digit |= 0x80
        result.append(digit)
        if not length:
            return bytes(result)


def _auxlink_frame(payload: bytes, sequence: int) -> bytes:
    total_length = len(payload) + 10
    prefix = (
        b"\xA5\xA5"
        + struct.pack("<H", total_length)
        + struct.pack("<H", 0x000B)
        + struct.pack("<H", sequence & 0xFFFF)
        + payload
    )
    return prefix + struct.pack("!H", _crc16_ccitt(prefix))


def _inner_command(body: bytes) -> bytes:
    prefix = b"\xBB\x00\x06\x80\x00\x00" + bytes((len(body), 0)) + body
    return prefix + struct.pack("!H", _inner_crc(prefix))


def _inner_crc(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    checksum = sum(
        (data[index] << 8) | data[index + 1]
        for index in range(0, len(data), 2)
    )
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return (~checksum) & 0xFFFF


def _crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _decode_temperatures(payload: bytes) -> dict[str, float] | None:
    inner = _auxlink_inner(payload)
    if inner is None:
        return None
    if len(inner) < 34 or inner[0] != 0xBB:
        return None
    body_length = inner[6]
    body = inner[8:8 + body_length]
    if len(body) < 24 or body[1] not in (0x21, 0x2C):
        return None

    return {
        "indoor_temperature": body[7] - 0x20 + (body[23] & 0x0F) / 10.0,
        "outdoor_temperature": float(body[12] - 0x20),
    }


def _auxlink_inner(payload: bytes) -> bytes | None:
    if len(payload) < 20 or payload[:2] != b"\xA5\xA5":
        return None
    declared_length = struct.unpack("<H", payload[2:4])[0]
    expected_crc = struct.unpack("!H", payload[-2:])[0]
    if declared_length != len(payload) or _crc16_ccitt(payload[:-2]) != expected_crc:
        return None
    return payload[8:-2]
