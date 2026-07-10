"""Protocol tests for the local AUXLink client."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).parents[1] / "custom_components" / "aux_a_plus"


def _load_module(name: str):
    full_name = f"custom_components.aux_a_plus.{name}"
    spec = importlib.util.spec_from_file_location(full_name, ROOT / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


custom_components = types.ModuleType("custom_components")
custom_components.__path__ = []
aux_a_plus = types.ModuleType("custom_components.aux_a_plus")
aux_a_plus.__path__ = [str(ROOT)]
sys.modules.setdefault("custom_components", custom_components)
sys.modules.setdefault("custom_components.aux_a_plus", aux_a_plus)
_load_module("mqtt")
lan = _load_module("lan")


class AuxLanProtocolTest(unittest.TestCase):
    def test_known_empty_frame(self) -> None:
        self.assertEqual(lan._build_frame(0x0005, 0, b""), lan.PASSCODE_QUERY)

    def test_frame_round_trip(self) -> None:
        frame = lan._build_frame(0x000B, 37, b"payload")
        self.assertEqual(lan._parse_frame(frame), (0x000B, 37, b"payload"))

    def test_invalid_crc_is_rejected(self) -> None:
        frame = bytearray(lan._build_frame(0x000B, 1, b"payload"))
        frame[-1] ^= 0x01
        with self.assertRaises(lan.AuxLanError):
            lan._parse_frame(bytes(frame))

    def test_cipher_round_trip(self) -> None:
        key = bytes(range(16))
        payload = bytes.fromhex("bb0006800000020011012b7e")
        self.assertEqual(lan._decrypt(key, lan._encrypt(key, payload)), payload)

    def test_real_discovery_frame(self) -> None:
        frame = bytes.fromhex(
            "a5a52f00030000000111100001000206348e892b8d3d16"
            "64353030303130303032333438653839326238643364fca3"
        )
        device_id, mac, secure_type = lan._parse_discovery(frame)
        self.assertEqual(device_id, "d500010002348e892b8d3d")
        self.assertEqual(mac, bytes.fromhex("348e892b8d3d"))
        self.assertEqual(secure_type, 1)


if __name__ == "__main__":
    unittest.main()
