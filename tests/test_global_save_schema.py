#!/usr/bin/env python3
"""Host-only guardrail test for the four original GlobalSaveData RTON arrays.

Synthetic RTON fixtures contain NO user data. Exact ARM byte validation
is separately run with --apk in tools/inspect_global_premium_rton.py.
"""
from pathlib import Path
import importlib.util

script = Path(__file__).resolve().parents[1] / "tools/inspect_global_premium_rton.py"
spec = importlib.util.spec_from_file_location("pvz2_global_rton", script)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def uvar(n: int) -> bytes:
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    return bytes(result + bytes([n]))


def field(name: str, ids: list[int]) -> bytes:
    key = name.encode("ascii")
    return b"\x90" + bytes([len(key)]) + key + b"\x86\xfd" + (
        uvar(len(ids)) + b"".join(b"\x24" + uvar(x) for x in ids)
    ) + b"\xfe"


def fixture(plants: list[int], unknown_skus: list[int] | None = None) -> bytes:
    return (
        b"RTON\x01\x00\x00\x00GlobalSaveData"
        + field("m_unlockedPlants", plants)
        + field("m_unlockedGameFeatures", [])
        + field("m_unlockedMapGates", [])
        + field("m_unknownSkus", unknown_skus or [])
        + b"DONE"
    )


def must_reject(src: bytes) -> None:
    try:
        mod.decode_known_global_arrays(src)
    except ValueError:
        return
    raise AssertionError("Unknown or ambiguous RTON erroneously accepted")


decoded = mod.decode_known_global_arrays(fixture([21, 39]))
assert decoded == {
    "m_unlockedPlants": [21, 39],
    "m_unlockedGameFeatures": [],
    "m_unlockedMapGates": [],
    "m_unknownSkus": [],
}
print("PASS: known original-global plant RTON arrays decoded")

original = fixture([21])
plant = field("m_unlockedPlants", [21])
must_reject(original.replace(plant, plant + plant))
print("PASS: duplicated global field rejected")

must_reject(fixture([21], [1]))
print("PASS: unverified unknown-SKU item encoding rejected")

must_reject(original[:-4])
print("PASS: truncated original RTON rejected")
print("ALL FOUR SYNTHETIC GLOBAL RTON TESTS PASSED")
