#!/usr/bin/env python3
"""READ ONLY: inspect original PvZ2 GlobalSaveData RTON premium ID arrays.

Supports the reference 2013 little-endian RTON encoding demonstrated by
real 1.5.252752 iPad saves; rejects unfamiliar/ambiguous data rather than
inventing an unlock. Never extracts or publishes player IDs or purchase tokens.
Pass one or two full snapshot folders or direct global_save_data files.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path

FIELDS = {
    "m_unlockedPlants": {
        21: "Snow Pea", 39: "Squash", 32: "Imitater",
        33: "Jalapeno", 18: "Torchwood", 38: "Power Lily",
    },
    "m_unlockedGameFeatures": {
        15: "Shovel Bonus", 19: "Plant Food Bonus",
        21: "Sun Bonus", 12: "Bonus Seed Slot",
    },
}

def _uvar(raw: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if pos >= len(raw):
            raise ValueError("Incomplete RTON numeric field")
        byte = raw[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 128:
            if value > 0xFFFFFFFF:
                raise ValueError("RTON integer outside 32-bit range")
            return value, pos
        shift += 7
    raise ValueError("Overlong RTON integer")

def decode_known_global_arrays(data: bytes) -> dict[str, list[int]]:
    if not data.startswith(b"RTON\x01\x00\x00\x00") or not data.endswith(b"DONE"):
        raise ValueError("Not the recognized PvZ2 reference GlobalSaveData RTON")
    if b"GlobalSaveData" not in data:
        raise ValueError("Not a GlobalSaveData object")
    result: dict[str, list[int]] = {}
    for field in FIELDS:
        encoded_name = field.encode("ascii")
        if len(encoded_name) > 127:
            raise ValueError("Unexpected property name size")
        anchor = b"\x90" + bytes([len(encoded_name)]) + encoded_name + b"\x86\xfd"
        if data.count(anchor) != 1:
            raise ValueError(f"Missing or duplicated typed global field {field}")
        pos = data.find(anchor) + len(anchor)
        count, pos = _uvar(data, pos)
        if count > 128:
            raise ValueError(f"Unexpectedly large global field {field}")
        values: list[int] = []
        for _ in range(count):
            if pos >= len(data) or data[pos] != 0x24:
                raise ValueError(f"Unsupported array item encoding in {field}")
            value, pos = _uvar(data, pos + 1)
            values.append(value)
        if pos >= len(data) or data[pos] != 0xFE:
            raise ValueError(f"Missing RTON array terminator in {field}")
        result[field] = values
    return result

def source_file(source: Path) -> Path:
    path = source / "UserData/No_Backup/global_save_data" if source.is_dir() else source
    if not path.is_file() or path.is_symlink():
        raise ValueError("Missing/unsafe GlobalSaveData file")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Refusing oversized GlobalSaveData file")
    return path

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", type=Path,
                        help="One/two snapshot folders or global_save_data files")
    args = parser.parse_args()
    if len(args.sources) > 2:
        parser.error("Compare at most two snapshots")
    seen: list[bytes] = []
    for i, source in enumerate(args.sources, start=1):
        raw = source_file(source).read_bytes()
        fields = decode_known_global_arrays(raw)
        print(f"snapshot {i}: {len(raw)} bytes, sha256={hashlib.sha256(raw).hexdigest()}")
        for field, values in fields.items():
            labels = [FIELDS[field].get(v, f"UNKNOWN({v})") for v in values]
            print(f"  {field}: {values} ({', '.join(labels) if labels else 'empty'})")
        seen.append(raw)
    if len(seen) == 2:
        print(f"GlobalSaveData byte-for-byte identical: {seen[0] == seen[1]}")
    print("NOTICE: array IDs contain NO receipt origin/provenance information.")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        raise SystemExit("FAIL (no files changed): " + str(exc))
