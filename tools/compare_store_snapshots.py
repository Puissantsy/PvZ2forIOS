#!/usr/bin/env python3
"""Read-only, SHA-256-verified diff of two v165/v166 PvZ2 save snapshots.

Use prelaunch vs poststop for A BUY, and another prelaunch vs poststop for
B CLAIM. Do not extract/publish profile contents or edit snapshot manifests.
The script validates the original three-part full backup before comparing.
"""
from __future__ import annotations
import argparse
import hashlib
import plistlib
import re
import sys
from pathlib import Path


def load_checked(snapshot: Path) -> dict[str, dict]:
    snapshot = snapshot.resolve(strict=True)
    manifest_path = snapshot / "snapshot-info.plist"
    with manifest_path.open("rb") as handle:
        m = plistlib.load(handle)
    if m.get("format") != "pvz2forios-save-v1":
        raise ValueError(f"{snapshot.name}: not a v165+ verified save snapshot")
    roots = m.get("roots")
    entries = m.get("files")
    if not isinstance(roots, list) or not isinstance(entries, list):
        raise ValueError("Snapshot missing file inventory")
    if not 1 <= len(roots) <= 128 or len(set(roots)) != len(roots):
        raise ValueError("Invalid snapshot root list")

    def safe_root(name: str) -> bool:
        return name == "config-v1.txt" or name == "UserData" or (
            name.startswith("UserData-") and "/" not in name and ".." not in name
        )

    if not all(isinstance(root, str) and safe_root(root) for root in roots):
        raise ValueError("Unknown or dangerous snapshot root")

    # Match the existing app's snapshot format before even reading payload
    # bytes. A verified manifest contains one regular config file and only
    # directory-based UserData roots, never symlinks.
    for root in roots:
        candidate = snapshot / root
        if candidate.is_symlink() or (
            (root == "config-v1.txt" and not candidate.is_file()) or
            (root != "config-v1.txt" and not candidate.is_dir())
        ):
            raise ValueError(f"Missing, invalid or symlinked snapshot root: {root}")

    verified: dict[str, dict] = {}
    if len(entries) > 16384:
        raise ValueError("Too many snapshot files")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Malformed file inventory item")
        path = entry.get("path")
        if not isinstance(path, str) or path.startswith("/") or "\\" in path:
            raise ValueError("Invalid inventory path")
        parts = path.split("/")
        if len(parts) == 0 or parts[0] not in roots or any(
            piece in ("", ".", "..") for piece in parts
        ):
            raise ValueError("Inventory path traversal detected")
        file = snapshot.joinpath(*parts)
        if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(snapshot):
            raise ValueError(f"Missing or escaped inventory file {path}")
        data = file.read_bytes()
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"File does not match hashed snapshot manifest: {path}")
        if path in verified:
            raise ValueError(f"Duplicate snapshot inventory entry: {path}")
        verified[path] = entry
    # Detect extra or injected files that the signed manifest never listed.
    extra = set()
    for candidate in snapshot.rglob("*"):
        if candidate.is_symlink():
            raise ValueError(f"Symbolic link in snapshot: {candidate.name}")
        if candidate.is_file():
            rel = candidate.relative_to(snapshot).as_posix()
            if rel != "snapshot-info.plist":
                extra.add(rel)
    if extra != set(verified):
        raise ValueError("Snapshot contains unexpected or unlisted files")
    print(f"PASS verified {snapshot.name}: {len(verified)} hashed files")
    return verified


def focus(path: str) -> bool:
    name = path.split("/")[-1]
    return (
        path == "config-v1.txt"
        or name in (
            "global_save_data", "global_save_data.hash", "local_profiles",
            "pp.dat", "snapshot2.dat",
        )
    )


# The v128 host bridge writes human-readable rows:
#   I<TAB>hex(UTF-8 key)<TAB>signed32
#   B<TAB>hex(UTF-8 key)<TAB>0-or-1
# Never print unrelated config keys or any USERFS binary data.
PROFILE_KEY = re.compile(r"^offline_store_profile_v1_([0-9]+)_(plants|features)$")
MIGRATION_KEY = "offline_store_profile_scope_migrated_v1"
PLANT_NAMES = ("Snow Pea", "Squash", "Imitater", "Jalapeno", "Torchwood", "Power Lily")
UPGRADE_NAMES = ("Shovel Bonus", "Plant Food Bonus", "Sun Bonus", "Bonus Seed Slot")


def extract_offline_profile_rights(snapshot: Path) -> dict[str, str]:
    config = snapshot / "config-v1.txt"
    if not config.exists():
        return {}
    result: dict[str, str] = {}
    # The manifest was already validated by load_checked(). No mutation.
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or parts[0] not in ("I", "B"):
            continue
        kind, key_hex, raw = parts
        try:
            key = bytes.fromhex(key_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        match = PROFILE_KEY.fullmatch(key)
        if match is None and key != MIGRATION_KEY:
            continue
        if key in result:
            raise ValueError("Duplicate premium key; ambiguous backup: " + key)
        if match is not None:
            if kind != "I":
                raise ValueError("Unexpected premium right type: " + key)
            try:
                value = int(raw, 10)
            except ValueError as exc:
                raise ValueError("Invalid premium mask: " + key) from exc
            if not -2147483648 <= value <= 2147483647:
                raise ValueError("Out-of-range premium mask: " + key)
            result[key] = f"0x{value & 0xffffffff:08x}"
        else:
            if kind != "B" or raw not in ("0", "1"):
                raise ValueError("Invalid migration flag")
            result[key] = raw
    return result


def describe_mask(label: str, value: str | None) -> str:
    if value is None:
        return "ABSENT"
    if label == MIGRATION_KEY:
        return "YES" if value == "1" else "NO"
    names = PLANT_NAMES if label.endswith("_plants") else UPGRADE_NAMES
    mask = int(value, 16)
    owned = [name for bit, name in enumerate(names) if mask & (1 << bit)]
    other = mask & ~((1 << len(names)) - 1)
    if other:
        owned.append(f"UNKNOWN_BITS=0x{other:x}")
    return value + (" [" + ", ".join(owned) + "]" if owned else " [none]")


def print_premium_diff(before_dir: Path, after_dir: Path) -> None:
    a = extract_offline_profile_rights(before_dir)
    b = extract_offline_profile_rights(after_dir)
    for key in sorted(set(a) | set(b)):
        old, new = a.get(key), b.get(key)
        status = "CHANGED" if old != new else "SAME"
        print(f"PREMIUM {status}: {key}: "
              f"{describe_mask(key, old)} -> {describe_mask(key, new)}")
    if not a and not b:
        print("PREMIUM: no v128 profile mask or migration key in either snapshot")
    print("PREMIUM comparison is HOST SIDECAR ONLY; native global CLAIM remains separate.")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before", type=Path, help="Unmodified save-...-prelaunch-... directory")
    p.add_argument("after", type=Path, help="Unmodified save-...-poststop-... directory")
    p.add_argument("--all", action="store_true", help="List changed non-store resources too")
    p.add_argument("--premium-diff", action="store_true",
                   help="Show only decoded host premium rights changes (no private config)")
    args = p.parse_args()
    before = load_checked(args.before)
    after = load_checked(args.after)
    modified = 0
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        modified += 1
        if not args.all and not focus(path):
            continue
        label = "ADDED" if old is None else "DELETED" if new is None else "CHANGED"
        a = "—" if old is None else str(old["size"]) + " bytes"
        b = "—" if new is None else str(new["size"]) + " bytes"
        print(f"{label}: {path}: {a} -> {b}")
    print(f"TOTAL: {modified} changed files across the entire verified snapshots.")
    print("The changed file set identifies WHERE to inspect next, not proof of")
    print("which specific field granted cross-profile CLAIM or who owned a receipt.")
    if args.premium_diff:
        print_premium_diff(args.before, args.after)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, plistlib.InvalidFileException) as exc:
        print(f"FAIL without modifying either snapshot: {exc}", file=sys.stderr)
        sys.exit(1)
