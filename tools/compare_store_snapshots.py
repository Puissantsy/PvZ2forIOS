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


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before", type=Path, help="Unmodified save-...-prelaunch-... directory")
    p.add_argument("after", type=Path, help="Unmodified save-...-poststop-... directory")
    p.add_argument("--all", action="store_true", help="List changed non-store resources too")
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
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, plistlib.InvalidFileException) as exc:
        print(f"FAIL without modifying either snapshot: {exc}", file=sys.stderr)
        sys.exit(1)
