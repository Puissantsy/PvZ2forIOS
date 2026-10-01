#!/usr/bin/env python3
"""Five self-contained synthetic tests; never reads the user's saves."""
from __future__ import annotations
import hashlib
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "tools/compare_store_snapshots.py"


def create_snapshot(folder: Path, a: int, b: int,
                    shared: bytes, duplicate: bool = False) -> Path:
    (folder / "UserData" / "No_Backup").mkdir(parents=True)
    (folder / "UserData" / "No_Backup" / "global_save_data").write_bytes(shared)
    (folder / "UserData" / "No_Backup" / "pp.dat").write_bytes(b"test data")

    def v128(kind: str, key: str, raw: str) -> str:
        return kind + "\t" + key.encode("utf-8").hex() + "\t" + raw + "\n"

    config = (
        v128("B", "offline_store_profile_scope_migrated_v1", "1")
        + v128("I", "offline_store_profile_v1_101_plants", str(a))
        + v128("I", "offline_store_profile_v1_102_plants", str(b))
        + v128("S", "private_test_key", "SECRET_NEVER_PRINT".encode().hex())
    )
    if duplicate:
        config += v128("I", "offline_store_profile_v1_101_plants", str(a))
    (folder / "config-v1.txt").write_text(config, encoding="utf-8")

    inventory = []
    for f in sorted(path for path in folder.rglob("*") if path.is_file()):
        contents = f.read_bytes()
        inventory.append({
            "path": f.relative_to(folder).as_posix(),
            "size": len(contents),
            "sha256": hashlib.sha256(contents).hexdigest(),
        })
    (folder / "snapshot-info.plist").write_bytes(plistlib.dumps({
        "format": "pvz2forios-save-v1",
        "roots": ["config-v1.txt", "UserData"],
        "files": inventory,
    }))
    return folder


def compare(before: Path, after: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(before), str(after), "--premium-diff"],
        capture_output=True, text=True, check=False)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="pvz2-qa-") as temp:
        base = Path(temp)
        before = create_snapshot(base / "before", 0, 0, b"shared-before")
        bought = create_snapshot(base / "a-bought", 1, 0, b"shared-after-a")
        b_claim = create_snapshot(base / "b-claim", 1, 0, b"shared-after-b")
        dup = create_snapshot(base / "duplicate", 1, 0, b"shared-after-a", duplicate=True)

        result = compare(before, bought)
        assert result.returncode == 0, result.stderr
        assert "0x00000000 [none] -> 0x00000001 [Snow Pea]" in result.stdout
        assert "SECRET_NEVER_PRINT" not in result.stdout
        print("PASS purchase: only profile-premium data exposed")

        result = compare(bought, b_claim)
        assert result.returncode == 0, result.stderr
        assert "SAME: offline_store_profile_v1_102_plants" in result.stdout
        print("PASS mock-CLAIM: changed global file while B sidecar remains zero (synthetic only)")

        result = compare(before, dup)
        assert result.returncode != 0 and "Duplicate premium key" in result.stderr
        print("PASS duplicate premium key refused")

        (b_claim / "UserData" / "No_Backup" / "global_save_data").write_bytes(b"tamper")
        result = compare(before, b_claim)
        assert result.returncode != 0 and "does not match" in result.stderr
        print("PASS altered manifest file refused")

        (b_claim / "UserData" / "No_Backup" / "global_save_data").write_bytes(b"shared-after-b")
        (b_claim / "UserData" / "No_Backup" / "rogue.txt").write_bytes(b"unlisted")
        result = compare(before, b_claim)
        assert result.returncode != 0 and "unexpected or unlisted" in result.stderr
        print("PASS extra unlisted snapshot file refused")

    print("ALL FIVE SYNTHETIC SNAPSHOT TESTS PASSED")


if __name__ == "__main__":
    main()
