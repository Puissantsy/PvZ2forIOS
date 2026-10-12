#!/usr/bin/env python3
"""Only synthetic disposable archives; no real profile or private cloud files."""
import hashlib
import plistlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from experimental_keyconv_rton_archive import build_disposable_copy
from inspect_pvz2_rton_save import RtonError, inspect_archive
from test_readonly_rton_save import sample

PREFIX = "synthetic-TEST/UserData/No_Backup/"
ROOT = "synthetic-TEST/"
EXTRA = b"untouched other save"


def synthetic_zip(destination, *, opened=True, keys=1, coins=7800,
                  mirror_matches=True, correct_manifest=True):
    pp = sample(coins=coins, old_keys=keys, opened=opened)
    other = sample(coins=coins + 1, old_keys=keys, opened=opened)
    members = {
        "UserData/No_Backup/pp.dat": pp,
        "UserData/No_Backup/snapshot2.dat": pp if mirror_matches else other,
        "UserData/No_Backup/other.bin": EXTRA,
    }
    inventory = [
        {"path": name, "size": len(data),
         "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in members.items()
    ]
    if not correct_manifest:
        inventory[0]["sha256"] = "0" * 64
    manifest = {"format": "pvz2forios-save-v1",
                "roots": ["UserData"], "files": inventory}
    with zipfile.ZipFile(destination, "x") as archive:
        for name, data in members.items():
            archive.writestr(ROOT + name, data)
        archive.writestr(ROOT + "snapshot-info.plist",
                         plistlib.dumps(manifest))


class DisposableRtonArchiveTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix="pvz2-rton-test-")
        self.root = Path(self.dir.name)
        self.before = self.root / "original.zip"
        self.after = self.root / "EXPERIMENTAL-ONLY.zip"

    def tearDown(self):
        self.dir.cleanup()

    def test_disposable_export_preserves_original_and_other_files(self):
        synthetic_zip(self.before)
        original = self.before.read_bytes()
        result = build_disposable_copy(self.before, self.after, 0)
        self.assertTrue(result["original_unchanged"])
        self.assertEqual(result["keys_recycled"], 1)
        self.assertEqual(result["coins_before"], 7800)
        self.assertEqual(result["coins_after"], 8800)
        self.assertEqual(self.before.read_bytes(), original)
        inspection = inspect_archive(self.after)
        self.assertEqual(inspection["manifest"]["status"], "VERIFIED")
        self.assertEqual(inspection["snapshot2_comparison"], "IDENTICAL")
        self.assertEqual(inspection["players"][0]["coins"], 8800)
        self.assertEqual(inspection["players"][0]["world_keys"]["entries"][0]["keys"], 0)
        with zipfile.ZipFile(self.after) as z:
            self.assertEqual(z.read(PREFIX + "other.bin"), EXTRA)

    def test_same_archive_cannot_be_written_over_itself(self):
        synthetic_zip(self.before)
        before = self.before.read_bytes()
        with self.assertRaises(RtonError):
            build_disposable_copy(self.before, self.before, 0)
        self.assertEqual(self.before.read_bytes(), before)

    def test_destination_must_not_exist(self):
        synthetic_zip(self.before)
        self.after.write_bytes(b"DO NOT CHANGE")
        with self.assertRaises(RtonError):
            build_disposable_copy(self.before, self.after, 0)
        self.assertEqual(self.after.read_bytes(), b"DO NOT CHANGE")

    def test_closed_gate_fails_without_writing(self):
        synthetic_zip(self.before, opened=False, keys=6)
        with self.assertRaisesRegex(RtonError, "nothing to export"):
            build_disposable_copy(self.before, self.after, 0)
        self.assertFalse(self.after.exists())

    def test_corrupt_manifest_fails_without_writing(self):
        synthetic_zip(self.before, correct_manifest=False)
        with self.assertRaises(RtonError):
            build_disposable_copy(self.before, self.after, 0)
        self.assertFalse(self.after.exists())

    def test_different_snapshot_mirror_fails(self):
        synthetic_zip(self.before, mirror_matches=False)
        with self.assertRaisesRegex(RtonError, "non-identical"):
            build_disposable_copy(self.before, self.after, 0)
        self.assertFalse(self.after.exists())

    def test_wrong_profile_slot_fails(self):
        synthetic_zip(self.before)
        with self.assertRaisesRegex(RtonError, "Profile slot"):
            build_disposable_copy(self.before, self.after, 1)
        self.assertFalse(self.after.exists())

    def test_repeat_export_refused_no_double_credit(self):
        synthetic_zip(self.before)
        build_disposable_copy(self.before, self.after, 0)
        second = self.root / "SECOND-EXPERIMENTAL.zip"
        with self.assertRaisesRegex(RtonError, "nothing to export"):
            build_disposable_copy(self.after, second, 0)
        self.assertFalse(second.exists())

    def test_source_unchanged_on_integer_size_growth(self):
        synthetic_zip(self.before, coins=16380, keys=6)
        original = self.before.read_bytes()
        result = build_disposable_copy(self.before, self.after, 0)
        self.assertEqual(result["coins_after"], 22380)
        self.assertEqual(self.before.read_bytes(), original)
        self.assertEqual(inspect_archive(self.after)["manifest"]["status"],
                         "VERIFIED")


if __name__ == "__main__":
    unittest.main()
