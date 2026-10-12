#!/usr/bin/env python3
"""Synthetic-only stopped-guest KEYCONV prelaunch transaction regression tests.

No personal backups, APK, OBB or private profile identifiers enter CI.
"""
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from experimental_keyconv_prelaunch import (
    DONE, JOURNAL, PrelaunchConflict, SimulatedInterruption,
    recover, settle_disposable_root, prepare
)
from inspect_pvz2_rton_save import RtonReader
from test_keyconv_rton_archive import synthetic_zip, ROOT


class PrelaunchTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pvz2-prelaunch-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.root = self.folder / "isolated-live"
        self.working = self.root / "UserData" / "No_Backup"
        self.working.mkdir(parents=True)
        self.source = self.folder / "synthetic.zip"
        self.make_save()

    def make_save(self, **kwargs):
        synthetic_zip(self.source, mirror_matches=False, **kwargs)
        with zipfile.ZipFile(self.source) as archive:
            for name in ("pp.dat", "snapshot2.dat", "local_profiles"):
                self.working.joinpath(name).write_bytes(
                    archive.read(ROOT + "UserData/No_Backup/" + name))

    def player(self, name):
        data = RtonReader(self.working.joinpath(name).read_bytes()).decode()
        return data["objects"][0]["objdata"]

    def balances(self):
        return tuple((self.player(name)["c"], self.player(name)["wsk"][0]["kc"])
                     for name in ("pp.dat", "snapshot2.dat"))

    def test_normal_commit_then_second_start_no_double_credit(self):
        self.assertEqual(self.balances(), ((7800, 1), (7801, 1)))
        answer = settle_disposable_root(self.root, 0, guest_stopped=True)
        self.assertEqual(answer["status"], "COMMITTED")
        self.assertEqual(answer["key_count"], 1)
        self.assertEqual(self.balances(), ((8800, 0), (8801, 0)))
        self.assertEqual(recover(self.root), "NO_JOURNAL")
        self.assertEqual(
            settle_disposable_root(self.root, 0, guest_stopped=True)["status"],
            "NOOP")
        self.assertEqual(self.balances(), ((8800, 0), (8801, 0)))

    def test_rollback_on_all_uncommitted_crash_points(self):
        for phase in ("after_prepare", "after_replace_0", "after_replace_1"):
            with self.subTest(phase=phase):
                # Every subcase reuses an identical independent fake save.
                before = (self.working / "pp.dat").read_bytes()
                other = (self.working / "snapshot2.dat").read_bytes()
                with self.assertRaises(SimulatedInterruption):
                    settle_disposable_root(self.root, 0, guest_stopped=True,
                                           crash_at=phase)
                self.assertEqual(recover(self.root), "ROLLED_BACK")
                self.assertEqual((self.working / "pp.dat").read_bytes(), before)
                self.assertEqual((self.working / "snapshot2.dat").read_bytes(), other)
                self.assertFalse((self.root / JOURNAL).exists())
                self.assertFalse((self.root / DONE).exists())

    def test_crash_after_durable_commit_prepare_rolls_back(self):
        with self.assertRaises(SimulatedInterruption):
            settle_disposable_root(self.root, 0, guest_stopped=True,
                                   crash_at="before_commit_marker")
        self.assertEqual(recover(self.root), "ROLLED_BACK")
        self.assertEqual(self.balances(), ((7800, 1), (7801, 1)))

    def test_crash_after_commit_preserves_both_images(self):
        with self.assertRaises(SimulatedInterruption):
            settle_disposable_root(self.root, 0, guest_stopped=True,
                                   crash_at="after_commit")
        self.assertEqual(recover(self.root), "CONFIRMED_COMMIT")
        self.assertEqual(self.balances(), ((8800, 0), (8801, 0)))
        self.assertEqual(
            settle_disposable_root(self.root, 0, guest_stopped=True)["status"],
            "NOOP")

    def test_disposable_done_cleanup_can_resume(self):
        journal = self.root / DONE
        journal.mkdir()
        (journal / "new-pp.dat").write_bytes(b"partial old cleanup")
        self.assertEqual(recover(self.root), "NO_JOURNAL")
        self.assertFalse(journal.exists())

    def test_unpublished_staging_is_safe_to_discard(self):
        journal = self.root / JOURNAL
        journal.mkdir()
        (journal / "old-pp.dat").write_bytes(b"partial staged image")
        self.assertEqual(recover(self.root), "DISCARDED_UNPUBLISHED")
        self.assertEqual(self.balances(), ((7800, 1), (7801, 1)))

    def test_corrupt_journal_refuses_launch_without_guess(self):
        with self.assertRaises(SimulatedInterruption):
            settle_disposable_root(self.root, 0, guest_stopped=True,
                                   crash_at="after_replace_0")
        (self.root / JOURNAL / "new-pp.dat").write_bytes(b"corrupted")
        with self.assertRaisesRegex(PrelaunchConflict, "Corrupt journal"):
            recover(self.root)
        self.assertTrue((self.root / JOURNAL).is_dir())

    def test_unexpected_live_write_blocks_rollback(self):
        with self.assertRaises(SimulatedInterruption):
            settle_disposable_root(self.root, 0, guest_stopped=True,
                                   crash_at="after_replace_0")
        (self.working / "snapshot2.dat").write_bytes(b"unexpected guest write")
        with self.assertRaisesRegex(PrelaunchConflict, "diverged"):
            recover(self.root)


    def test_registry_changed_after_first_file_crash_refuses_recovery(self):
        with self.assertRaises(SimulatedInterruption):
            settle_disposable_root(self.root, 0, guest_stopped=True,
                                   crash_at="after_replace_0")
        # Simulates a concurrent profile/restore change between sessions.
        registry = self.working / "local_profiles"
        registry.write_bytes(registry.read_bytes() + b"unexpected")
        with self.assertRaisesRegex(PrelaunchConflict, "registry changed"):
            recover(self.root)
        self.assertTrue((self.root / JOURNAL).is_dir())

    def test_corrupt_registry_unchanged_hash_rejected_pretransaction(self):
        (self.working / "local_profiles").write_bytes(b"bad registry")
        with self.assertRaises(Exception):
            settle_disposable_root(self.root, 0, guest_stopped=True)
        self.assertEqual(self.balances(), ((7800, 1), (7801, 1)))
        self.assertFalse((self.root / JOURNAL).exists())

    def test_wrong_native_profile_identity_refused(self):
        # Registry is one higher than original PlayerInfo native ID.
        self.source.unlink()
        self.make_save(local_profile_index=1790861460)
        with self.assertRaisesRegex(PrelaunchConflict, "identity mismatch"):
            settle_disposable_root(self.root, 0, guest_stopped=True)
        self.assertFalse((self.root / JOURNAL).exists())

    def test_fallback_stock_mismatch_refused(self):
        self.source.unlink()
        self.make_save(fallback_keys=2)
        with self.assertRaisesRegex(PrelaunchConflict, "stocks diverge"):
            settle_disposable_root(self.root, 0, guest_stopped=True)
        self.assertEqual(self.balances(), ((7800, 1), (7801, 2)))

    def test_closed_gate_and_zero_keys_are_noops(self):
        for setup in ({"opened": False, "keys": 6}, {"keys": 0}):
            with self.subTest(setup=setup):
                self.source.unlink()
                self.make_save(**setup)
                before = self.balances()
                result = settle_disposable_root(self.root, 0, guest_stopped=True)
                self.assertEqual(result["status"], "NOOP")
                self.assertEqual(self.balances(), before)

    def test_guest_must_explicitly_be_stopped(self):
        with self.assertRaisesRegex(PrelaunchConflict, "stopped guest"):
            settle_disposable_root(self.root, 0)
        self.assertEqual(self.balances(), ((7800, 1), (7801, 1)))

    def test_symlink_and_unknown_journal_entries_refused(self):
        journal = self.root / JOURNAL
        journal.mkdir()
        (journal / "unrecognized").write_bytes(b"bad")
        with self.assertRaisesRegex(PrelaunchConflict, "Unknown journal"):
            recover(self.root)
        (journal / "unrecognized").unlink()
        (journal / "old-pp.dat").symlink_to(self.working / "pp.dat")
        with self.assertRaisesRegex(PrelaunchConflict, "entry type"):
            recover(self.root)


if __name__ == "__main__":
    unittest.main()
