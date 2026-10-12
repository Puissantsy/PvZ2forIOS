#!/usr/bin/env python3
"""Synthetic tests only. Never commit a real player's RTON save or cloud ZIP."""
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from inspect_pvz2_rton_save import (
    RtonError, RtonReader, describe_world_keys, inspect_archive,
    summarize_player_save,
)


def var(n):
    assert 0 <= n < 2**32
    result = bytearray()
    while n > 127:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)


def text(s):
    data = s.encode("latin-1")
    return b"\x90" + var(len(data)) + data


def direct(s):
    data = s.encode("latin-1")
    return b"\x81" + var(len(data)) + data


def number(n):
    return b"\x24" + var(n)


def obj(fields):
    return b"\x85" + b"".join(text(k) + v for k, v in fields) + b"\xff"


def arr(values):
    return b"\x86\xfd" + var(len(values)) + b"".join(values) + b"\xfe"


def sample(coins=7800, old_keys=6, opened=False):
    gates = [13, 23, 33, 39, 41]
    wm = arr([obj([("W", number(2)),
                   ("E", b"\x12" + e.to_bytes(2, "little")),
                   ("S", number(3 if opened or e != 41 else 2))])
              for e in gates])
    wsk = arr([obj([("w", direct("egypt")),
                    ("k", number(old_keys))])])
    player = obj([("objclass", direct("PlayerInfo")),
                  ("objdata", obj([
                      ("n", direct("PRIVATE_USERNAME_DO_NOT_EMIT")),
                      ("c", number(coins)),
                      ("wsk", wsk),
                      ("wm", wm),
                  ]))])
    return b"RTON\x01\x00\x00\x00" + (
        text("version") + number(1) +
        text("objects") + arr([player]) + b"\xff"
    ) + b"DONE"


class ReadOnlyRtonSaveTests(unittest.TestCase):
    def test_closed_door_six_keys(self):
        result = summarize_player_save(sample())
        self.assertEqual(result["player_count"], 1)
        player = result["players"][0]
        self.assertEqual(player["coins"], 7800)
        self.assertFalse(player["gates"]["2"]["all_open"])
        self.assertEqual(player["world_keys"]["entries"],
                         [{"world": "egypt", "keys": 6}])
        self.assertNotIn("PRIVATE_USERNAME", json.dumps(result))

    def test_after_spend_door_open(self):
        player = summarize_player_save(
            sample(coins=7800, old_keys=1, opened=True)
        )["players"][0]
        self.assertTrue(player["gates"]["2"]["all_open"])
        self.assertEqual(player["world_keys"]["entries"][0]["keys"], 1)

    def test_after_possible_offline_reconciliation(self):
        player = summarize_player_save(
            sample(coins=8800, old_keys=0, opened=True)
        )["players"][0]
        self.assertEqual(player["coins"], 8800)
        self.assertEqual(player["world_keys"]["entries"][0]["keys"], 0)

    def test_archive_mirrors_and_no_write(self):
        data = sample()
        storage = io.BytesIO()
        root = "a/UserData/No_Backup/"
        with zipfile.ZipFile(storage, "w") as z:
            z.writestr(root + "pp.dat", data)
            z.writestr(root + "snapshot2.dat", data)
        before = storage.getvalue()
        report = inspect_archive(storage)
        self.assertEqual(report["snapshot2_comparison"], "IDENTICAL")
        self.assertTrue(report["read_only"])
        self.assertEqual(before, storage.getvalue())

    def test_different_mirror_detected(self):
        storage = io.BytesIO()
        root = "a/UserData/No_Backup/"
        with zipfile.ZipFile(storage, "w") as z:
            z.writestr(root + "pp.dat", sample())
            z.writestr(root + "snapshot2.dat", sample(coins=1))
        self.assertEqual(inspect_archive(storage)["snapshot2_comparison"],
                         "DIFFERENT")

    def test_missing_mirror(self):
        storage = io.BytesIO()
        with zipfile.ZipFile(storage, "w") as z:
            z.writestr("a/No_Backup/pp.dat", sample())
        self.assertEqual(inspect_archive(storage)["snapshot2_comparison"],
                         "MISSING")

    def test_duplicate_player_save_rejected(self):
        storage = io.BytesIO()
        with zipfile.ZipFile(storage, "w") as z:
            z.writestr("a/No_Backup/pp.dat", sample())
            z.writestr("b/No_Backup/pp.dat", sample())
        with self.assertRaises(RtonError):
            inspect_archive(storage)

    def test_rton_framing(self):
        for data in (b"", b"RTON", b"not an RTON file", sample()[:-2]):
            with self.assertRaises(RtonError):
                RtonReader(data)

    def test_wrong_array_count_fails_closed(self):
        data = sample()
        self.assertIn(b"\x86\xfd\x01", data)
        # Change objects array count to 2 but leave just one item.
        mutated = data.replace(b"\x86\xfd\x01", b"\x86\xfd\x02", 1)
        with self.assertRaises(RtonError):
            RtonReader(mutated).decode()

    def test_bad_interned_string(self):
        data = b"RTON\x01\x00\x00\x00\x91\x01\x24\x01\xffDONE"
        with self.assertRaises(RtonError):
            RtonReader(data).decode()

    def test_duplicate_mapping_key(self):
        data = b"RTON\x01\x00\x00\x00" + (
            text("x") + number(1) + text("x") + number(2)
        ) + b"\xffDONE"
        with self.assertRaises(RtonError):
            RtonReader(data).decode()

    def test_unsupported_token(self):
        data = b"RTON\x01\x00\x00\x00" + text("x") + b"\x99\xffDONE"
        with self.assertRaises(RtonError):
            RtonReader(data).decode()

    def test_unicode_value(self):
        # Character count 1, UTF-8 byte length 2.
        data = b"RTON\x01\x00\x00\x00" + (
            text("x") + b"\x82\x01\x02\xc3\xa9"
        ) + b"\xffDONE"
        self.assertEqual(RtonReader(data).decode(), {"x": "é"})

    def test_valid_cached_key(self):
        data = b"RTON\x01\x00\x00\x00" + (
            text("a") + number(1) +
            b"\x91\x00" + number(2)
        ) + b"\xffDONE"
        # Recalled duplicate key is forbidden, not silently overwritten.
        with self.assertRaises(RtonError):
            RtonReader(data).decode()

    def test_unknown_key_inventory_does_not_guess(self):
        self.assertEqual(describe_world_keys([{"secret": 12}])["status"],
                         "unknown_schema")
        self.assertEqual(describe_world_keys([{"w": "egypt", "k": 4},
                                               {"w": "egypt", "k": 1}])["status"],
                         "duplicate_world")


if __name__ == "__main__":
    unittest.main()
