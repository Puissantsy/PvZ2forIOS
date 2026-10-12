#!/usr/bin/env python3
"""No file I/O: test targeted numeric RTON patch candidate in a byte buffer."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from experimental_keyconv_rton_memory import (
    IndexedRtonReader, RtonError, encode_preserving_integer_tag,
    in_memory_egypt_surplus_candidate,
)
from test_readonly_rton_save import sample, number, var


class InMemoryRtonMutationTests(unittest.TestCase):
    def test_single_surplus_key_changes_only_two_fields(self):
        original = sample(coins=7800, old_keys=1, opened=True)
        changed, report = in_memory_egypt_surplus_candidate(original, 0)
        self.assertTrue(report["changed"])
        self.assertEqual(report["modified_token_count"], 2)
        self.assertEqual(report["key_count"], 1)
        self.assertEqual(report["coins_before"], 7800)
        self.assertEqual(report["coins_after"], 8800)
        p = IndexedRtonReader(changed).decode()["objects"][0]["objdata"]
        self.assertEqual(p["c"], 8800)
        self.assertEqual(p["wsk"][0]["kc"], 0)
        self.assertEqual(p["n"], "PRIVATE_USERNAME_DO_NOT_EMIT")

    def test_no_second_credit_after_first_conversion(self):
        original = sample(coins=7800, old_keys=1, opened=True)
        once, _ = in_memory_egypt_surplus_candidate(original, 0)
        twice, info = in_memory_egypt_surplus_candidate(once, 0)
        self.assertEqual(once, twice)
        self.assertFalse(info["changed"])
        self.assertEqual(info["status"], "NO_ELIGIBLE_OLD_KEYS")

    def test_closed_gate_preserves_every_byte(self):
        original = sample(coins=7800, old_keys=6, opened=False)
        updated, info = in_memory_egypt_surplus_candidate(original, 0)
        self.assertEqual(updated, original)
        self.assertEqual(info["status"], "GATES_NOT_ALL_OPEN")

    def test_wallet_overflow_refused(self):
        original = sample(coins=0x7fffffff, old_keys=1, opened=True)
        with self.assertRaisesRegex(RtonError, "overflow"):
            in_memory_egypt_surplus_candidate(original, 0)

    def test_wrong_profile_refused(self):
        with self.assertRaises(RtonError):
            in_memory_egypt_surplus_candidate(sample(opened=True), 1)

    def test_varint_increase_maintains_full_rton(self):
        original = sample(coins=16380, old_keys=5, opened=True)
        changed, info = in_memory_egypt_surplus_candidate(original, 0)
        self.assertEqual(info["coins_after"], 21380)
        decoded = IndexedRtonReader(changed).decode()
        self.assertEqual(decoded["objects"][0]["objdata"]["c"], 21380)
        self.assertEqual(decoded["objects"][0]["objdata"]["wsk"][0]["kc"], 0)

    def test_integer_codec(self):
        self.assertEqual(encode_preserving_integer_tag(36, 1000),
                         number(1000))
        self.assertEqual(encode_preserving_integer_tag(10, 42),
                         b"\x0a*")
        self.assertEqual(encode_preserving_integer_tag(38, 1000),
                         b"\x26\xe8\x03\x00\x00")
        with self.assertRaises(RtonError):
            encode_preserving_integer_tag(10, 1000)
        with self.assertRaises(RtonError):
            encode_preserving_integer_tag(36, -1)

    def test_parser_index_maps_to_actual_native_fields(self):
        reader = IndexedRtonReader(
            sample(coins=7800, old_keys=1, opened=True))
        reader.decode()
        c = reader.integer_spans[("objects", 0, "objdata", "c")]
        k = reader.integer_spans[
            ("objects", 0, "objdata", "wsk", 0, "kc")]
        self.assertEqual((c[2], c[3]), (36, 7800))
        self.assertEqual((k[2], k[3]), (36, 1))

    def test_malformed_player_info_refused(self):
        with self.assertRaises(RtonError):
            in_memory_egypt_surplus_candidate(
                b"RTON\x01\x00\x00\x00\xffDONE", 0)


if __name__ == "__main__":
    unittest.main()
