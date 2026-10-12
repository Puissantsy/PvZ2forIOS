#!/usr/bin/env python3
"""Cross-language, synthetic-only C++20 vs tested Python exact RTON tokens."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(HERE)]
from test_readonly_rton_save import sample
from experimental_keyconv_rton_memory import in_memory_egypt_surplus_candidate


class NativeRtonParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="keyconv-native-synthetic-")
        cls.cli = Path(cls.temp.name) / "native_fixture_converter"
        compile_result = subprocess.run([
            "clang++", "-std=c++20", "-O1", "-Wall", "-Wextra",
            "-Werror", "-pedantic", "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-I" + str(HERE), str(HERE / "keyconv_rton_native_cli.cpp"),
            "-o", str(cls.cli)
        ], text=True, capture_output=True)
        if compile_result.returncode:
            raise AssertionError(compile_result.stdout + compile_result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_converter(self, original, slot=0):
        with tempfile.TemporaryDirectory(prefix="keyconv-native-input-") as tmp:
            source = Path(tmp) / "input.rton"
            output = Path(tmp) / "output.rton"
            source.write_bytes(original)
            proc = subprocess.run([str(self.cli), str(source), str(output), str(slot)],
                                  capture_output=True, text=True)
            return proc, output.read_bytes() if output.exists() else None, source.read_bytes()

    def test_exact_byte_parity_across_varint_sizes(self):
        for keys,coins in ((1,7800),(5,16380),(6,16380),(99,1000),
                           (1,0),(99,0x7fffffff-99000)):
            with self.subTest(keys=keys,coins=coins):
                original=sample(coins=coins,old_keys=keys,opened=True)
                python_bytes, report=in_memory_egypt_surplus_candidate(original,0)
                process, cxx_bytes, source_bytes=self.run_converter(original)
                self.assertEqual(process.returncode,0,process.stderr)
                self.assertEqual(process.stdout.strip(),"CONVERTED")
                self.assertEqual(cxx_bytes,python_bytes)
                self.assertEqual(source_bytes,original)
                self.assertTrue(report["changed"])

    def test_fallback_coins_remain_independent(self):
        original=sample(coins=7801,old_keys=1,opened=True)
        python_bytes,_=in_memory_egypt_surplus_candidate(original,0)
        process,cxx_bytes,_=self.run_converter(original)
        self.assertEqual(process.returncode,0,process.stderr)
        self.assertEqual(cxx_bytes,python_bytes)
        self.assertNotEqual(cxx_bytes,
                            in_memory_egypt_surplus_candidate(
                                sample(coins=7800,old_keys=1,opened=True),0)[0])

    def test_closed_last_gate_is_exact_noop(self):
        original=sample(coins=7800,old_keys=6,opened=False)
        proc,converted,_=self.run_converter(original)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(proc.stdout.strip(),"NOOP")
        self.assertEqual(converted,original)

    def test_empty_stock_then_no_double_credit(self):
        first=sample(coins=7800,old_keys=1,opened=True)
        proc,once,_=self.run_converter(first)
        self.assertEqual(proc.returncode,0,proc.stderr)
        proc2,twice,_=self.run_converter(once)
        self.assertEqual(proc2.returncode,0,proc2.stderr)
        self.assertEqual(proc2.stdout.strip(),"NOOP")
        self.assertEqual(twice,once)

    def test_overflow_rejected_no_output(self):
        original=sample(coins=0x7fffffff,old_keys=1,opened=True)
        proc,converted,_=self.run_converter(original)
        self.assertEqual(proc.returncode,2)
        self.assertIsNone(converted)

    def test_wrong_player_slot_rejected(self):
        original=sample(coins=7800,old_keys=1,opened=True)
        proc,converted,_=self.run_converter(original,slot=1)
        self.assertEqual(proc.returncode,2)
        self.assertIsNone(converted)

    def test_unsupported_tag_rejected(self):
        original=sample(opened=True)
        corrupted=original.replace(b"\x85",b"\x99",1)
        self.assertNotEqual(original,corrupted)
        proc,converted,_=self.run_converter(corrupted)
        self.assertEqual(proc.returncode,2)
        self.assertIsNone(converted)

    def test_unknown_world_rejected(self):
        original=sample(opened=True,old_keys=1)
        corrupted=original.replace(b"egypt",b"other",1)
        self.assertNotEqual(original,corrupted)
        proc,converted,_=self.run_converter(corrupted)
        self.assertEqual(proc.returncode,2)
        self.assertIsNone(converted)


if __name__=="__main__":
    unittest.main()
