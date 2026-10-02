#!/usr/bin/env python3
"""Read-only source wiring invariant checks for the opt-in world-key probe.

This is intentionally NOT a substitute for an iOS compile or physical-iPad
verification. It verifies staging integration on an ordinary checkout.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PATHS = {
    "header": "platform/ios/src/pvz2_apk_probe.hpp",
    "root": "platform/ios/src/pvz2_apk_probe.cpp",
    "defs": "platform/ios/src/pvz2_apk_probe_parts/part_00.inc",
    "state": "platform/ios/src/pvz2_apk_probe_parts/part_01.inc",
    "modes": "platform/ios/src/pvz2_apk_probe_parts/part_02.inc",
    "svc": "platform/ios/src/pvz2_apk_probe_parts/part_04.inc",
    "install": "platform/ios/src/pvz2_apk_probe_parts/part_08.inc",
}
parts = {key: (ROOT / path).read_text() for key, path in PATHS.items()}

def require(cond, what):
    if not cond:
        raise AssertionError(what)

require("ResearchWorldKeyReadOnly = 200u" in parts["header"], "missing optional mode")
require(re.search(
    r"constexpr PvZ2DiagnosticMode kSelectableDiagnosticModes\[\]\s*=\s*\{\s*"
    r"PvZ2DiagnosticMode::ResearchWorldKeyReadOnly,\s*"
    r"PvZ2DiagnosticMode::V151ProductionQsortCompat,",
    parts["defs"]) is not None,
    "research branch launcher must choose opt-in key mode first")
require("V151ProductionQsortCompat ||\n               WorldKeyResearchEnabled()" in parts["modes"],
        "optional mode must inherit production qsort behavior")
require('world_key_event_view.hpp"' in parts["root"], "missing vetted event decoder")
require("WorldKeyReadOnlyGateSnapshot" in parts["state"], "missing guest bounds-check snapshot")
require("mem.Ptr(begin, end-begin) == nullptr" in parts["state"], "missing vector memory bounds")
require("WorldKeyReadOnlyWorldName" in parts["state"], "missing capped native string reader")
install = parts["install"]
start = install.index("if (callbacks.WorldKeyResearchEnabled()) {")
stop = install.index("    // v85 keeps only", start)
isolated = install[start:stop]
for off, word, marker in (
    ("0x0042ccd0u", "0xe1a0a000u", "kJniProbeSvcWorldKeyAddObserve"),
    ("0x005b846cu", "0xe3a03003u", "kJniProbeSvcWorldKeyGateBefore"),
    ("0x005b8474u", "0xe59f0088u", "kJniProbeSvcWorldKeyGateAfter"),
):
    require(off in isolated and word in isolated and marker in isolated,
            f"opt-in exact-instruction patch missing at {off}")
    require(marker not in install[stop:], f"probe leaked into unconditional patches: {marker}")
svc = parts["svc"]
require("regs[10] = regs[0];" in svc, "incorrect AddWorldKeys original MOV")
require("regs[3]=3u;" in svc, "incorrect gate original MOV")
require("regs[0]=mem.Read32Guest(kGuestBase+0x005b8504u);" in svc,
        "incorrect post-gate LDR emulation")
require("keyobs_grants_logged < 64u" in svc, "missing grant log cap")
require("keyobs_gate_pairs_logged < 16u" in svc, "missing gate log cap")
# The research branch must use a distinct sandbox from the real user install.
cmake = (ROOT / "platform/ios/CMakeLists.txt").read_text()
plist = (ROOT / "platform/ios/Info.plist.in").read_text()
for value in (cmake, plist):
    require("com.puissantsy.pvz2forios.keyobs" in value,
            "research build would overwrite the regular app sandbox")
require("keyobs_pending_gate_thread==current_probe_thread_id" in svc,
        "missing pre/post thread pairing")
print("PASS: opt-in research mode, exact three-point hooks, original-instruction emulation, bounded snapshot and logs")
