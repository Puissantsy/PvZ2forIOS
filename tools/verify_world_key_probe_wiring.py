#!/usr/bin/env python3
"""Source wiring invariant checks for the opt-in world-key read-only/active probes.

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

require("ResearchWorldKeyReadOnly = 200u" in parts["header"], "missing read-only mode")
require("ResearchWorldKeyConvert = 201u" in parts["header"], "missing active conversion mode")
require(re.search(
    r"constexpr PvZ2DiagnosticMode kSelectableDiagnosticModes\[\]\s*=\s*\{[^}]*"
    r"PvZ2DiagnosticMode::ResearchWorldKeyConvert,\s*"
    r"PvZ2DiagnosticMode::ResearchWorldKeyReadOnly,\s*"
    r"PvZ2DiagnosticMode::V151ProductionQsortCompat,",
    parts["defs"], re.S) is not None,
    "active child branch launcher must choose conversion mode first and retain read-only fallback")
require("V151ProductionQsortCompat ||\n               WorldKeyResearchEnabled()" in parts["modes"],
        "optional mode must inherit production qsort behavior")
require('world_key_event_view.hpp"' in parts["root"], "missing vetted event decoder")
require("WorldKeyReadOnlyGateSnapshot" in parts["state"], "missing guest bounds-check snapshot")
require(re.search(r"mem\.Ptr\(begin,\s*end-begin\)\s*==\s*nullptr", parts["state"]) is not None,
        "missing vector memory bounds")
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
require("regs[10]=regs[0];" in svc, "fail-open path must reproduce AddWorldKeys original MOV")
require("regs[3]=3u;" in svc, "incorrect gate original MOV")
require("regs[0]=mem.Read32Guest(kGuestBase+0x005b8504u);" in svc,
        "incorrect post-gate LDR emulation")
# Regression: the v85/v118 production-performance filter discards Legacy
# lines that don't start with allowed Vxx prefixes. The first physical KEYOBS
# log had no GRANT/GATE events for precisely this reason; every opt-in marker
# MUST use Diagnostic, whose ShouldKeepLogLine path bypasses that filter.
for marker in (
    "KEYOBS GATE_BEFORE", "KEYOBS GATE_AFTER ",
    "KEYOBS GATE_AFTER no matching", "KEYOBS GATE logs capped",
    "KEYCONV APPLY world=", "KEYCONV FAIL_OPEN preserve original key world=",
):
    require(marker in svc,
            "world-key evidence missing from active SVC source: "+marker)
require("KEYCONV GRANT_PRE sourceLR=0x" in svc and
        "KEYOBS GRANT_PRE sourceLR=0x" in svc,
        "active/read-only grant logs must share the unfiltered diagnostic path")
require('callbacks.AppendDiagnostic("KEYOBS READ ONLY installed' in install,
        "missing installation signature in visible diagnostic channel")
require('Append("KEYOBS' not in svc and 'callbacks.Append("KEYOBS' not in install,
        "KEYOBS incorrectly passed to legacy performance filter")
require("log_class == ProbeLogClass::Diagnostic" in
        (ROOT / "platform/ios/src/pvz2_apk_probe_parts/part_02.inc").read_text(),
        "diagnostic channel no longer guaranteed to bypass legacy filters")
require('line.rfind("V144 SELECTION DRAW ", 0u) == 0u' in
        (ROOT / "platform/ios/src/pvz2_apk_probe_parts/part_08.inc").read_text(),
        "research graphics log noise guard missing")
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
print("PASS: active/read-only research modes, exact hooks, fail-open native path, bounded snapshots and unfiltered logs")
