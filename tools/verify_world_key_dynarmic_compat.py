#!/usr/bin/env python3
"""Regression checks for KEYCONV replacement-Dynarmic startup compatibility."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_08.inc").read_text()
log_filter=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_02.inc").read_text()
cmake=(ROOT/"platform/ios/CMakeLists.txt").read_text()
workflow=(ROOT/".github/workflows/build-ios-probe.yml").read_text()
patcher=(ROOT/"tools/patch_dynarmic_a14_nontxm.py").read_text()

def need(ok,msg):
    if not ok:
        raise AssertionError(msg)

need("const bool keyconv_callback_memory =\n            callbacks.WorldKeyConversionEnabled();" in src,
     "KEYCONV-specific memory compatibility gate missing")
need("callbacks.V113Enabled() &&\n            !keyconv_callback_memory" in src,
     "validated parent modes must retain their V113 page table")
need("config.page_table = nullptr;" in src and
     "callbacks.V113AttachPageTable(nullptr);" in src,
     "active mode must explicitly remain callback-backed")
need("KEYCONV DYNARMIC COMPAT: V113/V115/V116 direct page table disabled" in src,
     "missing runtime callback-memory marker")
need("KEYCONV JIT BACKEND: A14/pre-TXM single-map RWX forced; BRK #0xf00d broker disabled." in src,
     "missing runtime marker for the A14 single-map RWX backend")
need("KEYCONV JIT CONSTRUCT BEGIN pageTable=" in src and
     "KEYCONV JIT CONSTRUCT END" in src,
     "must bracket replacement-Dynarmic JIT construction for physical acceptance")

# There is an older JNI-only Jit constructor earlier in part_08; scope to full-load KEYCONV.
begin=src.index("KEYCONV JIT CONSTRUCT BEGIN")
jit=src.index("Dynarmic::A32::Jit jit{config}", begin)
end=src.index("KEYCONV JIT CONSTRUCT END", jit)
need(begin < jit < end,
     "JIT diagnostic markers do not actually bracket full-load construction")

# Don't globally turn V113 off: the proven KEYOBS parent still needs its original behavior.
need("if (callbacks.V113Enabled() &&\n            !keyconv_callback_memory)" in src,
     "page table disable leaked beyond active conversion mode")

# The public f488 iOS fork enters an external broker with BRK #0xf00d on physical
# iOS. The project target is A14/pre-TXM under StikDebug/CS_DEBUGGED, so this
# isolated build uses one persistent RWX mapping. A single RX<->RW mapping is
# invalid for Dynarmic because its generated dispatcher calls GetOrEmit() while
# executing inside the code cache itself.
need("PVZ2_DYNARMIC_FORCE_NONTXM_JIT=1" in cmake,
     "Dynarmic target is not forced onto the A14/pre-TXM path")
need("single-map RWX Dynarmic code cache" in cmake,
     "CMake does not document the required persistent RWX code-cache contract")
need("tools/patch_dynarmic_a14_nontxm.py" in workflow and
     'python3 "$GITHUB_WORKSPACE/tools/patch_dynarmic_a14_nontxm.py"' in workflow,
     "IPA workflow does not invoke the exact f488 A14 patcher")
need("PROT_READ | PROT_WRITE | PROT_EXEC" in patcher,
     "A14 patcher does not create/upgrade to persistent RWX")
need("PVZ2_DYNARMIC_FORCE_NONTXM_JIT" in patcher,
     "A14 patcher does not compile the broker branch out")
need("TARGET_OS_SIMULATOR || defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)" not in patcher,
     "unsafe forced-mode RX<->RW mprotect condition reintroduced")
need("CHECKPOINT constructor[" in log_filter and
     "WorldKeyConversionEnabled()" in log_filter,
     "KEYCONV constructor breadcrumbs are not exempt from performance filtering")

print(
    "PASS: KEYCONV keeps callback guest memory, forces A14/pre-TXM persistent "
    "single-map RWX Dynarmic code cache, and preserves constructor breadcrumbs; "
    "parent V113 behavior remains isolated"
)
