#!/usr/bin/env python3
"""Regression checks for KEYCONV replacement-Dynarmic startup compatibility."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_08.inc").read_text()
cmake=(ROOT/"platform/ios/CMakeLists.txt").read_text()
workflow=(ROOT/".github/workflows/build-ios-probe.yml").read_text()
patch=(ROOT/"platform/ios/patches/dynarmic-ios-a14-nontxm-codeblock.patch").read_text()

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
     "missing runtime compatibility marker")
need("KEYCONV JIT BACKEND: A14/pre-TXM legacy W^X forced; BRK #0xf00d broker disabled." in src,
     "missing runtime marker for the physical-iPad JIT backend")
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

# The public f488 iOS fork enters an external broker with BRK #0xf00d on every
# physical iOS CodeBlock. This project's target iPad is A14/pre-TXM and uses
# the already-established StikDebug non-TXM W^X path, so the active build must
# compile the broker branch out and restore mmap(RX) <-> mprotect(RW).
need("PVZ2_DYNARMIC_FORCE_NONTXM_JIT=1" in cmake,
     "Dynarmic target is not forced onto the pre-TXM code-cache path")
need("dynarmic-ios-a14-nontxm-codeblock.patch" in workflow and
     'git apply "$GITHUB_WORKSPACE/platform/ios/patches/dynarmic-ios-a14-nontxm-codeblock.patch"' in workflow,
     "IPA workflow does not apply the pinned f488 pre-TXM CodeBlock patch")
need("!defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)" in patch,
     "CodeBlock patch does not compile the BRK broker out")
need("TARGET_OS_SIMULATOR || defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)" in patch,
     "CodeBlock patch does not restore mprotect W^X on physical pre-TXM iOS")
need("brk #0xf00d" not in patch,
     "project patch must not introduce a new broker trap")

print("PASS: KEYCONV keeps callback guest memory and forces the A14/pre-TXM Dynarmic W^X code-cache path; parent V113 behavior remains isolated")
