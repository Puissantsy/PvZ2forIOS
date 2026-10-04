#!/usr/bin/env python3
"""Regression checks for KEYCONV replacement-Dynarmic startup compatibility."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_08.inc").read_text()

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
print("PASS: KEYCONV alone uses callback-backed guest memory and brackets JIT construction; parent modes retain V113")
