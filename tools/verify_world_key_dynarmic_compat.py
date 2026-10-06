#!/usr/bin/env python3
"""Regression checks for KEYCONV restoration to the proven Dynarmic runtime."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_08.inc").read_text()
log_filter=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_02.inc").read_text()
cmake=(ROOT/"platform/ios/CMakeLists.txt").read_text()
workflow=(ROOT/".github/workflows/build-ios-probe.yml").read_text()

def need(ok,msg):
    if not ok:
        raise AssertionError(msg)

need("const bool keyconv_callback_memory" not in src,
     "temporary KEYCONV callback-memory workaround is still present")
need("config.page_table = nullptr;" not in src,
     "temporary KEYCONV page-table disable is still present")
need("if (callbacks.V113Enabled()) {" in src and
     "config.page_table = v113_page_table.get();" in src and
     "callbacks.V113AttachPageTable(" in src,
     "validated V113 direct page table was not restored")
need("KEYCONV DYNARMIC RESTORE: exact proven LiveContainer c97c525e + historical V113 direct page table." in src,
     "missing historical runtime restoration marker")
need("KEYCONV JIT BACKEND: exact proven LiveContainer c97c525e allocator; native A14/TXM policy preserved." in src,
     "missing exact historical Dynarmic runtime marker")
need("KEYCONV JIT CONSTRUCT BEGIN pageTable=" in src and
     "KEYCONV JIT CONSTRUCT END" in src,
     "JIT construction must remain bracketed")
need("KEYCONV FIRST CONSTRUCTOR RUN BEGIN" in src and
     "KEYCONV FIRST CONSTRUCTOR RUN END" in src,
     "first guest dispatch must remain bracketed")

begin=src.index("KEYCONV JIT CONSTRUCT BEGIN")
jit=src.index("Dynarmic::A32::Jit jit{config}", begin)
end=src.index("KEYCONV JIT CONSTRUCT END", jit)
need(begin < jit < end,
     "JIT diagnostics do not bracket full-load construction")

sha="c97c525ec1432b1e5404ebf091027738005ec168"
need("https://github.com/LiveContainer/dynarmic.git" in workflow,
     "workflow is not cloning LiveContainer/dynarmic")
need(sha in workflow and sha in cmake,
     "historical Dynarmic SHA is not pinned consistently")
need("johnny901901901/dynarmic" not in workflow,
     "replacement f488 Dynarmic still appears in active workflow")
need("patch_dynarmic_a14_nontxm.py" not in workflow,
     "experimental allocator patcher is still active")
need("PVZ2_DYNARMIC_FORCE_NONTXM_JIT" not in cmake,
     "experimental allocator compile override is still active")
need('git apply "$GITHUB_WORKSPACE/platform/ios/patches/dynarmic-ios-nontxm.patch"' in workflow,
     "historical iOS spinlock patch is not applied")
need("m_xmem = (std::uint32_t\\*)mmap(nullptr, size, PROT_READ | PROT_EXEC" in workflow,
     "workflow does not assert RX-first historical allocator")
need("vm_remap(mach_task_self(), &wmem" in workflow,
     "workflow does not assert historical RX-to-RW vm_remap")
need("mprotect(m_wmem, size, PROT_READ | PROT_WRITE)" in workflow,
     "workflow does not assert historical RW alias protection")
need("if (DeviceHasTXM())" in workflow and
     "JIT26PrepareRegion(m_xmem, m_size)" in workflow,
     "workflow does not assert native A14/TXM allocator policy")
need("CHECKPOINT constructor[" in log_filter and
     "WorldKeyConversionEnabled()" in log_filter,
     "KEYCONV constructor breadcrumbs are not exempt from performance filtering")

print(
    "PASS: KEYCONV is back on the exact proven c97c LiveContainer Dynarmic, "
    "historical iOS spinlock patch and validated V113 direct page table; "
    "first guest dispatch remains instrumented"
)
