#!/usr/bin/env python3
"""No-IPA checks for the exact historical Dynarmic integration in functional Probe V151."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
runtime=(root/"platform/ios/src/pvz2_apk_probe_parts/part_08.inc").read_text()
modes=(root/"platform/ios/src/pvz2_apk_probe_parts/part_00.inc").read_text()
cmake=(root/"platform/ios/CMakeLists.txt").read_text()
workflow=(root/".github/workflows/build-ios-probe.yml").read_text()
launcher=(root/"platform/ios/src/main.mm").read_text()
sha="c97c525ec1432b1e5404ebf091027738005ec168"
tree="fd5b3ab282948fcdacc202ee11ee6d7aec339125"
def require(ok, label):
    if not ok: raise AssertionError(label)
require("config.page_table = nullptr;" not in runtime,"V113 direct page table disabled")
require("const bool keyconv_callback_memory" not in runtime,"temporary callback-memory workaround reintroduced")
require("config.page_table = v113_page_table.get();" in runtime,"historical V113 direct page table missing")
require("callbacks.V113AttachPageTable(" in runtime,"historical V113 attach missing")
require("Dynarmic::A32::Jit jit{config}" in runtime,"Dynarmic runtime construction missing")
require("CHECKPOINT constructor[" in runtime,"original constructor checkpoints missing")
require(modes.count("PvZ2DiagnosticMode::V151ProductionQsortCompat")>=2,"V151 functional capability missing")
require("ResearchWorldKeyConvert" not in modes,"KEYOBS diagnostic mode leaked into Probe")
require("PVZ2_KEYCONV_PROBE_BUILD=1" in cmake,"Probe build isolation disabled")
require("PVZ2_KEYCONV_RESEARCH_BUILD=1" not in cmake,"KEYOBS isolation leaked into Probe")
require("com.puissantsy.pvz2forios.keyobs" not in cmake,"incorrect research bundle")
require(sha in cmake and sha in workflow and tree in workflow,"Dynarmic SHA/tree not pinned")
require("https://github.com/lioncash/dynarmic.git" in workflow,"historical source origin missing")
require('git apply "$GITHUB_WORKSPACE/platform/ios/patches/dynarmic-ios-nontxm.patch"' in workflow,"historical spinlock patch missing")
require("PVZ2_DYNARMIC_FORCE_NONTXM_JIT" not in cmake,"allocator forcing enabled")
require("patch_dynarmic_a14_nontxm.py" not in workflow,"experimental allocator patch reintroduced")
require("vm_remap(mach_task_self(), &wmem" in workflow,"dual-map allocator check missing")
require("if (DeviceHasTXM())" in workflow,"native A14/TXM policy check missing")
require("JIT26PrepareRegion(m_xmem, m_size)" in workflow,"historical TXM check missing")
require("self.keyconvRewardOptIn == YES" in launcher,"Probe Egypt award opt-in not forwarded")
require("0x0042ccd0u,0xe1a0a000u,kJniProbeSvcWorldKeyAddObserve" in runtime,"exact additive key hook signature absent")
print("PASS: Probe V151 + optional Egypt reward SVC on exact c97c Dynarmic; historical allocator unchanged")
