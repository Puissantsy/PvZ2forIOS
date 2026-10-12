#!/usr/bin/env python3
"""Static CI wiring checks for the pinned Dynarmic source dependency.

Production historically used Applesauce f488; KEYCONV now strictly requires the
device-proven LiveContainer c97c with the original iOS spinlock patch.
Do not accept an unpinned or mixed backend in either mode.
"""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
workflow=(ROOT/".github/workflows/build-ios-probe.yml").read_text()
cmake=(ROOT/"platform/ios/CMakeLists.txt").read_text()

def need(ok,msg):
    if not ok:
        raise AssertionError(msg)

old_url="https://github.com/johnny901901901/dynarmic.git"
old_sha="f488f760c69c42a97331961e8e6c359b46ccc9e9"
proven_url="https://github.com/lioncash/dynarmic.git"
proven_sha="c97c525ec1432b1e5404ebf091027738005ec168"
proven_tree="fd5b3ab282948fcdacc202ee11ee6d7aec339125"
if proven_url in workflow:
    need(proven_sha in workflow and old_url not in workflow,
         "KEYCONV must pin only physically proven Dynarmic c97c commit")
    need('git reset --hard "$DYN_SHA"' in workflow,
         "cached historical source must be reset before patching")
    need("actions/cache@v4" in workflow and proven_sha+"-upstream-v2" in workflow,
         "historical checkout must be cached under exact SHA")
    need('git apply --check "$GITHUB_WORKSPACE/platform/ios/patches/dynarmic-ios-nontxm.patch"' in workflow and
         'git apply "$GITHUB_WORKSPACE/platform/ios/patches/dynarmic-ios-nontxm.patch"' in workflow,
         "historical iOS spinlock patch is missing")
    need("m_xmem = (std::uint32_t\\*)mmap(nullptr, size, PROT_READ | PROT_EXEC" in workflow and
         "vm_remap(mach_task_self(), &wmem" in workflow and
         "mprotect(m_wmem, size, PROT_READ | PROT_WRITE)" in workflow and
         "if (DeviceHasTXM())" in workflow and
         "JIT26PrepareRegion(m_xmem, m_size)" in workflow,
         "historical RX-first dual-map/TXM allocator signatures missing")
    need(proven_tree in workflow, "actual immutable Dynarmic source tree not checked")
    need("https://github.com/LiveContainer/dynarmic.git" not in workflow,
         "missing old LiveContainer origin should not be cloned")
    source_name="verified Dynarmic c97c commit and tree from public upstream"
else:
    need(old_url in workflow and old_sha in workflow,
         "production must pin the exact public Applesauce Dynarmic gitlink")
    need("TARGET_OS_IPHONE" in workflow and "__atomic_exchange_n" in workflow,
         "production must assert proven iOS spin-lock implementation")
    source_name="verified Applesauce f488 public gitlink"

need('git submodule update --init --recursive' in workflow,
     "Dynarmic bundled externals must be materialized before CMake")
need('test "$(git rev-parse HEAD)" = "$DYN_SHA"' in workflow,
     "workflow must verify exact Dynarmic revision")
need('-DPVZ2_DYNARMIC_SOURCE_DIR="$PVZ2_DYNARMIC_SOURCE_DIR"' in workflow,
     "CMake must receive the staged exact source directory")
need('set(PVZ2_DYNARMIC_SOURCE_DIR "" CACHE PATH' in cmake,
     "CMake staged-source cache variable missing")
need("elseif(PVZ2_DYNARMIC_SOURCE_DIR)" in cmake,
     "CMake staged-source branch missing")
need('add_subdirectory(' in cmake and
     '"${PVZ2_DYNARMIC_SOURCE_DIR}"' in cmake and
     'EXCLUDE_FROM_ALL' in cmake,
     "exact Dynarmic source is not added as a subproject")
need('if(NOT TARGET dynarmic)' in cmake,
     "CMake must verify staged source exported target dynarmic")
need('set(DYNARMIC_FRONTENDS "A32"' in cmake and
     'set(DYNARMIC_USE_BUNDLED_EXTERNALS ON' in cmake and
     'set(DYNARMIC_USE_LLVM OFF' in cmake,
     "PvZ2's known Dynarmic configuration was not preserved")
print("PASS: "+source_name+" is pinned, recursively staged and wired into CMake")
