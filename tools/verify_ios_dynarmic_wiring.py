#!/usr/bin/env python3
"""Static CI wiring checks for the exact public iOS Dynarmic source dependency."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
workflow=(ROOT/".github/workflows/build-ios-probe.yml").read_text()
cmake=(ROOT/"platform/ios/CMakeLists.txt").read_text()

def need(ok,msg):
    if not ok:
        raise AssertionError(msg)

URL="https://github.com/johnny901901901/dynarmic.git"
SHA="f488f760c69c42a97331961e8e6c359b46ccc9e9"

need(URL in workflow and SHA in workflow,
     "build workflow must pin the exact public Applesauce Dynarmic gitlink")
need('git submodule update --init --recursive' in workflow,
     "Dynarmic bundled externals must be materialized before CMake")
need('test "$(git rev-parse HEAD)" = "$DYN_SHA"' in workflow,
     "workflow must verify exact Dynarmic revision")
need("TARGET_OS_IPHONE" in workflow and "__atomic_exchange_n" in workflow,
     "workflow must assert the proven iOS spin-lock implementation")
need('-DPVZ2_DYNARMIC_SOURCE_DIR="$PVZ2_DYNARMIC_SOURCE_DIR"' in workflow,
     "CMake must receive the staged exact source directory")
need("PVZ2_PREBUILT_DYNARMIC_ROOT=\"$PVZ2_DYNARMIC_ROOT\"" not in workflow,
     "dead LiveExec32 prebuilt path still drives CI")

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
print("PASS: exact public Applesauce iOS Dynarmic gitlink is pinned, recursively staged and wired into CMake source build")
