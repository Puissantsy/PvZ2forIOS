#!/usr/bin/env python3
"""Patch the pinned public Dynarmic/Oaknut CodeBlock for A14 pre-TXM JIT.

The public f488 iOS fork assumes every physical iOS device uses the TXM-era
BRK #0xf00d broker + RX/RW dual mapping. The PvZ2 target iPad is A14/pre-TXM
and is launched under StikDebug with CS_DEBUGGED, where the classic debugger
JIT model can keep one anonymous code mapping RWX.

A same-address RX<->RW mprotect toggle is NOT safe for Dynarmic: its generated
dispatcher calls GetOrEmit() while executing inside that very code cache.
Removing EXEC from the current mapping during emission faults immediately.
"""

from pathlib import Path
import sys

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    ".deps/dynarmic/externals/oaknut/include/oaknut/code_block.hpp"
)
source = path.read_text()

physical_guard = (
    "defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR"
)
guard_count = source.count(physical_guard)
if guard_count != 7:
    raise SystemExit(
        f"unexpected f488 physical-iOS guard count: {guard_count} (expected 7)"
    )

# Compile the broker-only structures/calls out when PvZ2 explicitly selects its
# pre-TXM path. This also makes the existing m_wmemory=m_memory fallback apply.
source = source.replace(
    physical_guard,
    physical_guard + " && !defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)",
)

old_fallback = """#    elif TARGET_OS_IPHONE
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);"""

new_fallback = """#    elif TARGET_OS_IPHONE
#        if defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)
        // A14/pre-TXM + CS_DEBUGGED: Dynarmic must be able to emit new host
        // blocks while its dispatcher is executing from the same cache.
        // Keep one mapping RWX; toggling that same mapping to RW would remove
        // EXEC under the current PC during GetOrEmit().
        m_memory = (std::uint32_t*)mmap(
            nullptr,
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0);
        if (m_memory == MAP_FAILED) {
            // Some pre-TXM kernels reject RWX at mmap time but allow adding
            // EXEC after StikDebug has attached. Preserve RWX afterwards.
            m_memory = (std::uint32_t*)mmap(
                nullptr,
                size,
                PROT_READ | PROT_WRITE,
                MAP_ANON | MAP_PRIVATE,
                -1,
                0);
            if (m_memory != MAP_FAILED &&
                mprotect(
                    m_memory,
                    size,
                    PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                munmap(m_memory, size);
                m_memory = (std::uint32_t*)MAP_FAILED;
            }
        }
#        else
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#        endif"""

if source.count(old_fallback) != 1:
    raise SystemExit("expected exactly one f488 iPhone fallback allocation")
source = source.replace(old_fallback, new_fallback)

# The physical forced branch must leave CodeBlock::protect/unprotect as no-ops.
# f488 only mprotects on the iOS simulator, so do not broaden those conditions.
if "TARGET_OS_SIMULATOR || defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)" in source:
    raise SystemExit("unsafe physical-iOS mprotect toggle is still present")
if source.count("PROT_READ | PROT_WRITE | PROT_EXEC") < 2:
    raise SystemExit("pre-TXM RWX allocation/fallback was not installed")

path.write_text(source)
print(
    "PASS: patched f488 Oaknut for A14/pre-TXM single-map RWX; "
    "TXM BRK broker remains available only outside PVZ2 forced mode"
)
