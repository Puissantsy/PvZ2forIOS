#!/usr/bin/env python3
"""Patch pinned f488 Dynarmic/Oaknut for the project's A14 non-TXM JIT path.

The public f488 iOS fork assumes physical iOS uses a BRK #0xf00d JIT broker.
That broker is not the protocol used by this project's A14 StikDebug flow.

The historical PvZ2 Dynarmic fork was explicitly wired for dual-mapped
executable memory: one permanent RW alias for Oaknut emission and one permanent
RX alias for execution. Recreate that contract on the pinned public source.
"""
from pathlib import Path
import sys

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    ".deps/dynarmic/externals/oaknut/include/oaknut/code_block.hpp"
)
source = path.read_text()

force = "PVZ2_DYNARMIC_FORCE_NONTXM_JIT"

# Broker helpers are not compiled in the isolated A14 path.
namespace_guard = (
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR\n"
    "namespace detail {"
)
if source.count(namespace_guard) != 1:
    raise SystemExit("unexpected f488 physical-iOS broker namespace")
source = source.replace(
    namespace_guard,
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR && "
    f"!defined({force})\nnamespace detail {{",
    1,
)

# Split the physical-device allocation branch: forced PvZ2 mode uses the
# standard Oaknut dual-map pattern (RW primary mapping + RX vm_remap alias);
# all other physical-iOS builds keep f488's broker path untouched.
alloc_anchor = """#    if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
        auto& reusable_region = detail::reusable_jit_region();"""
if source.count(alloc_anchor) != 1:
    raise SystemExit("unexpected f488 physical-iOS allocation anchor")
forced_alloc = f"""#    if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
#        if defined({force})
        m_wmemory = (std::uint32_t*)mmap(
            nullptr,
            size,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0);
        if (m_wmemory == MAP_FAILED) {{
            m_wmemory = nullptr;
            throw std::bad_alloc{{}};
        }}

        vm_prot_t current_protection = 0;
        vm_prot_t maximum_protection = 0;
        vm_address_t executable_address = 0;
        const kern_return_t remap_result = vm_remap(
            mach_task_self(),
            &executable_address,
            size,
            0,
            VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
            mach_task_self(),
            reinterpret_cast<mach_vm_address_t>(m_wmemory),
            false,
            &current_protection,
            &maximum_protection,
            VM_INHERIT_NONE);
        if (remap_result != KERN_SUCCESS) {{
            munmap(m_wmemory, size);
            m_wmemory = nullptr;
            throw std::bad_alloc{{}};
        }}

        m_memory = reinterpret_cast<std::uint32_t*>(executable_address);
        if (vm_protect(
                mach_task_self(),
                executable_address,
                size,
                false,
                VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {{
            munmap(m_memory, size);
            munmap(m_wmemory, size);
            m_memory = nullptr;
            m_wmemory = nullptr;
            throw std::bad_alloc{{}};
        }}
#        else
        auto& reusable_region = detail::reusable_jit_region();"""
source = source.replace(alloc_anchor, forced_alloc, 1)

alloc_tail = """            m_should_detach_jit_server = true;
        }
#    elif TARGET_OS_IPHONE"""
if source.count(alloc_tail) != 1:
    raise SystemExit("unexpected f488 physical-iOS allocation tail")
source = source.replace(
    alloc_tail,
    """            m_should_detach_jit_server = true;
        }
#        endif
#    elif TARGET_OS_IPHONE""",
    1,
)

# Physical iOS already keeps protect()/unprotect() as no-ops, which is exactly
# what a permanent dual mapping requires. Ensure the generic post-constructor
# m_wmemory=m_memory assignment does not affect this branch (f488 already
# excludes all physical iOS from that assignment).

# Free both aliases in forced mode; retain f488's reusable broker region logic
# for all other physical devices.
destructor_anchor = """#    if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
        auto& reusable_region = detail::reusable_jit_region();"""
if source.count(destructor_anchor) != 1:
    raise SystemExit("unexpected f488 physical-iOS destructor anchor")
source = source.replace(
    destructor_anchor,
    f"""#    if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
#        if defined({force})
        if (m_wmemory != nullptr) {{
            munmap(m_wmemory, m_size);
            m_wmemory = nullptr;
        }}
#        else
        auto& reusable_region = detail::reusable_jit_region();""",
    1,
)

destructor_tail = """        munmap(m_wmemory, m_size);
#    endif
        munmap(m_memory, m_size);"""
if source.count(destructor_tail) != 1:
    raise SystemExit("unexpected f488 physical-iOS destructor tail")
source = source.replace(
    destructor_tail,
    """        munmap(m_wmemory, m_size);
#        endif
#    endif
        munmap(m_memory, m_size);""",
    1,
)

# Forced mode has no external broker to detach from and no broker-only field.
for old in [
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR\n"
    "        if (m_should_detach_jit_server) {",
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR\n"
    "    bool m_should_detach_jit_server = false;",
]:
    if source.count(old) != 1:
        raise SystemExit("unexpected f488 broker-only guard")
source = source.replace(
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR\n"
    "        if (m_should_detach_jit_server) {",
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR && "
    f"!defined({force})\n        if (m_should_detach_jit_server) {{",
    1,
)
source = source.replace(
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR\n"
    "    bool m_should_detach_jit_server = false;",
    "#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR && "
    f"!defined({force})\n    bool m_should_detach_jit_server = false;",
    1,
)

# Contract checks on the generated source.
needles = [
    "m_wmemory = (std::uint32_t*)mmap(",
    "PROT_READ | PROT_WRITE",
    "const kern_return_t remap_result = vm_remap(",
    "VM_PROT_READ | VM_PROT_EXECUTE",
    f"!defined({force})",
]
for needle in needles:
    if needle not in source:
        raise SystemExit(f"dual-map patch missing generated marker: {needle}")
if "TARGET_OS_SIMULATOR || defined(PVZ2_DYNARMIC_FORCE_NONTXM_JIT)" in source:
    raise SystemExit("forced physical mode must not use same-map mprotect toggles")

path.write_text(source)
print(
    "PASS: patched f488 Oaknut for A14/pre-TXM permanent RW/RX dual mapping; "
    "BRK #0xf00d broker remains untouched outside PVZ2 forced mode"
)
