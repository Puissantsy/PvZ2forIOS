#!/usr/bin/env python3
"""Read-only exact-ELF key-grant callsite coverage; user supplies their own ELF.

Does not patch the binary, infer in-game event provenance, or alter saves.
"""
import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA = "f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f"
ADD_WORLD_KEYS = 0x42CCC8
# RVAs found via full ARM-mode .text BL scan. Group names are static hints,
# not proof of actual device-level reward provenance.
CALLS = {
    0x161E60: ("generic-present-dispatch", None),
    0x176404: ("secondary-key-grant", 1),
    0x357128: ("hundred-key-path", 100),
    0x357170: ("hundred-key-path", 100),
    0x3571B8: ("hundred-key-path", 100),
    0x357200: ("hundred-key-path", 100),
    0x357248: ("hundred-key-path", 100),
    0x35AAD8: ("one-key-path", 1),
    0x35AB20: ("one-key-path", 1),
    0x35AB68: ("one-key-path", 1),
    0x35ABB0: ("one-key-path", 1),
    0x479620: ("key-present-type-grant-candidate", None),
    0x796540: ("additional-one-key-path", 1),
}
EXTRA_CALLS = {
    0x161CAC: 0x42CB20,
    0x5B8454: 0x42CEEC,
    0x5B8470: 0x42D270,
}
OPCODES = {
    0x161AA4: 0xE92D4FF0,
    0x161AAC: 0xE2400003,
    0x161AC4: 0xE59D4078,
    0x161E58: 0xE1A01009,
    0x161E5C: 0xE1A0200B,
    0x176400: 0xE3A02001,
    0x4795DC: 0xE92D4830,
    0x479618: 0xE594201C,
    0x47961C: 0xE2841018,
    0x79653C: 0xE3A02001,
}

def word(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def arm_bl_target(pc, opcode):
    if opcode & 0x0F000000 != 0x0B000000:
        raise ValueError(f"Expected ARM BL at {pc:#x}, got {opcode:#x}")
    displacement = opcode & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    return pc + 8 + 4 * displacement

def verify(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError("Unknown binary; refusing offsets (sha256=" + digest + ")")
    for pc, (kind, quantity) in CALLS.items():
        assert arm_bl_target(pc, word(data, pc)) == ADD_WORLD_KEYS, (pc, kind)
        if quantity is not None:
            assert word(data, pc - 4) == 0xE3A02000 | quantity, (pc, kind)
    for pc, target in EXTRA_CALLS.items():
        assert arm_bl_target(pc, word(data, pc)) == target, (pc, target)
    for pc, opcode in OPCODES.items():
        assert word(data, pc) == opcode, (pc, opcode)
    base = 0x161AD8
    targets = [base + word(data, base + i*4) for i in range(14)]
    assert targets[11-3] == 0x161C70, ("coin case", targets[11-3])
    assert targets[13-3] == 0x161E20, ("key case", targets[13-3])
    found = []
    for pc in range(0x000E9558, 0x00C25B9C, 4):
        opcode = word(data, pc)
        if opcode & 0x0F000000 != 0x0B000000:
            continue
        if arm_bl_target(pc, opcode) == ADD_WORLD_KEYS:
            found.append(pc)
    if set(found) != set(CALLS):
        raise ValueError(
            f"Coverage drift: expected-not-found={sorted(set(CALLS)-set(found))}, "
            f"unclassified={sorted(set(found)-set(CALLS))}")
    print(f"PASS: exact original ELF; {len(CALLS)} of {len(found)} direct ARM BL callers fully catalogued")
    print("PASS: opcode witnesses, coin/key dispatch targets and two native door-path calls")
    for pc, (kind, qty) in CALLS.items():
        print(f"  {pc:#010x}: {kind}, statically visible quantity={qty}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True,
                        help="Your original locally extracted libPVZ2.so")
    verify(parser.parse_args().elf.read_bytes())
