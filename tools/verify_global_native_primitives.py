#!/usr/bin/env python3
"""Read-only exact-version native GlobalSaveData primitive verification.

PvZ2 Android 1.5.252752 armeabi-v7a libPVZ2.so ONLY. Does not modify
the APK, the iPad runtime, an original save, or a receipt. Disassembler
findings here are source-level evidence, not proof a specific A receipt
executed a given caller.
"""
import argparse
import struct
import zipfile

WORDS = {
    # Returns runtime native GlobalSaveData*, r0=0 lookup or r0=1 create.
    0x43EBD0: 0xE92D47F0,
    0x43ED30: 0xE3560000,
    0x43ED34: 0x02350001,
    0x43EDEC: 0xE1A00006,
    # HasGlobalPlant(id) calls getter(0), checks std::vector<int> +4/+8.
    0x43EFEC: 0xE92D4830,
    0x43EFF4: 0xE3A00000,
    0x43EFFC: 0xEBFFFEF3,
    0x43F008: 0xE5901004,
    0x43F014: 0xE1A02242,
    0x43F05C: 0xE2811010,
    0x43F0E4: 0xE1530000,
    # HasGlobalFeature(id) calls getter(0), checks vector +16/+20.
    0x43F220: 0xE92D4830,
    0x43F228: 0xE3A00000,
    0x43F230: 0xEBFFFE66,
    0x43F23C: 0xE5901010,
    0x43F248: 0xE1A02242,
    # AddGlobalPlant(id) calls getter(1), appends 4-byte ints, native SAVE.
    0x43EAA4: 0xE92D41F0,
    0x43EAB0: 0xE3A00001,
    0x43EABC: 0xEB000043,
    0x43EAC4: 0xE5B26004,
    0x43EAD0: 0xE1A05243,
    0x43EB18: 0xE2866010,
    0x43EBAC: 0xE2811004,
    0x43EBC0: 0xEBF5BD0D,
    0x43EBC4: 0xEB000096,
    # AddGlobalFeature(id) uses its own category and same SAVE.
    0x43F0F4: 0xE92D41F0,
    0x43F100: 0xE3A00001,
    0x43F10C: 0xEBFFFEAF,
    0x43F114: 0xE5B26010,
    0x43F120: 0xE1A05243,
    0x43F200: 0xE5801014,
    0x43F214: 0xEBFFFF02,
    # SaveGlobalOriginal() fetches global_save_data key/file path.
    0x43EE24: 0xE92D4070,
    0x43EE30: 0xEB000329,
}

CALLEES = {
    0x43EFEC: {0x16154C, 0x3036F8, 0x303A8C, 0x34387C},
    0x43F220: {0x16183C, 0x3037C8, 0x303B58, 0x3466C0},
    0x43EAA4: {0x162420, 0x304DAC},
    0x43F0F4: {0x162048, 0x304E8C},
    0x43EE24: {0x43EBC4, 0x43F214, 0x43F39C, 0x43F460, 0x43F73C},
}


def check(apk):
    with zipfile.ZipFile(apk) as archive:
        elf = archive.read("lib/armeabi-v7a/libPVZ2.so")
    if len(elf) != 13_950_396 or elf[:6] != b"\x7fELF\x01\x01":
        raise ValueError("NOT the known original ARM32 ELF; refusing offsets")
    for addr, expected in WORDS.items():
        actual = struct.unpack_from("<I", elf, addr)[0]
        if actual != expected:
            raise ValueError(f"Native primitive mismatch at 0x{addr:08x}")
    print(f"PASS {len(WORDS)}/{len(WORDS)} exact GlobalSaveData getter/HAS/ADD/SAVE ARM words")

    # A strict direct BL call graph cannot prove which virtual/indirect
    # caller invokes these routines, but proves the listed direct users.
    found = {addr: set() for addr in CALLEES}
    start, end = 0xE9558, 0xE9558 + 0xB3C644
    for addr in range(start, min(end, len(elf)-4), 4):
        instruction = struct.unpack_from("<I", elf, addr)[0]
        if instruction & 0x0F000000 != 0x0B000000:
            continue
        imm = instruction & 0xFFFFFF
        if imm & 0x800000:
            imm -= 1 << 24
        target = (addr + 8 + imm*4) & 0xFFFFFFFF
        if target in found:
            found[target].add(addr)
    for target, expected in CALLEES.items():
        if found[target] != expected:
            raise ValueError(
                f"Original BL xrefs changed for 0x{target:08x}: "
                f"expected {sorted(expected)}, actual {sorted(found[target])}")
    print(f"PASS {len(CALLEES)}/{len(CALLEES)} complete direct-BL caller sets")
    print("Confirmed: scalar DWORD vector elements; native search unrolls FOUR")
    print("per iteration, so a +16 loop stride DOES NOT mean 16-byte elements")
    print("NOTE: authentic-vs-v2 purchase origin at callers remains UNPROVEN")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", help="User-provided EXACT 1.5.252752 ARM32 APK")
    args = parser.parse_args()
    try:
        check(args.apk)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"FAIL (no file was changed): {exc}")
