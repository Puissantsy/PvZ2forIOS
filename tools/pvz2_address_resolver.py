#!/usr/bin/env python3
"""Resolve PvZ2 ARM guest addresses and annotate full diagnostic logs.

No proprietary game files are stored in this repository. Point the tool at the
user-supplied PvZ2 1.5.252752 APK (or an extracted libPVZ2.so).

Examples:
  python tools/pvz2_address_resolver.py --apk pvz2.apk 0x1086fa84
  python tools/pvz2_address_resolver.py --apk pvz2.apk --log full-log.txt \
      --report address-report.txt --annotated-log annotated-log.txt

The tool is standard-library-only. If the optional capstone package is present,
it is used for richer ARM/Thumb disassembly.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import json
import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

GUEST_BASE = 0x10000000
STACK_BASE, STACK_SIZE = 0x20000000, 0x00100000
HEAP_BASE, HEAP_SIZE = 0x30000000, 0x04000000
TRAMP_BASE, TRAMP_SIZE = 0x40000000, 0x00100000
JNI_BASE, JNI_SIZE = 0x50000000, 0x00010000
OBJECT_BASE, OBJECT_SIZE = 0x51000000, 0x00010000
APK_LIB_PATH = "lib/armeabi-v7a/libPVZ2.so"
SHT_DYNSYM = 11
SHT_ARM_EXIDX = 0x70000001
PT_LOAD = 1

CONTROL_RE = re.compile(r"\b(PC|LR|returnPC|callerLR|SP)=0x([0-9a-fA-F]{1,8})")
HEX_RE = re.compile(r"0x([0-9a-fA-F]{7,8})")


@dataclass(frozen=True)
class Section:
    name: int
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int


@dataclass(frozen=True)
class ProgramHeader:
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    info: int
    shndx: int


class Elf32Arm:
    def __init__(self, data: bytes, source: str):
        self.data = data
        self.source = source
        self.sections: list[Section] = []
        self.phdrs: list[ProgramHeader] = []
        self.symbols: list[Symbol] = []
        self.function_starts: list[int] = []
        self.image_end = 0
        self._parse()

    @staticmethod
    def _cstring(blob: bytes, offset: int) -> str:
        if not 0 <= offset < len(blob):
            return ""
        end = blob.find(b"\0", offset)
        if end < 0:
            end = len(blob)
        return blob[offset:end].decode("utf-8", errors="replace")

    def _parse(self) -> None:
        if len(self.data) < 52:
            raise ValueError("ELF is too small")
        eh = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data, 0)
        ident, e_type, e_machine, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, _ = eh
        if ident[:4] != b"\x7fELF" or ident[4] != 1 or ident[5] != 1 or e_type != 3 or e_machine != 40:
            raise ValueError("Expected ELF32 little-endian ARM shared object")
        if e_phentsize != 32 or e_shentsize != 40:
            raise ValueError("Unexpected ELF table sizes")

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            self.phdrs.append(ProgramHeader(*struct.unpack_from("<IIIIIIII", self.data, off)))
        loads = [p for p in self.phdrs if p.type == PT_LOAD]
        if not loads:
            raise ValueError("ELF has no PT_LOAD segment")
        self.image_end = max(p.vaddr + p.memsz for p in loads)

        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            self.sections.append(Section(*struct.unpack_from("<IIIIIIIIII", self.data, off)))

        for sh in self.sections:
            if sh.type != SHT_DYNSYM or sh.link >= len(self.sections):
                continue
            strings_sh = self.sections[sh.link]
            strings = self.data[strings_sh.offset:strings_sh.offset + strings_sh.size]
            entsize = sh.entsize or 16
            for off in range(sh.offset, sh.offset + sh.size, entsize):
                if off + 16 > len(self.data):
                    break
                name_off, value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", self.data, off)
                name = self._cstring(strings, name_off)
                if name:
                    self.symbols.append(Symbol(name, value, size, info, shndx))

        starts: set[int] = set()
        for sh in self.sections:
            if sh.type != SHT_ARM_EXIDX:
                continue
            for rel in range(0, sh.size - 7, 8):
                word = struct.unpack_from("<I", self.data, sh.offset + rel)[0]
                place = sh.addr + rel
                delta = word & 0x7fffffff
                if delta & 0x40000000:
                    delta -= 0x80000000
                target = (place + delta) & 0xffffffff
                target &= ~1
                if 0 < target < self.image_end:
                    starts.add(target)
        self.function_starts = sorted(starts)

    def vaddr_to_file(self, vaddr: int) -> Optional[int]:
        for p in self.phdrs:
            if p.type == PT_LOAD and p.vaddr <= vaddr < p.vaddr + p.filesz:
                return p.offset + (vaddr - p.vaddr)
        return None

    def read(self, vaddr: int, size: int) -> bytes:
        off = self.vaddr_to_file(vaddr)
        if off is None or off + size > len(self.data):
            return b""
        return self.data[off:off + size]

    def function_range(self, offset: int) -> tuple[Optional[int], Optional[int]]:
        i = bisect.bisect_right(self.function_starts, offset) - 1
        if i < 0:
            return None, None
        start = self.function_starts[i]
        end = self.function_starts[i + 1] if i + 1 < len(self.function_starts) else None
        return start, end

    def nearest_symbol(self, offset: int) -> Optional[tuple[Symbol, int, bool]]:
        best = None
        for sym in self.symbols:
            if sym.shndx == 0:
                continue
            value = sym.value & ~1
            if value > offset:
                continue
            delta = offset - value
            contains = sym.size > 0 and delta < sym.size
            if best is None or (contains and not best[2]) or (contains == best[2] and delta < best[1]):
                best = (sym, delta, contains)
        if best is not None and (best[2] or best[1] <= 0x10000):
            return best
        return None


def load_elf(apk: Optional[Path], so: Optional[Path]) -> Elf32Arm:
    if bool(apk) == bool(so):
        raise ValueError("Specify exactly one of --apk or --so")
    if apk:
        with zipfile.ZipFile(apk) as zf:
            data = zf.read(APK_LIB_PATH)
        return Elf32Arm(data, f"{apk}!/{APK_LIB_PATH}")
    assert so is not None
    return Elf32Arm(so.read_bytes(), str(so))


def load_labels(path: Optional[Path]) -> dict[int, str]:
    labels: dict[int, str] = {}
    candidate = path or Path(__file__).with_name("pvz2_known_addresses.json")
    if candidate.exists():
        raw = json.loads(candidate.read_text(encoding="utf-8"))
        for key, value in raw.items():
            labels[int(key, 0)] = str(value)
    return labels


def classify(address: int, elf: Elf32Arm) -> tuple[str, Optional[int]]:
    plain = address & ~1
    if GUEST_BASE <= plain < GUEST_BASE + elf.image_end:
        return "libPVZ2.so", plain - GUEST_BASE
    for name, base, size in (
        ("guest-stack", STACK_BASE, STACK_SIZE),
        ("guest-heap", HEAP_BASE, HEAP_SIZE),
        ("host-trampoline", TRAMP_BASE, TRAMP_SIZE),
        ("synthetic-JNI", JNI_BASE, JNI_SIZE),
        ("synthetic-object", OBJECT_BASE, OBJECT_SIZE),
    ):
        if base <= plain < base + size:
            return name, plain - base
    if address == 0:
        return "null", 0
    return "other", None


def resolve(address: int, elf: Elf32Arm, labels: dict[int, str]) -> str:
    region, offset = classify(address, elf)
    if region != "libPVZ2.so":
        if offset is None:
            return f"0x{address:08x} [{region}]"
        return f"0x{address:08x} [{region}+0x{offset:x}]"

    assert offset is not None
    parts = [f"0x{address:08x} [libPVZ2.so+0x{offset:08x} {'Thumb' if address & 1 else 'ARM'}"]
    if offset in labels:
        parts.append(f"known={labels[offset]}")

    fn_start, fn_end = elf.function_range(offset)
    if fn_start is not None:
        fn = f"fn=+0x{fn_start:08x}+0x{offset-fn_start:x}"
        if fn_end is not None:
            fn += f"/0x{fn_end-fn_start:x}"
        parts.append(fn)

    near = elf.nearest_symbol(offset)
    if near:
        sym, delta, contains = near
        parts.append(f"{'symbol' if contains else 'near-symbol'}={sym.name}+0x{delta:x}")
    return " ".join(parts)


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def reg(n: int) -> str:
    return {13: "sp", 14: "lr", 15: "pc"}.get(n, f"r{n}")


def basic_arm(word: int, address: int) -> str:
    cond = (word >> 28) & 0xf
    suffix = {0:"eq",1:"ne",2:"cs",3:"cc",4:"mi",5:"pl",6:"vs",7:"vc",8:"hi",9:"ls",10:"ge",11:"lt",12:"gt",13:"le",14:"",15:"nv"}.get(cond, "")
    if (word & 0x0f000000) == 0x0f000000:
        return f"svc{suffix} #0x{word & 0x00ffffff:x}"
    if (word & 0x0ffffff0) == 0x012fff10:
        return f"bx{suffix} {reg(word & 0xf)}"
    if (word & 0x0ffffff0) == 0x012fff30:
        return f"blx{suffix} {reg(word & 0xf)}"
    if (word & 0x0e000000) == 0x0a000000:
        delta = sign_extend(word & 0x00ffffff, 24) << 2
        target = (address + 8 + delta) & 0xffffffff
        return f"{'bl' if word & 0x01000000 else 'b'}{suffix} 0x{target:08x}"
    if (word & 0x0c000000) == 0x04000000 and not (word & (1 << 25)):
        load = bool(word & (1 << 20))
        rn, rd, imm = (word >> 16) & 0xf, (word >> 12) & 0xf, word & 0xfff
        up, pre = bool(word & (1 << 23)), bool(word & (1 << 24))
        sign = "+" if up else "-"
        where = f"[{reg(rn)},#{sign}0x{imm:x}]" if pre else f"[{reg(rn)}],#{sign}0x{imm:x}"
        return f"{'ldr' if load else 'str'}{suffix} {reg(rd)},{where}"
    if (word & 0x0fe00000) == 0x01a00000:
        return f"mov{suffix} {reg((word >> 12) & 0xf)},{reg(word & 0xf)}"
    return ""


def disassemble(elf: Elf32Arm, runtime_address: int, before: int = 2, after: int = 3) -> list[str]:
    region, offset = classify(runtime_address, elf)
    if region != "libPVZ2.so" or offset is None:
        return []
    plain = runtime_address & ~1
    thumb = bool(runtime_address & 1)

    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB  # type: ignore
        width = 2 if thumb else 4
        start = max(0, offset - before * width)
        blob = elf.read(start, (before + after + 1) * width)
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        lines = []
        for insn in md.disasm(blob, GUEST_BASE + start):
            marker = "=>" if (insn.address & ~1) == plain else "  "
            lines.append(f"{marker} 0x{insn.address:08x}: {insn.mnemonic:<9} {insn.op_str}")
        if lines:
            return lines
    except Exception:
        pass

    if thumb:
        return ["(install capstone for Thumb disassembly)"]

    start = max(0, offset - before * 4)
    blob = elf.read(start, (before + after + 1) * 4)
    lines = []
    for i in range(0, len(blob) - 3, 4):
        address = GUEST_BASE + start + i
        word = struct.unpack_from("<I", blob, i)[0]
        decoded = basic_arm(word, address)
        marker = "=>" if address == plain else "  "
        lines.append(f"{marker} 0x{address:08x}: 0x{word:08x}" + (f"  {decoded}" if decoded else ""))
    return lines


def analyse_log(text: str, elf: Elf32Arm, labels: dict[int, str], top: int) -> str:
    control: dict[str, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    all_addresses: collections.Counter[int] = collections.Counter()

    for line in text.splitlines():
        for key, raw in CONTROL_RE.findall(line):
            control[key][int(raw, 16)] += 1
        for raw in HEX_RE.findall(line):
            all_addresses[int(raw, 16)] += 1

    out = [
        "PvZ2 address report",
        f"ELF: {elf.source}",
        f"guest base: 0x{GUEST_BASE:08x}; image size: 0x{elf.image_end:x}",
        f"dynamic symbols: {len(elf.symbols)}; .ARM.exidx function starts: {len(elf.function_starts)}",
        "",
        "Control-flow addresses",
        "----------------------",
    ]

    disassembled: set[int] = set()
    for key in ("PC", "LR", "returnPC", "callerLR", "SP"):
        if key not in control:
            continue
        out.append(f"\n{key}:")
        for address, count in control[key].most_common(top):
            out.append(f"  {count:5d}x  {resolve(address, elf, labels)}")
            if key != "SP" and classify(address, elf)[0] == "libPVZ2.so" and address not in disassembled:
                disassembled.add(address)
                for line in disassemble(elf, address):
                    out.append("           " + line)

    region_counts = collections.Counter()
    code = []
    for address, count in all_addresses.items():
        region, _ = classify(address, elf)
        region_counts[region] += count
        if region == "libPVZ2.so":
            code.append((count, address))

    out += ["", "Address-region totals", "---------------------"]
    for region, count in region_counts.most_common():
        out.append(f"  {region:<18} {count}")

    out += ["", "Most frequent libPVZ2 addresses", "-------------------------------"]
    for count, address in sorted(code, reverse=True)[:top]:
        out.append(f"  {count:5d}x  {resolve(address, elf, labels)}")
    return "\n".join(out) + "\n"


def annotate_log(text: str, elf: Elf32Arm, labels: dict[int, str]) -> str:
    cache: dict[int, str] = {}

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        address = int(match.group(2), 16)
        if address not in cache:
            cache[address] = resolve(address, elf, labels)
        return f"{key}=0x{address:08x}<{cache[address]}>"

    return CONTROL_RE.sub(repl, text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--apk", type=Path)
    src.add_argument("--so", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--annotated-log", type=Path)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--top", type=int, default=30)
    parser.add_argument("addresses", nargs="*")
    args = parser.parse_args()

    elf = load_elf(args.apk, args.so)
    labels = load_labels(args.labels)

    if not args.addresses and not args.log:
        parser.error("provide addresses and/or --log")

    for raw in args.addresses:
        address = int(raw, 0)
        print(resolve(address, elf, labels))
        for line in disassemble(elf, address):
            print("  " + line)

    if args.log:
        log = args.log.read_text(encoding="utf-8", errors="replace")
        report = analyse_log(log, elf, labels, args.top)
        if args.report:
            args.report.write_text(report, encoding="utf-8")
            print(f"wrote {args.report}")
        else:
            print(report, end="")
        if args.annotated_log:
            args.annotated_log.write_text(annotate_log(log, elf, labels), encoding="utf-8")
            print(f"wrote {args.annotated_log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
