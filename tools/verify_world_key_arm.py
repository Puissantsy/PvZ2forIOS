#!/usr/bin/env python3
"""Read-only native-offset verifier: requires user's own PvZ2 1.5.252752 libPVZ2.so."""
import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA = "f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f"
CALLS = {
    0x161CAC:0x42CB20, # present -> add coins
    0x161E60:0x42CCC8, # present -> add world keys
    0x176404:0x42CCC8, # secondary grant -> add a world key
    0x5B8454:0x42CEEC, # key gate -> spend keys
    0x5B8470:0x42D270, # key gate -> set world event
    0x375A74:0x42E680, # read original coins
    0x375A80:0x42E5AC, # write original coins
}
INSTRUCTIONS = {
    # Optional research probe exact-instruction sites: original MOV/MOV/LDR.
    0x42CCD0:0xE1A0A000, # AddWorldKeys prologue: MOV r10,r0
    0x5B846C:0xE3A03003, # gate before native update: MOV r3,#3
    0x5B8474:0xE59F0088, # gate after: LDR r0,[pc,#0x88]
    0x5B8448:0xE594202C, # map item key cost +0x2c
    0x5B846C:0xE3A03003, # desired saved event state 3
    0x42D2C0:0xE1510007, # monotonic event-state comparison
    0x42D2C8:0xE5807000, # state write
    0x42CC58:0xE590607C, # key vector begin
    0x42CC5C:0xE5908080, # key vector end
    0x42CE38:0xE082200B, # count increase
    0x42CE3C:0xE3520063, # cap count to 99
    0x42CE44:0xE5802004, # write new count
    # Verified directly against the uploaded reference APK's native ELF:
    # GetWorldKeys compares original libstdc++ COW string length via ptr-12;
    # SpendWorldKeys consumes the same per-world vector + count.
    0x42CC74:0xE244000C, # GetWorldKeys COW name header = chars-12
    0x42CC78:0xE5905000, # GetWorldKeys name string length
    0x42CEEC:0xE92D4BF0, # SpendWorldKeys native prologue
    0x42CEF0:0xE590707C, # SpendWorldKeys vector begin at profile+0x7c
    0x42CEF8:0xE5909080, # SpendWorldKeys vector end at profile+0x80
    0x42CF0C:0xE245000C, # SpendWorldKeys input name chars-12
    0x42CF10:0xE5906000, # SpendWorldKeys COW string length
    0x42CF50:0xE0870184, # SpendWorldKeys entry stride 8
    0x42CF60:0xE5907004, # SpendWorldKeys old stock count +4
    0x42CF68:0xE0573008, # new count = old - requested spend
    0x42CF70:0xD3A03000, # clamp negative result to zero
    0x42CF74:0xE5803004, # write new count through native path
}
def verify(path):
    data=path.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest!=EXPECTED_SHA:
        raise ValueError("Wrong or modified ELF; refuse all offsets: "+digest)
    for pc,expected in CALLS.items():
        insn,=struct.unpack_from("<I",data,pc)
        if (insn&0x0f000000)!=0x0b000000:
            raise ValueError(f"Not an ARM BL at {pc:#x}")
        disp=insn&0xffffff
        if disp&0x800000: disp-=0x1000000
        actual=pc+8+disp*4
        if actual!=expected:
            raise ValueError(f"Wrong branch at {pc:#x}: {actual:#x} not {expected:#x}")
    for pc,expected in INSTRUCTIONS.items():
        actual,=struct.unpack_from("<I",data,pc)
        if actual!=expected:
            raise ValueError(f"Wrong instruction at {pc:#x}: {actual:#x} not {expected:#x}")
    print(f"PASS: exact ELF hash, {len(CALLS)} callsites and {len(INSTRUCTIONS)} instructions")
if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf",type=Path,required=True,help="Your original extracted libPVZ2.so")
    verify(parser.parse_args().elf)
