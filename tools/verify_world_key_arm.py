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
    0x5B8448:0xE594202C, # map item key cost +0x2c
    0x5B846C:0xE3A03003, # desired saved event state 3
    0x42D2C0:0xE1510007, # monotonic event-state comparison
    0x42D2C8:0xE5807000, # state write
    0x42CC58:0xE590607C, # key vector begin
    0x42CC5C:0xE5908080, # key vector end
    0x42CE38:0xE082200B, # count increase
    0x42CE3C:0xE3520063, # cap count to 99
    0x42CE44:0xE5802004, # write new count
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
