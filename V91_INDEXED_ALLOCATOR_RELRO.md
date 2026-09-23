# PvZ2 v91 — Exact Indexed First-Fit + GNU_RELRO

Date: 2026-09-23

## Why this version exists

v90 separated presentation cost from real guest/runtime stalls. The direct GPU
path is healthy, while allocator scan depth tracks guest wall time almost
perfectly.

v90 allocator summary:
- 1,759,516 allocations;
- 190,480,259,650 free-list entries examined;
- 108,257 entries examined per allocation on average;
- maximum scan depth 207,215;
- roughly 214k free blocks at the end.

The first returned draw alone performed roughly 393k allocations and about
53.5 billion first-fit scan steps. PopCap Presents frame 432 took about 74.9 s
while performing about 12.1 billion scan steps.

v91 therefore changes the lookup algorithm, not the guest allocation contract.

## Exact indexed first-fit

The authoritative free map remains:
    std::map<offset,size> heap_free_blocks

The 128 MiB guest heap is divided into 4 KiB start-address buckets. For the
indexed alignment classes an auxiliary segment tree stores the maximum usable
size of any free block that starts in each bucket.

Allocation:
1. find the earliest bucket whose maximum can satisfy the request;
2. scan the free blocks in only that bucket in address order;
3. select the first fitting block;
4. perform exactly the same prefix/suffix split and coalescing as v90.

Because all earlier buckets are proven unable to satisfy the request and the
chosen bucket is still scanned in address order, this returns the same block as
the old global first-fit. Unsupported alignment values retain the old safe
linear fallback.

The allocator still preserves:
- guest base 0x30000000;
- 128 MiB capacity;
- requested allocation sizes;
- alignment behavior;
- shrink-in-place realloc;
- grow realloc = allocate/copy/free;
- address-ordered coalescing;
- bump-tail contraction.

Useful log:
    V91 INDEX SUMMARY

## Crash analysis: free GOT corruption

The recurrent v88/v89/v90 crash is not an unsupported instruction.

Static chain in the supplied Android libPVZ2.so:
- 0x10868b50 calls 0x10b739a0;
- 0x10b739a0 forwards to operator delete;
- operator delete at 0x10b368f8 branches to the free PLT entry;
- free PLT resolves through runtime address 0x10d01c20;
- ELF relocation 0x00d01c20 is R_ARM_JUMP_SLOT free.

The synthetic loader's expected free target is its ARM SVC trampoline. At the
crash, r12 is exactly 0x10d01c20, LR is 0x10868b54, but execution lands at
0x1086fcea with CPSR.T set. 0x1086fcea is two bytes into an ARM instruction,
consistent with an odd corrupted function pointer read from the free GOT slot.

## GNU_RELRO fidelity

The supplied libPVZ2.so contains:
- PT_GNU_RELRO: vaddr 0x00ccbf90 through 0x00d02000;
- free GOT 0x00d01c20 inside that range;
- BIND_NOW/NOW dynamic flags.

A real Android linker resolves these imports and then seals GNU_RELRO
read-only. The synthetic runtime previously left the entire mapped ELF image
writable.

v91:
- parses PT_GNU_RELRO from the actual APK ELF;
- registers resolved JUMP_SLOT/GLOB_DAT imports that live inside RELRO;
- verifies the exact free slot at guest 0x10d01c20;
- arms RELRO only after synthetic relocation/import/code setup is complete;
- rejects later guest writes to RELRO;
- guards host bridges that can write arbitrary guest buffers, including
  memcpy/memmove/memset, wide memory helpers, VFS reads, zlib outputs, selected
  JNI array transfers, formatted output and GLES log output;
- records the first attempted RELRO writer with PC/LR/tid/phase/destination;
- verifies/repairs protected import slots in terminal diagnostics.

Useful logs:
    V91 RELRO CONFIG
    V91 RELRO ARMED
    V91 RELRO BLOCK first ...
    V91 RELRO REPAIR ...
    V91 RELRO SUMMARY

## What v91 does not change

- scheduler policy;
- resource lookup/remapping;
- OBB/RSB contents;
- UI_IPAD package remap;
- font cmap algorithm;
- audio semantics;
- direct GPU 1:1 presentation;
- touch/keyboard bridges.

## iPad validation

Use **V91 Alloc+RELRO**, the default mode.

Measure and report:
1. Run -> first visible frame;
2. whether PopCap Presents frames ~430-475 are dramatically faster;
3. Settings/dialog open vs closed frame speed;
4. whether the previous UI_Dialog_1536 crash still occurs;
5. if the app passes that point, every new visual/state milestone after it.

Export the complete log. The key comparisons are:
- startup wall time v90 vs v91;
- V90 allocator scan metrics vs V91 INDEX SUMMARY;
- first V91 RELRO BLOCK, if any;
- free GOT expected/current in V91 RELRO SUMMARY;
- final frame/milestone reached.
