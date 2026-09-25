# v113 — Dynarmic heap page-table optimization

## Root cause targeted

v112 measured 82.558 s inside CAkAudioThread jit.Run spans. Only 0.320 s
(0.39%) was spent in host import handlers. 67.751 s was guest execution
between imports and another 14.343 s was guest tail execution.

The dominant natural boundary was mapping_inverse -> memset at LR 0x10c20c30:
148,609 calls and 50.732 s of preceding guest execution. Static disassembly
shows floor1_inverse1 immediately before that memset inside mapping_inverse.

The current Dynarmic configuration has no page table or fastmem, so ordinary
guest loads/stores call MemoryRead*/MemoryWrite* C++ callbacks.

## Optimization

v113 gives Dynarmic a page table from JIT construction, initially all null.
Therefore constructors, JNI and startup keep the exact callback-backed memory
semantics used by v112.

Immediately before real frame 1, v113 maps only the stable guest heap:
0x30000000 + 128 MiB, 32768 4-KiB pages.

This directly covers worker stacks, Wwise state and audio buffers allocated in
the heap. It deliberately does NOT map:
- libPVZ2 image / GOT / RELRO;
- main guest stack;
- import trampolines;
- JNI table;
- synthetic object region.

Those regions continue using MemoryRead*/MemoryWrite* callbacks and retain
their protection/diagnostic behavior. Exclusive memory operations also remain
callback-backed in Dynarmic's ARM64 backend.

## Measurement

v112 natural-boundary telemetry remains enabled in v113. Compare:
- tid5 worker wall time;
- V112 runWall / guestGap / hostImport / tail;
- mapping_inverse callsite guestGap;
- slow-frame audio112 breakdown;
- visual/audio behavior and pinch.

## iPad test

1. Confirm startup reaches the same game state as v112.
2. Observe whether animation/audio smoothness changes immediately.
3. Reproduce heavy SFX and rapid seed selection.
4. Test ordinary interaction and World Map pinch.
5. Hard Stop and export the complete log.

Any crash/regression after frame 1 should be treated as page-table coverage
semantics first, not as a Wwise bug.
