# PvZ2 v86 — Heap + Performance Fix

Date: 2026-09-23

## Evidence from the real iPad v85 run

v85 improved responsiveness slightly, but the game remained slow and stopped
after the user pressed PLAYER.

The terminal v85 state is decisive:

- guest heap capacity: 67,108,864 bytes (64 MiB);
- heap high-water: 67,104,288 bytes;
- live heap bytes: 65,242,466 bytes;
- live allocations: 233,281;
- only 4,576 bytes remained below the arena limit;
- the terminal error was:
  __aeabi_memset attempted to write outside guest memory.

The log itself does not name the PLAYER control at the terminal instruction,
but the real iPad observation places this failure immediately after PLAYER.

v85 also exposed a cleanup bug: the log filter retained every line containing
the substring "failed", so normal lines ending in "failed=NO" survived. This
left thousands of V22 worker-slice log lines in the hot path.

## Root causes targeted

v86 targets two independent, now-observed causes in one version:

1. the synthetic 64 MiB guest heap is exhausted at the post-PLAYER boundary;
2. residual scheduler logging still adds avoidable runtime/file-I/O overhead.

No scheduler behavior is changed in this version.

## Heap change

Only V86_HEAP_PERFORMANCE_FIX uses a 128 MiB guest heap:

- base remains 0x30000000;
- v85/older modes remain 64 MiB;
- v86 capacity is 0x08000000 (128 MiB);
- the region therefore ends at 0x38000000, safely below the existing
  trampoline region at 0x40000000.

The guest allocator and all heap-address diagnostics now use the actual
per-mode heap vector capacity rather than a hard-coded 64 MiB range.

If memset still exits the guest arena, v86 logs:

V86 PERF MEMSET OOB

with destination, size, value, PC, LR and heap capacity/high-water/live/allocation
counts.

Allocator failures that return 0 are also retained even under the strict
performance log filter.

## Hot-log correction

v86 keeps the lightweight v85 timing measurements but uses a stricter filter.
It no longer treats the harmless text "failed=NO" as a failure.

Normal high-frequency scheduler strings are disabled before formatting for:

- V22 WORKER SLICE
- V30 WAIT OBJECT PROGRESS
- V38 BOUNDARY WORKER SLICE
- V61 RES-STREAM PUMP SLICE

Real failures remain visible: failed=YES, FAIL-FAST, FAILED, ERROR, exceptions,
execution-budget failures, unsupported calls, allocator OOM and guest-memory
faults.

## Preserved behavior

v86 keeps unchanged:

- Points=Pixels 2048x1536;
- UI_IPAD remap;
- VFS + OBB;
- zlib;
- ETC1;
- GLES;
- cooperative scheduler semantics;
- resource workers;
- touch;
- keyboard/text;
- USERFS;
- the minimal verified Profile button dispatcher timing trap.

UIKit presentation is not rewritten in v86. v85 measured the NSData copy near
1.1-1.5 ms and UIImage presentation near 0.3 ms, while guest/capture and
worker activity were much larger.

## iPad test

Use V86 Heap+Perf, which is the new default.

1. Load the same APK + OBB.
2. Confirm rendering remains correct.
3. Exercise a few menus/buttons before PLAYER and compare transition latency.
4. Use Profile TextEntry/ACCEPT if convenient.
5. Press PLAYER.
6. Report what appears after PLAYER and whether the old memset stop is gone.
7. Export the complete log.

Useful markers:

- V86 PERF HEAP
- V85 PERF guest
- V85 PERF capture
- [V85 PERF HOST]
- V85 PERF input
- V27 HEAP ... -> 0x00000000
- V86 PERF MEMSET OOB
- STEP 3C2
- STEP 3D

## Next decision

If PLAYER now advances beyond the old stop, 64 MiB was a real blocker and the
next failure can be handled from the new terminal evidence.

If the same memset fault survives while heap usage is far below 128 MiB, the
new OOB record should expose whether the destination/size is corrupt rather
than allocation exhaustion.

If responsiveness is still poor after the hot-log fix, the remaining target is
the actual guest/resource-worker scheduling cost. The framebuffer capture
(roughly 65-85 ms on many published frames in v85) is a secondary optimization
target, while UIKit copy/presentation is not.
