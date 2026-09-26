# v131 — Swipe history + Android rand48

v131 preserves the complete v130 runtime and fixes two platform-bridge bugs.

## Swipe/fling

The v72 bridge previously emitted only the final UITouch from each touchesMoved:
callback. UIKit may coalesce multiple hardware samples into one callback, so
fast swipes lost most of their timestamped trajectory and PvZ2 could not
reconstruct release velocity correctly.

v131 uses UIEvent::coalescedTouchesForTouch:, serializes every sample in
chronological order using the existing verified 48-byte Android UITouchEvent
ABI, chains previousX/Y between emitted samples, and keeps the real UIKit
timestamps. DOWN/UP/CANCEL semantics are unchanged. No host-side inertia is
fabricated.

## srand48/lrand48

The old import fallback returned constant 0x12345678 for every lrand48 call and
ignored srand48. The real Android game seeds this libc RNG from gettimeofday.

v131 implements the POSIX/Bionic 48-bit LCG:
- srand48(seed): X=(seed<<16)|0x330e
- X=(0x5deece66d*X+0xb) mod 2^48
- lrand48(): X>>17

This is a global guest libc RNG state, not a Potato Mine-specific workaround.

## iPad validation

1. Flick a scrollable PvZ2 list/bar rapidly and release. It should continue with
   momentum according to release velocity.
2. Repeat Potato Mine Plant Food at least 10 times with several free cells. The
   two spawned armed mines should no longer show the deterministic bottom-right
   bias and should vary across valid cells.
3. Recheck save, audio, board scale and launcher behavior from v130.
