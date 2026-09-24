# v109 — Lean Audio Performance

## Root cause targeted

The long v108 iPad run reached Day 3 and 34,043 rendered frames without a permanent transition freeze. The v108 SoundBank completion path is therefore preserved unchanged.

The same run also shows that performance measurements are being taken with historical diagnostic instrumentation still active in the hottest Wwise path:

- worker tid=5 (CAkAudioThread) accumulated about 149.46 s of worker wall time;
- all other deferred workers together stayed below 0.5 s;
- the v105 CAkResampler SetPitch observer reached at least #65536;
- v108 still inherited kCapWwiseResamplerProbe, so every matching Init/SetPitch/SwitchTo instruction was replaced by an SVC even when the sampled diagnostic line was not emitted;
- V88 emitted BEGIN/END strings around every Native_onDrawFrame and OpenSL callback lifecycle, producing tens of thousands of hot-path trace lines.

This means the v108 FPS drop mixes real ARM32->A64 Wwise cost with instrumentation overhead that is no longer needed to establish the 32 kHz root cause.

## v109 changes

- Adds V109_LEAN_AUDIO_PERFORMANCE.
- Preserves every functional v108 capability:
  - 32 kHz Wwise/OpenSL contract;
  - realtime OpenSL callback pump;
  - CAkAudioThread handshake;
  - synchronous UnloadBank BankMgr priority;
  - v107 semaphore wake repair;
  - v108 real SoundBank completion/liveness pulse.
- Removes only kCapWwiseResamplerProbe from the v109 capability mask.
  - Original CAkResampler Init/SetPitch/SwitchTo ARM instructions are left untouched.
  - No v105 SVC trap is installed in those hot paths.
- Suppresses V88 STARTUP BEGIN/END logging for:
  - Native_onDrawFrame;
  - V100_OpenSL_BufferQueueCallback;
  - V99_OpenSL_BufferQueueCallback.
- Keeps V90 frame, per-worker, allocator, host-cost and terminal summaries enabled.

## What this does not change

v109 intentionally does not change:
- Wwise's audio cadence;
- PCM contents;
- voice limits;
- worker slice size;
- scheduler ordering;
- main-thread blocking semantics;
- SoundBank completion semantics.

This is the safest first performance pass because it removes observer cost before changing scheduling policy.

## iPad validation

Compare directly with v108 in the same places:

1. PopCap transition / plant+zombie animation:
   - visual FPS;
   - V90 FRAME mainApproxMs;
   - V90 FRAME waitWorkerMs.
2. Day 3 with many plants and zombies:
   - whether the light gameplay slowdown improves;
   - whether sound remains normal and uninterrupted.
3. Transition completion:
   - no permanent freeze;
   - v108 BANK COMPLETION NOTIFY / DEFAULT CALLBACK still complete when needed.

A useful success signal is materially lower waitWorkerMs during the heavy transition without audio glitches. If waitWorkerMs remains dominant after removing the v105 SVC observer, the remaining cost is real emulated CAkAudioThread work and the next change can target scheduling/parallelism with a clean baseline.
