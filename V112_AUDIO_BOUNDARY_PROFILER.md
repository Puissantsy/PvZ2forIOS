# v112 — CAkAudioThread natural import-boundary profiler

## Why v111 was not enough

The real-iPad v111 log proved that periodic HaltExecution sampling aliases to
host import trampolines. All 75,319 samples were in the trampoline arena; about
91% landed on sem_timedwait and about 8.65% on atan2f. The synthetic
sem_timedwait handler does not host-block: it records a cooperative wait and
halts the guest so the existing scheduler can run. Therefore the v111 sample
distribution is a visibility-boundary distribution, not a CPU hotspot profile.

## v112 design

v112 removes the periodic v111 audio sample halt entirely. It preserves the
validated v110 runtime, Android UI control and pinch bridge.

Instrumentation runs only on tid5 / CAkAudioThread and only around import SVCs
that the guest naturally executes.

For every natural import call v112 records:
- import/SVC identity;
- exact guest LR/callsite;
- host handler wall time;
- wall time spent executing guest code since the preceding import, but only
  while still inside the same jit.Run worker span.

Each jit.Run span also records tail time after its last import, or the complete
span as no-import time if it executes no import.

No extra guest SVC, guest code patch or periodic HaltExecution is installed.

## Expected logs

Slow frames append:
audio112={runMs=...,guestGapMs=...,hostImportMs=...,tailMs=...,
noImportMs=...,calls=...,maxGapMs=...,maxHostMs=...}

Hard Stop emits:
- V112 AUDIO BOUNDARY SUMMARY
- V112 IMPORT GAP ... top imports by preceding guest-execution time
- V112 IMPORT HOST ... top imports by host handler cost
- V112 CALLSITE GAP ... top exact guest LR/callsites

## iPad test

1. Confirm behavior/audio/pinch are equivalent to v110.
2. Reproduce a heavy-SFX animation stall.
3. Spam seed packets rapidly.
4. Keep running through both normal and bad periods.
5. Hard Stop and export the complete log.

Decision rule for the next build:
- large hostImportMs => optimize the named host bridge/import;
- small hostImportMs but large guestGap/noImport => optimize/emulate the
  identified Wwise guest path instead;
- do not change scheduler/audio semantics until this split is measured.
