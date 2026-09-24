# v110 — Audio attribution + pinch + UI package A/B

## Root causes targeted

### Audio performance
v109 real-iPad telemetry reached 41,718 frames and still measured about 185.3 s in
worker tid5 / CAkAudioThread while every other deferred worker stayed below ~0.7 s.
GPU presentation was secondary. v110 therefore measures **where tid5 spends time**
before changing Wwise scheduling.

The profiler adds no Wwise SVC trap. Dynarmic AddTicks contributes cheap guest-PC tick
counters, and the already-existing worker wall-time quantum is attributed to the
dominant function family: audio manager/scheduler, VPL/mixer, resampler/pitch,
Vorbis/MDCT, or other. Detailed lines are added only for slow frames
(guest >=100 ms or audio worker >=50 ms), plus one terminal histogram.

### World Map pinch
The Android classes.dex path uses ScaleGestureDetector and serializes UIPinchEvent as
exactly 32 bytes: type=3, X, Y, scaleDistSq, scaleDelta, then three 0xDEADBEEF words.
The existing iOS bridge delivered multiple raw UITouchEvent records but never type 3.
v110 keeps the raw touches and additionally synthesizes the exact pinch record from
two active UIKit contacts on movement.

### Day 1 / SeedBank UI geometry
v109 inherits the v75 UI_ANDROID -> UI_IPAD resource-ID remap. Static RTON comparison
shows UI_IPAD already contains dimensions adapted to the 768-space, while the Android
guest keeps Android-side layout/scaling code. v110 makes this a causal A/B in one IPA:

- **Android UI (control)**: stop only the v75 package remap; load native UI_ANDROID.
- **iPad UI (remap)**: keep the existing UI_IPAD remap.

All other v109 capabilities remain identical.

## Source-layout refactor

The former ~39k-line pvz2_apk_probe.cpp is mechanically split into ordered .inc
fragments while remaining a single C++ translation unit. This avoids connector size
failures without changing shared-state/linkage semantics.

## Explicitly not in v110

Persistent USERFS/save support is deferred so it cannot confound audio/input/UI
results.

## iPad test contract

1. Start with Android UI (control), reach Ancient Egypt Day 1 and capture SeedBank /
   HUD / lawn placement.
2. Repeat the same scene with iPad UI (remap).
3. On World Map, verify two-finger pinch zoom and confirm ordinary tap/drag still work.
4. Reproduce the heavy animation / seed-spam slowdown and export the full log.
5. Confirm sound, bank unload transitions and long-run stability did not regress.
6. Inspect V110 AUDIO QUANTUM SUMMARY and slow V90 FRAME lines with audio110 buckets.
