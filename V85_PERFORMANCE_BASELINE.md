# PvZ2 v85 — Performance Baseline

Date: 2026-09-23

## Goal

v84 V84_POINTS_EQUAL_PIXELS proved the global render-contract fix on the real
iPad: logical points and framebuffer pixels must both be 2048x1536 for this
Android APK compatibility path.

v85 makes that fix permanent in the new default mode and isolates the next
blocker: guest/runtime performance and interaction freezes.

This build deliberately does **not** change guest heap size or scheduler
semantics.

## Functional behavior preserved

V85_PERFORMANCE_BASELINE inherits the validated functional ladder:

- VFS + original OBB/resource bridges;
- cooperative scheduler and blocking-wait semantics;
- zlib stream ownership fix;
- ETC1 -> host RGB bridge;
- GLES host rendering;
- UI_IPAD package remap;
- 2048x1536 legacy iPad framebuffer geometry;
- Graphics_GetScreenSizeInPoints = 2048x1536;
- UIKit touch bridge;
- UIKit keyboard/text bridge;
- USERFS behavior.

The old v84 modes remain selectable for regression comparison.

## Hot diagnostics removed from v85

v85 intentionally does not inherit the V80 -> V82 -> V83 diagnostic chain.
It therefore avoids the global transform probe, Profile widget radar and rich
button-dispatch radar.

The performance mode also removes the observation-only StartupLogo/GameState/
registry-pipeline instruction traps, v69 TaskResource lifecycle provenance and
v67 completion-token provenance, disables post-EA JNI callsite/state-graph
scouts, skips sampled framebuffer diagnostics, suppresses scheduler wait spam
and bypasses small-allocation provenance maps.

The six resource-registry/wrapper instruction traps remain because they are
functional compatibility bridges rather than diagnostics.

## Lightweight timings kept

Guest/runtime log markers:

- V85 PERF guest ... guestDrawMs=
- V85 PERF capture ... frameCaptureMs=
- V85 PERF input stage=UI_ProcessEvents ... touchToUIProcessMs=
- V85 PERF input stage=guestAction ... touchToGuestActionMs=
- V85 PERF SUMMARY ...

Host/UIKit marker:

- [V85 PERF HOST] ... frameCopyMs=... UIKitPresentMs=... mainQueueMs=...

The host marker measures the existing presentation path without changing it:
full RGBA framebuffer -> NSData copy -> dispatch to main -> CGImage/UIImage.
At 2048x1536 RGBA8 that payload is 12,582,912 bytes per published live frame.

Normal performance lines are emitted only for the first few frames and then
every 30 guest frames, plus discrete input/action events. Historical diagnostic
logs are filtered before trace buffering and the Objective-C persistent-log
callback.

## Minimal input action trap

v85 keeps only the verified Profile button dispatcher instruction needed to
measure a real touch -> guest action boundary. It emulates the replaced
MOV r9,r0 exactly and records only the button ID/timing.

This is intentionally separate from the old V82/V83 Profile radar.

## iPad test

1. Leave the new default mode **V85 Perf** selected.
2. Run the same original APK + OBB.
3. Confirm the rendering stays correct at 2048x1536.
4. On Profile, tap the text entry, type a short name, then tap ACCEPT.
5. Compare subjective freezes with v84: startup animation, tap response,
   keyboard appearance, text entry and ACCEPT transition.
6. Stop/finish the run and export the complete log.

Important markers to return:

- V85 PERF BASELINE
- V85 PERF guest
- V85 PERF capture
- [V85 PERF HOST]
- V85 PERF input
- V85 PERF SUMMARY

## What the test decides

If interaction becomes materially smoother, the accumulated research probes
and persistent logging were a significant part of the slowdown.

If guestDrawMs remains dominant after the cleanup, the next optimization
target is inside guest execution/scheduler/resource work rather than UIKit.

If frameCaptureMs, frameCopyMs or UIKitPresentMs is large, the next step should
replace/avoid the current CPU 12 MiB-per-published-frame readback/copy/image
creation path.

Only after this baseline should guest heap changes be tested, so heap effects
are not mixed with the instrumentation cleanup.
