# PvZ2 v92 — Long-Run Interactive

Date: 2026-09-23

## Root cause targeted

v91 succeeds on the real iPad and reaches the real interactive game quickly.
Its 600-frame termination is clean: the remaining short-session limit is the
historical fixed probe ceiling, not a crash.

## v92 behavior

v92 remains separate from the reproducible v91 600-frame baseline.

- preserves the v91 exact indexed first-fit allocator;
- preserves v91 GNU_RELRO/import protection;
- preserves v90 direct shared-EAGL presentation and frame pacing;
- preserves scheduler, VFS/resource, touch and keyboard bridges;
- removes the 600-frame loop ceiling only in V92 Long Run;
- continues until Hard Stop or a real guest/runtime failure;
- keeps terminal allocator/RELRO/performance summaries;
- marks frame-boundary user stops explicitly;
- throttles periodic frame/performance logs for sustained sessions while still
  retaining startup checkpoints, 600-frame checkpoints, minute-scale
  checkpoints and >=250 ms stalls.

## What v92 does not change

Allocator semantics, RELRO policy, scheduler policy, resource remapping,
UI package selection, GLES contract, touch mapping, keyboard bridge and
audio/network compatibility behavior are unchanged from v91.

## iPad validation

Use **V92 Long Run**, which is the default mode.

1. Run the same APK + OBB.
2. Let the first real frame appear.
3. Enter the player name.
4. Continue through every reachable menu/state beyond the former 600-frame
   point.
5. Use Hard Stop only when intentionally ending the run or after recording a
   problem.
6. Export the complete log.

Report text-entry behavior, every new menu/level transition, visual/audio
anomalies, freezes or crashes. If iOS actually crashes, include the .ips report.
