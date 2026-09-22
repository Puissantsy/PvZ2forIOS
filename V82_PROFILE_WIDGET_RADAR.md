# PvZ2 v82 — Profile Widget / Action Radar

Date: 2026-09-22

## Why v82

The v81 logical-touch A/B did exactly what the /2 transform predicts: the
physical place required to reach the same internal TextEntry hit moved farther
from screen origin. That rejects a simple pixels->points /2 as the final input
fix.

The iPad observation is more interesting: the place that activates the
TextEntry in v81 appears close to where the TextEntry would plausibly sit if
the first-run Profile were rendered at the intended layout. v82 therefore
tests whether layout/hit logic is more coherent than the visible rendering.

## Preserved behavior

V82 inherits V81 logical touch delivery only as a diagnostic coordinate space.
It does not change:

- 2048x1536 framebuffer / 1024x768 historical iPad points;
- UI_IPAD selection;
- screenMatrix, FBO, viewport or presentation;
- v39 Native_onSurfaceChanged height,width ordering;
- widget rectangles or GameState;
- keyboard behavior.

V80 and V81 remain selectable controls in the same IPA.

## Static widget candidates

The Android 1.5.252752 broad Profile constructor contains 448-byte button-like
objects constructed with IDs 5, 7 and 6. Their semantic names are NOT assumed.

Exact post/pre-layout observation traps:

- candidate5 post-layout: 0x10309f94, original LDR r0,[r11,#0xa0]
- candidate7 post-layout: 0x1030a558, original LDR r0,[r11]
- candidate6 pre-layout:  0x1030a68c, original MOV r0,r9
- candidate6 post-layout: 0x1030a694, original ADD r8,sp,#56

All opcodes are signature checked against the reference APK and emulated
unchanged.

## Radar data

For Profile and candidate5/6/7, v82 records raw common-widget fields at:

- +0x28 / +0x2c
- +0x30 / +0x34

They are logged as `rawXYWH` candidates, not asserted semantics. Every
began/ended/cancelled touch receives `containsTouch=YES/NO` against these raw
rectangles.

Markers:

- `V82 WIDGET`
- `V82 TOUCH RADAR`
- `V82 PROFILE STATE`
- `V82 ACTION KEYBOARD`
- `V82 ACTION GAMESTATE`
- `V82 PROFILE RADAR SUMMARY`

The existing V79/V80/V81 markers stay active.

## iPad test

Leave **V82 Radar** selected.

1. Reach the Profile screen.
2. Enter at least one character so a Continue/Create-style action, if present,
   is not blocked by an empty name.
3. Dismiss the keyboard if useful.
4. Tap around the plausible lower/middle Profile area, including places where
   a correctly scaled TextEntry or Continue button might normally be.
5. If the screen changes, a button reacts, the keyboard opens, or anything
   visually changes, note approximately where you tapped.
6. Continue a few exploratory taps, then press Stop and export the full log.

If a hidden Continue-like action is reached, v82 should correlate the tap with
a candidate widget and/or a Profile/GameState state transition. Candidate IDs
remain unnamed until the runtime evidence identifies them.
