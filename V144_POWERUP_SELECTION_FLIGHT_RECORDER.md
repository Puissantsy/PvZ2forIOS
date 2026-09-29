# v144 — Power Up Selection Flight Recorder

## Goal

v143 proved that merely selecting a Power Up does not submit the active
program-11 BoardTimerColor path and does not submit a large uniform solid-color
fallback. v144 therefore observes the selection transition itself instead of
patching GLES output.

## Runtime behavior

v144 inherits every validated v143/v142/v141 behavior, including the pp.dat
sandbox. It adds no gameplay or rendering correction.

After frame 1000, each terminal touch (Android phase 3 / ACTION_UP) opens a
150-frame capture window. During that window the probe records de-duplicated
blended draws that are either:

- program 11 or program 12; or
- spatially large enough to plausibly be a lawn overlay/border/UI state.

Each V144 SELECTION DRAW record contains:

- touch window number, touch coordinates and frame age;
- arrays/elements, program, primitive mode and count;
- full position bbox and size;
- texture units 0/1 and blend factors;
- first vertex RGBA when available;
- guest caller LR;
- guest SP plus up to eight libPVZ2-looking stack return candidates.

This allows selection and deselection windows to be compared even when the
missing full tint emits no draw at all. The visible Power Up border should act
as the positive selection-state marker and its native call chain can then be
followed upstream toward the missing tint logic.

## iPad test

1. Enter a playable level.
2. Do not touch anything for about 2 seconds.
3. Tap the green Pinch Power Up once to select it, but do not activate it.
4. Wait about 3 seconds.
5. Tap again / cancel so the Power Up is no longer selected.
6. Wait about 2 seconds.
7. Hard Stop and export the complete log.

Do not spend/use the Power Up for this first v144 run.

## What the test must decide

- Which draw signatures exist only while selected.
- Which caller LR / stack candidates produce the visible border.
- Whether any non-program-11 draw appears only during selection and could be
  the missing board tint path.
- Whether selection and active BoardTimerColor eventually converge on a common
  native parent path.

No synthetic green quad, angle fix, Board-scale change or blend workaround is
applied in v144.
