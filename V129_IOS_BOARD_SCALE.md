# v129 — Historical iOS Board world scale

## Root cause

Static Android 1.5.252752 ↔ historical iOS 1.5.252123 comparison showed that
both builds use the same logical lawn geometry (200/160 origin, 576x380 board,
9x64 columns and 5x76 rows), but diverge on an additional Board transform.

Android writes an adaptive fit factor to Board+0x678 using
max(1.0, min(horizontalFit, verticalFit)). At the validated 2048x1536 / 2.56
contract this produces roughly 1.08, enlarging the whole gameplay world.

The historical iOS counterpart writes scale=1.0 and offsets=0/0 instead. The
same platform difference appears in two independent Board initialization paths.

## Functional correction

v129 keeps the entire v128/v127 runtime and patches only the final adaptive
scale stores at these exact Android 1.5.252752 instructions:

- lib+0x00174a50: VSTR s0,[r0]
- lib+0x00178a58: VSTR s0,[r2]
- lib+0x001791b8: VSTR s0,[r0]

All three are opcode-signature checked before startup. Their SVC replacements
derive the Board pointer from the destination and atomically impose:

- Board+0x678 = 1.0f
- Board+0x67c = 0
- Board+0x680 = 0

Consumers of the transform are untouched. Resolution, Points=Pixels, FBO,
presenter, UI RTON selection, touch, save persistence and audio behavior are
unchanged.

## iPad validation

Reach Ancient Egypt Day 1 and compare against the historical iOS reference:

- lawn should be visibly less enlarged;
- lawn mowers should have more breathing room;
- more environment should be visible around the board;
- SeedBank should no longer appear pushed onto the lawn by the enlarged world.

The terminal summary reports how many times each of the three verified scale
writers was replaced.
