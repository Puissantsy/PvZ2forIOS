# v143 — Power Up selection caller probe

## Why this exists

v142 proved that the active Pinch BoardTimerColor is CPU-rasterized into
horizontal 1-pixel scanline quads. The real witness video also proves that the
same board tint is already fully present as soon as a Power Up is selected,
before the paid activation begins.

The port currently shows only the independent lawn border at selection time.
Because v142 only armed after the late pp.dat purchase flush, it could not tell
whether the pre-purchase full tint draw was absent or merely outside the old
<=256-vertex recorder.

## What v143 records

Observation-only graphics diagnostics, inheriting v142/v141 behavior.

Before *and* after purchase, while the Board is active, v143 watches program 11
solid-color draws up to 32768 vertices/indices.

It records:
- all exact known BoardTimerColor RGBA values:
  - Pinch: 150,250,120,125
  - Wizard: 255,145,250,125
  - Flick: 255,230,60,125
- rare large uniform solid-color board-like fallback candidates;
- arrays/elements, vertex count, full bbox, sample vertices;
- blend factors;
- crucially the guest caller LR at the GL draw import.

Stable geometry is signature-deduplicated to keep the log compact.

## First test is free

Do **not** activate the Power Up.

1. Enter a level and wait ~2 seconds.
2. Select the Pinch Power Up so the green lawn border appears.
3. Leave it selected for ~3 seconds.
4. Deselect/cancel it without using it.
5. Hard Stop and export the full log.

This costs zero coins.

The decisive outcomes are:
- exact green pre-purchase draw exists -> inspect its geometry and caller;
- only another large solid color exists -> inspect transformed selection path;
- no qualifying solid board draw at all -> selection state never submits the
  expected tint geometry, shifting investigation upstream of GLES.

If a later active test is needed, v141 pp.dat sandbox remains inherited.
