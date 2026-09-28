# v141 — Power Up laboratory

## Why v140 missed the real Power Up

The real v140 iPad log proved both diagnostic budgets expired before activation:
- V140 POWERUP SUPER #900 ended at frame 1384.
- V138 POWERUP GEOM #1200 ended at frame 2965.
- The real Power Up interaction started later, around frame 3300+, with
  V110 PINCH EVENTS and a pp.dat flush at 09:34:51.

Therefore earlier "Power Up candidates" were normal level/UI geometry.

## v141 strategy

### Reversible test economy

In v141 only, the real pp.dat is loaded normally but writes to that one file are
not persisted to disk. The game still deducts the Power Up price in memory for
the current process, but restarting the app reloads the untouched persistent
pp.dat. Other UserFS files keep their normal behavior.

This build is diagnostic-only: normal profile progression made while it is
running should not be relied on because pp.dat changes intentionally do not
persist.

### Correct trigger

A pp.dat flush at frame >=2500 arms the recorder. Real captures place startup
around frame 850 and the paid Power Up flush around frame 3300, so startup saves
cannot exhaust the recorder.

Once armed, v141 records for 1200 frames and resets prior v138/v140 budgets.

### Comprehensive graphics capture

During the armed window:
- the old large-geometry filter is bypassed;
- all blended program 11/12 draws up to 256 vertices/indices are eligible,
  including the tiny early radial wedge;
- up to 16 records/frame and 6000 total;
- all v140 details remain: geometry, UV, vertex color, blend, color mask,
  textures, uniforms, viewport/scissor/FBO, arrays/elements.

## Test loop

Install v141, enter a level and use one Power Up normally. Let the timer finish,
Hard Stop, export the log. Restarting the app restores the pre-test pp.dat/coin
balance, allowing repeated diagnostic runs without consuming the persistent
coin reserve.
