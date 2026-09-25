# v123 — Non-silent PCM repeat telemetry

## What v122 showed

The v122 iPad run reproduced audible crackle around ~1300 and ~11500 while the host
sink remained healthy:

- one startup underrun only, at guest frame 2;
- 112 inter-block jumps >4096, 21 >8192, 1 >16384;
- maximum edge jump 23846 at guest frame 2085;
- 185 sparse-identical consecutive PCM blocks;
- the last sparse repeat occurred at guest frame 11542, directly inside the
  user-reported ~11500 crackle/input-stress region.

However, v122 did not distinguish repeated silence from repeated audible PCM.

## v123

No functional behavior changes. The same v118 scheduler/audio runtime remains active.

For each sparse-identical consecutive block, v123 measures the peak absolute value of
the same 16 sampled frames. A repeat is classified as non-silent only when sparse peak
>=256.

Aggregate terminal counters include:

- total non-silent repeated blocks;
- maximum consecutive non-silent repeat run;
- first/last non-silent repeat guest frame;
- repeat counts + first/last event in animation window 800..2500;
- repeat counts + first/last event in late stress window 10000..12500;
- >8192 edge-jump counts in both windows.

No PCM modification, no per-buffer log, no scheduler change.

## Test

Repeat the same Day 4 path, noting audible crackle frames. Hard Stop and provide the
full log.