# v142 — BoardTimerColor exact recorder

v141 finally captured the real Power Up window and isolated the only
non-white/non-black solid-color draw:

RGBA (150,250,120,125), program 11, standard alpha blending.

The three captured states had tiny horizontal scanline-like geometry, but v141
still had a <=256 vertex filter. Therefore those three samples may merely be
moments where the radial tessellation happened to shrink below that threshold.

v142 keeps the v141 pp.dat sandbox and late purchase trigger, but adds a separate
recorder BEFORE the <=256 filter. It recognizes the exact timer color and traces
up to 16384 vertices, computing the full bbox and count once per frame.

The noisy v140 super-probe is disabled in v142 so the log is small and the
BoardTimerColor timeline can run through the entire effect.

Test: use one green Power Up, let it expire, Hard Stop, export the full log.
Restarting the app still restores the persistent pp.dat/coin balance.
