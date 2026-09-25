# v124 — Exact PCM repeat provenance

## Why this pass exists

v123 strongly correlated non-silent sparse-identical PCM with the two audible crackle
windows:

- user crackle ~1150; non-silent repeats 1141..1406 (28 events);
- user crackle ~10800; non-silent repeats 10769..10932 (7 events);
- those same windows also contained 27 and 10 inter-block jumps >8192.

This is strong correlation, but a 16-point sparse signature is not proof that the
entire PCM blocks are identical.

## v124

The runtime remains behavior-identical to v123/v118.

Only inside guest-frame windows 800..2500 and 10000..12500:

- compute full FNV-1a 64-bit over the entire PCM block;
- classify consecutive exact non-zero duplicates;
- record whether the exact duplicate came from the same guest buffer address or a
  different address;
- split counts between animation and late input-stress windows;
- record first/last repeat frame in each window;
- record queue depth at each exact duplicate.

No PCM is dropped, rewritten, interpolated or muted. No scheduler, OpenSL callback,
BankMgr, 32 kHz clock or AVAudioEngine behavior changes. No per-buffer logging.

## Test

Repeat the same Day 4 route, noting approximate crackle frames, then Hard Stop and
provide the full log.