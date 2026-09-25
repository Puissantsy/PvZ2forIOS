# v118 — Production lean audio/bank pass

## Why v118 exists

v117 proved that the former animation slowdown was largely self-inflicted by hot
instrumentation. The full iPad run averaged about 9.98 ms of guest time per frame and
the previously severe animation became visually smooth.

Two residual symptoms remained:

- slight audible glitches during SFX-heavy bursts and rapid plant-selection stress;
- isolated long frames around synchronous SoundBank lifecycle work.

The v117 log also showed that instrumentation was still active exactly in those paths.

## Root cause targeted

V104 still hashed every enqueued PCM block byte-by-byte (normally 4096 bytes) to detect
identical non-zero buffers and emitted PCM REPEAT diagnostics. V85 still emitted a log
line for nearly every touch begin/end during the stress test. V96/V106/V107/V108 also
emitted detailed synchronous BankMgr/semaphore diagnostics during SoundBank work.

Because logging/profiling already caused the large pre-v117 regression, v118 removes
this remaining observational work before changing any validated audio semantics.

## Functional behavior unchanged

v118 is capability-identical to v117. It does NOT:

- drop or rewrite identical PCM buffers;
- change the 32 kHz Wwise/OpenSL source rate;
- change AVAudioEngine format or queue capacity;
- fabricate buffer-complete callbacks;
- fabricate UnloadBank completion;
- change the audio-worker handshake;
- change semaphore/mutex/condition scheduling;
- change gameplay/render/input behavior.

## Removed hot diagnostics

- V104 4096-byte FNV PCM fingerprint/repeat scan;
- V104 PCM REPEAT logging;
- detailed V99 enqueue/callback and V100 callback ABI logging;
- V102 pacer spam;
- V104 handshake spam;
- V96 main-block enter/resume logging;
- V106/V107/V108 BankMgr/audio-event hot diagnostics;
- per-event V85 touch and guest-action lines.

Aggregate counters and lightweight periodic V90 frame timing remain available.

## Test contract

Repeat the same full route through Day 4.

1. Verify the old animation remains visually smooth.
2. Listen carefully during the SFX-heavy section that glitched in v117.
3. Repeat rapid plant-selection stress.
4. Observe transitions around SoundBank load/unload.
5. Finish the last wave, Hard Stop, export the complete log.

If the audible glitches disappear, the remaining issue was diagnostic overhead and
v118 becomes the new production baseline. If they remain, the next version can modify
the actual producer/consumer behavior with much higher confidence because all known
observer overhead has been removed.