# v120 — Audio one-shot handshake

## Why v119 stalled

The v119 iPad log made the regression deterministic:

- real callback deliveries: 3,701
- audio scheduler handoffs: 96,760
- first draw entered but did not return for 118.3 seconds before Hard Stop

The v119 per-service marker stayed non-zero after the scheduler consumed it. During a
blocked-wait loop, later iterations therefore kept prioritizing CAkAudioThread even
when no new CoreAudio completion had arrived.

This was scheduler starvation caused by a sticky handoff token, not slow rendering.

## v120 fix

v120 keeps the useful cross-checkpoint handoff idea but restores the validated V104
ordering:

1. exactly one real host completion is delivered per service;
2. exactly one OpenSL callback is executed;
3. a one-shot handoff token is consumed immediately;
4. CAkAudioThread gets exactly one immediate priority pass;
5. the next callback is not delivered until a later service/checkpoint.

Frame-boundary delivery also remains one-at-a-time and explicitly gives its single
worker slice to CAkAudioThread.

No callback, semaphore post or SoundBank completion is fabricated. 32 kHz, pitch,
AVAudioEngine, BankMgr, rendering, input and direct-memory mappings remain unchanged.

## Test

First criterion: first frame must return with normal v118-like startup latency.

If it does, repeat the same full Day 4 test with attention to:
- end-of-animation crackle;
- rapid plant-selection SFX stress;
- last-wave visual performance.

Hard Stop and export the full log.