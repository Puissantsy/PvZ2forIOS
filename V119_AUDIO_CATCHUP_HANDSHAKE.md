# v119 — Audio catch-up handshake

## Root cause targeted

v117 removed the main performance pathology; v118 removed the remaining hot diagnostic
work. The audible crackle still reproduced at the end of the animation and during
rapid plant-selection SFX bursts while frame times stayed healthy.

The remaining scheduler asymmetry is concrete: V102 can deliver the same real OpenSL
buffer-complete callback from several safe contexts, but V104 immediately prioritizes
CAkAudioThread only when the scheduler checkpoint itself was caused by CoreAudio.
Callbacks delivered at a normal scheduler checkpoint, blocked main wait or frame
boundary can therefore wake Wwise without giving the producer immediate execution.
V104 also services only one callback even when multiple host buffers have already
completed.

## v119 behavior

v119 preserves the complete v118 production-lean runtime and changes only callback /
worker handoff scheduling.

- Up to the advertised OpenSL queue depth (4) real completions may be acknowledged in
  one bounded catch-up service.
- Every callback still corresponds to one buffer actually reported consumed by the
  host. No completion is fabricated.
- Any service that delivered at least one callback immediately prioritizes the real
  CAkAudioThread before main resumes, including scheduler checkpoints and blocked
  waits.
- Frame-boundary fallback explicitly points its single background slice at
  CAkAudioThread after delivering real audio completions.

Unchanged: 32 kHz source clock, pitch/resampler state, AVAudioEngine format/ring,
OpenSL queue capacity, BankMgr liveness, renderer, input and heap/stack/RX mappings.

## Validation

Terminal logging remains aggregate-only and adds:

V119 AUDIO CATCHUP SUMMARY services=... callbacks=... schedulerHandoffs=...
boundaryHandoffs=... maxPending=... maxBatch=... hostConsumed=...
callbackDeliveries=... pending=... queued=... underrunEvents=...

Repeat the normal route through Day 4, listening especially at the end of the
problematic animation and during rapid plant-selection SFX stress. Visual performance
and the final wave must remain as smooth as v118.