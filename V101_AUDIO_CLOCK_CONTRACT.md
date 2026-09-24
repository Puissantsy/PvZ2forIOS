# v101 — Audio clock contract

## Symptom

The first successful v100 iPad run has audible, continuously refilled audio,
but music/SFX are faster and higher pitched.

v100 proves the OpenSL callback ABI and BufferQueue refill loop are stable.
Static inspection of libPVZ2.so also proves CAkLEngine's default
AkPlatformInitSettings sample rate is 48,000 Hz (0xBB80), matching the OpenSL
player request in the log. A hard-coded 44.1 kHz workaround is therefore not
justified.

## Root class addressed

v99/v100 created AVAudioSourceNode with initWithRenderBlock: and supplied the
Wwise rate only on the engine connection. v101 makes the source node's own
format authoritative with initWithFormat:renderBlock:.

The guest audio clock is now explicitly:

    Wwise/OpenSL PCM rate -> AVAudioSourceNode source rate

If the iPad audio session or mixer runs another rate, AVAudioEngine performs
that conversion downstream. The ring buffer itself remains in Wwise frames and
must not be consumed according to an implicitly negotiated hardware clock.

## Runtime telemetry

v101 logs after AVAudioEngine starts:

    V101 AUDIO CLOCK requested=<Hz> session=<Hz> source=<Hz> mixer=<Hz>

For this build, requested=48000 and source=48000 are required. Session/mixer may
legitimately differ.

## iPad test

Confirm whether:
- audio is still present;
- music/SFX pitch and duration are normal;
- gameplay/rendering remain as v100.

Keep the complete log, especially V101 AUDIO CLOCK. If pitch is still wrong
while source=48000, the next target is measured render-frame consumption versus
host time/output route rather than guessing a new sample rate.
