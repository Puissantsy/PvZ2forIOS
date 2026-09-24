# v99 — Wwise OpenSL ES → AVAudioEngine bridge

## Root cause

The Android PvZ2 1.5.252752 binary already contains Wwise, its decoders, mixers,
SoundBank/WEM handling and the Android \`CAkSinkOpenSL\` sink. The compatibility
runtime deliberately returned a non-success result from \`slCreateEngine\`, so
Wwise selected its dummy/silent sink even though the rest of the audio runtime
and worker scheduling were alive.

The APK imports only one OpenSL function and five IID data symbols:

- \`slCreateEngine\`
- \`SL_IID_ENGINE\`
- \`SL_IID_PLAY\`
- \`SL_IID_BUFFERQUEUE\`
- \`SL_IID_ANDROIDCONFIGURATION\`
- \`SL_IID_AUDIOIODEVICECAPABILITIES\`

All later OpenSL calls are vtable dispatches from \`CAkSinkOpenSL\`.

## v99 implementation

v99 preserves every validated v98 capability and adds one narrow OpenSL
compatibility class:

1. Imported IID symbols now have the Android pointer-valued data-symbol shape.
2. \`slCreateEngine\` returns a real guest \`SLObjectItf\` handle.
3. Guest vtables implement the subset observed in \`CAkSinkOpenSL\`:
   - Object: Realize / GetState / GetInterface / RegisterCallback / Destroy
   - Engine: CreateOutputMix / CreateAudioPlayer
   - Play: SetPlayState
   - BufferQueue: Enqueue / Clear / GetState / RegisterCallback
   - AndroidConfiguration: SetConfiguration
   - AudioIODeviceCapabilities: GetAvailableAudioOutputs /
     QueryAudioOutputCapabilities
4. The capabilities interface advertises one integrated stereo output at
   48,000 Hz.
5. \`CreateAudioPlayer\` reads Wwise's real PCM contract from the guest
   \`SLDataSource\`. v99 accepts 16-bit mono/stereo PCM and configures the host
   backend at the requested rate.
6. BufferQueue \`Enqueue\` copies the already-mixed Wwise PCM16 into a bounded
   native ring buffer.
7. \`AVAudioSourceNode\` converts PCM16 to Float32 on the CoreAudio real-time
   thread and sends it through \`AVAudioEngine\`.
8. The real-time thread **never enters Dynarmic**. It only increments an atomic
   completed-buffer counter.
9. At the next safe lifecycle/frame boundary the existing cooperative scheduler
   invokes Wwise's registered BufferQueue callback inside the guest. That
   callback can use the existing v96/v97 mutex/condition/semaphore semantics
   normally, then enqueue the next Wwise block.

## Why this avoids hand-converting audio

The RSB already contains the real SoundBanks and streaming media. Wwise remains
responsible for BNK/WEM decoding, event routing, music transitions, voices,
mixing and volume/effect logic. v99 only replaces the missing final Android
OpenSL device edge with an iOS audio device edge.

## Files

- \`platform/ios/src/host_audio.hpp\`
- \`platform/ios/src/host_audio.mm\`
- \`platform/ios/src/pvz2_apk_probe.cpp\`
- \`platform/ios/src/pvz2_apk_probe.hpp\`
- \`platform/ios/src/main.mm\`
- \`platform/ios/CMakeLists.txt\`

## Bounded runtime probes

Useful markers for the first real-iPad run:

\`\`\`text
V99 AUDIO OPENSL OBJECTS READY
V99 AUDIO ENGINE CREATE #1
V99 AUDIO OUTPUT MIX CREATE
V99 AUDIO PLAYER 48000 Hz channels=2 ...
V99 AUDIO HOST START backend=AVAudioEngine ...
V99 AUDIO BUFFERQUEUE CALLBACK registered ...
V99 AUDIO PLAY STATE 3 PLAYING
V99 AUDIO ENQUEUE #1 frames=1024 bytes=...
V99 AUDIO CALLBACK #1 ...
\`\`\`

Enqueue/callback logs are emitted for the first 16 occurrences and then at
power-of-two counts so audio cannot recreate a hot logging path.

## iPad test contract

A successful first v99 run should confirm all of the following:

- the game still reaches the same playable v98 state;
- \`slCreateEngine\` no longer falls back to DummySink;
- the first audio player reports the actual Wwise PCM format;
- BufferQueue enqueues contain real 1024-frame PCM blocks;
- AVAudioEngine starts;
- completed host buffers cause scheduler-safe guest callbacks;
- music/SFX are audible without a new scheduler crash or visible regression.

If sound is still silent, export the complete v99 log. The marker sequence
separates engine creation, PCM production, queueing, host playback and callback
delivery, so the next failure class can be identified without making one build
per missing OpenSL method.
