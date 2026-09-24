# v104 — Wwise audio worker handshake

## What the real-iPad v103 run proved

v103 restored startup and reached stable gameplay. The host audio clock is not
the source of the speed/pitch defect:

- Wwise/OpenSL requests 48,000 Hz stereo PCM16;
- AVAudioSession, AVAudioSourceNode and mixer are all 48,000 Hz;
- the measured CoreAudio request rate converges to ~47.9 kHz;
- during the 5.229 s loading frame 291, CoreAudio continues consuming buffers.

The user nevertheless hears the last sound repeated extremely rapidly during
that loading stall, and the normal audio remains too fast/high ("nightcore").

## Static Wwise evidence

The imported guest mutex repeatedly held by deferred worker tid=5 is guest
0x10df90f0. libPVZ2.so exports that exact BSS symbol as:

    g_csMain

which is Wwise's main sound-engine critical section.

The native Wwise flow is also explicit in libPVZ2.so:

    CAkSinkOpenSL::EnqueueBufferCallback
        -> consumes/enqueues sink PCM
        -> CAkAudioThread::WakeupEventsConsumer()

    CAkAudioThread::EventMgrThreadFunc
        -> CAkAudioMgr::Perform()
        -> sem_wait(...)
        -> repeat

Most importantly, EnqueueBufferCallback contains a starvation path: when the
OpenSL queue is empty while the sink has <=1023 fresh samples, it marks the sink
starved and enqueues one 1024-frame block from the sink ring anyway. On real
Android the subsequent WakeupEventsConsumer lets the audio thread refill before
that concealment path repeats. In v103 we could service another completion
before guaranteeing that the awakened Wwise worker ran.

## Root cause targeted by v104

v103 implemented only the consumer half of the real contract:

    CoreAudio completion -> OpenSL callback -> resume main

v104 restores the producer half:

    CoreAudio completion
      -> exactly one OpenSL callback
      -> schedule exact CAkAudioThread worker
      -> CAkAudioMgr::Perform
      -> worker reaches its modeled sem_wait / safe preemption
      -> resume main

The async path remains restricted to Native_onDrawFrame, preserving the v103
fix for Native_onSurfaceCreated.

## Additional proof telemetry

v104 identifies the deferred worker whose start routine is the exported
CAkAudioThread::EventMgrThreadFunc at libPVZ2.so+0x00bfdb70 and logs:

    V104 AUDIO WORKER FOUND ...
    V104 AUDIO HANDSHAKE ...

Every sampled OpenSL Enqueue now also includes guest source address and a
32-bit FNV-1a fingerprint. Consecutive identical non-zero blocks emit:

    V104 AUDIO PCM REPEAT ...

This allows a remaining extratone symptom to be tied directly to stale guest
PCM instead of requiring another diagnostic-only build.

## iPad test contract

1. Startup and first frame must remain as stable as v103.
2. Look for V104 AUDIO WORKER FOUND, expected to identify the Wwise audio
   deferred thread (historically tid=5 in the v103 run).
3. During the long loading frame, V104 AUDIO HANDSHAKE should continue while
   the visual frame is still in progress.
4. The previous "last sound repeated like extratone" should disappear or be
   substantially reduced.
5. Report whether ordinary music/SFX speed and pitch are now normal.
6. Send the full log even if sound is fixed; PCM REPEAT counters and worker
   handshake cadence determine the next step.

No sample-rate, ring-buffer, rendering, UI, resource, or v96/v97 mutex semantics
are changed in this version.
