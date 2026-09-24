# v102 — real-time OpenSL completion pump

## Confirmed from the real iPad v101 log

v101 eliminated the host sample-clock mismatch hypothesis:

- Wwise requested 48,000 Hz stereo PCM16;
- AVAudioSession = 48,000 Hz;
- AVAudioSourceNode = 48,000 Hz;
- main mixer = 48,000 Hz.

The remaining defect is scheduler coupling. The guest has four 1024-frame
OpenSL buffers, only about 85.3 ms at 48 kHz. During the first real game frame
Native_onDrawFrame took about 5.04 seconds. CoreAudio consumed all four buffers,
but v101 did not call CAkSinkOpenSL::EnqueueBufferCallback until that frame
returned. The user independently observed the same contract: when visual frame
progress stops during loading, audio stops too.

## Root cause targeted by v102

CoreAudio already ran independently, but its completion events were only
*delivered back to Wwise* from pre-frame/frame-boundary drains. That made visual
frame boundaries an accidental refill clock.

High FPS does not directly change AVAudioEngine's 48 kHz sample clock. However,
starve/refill bursts can create discontinuities and perceived fast-forward, and
the coupling is invalid regardless of whether it is the entire remaining pitch
problem.

## Implementation

CoreAudio still never enters Dynarmic.

The AVAudioSourceNode render thread only updates atomics:
- render callback count;
- frames requested by CoreAudio;
- PCM frames actually supplied;
- underrun frames/events;
- completed OpenSL buffers.

During long guest lifecycle execution, AddTicks samples the host completion
total every 32,768 guest ticks. If a completed buffer is waiting and the Wwise
sink mutex is free, it requests the ordinary soft Dynarmic scheduler halt.

At that scheduler checkpoint v102:
1. saves the paused guest state;
2. runs the native OpenSL buffer-complete callback with raw ARM ABI
   (r0=queue, r1=CAkSinkOpenSL context);
3. uses a dedicated 64 KiB guest callback stack and distinct synthetic thread id;
4. requires the callback to return cleanly with no mutex left held;
5. restores the paused guest state exactly and resumes onDrawFrame.

Existing pre-frame/frame-boundary drains remain as fallback only.

## New telemetry

V102 AUDIO INLINE ...
V102 AUDIO PACER phase=... elapsedMs=... renderCallbacks=...
  requestedFrames=... pcmFrames=... underrunFrames=...
  underrunEvents=... effectiveRequestedHz=... queued=...
  pendingGuestCallbacks=...

For a healthy host clock, effectiveRequestedHz should converge near 48,000.
During a long visual frame, V102 AUDIO INLINE markers should now appear *before*
Native_onDrawFrame ends and the queue should continue refilling.

## Real-iPad test contract

1. Listen through the initial loading stalls.
2. Check whether audio continues while the visual frame counter is temporarily
   stationary.
3. Check whether music/SFX pitch and tempo return to normal.
4. Preserve gameplay/rendering stability.
5. Send the full log even if the audio sounds correct.

If effectiveRequestedHz is ~48 kHz and underruns collapse but pitch is still
high, the next investigation is inside the guest Wwise timing/mix producer,
not AVAudioEngine sample-rate negotiation.
