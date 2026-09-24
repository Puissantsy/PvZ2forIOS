# v103 — OpenSL draw-frame gate

## Real-iPad v102 regression

The v102 iPad log proved that the host audio clock itself is healthy:
- requested/session/source/mixer are all 48,000 Hz;
- CoreAudio consumes 1024 frames about every 21.3 ms;
- effectiveRequestedHz converges to ~47.85 kHz;
- pcmFrames equals requestedFrames and underrunFrames stays zero.

However v102 regressed startup before the first frame. Native_onSurfaceCreated
hit the existing 2B-tick safety ceiling.

The causal boundary is visible in the logs. In the validated v101 run,
LR-SLOT ARM #4 is followed by its POP and then the expected sem-wait sequence.
In v102, the first asynchronous audio-preempt callback is injected after
LR-SLOT ARM #4 and before that POP; the POP never appears and surface creation
never completes.

## Root cause targeted

v102 allowed CoreAudio-driven guest callback injection during every lifecycle,
including Native_onSurfaceCreated. Earlier scheduler work already established
that surface creation contains mutation windows where synthetic interleaving is
unsafe. A callback can be valid in real Android concurrency while still being
unsafe inside the current cooperative guest pthread model.

## v103 policy

Keep the v102 audio bridge, clock telemetry, dedicated callback stack/thread id,
raw OpenSL ABI, and fallback drains.

Change only the eligibility window for asynchronous injection:

    allowed: Native_onDrawFrame
    denied:  Native_onSurfaceCreated and every other startup lifecycle

When injection is denied, CoreAudio may consume the initial four buffers and
publish completion counters, but Dynarmic is not interrupted. The existing
pre-frame drain services those completions after surface initialization, exactly
like the validated v101 startup.

Once Native_onDrawFrame begins, CoreAudio completion events may again request a
soft scheduler checkpoint. This directly targets the user's observed case:
during a long visual frame/loading stall, audio should continue without making
surface initialization concurrent.

## iPad test contract

1. Native_onSurfaceCreated must complete and firstDraw must be reached.
2. Before first frame, there must be no V102 AUDIO INLINE phase=audio-preempt.
3. Initial accumulated completions may drain at pre-frame.
4. During the long first Native_onDrawFrame, V102 AUDIO INLINE
   phase=audio-preempt should appear before that frame ends.
5. Audio should continue during a visual frame stall.
6. Report whether pitch/tempo is still "nightcore".
7. Preserve the complete log for V102 AUDIO PACER effectiveRequestedHz,
   pcmFrames and underrun counters.

If the first frame is stable and effectiveRequestedHz remains ~48 kHz with no
underruns while pitch is still high, the next target is guest Wwise
mix/producer timing rather than AVAudioEngine or sample-rate negotiation.
