# v111 — CAkAudioThread sampled-PC profiler

## Root cause targeted

v110 confirmed on the real iPad that the large slow-frame stalls are dominated by
`tid5 / CAkAudioThread`: in the instrumented slow frames, `audio110Ms`
accounts for about 98% of `waitWorkerMs`. However, the v110 sub-buckets are
not reliable enough to choose an optimization target: almost all time landed in
`other`.

The v110 profiler reads `jit->Regs()[15]` from `AddTicks`. That callback does
not provide a sufficiently trustworthy live guest PC for attributing the code
executed inside the current Dynarmic run.

## v111 change

v111 preserves the validated v110 runtime and Android UI control. It adds an
observational sampler only:

- only the Wwise audio worker (normally tid5) participates;
- every 131072 guest ticks, a private Dynarmic checkpoint is requested;
- once `jit.Run()` returns at that checkpoint, v111 samples the saved guest PC;
- the same worker is resumed immediately with its remaining slice budget;
- no Wwise SVC trap is installed;
- no guest mutex/semaphore/scheduler policy is changed;
- pinch remains inherited from v110.

Samples are classified into AudioMgr, VPL/mixer, resampler/pitch,
Vorbis/MDCT, or other. v111 also retains a capped 64-byte PC-bin histogram so
an unexpected `other` bucket can still identify concrete hot code addresses.

## Expected log

Slow frames keep the v110 wall-time fields and add:

`audio111Samples={audioMgr:...,vplMixer:...,resamplerPitch:...,vorbisMdct:...,other:...}`

Hard Stop emits:

`V111 AUDIO SAMPLE SUMMARY ... buckets={...} topPcBins={...}`

The v110 terminal summary is also emitted as a diagnostic so it can no longer
be lost to the performance log whitelist.

## iPad validation

1. Confirm normal gameplay/audio behavior remains equivalent to v110.
2. Reproduce a heavy-SFX animation lag.
3. Rapidly select seed packets to reproduce the known input/SFX stall.
4. Hard Stop.
5. Export the complete runtime log.
6. Check that `V111 AUDIO SAMPLE SUMMARY` contains a useful sample count and
   that one or more Wwise buckets / PC bins dominate.

If v111 itself noticeably changes sound, timing, pinch, or the severity of the
lag, treat that as profiler overhead/regression rather than as an optimization.

USERFS persistence remains intentionally out of scope.
