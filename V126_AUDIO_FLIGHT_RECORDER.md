# v126 — Audio Flight Recorder

## Root cause class targeted

v124/v125 proved that the remaining audible crackles correlate with exact
consecutive non-zero PCM duplicates from the same guest buffer, at queue depth
zero, almost always while the emulated OpenSL buffer callback is running.

Static ARM analysis of the exact Android `libPVZ2.so` resolves the key
ambiguity:

- `CAkSinkOpenSL::EnqueueBufferCallback` is ELF `0x00bb02b0`.
- Fresh-data Enqueue is called at `0x00bb0324`; synthetic OpenSL sees
  LR `0x10bb0328`.
- With `availableFrames <= 1023`, the callback asks OpenSL GetState. If the
  queue is empty it sets `sink+0x24 = 1`, calls Enqueue at `0x00bb0400`,
  and synthetic OpenSL sees LR `0x10bb0404`.
- That fallback does not decrement `sink+0x18` or advance `sink+0x10`: it
  replays the current read slot.
- Every exact repeat in the v125 real-iPad log used LR `0x10bb0404`; the user
  heard the two crackle clusters around ~1250 and ~11700.

Static sink fields recorded by v126:

- `+0x10` read index (frames)
- `+0x14` ring capacity (frames)
- `+0x18` fresh/available frames
- `+0x1c` PCM ring base
- `+0x24` starved flag
- `+0x28` platform buffer-count/config
- `+0x30` PassSilence run counter (PassData resets it)
- `+0x4c` successful OpenSL enqueue count
- `+0x50` playing flag

`CAkSinkOpenSL::Init` calls `AllocBuffer((sink+0x28) << 10)`; this build
configures `sink+0x28 = 4`, so the PCM ring is exactly four 1024-frame slots.
v126 therefore hashes the complete sink ring, not a sample.

`CAkSink::PassData` advances `+0x18` by 1024 frames. `PassSilence` also
advances availability in 1024-frame blocks. `CAkSinkOpenSL::IsDataNeeded`
calls OpenSL GetState with return LR `0x10bb011c` and computes
`max(0, capacity - available - queued*1024) / 1024`.

## Inspector integration

Inspector's existing exact call graph is reused through the already-present
natural AddTicks buckets: audio manager, VPL/mixer, resampler/pitch,
Vorbis/MDCT, other. v126 only accumulates these natural samples inside the two
probe windows; it does not install new Wwise SVC traps or periodic halts.

## One-run recorder

Only in frames **800–2500** and **10000–12500**, v126 stores bounded in-memory
records for host completions, inline callback pre/post, boundary fallback
callback pre/post (including `pre-frame` vs `frame-boundary` provenance),
OpenSL Enqueue/GetState, and tid5 worker pre/post.

Every flight event has a monotonic microsecond timestamp, allowing direct
measurement of `host completion -> callback -> callback return/wake -> worker`
latency. Static disassembly places `WakeupEventsConsumer` at ELF
`0x00bb0388`, immediately before callback return.

Worker snapshots always include sink state. Full hashes of all four ring slots
are armed only by starvation and sampled for the next two audio-worker rounds,
so the probe can prove which slot changed without paying that cost on every
normal callback. This keeps v126 much closer to v125 timing while still telling
whether tid5 actually produced a new 1024-frame block
before the next completion. The recorder covers both the v104 prioritized
audio handoff and ordinary boundary-worker scheduling, and logs every boundary
worker selection so a fallback callback can be correlated with whichever worker
actually ran next. Enqueue LR classification tells whether playback used fresh data or
the exact Wwise starvation replay branch. The terminal dump emits aggregate
summaries plus bounded anomaly-centered timelines for both windows.

## Invariants

v126 is observational only. It does not modify PCM, drop repeats, change
callback cadence, alter the v104 worker handoff, retune scheduler quanta,
change SoundBank behavior, or change the 32 kHz Wwise/AVAudioEngine clock
contract.

The in-memory event capacity is 65,536 records. Four-slot hashes are stored
only for starvation-adjacent audio-worker rounds, so the first window cannot
normally exhaust the recorder or materially perturb the second window.
