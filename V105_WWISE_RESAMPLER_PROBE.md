# v105 — Wwise resampler state probe

## Why v105 exists

v104 established that the host audio clock and OpenSL producer/consumer handshake
are behaving correctly on the real iPad:

- Wwise/OpenSL requests 48,000 Hz stereo PCM16;
- AVAudioSession/source/mixer all report 48,000 Hz;
- measured CoreAudio consumption converges to about 47.9 kHz;
- the Wwise audio worker continues running during multi-second draw frames;
- startup underruns stop growing once steady state is reached;
- no consecutive non-zero PCM block repetition was observed.

The remaining defect is independent: normal music/SFX still sound too fast and
too high in pitch.

## Static evidence before changing code

The Android Wwise path is explicit:

    CAkVPLSrcCbxNode::AddPipeline
      -> copies CAkPBI+0x70 AkAudioFormat
      -> CAkVPLPitchNode::Init
      -> CAkResampler::Init(format, node+0x14c)

CAkResampler::Init converts the source sample rate from AkAudioFormat[0],
converts the target rate argument, divides source/target, and stores that base
ratio at resampler+0x2c.

CAkResampler::SetPitch clamps pitch to +/-2400 cents and multiplies the base
ratio by 2^(pitch/1200) and 65536 to obtain its fixed-point stepping state.

The decrypted ARMv7 iOS 1.5 executable supplied with the project uses the same
resampler ratio semantics. This makes an Android-vs-iOS algorithm difference
unlikely.

The canonical OBB contains 222 STREAMINGWAVES/*.WEM files. Matching those exact
entries back to their RIFF payloads gives this source-rate distribution:

- 187 at 32,000 Hz
- 17 at 48,000 Hz
- 7 at 36,000 Hz
- 3 at 44,100 Hz
- 2 at 16,000 Hz
- 2 at 8,000 Hz
- 1 each at 12,000 / 6,000 / 24,000 / 14,000 Hz

A 32 kHz source incorrectly reaching the sink without the intended 32->48 kHz
resampling would produce exactly a 1.5x speed/pitch error.

## What v105 changes

Nothing in the audio path is corrected yet.

v105 inherits all v104 behavior and installs three verified ARM observational
traps:

1. CAkResampler::Init @ lib+0x00c141f8
   - source AkAudioFormat rate
   - target rate argument
   - global Wwise pipeline frequency
   - stored base ratio
   - selected DSP function index
   - CAkPBI/source/sound IDs

2. CAkResampler::SetPitch @ lib+0x00c14498
   - stored base ratio
   - requested pitch in cents
   - fixed-point stepA/stepB after calculation
   - current state plus the exact next state implied by the following compare

3. CAkResampler::SwitchTo @ lib+0x00c145d8
   - new source format/rate and target-rate stack argument
   - updated ratio/steps after the transition
   - reselected DSP function index

Each trap emulates the replaced original instruction exactly. CAkResampler::Execute
is intentionally not trapped in v105 because it is a per-buffer hot path and
would unnecessarily perturb the audio timing.

## Deterministic interpretations

For a 32,000 Hz source targeting 48,000 Hz at 0 cents pitch, the expected state is:

    sourceHz      = 32000
    targetHintHz  = 48000
    pipelineHz    = 48000
    ratio         ~= 0.666667
    fixed step    ~= round((32000/48000) * 65536) = 43691

The probe distinguishes these cases:

- sourceId maps to a 32 kHz WEM, but sourceHz=48000:
  format/media metadata is already wrong before the resampler.

- sourceHz=32000 but targetHintHz=32000 while pipelineHz=48000:
  target-rate propagation into the voice pipeline is wrong.

- sourceHz=32000, target=48000, ratio~=0.666667, but step~=65536:
  SetPitch/powf/fixed-point state is wrong or corrupted.

- sourceHz=32000, target=48000, ratio~=0.666667, pitch~=0,
  step~=43691, and the DSP index is coherent while the audible output is still 1.5x:
  Init/SetPitch/dispatch selection are correct and the next probe should move
  into Execute itself rather than changing AVAudioEngine or WEM metadata.

- source/target/ratio/step are correct but the DSP index changes unexpectedly:
  investigate GetDSPFunctionIndex/dispatch-table selection before instrumenting
  the per-buffer Execute hot path.

A non-zero pitch value is also recorded so an intentional/unintentional Wwise
pitch request cannot be confused with a sample-rate defect.

## iPad test contract

Run exactly as v104 with the same APK + OBB. Let the first audible music/SFX play
for several seconds, including one loading slowdown if convenient, then Hard Stop
and send the full runtime log.

The decisive lines begin with:

    V105 WWISE RESAMPLER INIT
    V105 WWISE RESAMPLER SETPITCH
    V105 WWISE RESAMPLER SWITCHTO

Also report whether the ordinary audio still sounds accelerated/high. No other
visual, input, VFS, scheduler or audio behavior is intended to change.
