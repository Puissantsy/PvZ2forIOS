# v106 — Android audio-rate contract + BankMgr wait diagnostics

## Root cause confirmed by the v105 iPad run

v105 separated the host clock from Wwise's internal pipeline:

- the synthetic OpenSL player and AVAudioEngine source were created at 48,000 Hz;
- the first real Wwise voice reported sourceHz=32000, targetHintHz=32000,
  pipelineHz=32000, ratio=1.0 and a 65536 fixed-point step;
- therefore Wwise produced 32 kHz PCM with no resampling while the host consumed
  those frames as 48 kHz PCM: exactly 48/32 = 1.5x tempo and pitch.

Static ARM analysis explains why. PvZ2 1.5 calls
AK::SoundEngine::GetDefaultPlatformInitSettings(), then explicitly overwrites the
platform sample rate with 32,000 Hz (24,000 Hz on its alternate branch) before
AK::SoundEngine::Init(). CAkLEngine stores that rate in
AkAudioLibSettings::g_pipelineCoreFrequency before creating the OpenSL sink.

The v99 synthetic SLAudioIODeviceCapabilities descriptor incorrectly advertised
only 48 kHz. CAkSinkOpenSL therefore fell back to 48 kHz after Wwise's global
pipeline had already been fixed at 32 kHz.

## Audio correction

v106 changes the virtual OpenSL device contract, not game data and not Wwise DSP.

The synthetic output now advertises three discrete supported rates:

    24,000 Hz
    32,000 Hz
    48,000 Hz

PvZ2's normal 32 kHz request can therefore remain intact end-to-end through the
OpenSL player. host_audio.mm already creates its AVAudioSourceNode at the rate
requested by Wwise, while AVAudioEngine can convert downstream to the iPad's
actual mixer/session rate (normally 48 kHz).

Expected verification:

    V99 AUDIO PLAYER 32000 Hz ...
    V101 AUDIO CLOCK requested=32000 source=32000 mixer=48000 ...
    V105 WWISE RESAMPLER INIT ... sourceHz=32000 targetHintHz=32000
        pipelineHz=32000 ratio=1.000000 ...
    V105 WWISE RESAMPLER SETPITCH ... stepA=65536 stepB=65536 ...

Those Wwise values are now correct because the sink consumes 32 kHz frames.
A 48 kHz WEM should still show sourceHz=48000 target=32000 ratio=1.5.

## Long-run FPS/freeze evidence

The same v105 run later reached frame 3665. Before the final stall, frame time
rose primarily in waitWorkerMs rather than presentation. The final frame entered
a synchronous sem_wait with LR lib+0x00bb9afc.

Static disassembly maps that LR exactly to AK::SoundEngine::UnloadBank(): after
CAkBankMgr::QueueBankCommand(), the main thread waits on a completion semaphore.
Several consecutive UnloadBank waits completed in one worker round; the final
one did not complete before the user Hard Stop about 85 seconds later.

## BankMgr handling in v106

v106 does not fake UnloadBank success.

It identifies the real CAkBankMgr::BankThreadFunc entry
(lib+0x00bc7b8c) at pthread creation, including through the generic PvZ2 pthread
wrapper. During the exact synchronous UnloadBank sem_wait, that worker receives
first priority in the existing cooperative scan. Other workers are still scanned,
so this is dependency-aware scheduling rather than a BankMgr-only loop.

Power-of-two wait snapshots record:

- completion semaphore address/count;
- BankMgr worker tid;
- scheduler cursor;
- each deferred worker's PC/start/done/block state;
- held guest mutex count.

This should either prevent the starvation observed in v105 or leave enough state
to identify the next exact dependency without another generic probe.

## iPad test

Use the same APK + OBB.

1. Confirm the first music/SFX no longer sounds accelerated/high.
2. Continue past the point where v105's FPS degraded if possible.
3. If a frame stalls, Hard Stop rather than force-closing the whole app when the
   button remains responsive.
4. Send the complete log and describe what was visible/audible at the slowdown.

Key lines:

    V99 AUDIO PLAYER
    V101 AUDIO CLOCK
    V105 WWISE RESAMPLER INIT
    V106 BANK WORKER FOUND
    V106 BANK WORKER PRIORITY
    V106 BANK WAIT ROUND
