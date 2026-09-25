# v121 — Host audio telemetry

## Baseline

v121 branches directly from `v118-production-lean`.

The v119/v120 scheduler experiments are intentionally NOT inherited. v118 remains the
last stable and fluid runtime.

## Root cause being isolated

The remaining audible crackle reproduced around the Play animation and during dense
plant-selection SFX even after v118 removed the remaining hot guest diagnostics.

v121 asks one narrow question: when the crackle is heard, is the host
AVAudioSourceNode actually short of PCM, or is the discontinuity already present in
the PCM supplied by Wwise?

## Runtime behavior

No functional audio behavior changes:

- same V104 callback/CAkAudioThread handshake;
- same guest worker ordering;
- same 32 kHz Wwise/OpenSL source clock;
- same AVAudioEngine graph and format;
- same ring size and queue capacity;
- same underflow policy (zero-fill);
- same BankMgr / semaphore / input / renderer behavior;
- same v118 heap, full-stack and RX direct mappings.

## Telemetry

The CoreAudio render callback performs atomic counter updates only. No logging,
allocation, mutex or guest execution is added there.

After guest frame 1, diagnostics track:

- render callbacks / requested / actually rendered PCM frames;
- empty vs partial underruns and missing frame count;
- first/last guest frame tagged when an underrun occurs;
- low-water events and min/max PCM frames available before each render;
- min/max queued OpenSL blocks;
- maximum blocks completed by one render callback;
- ring read/enqueue wrap counts;
- Clear-vs-render read CAS conflicts;
- enqueue calls/frames and ring/block-capacity rejects.

Only one `V121 HOST AUDIO SUMMARY` line is emitted at terminal/Hard Stop.

## iPad test

Use the normal full Day 4 path. Note approximate frame numbers for any audible
crackle, especially:

1. the Play transition/animation;
2. dense SFX;
3. rapid plant-selection input;
4. final wave.

Hard Stop and provide the full log.