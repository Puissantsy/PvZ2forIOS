# v125 — Exact repeat enqueue context

## v124 result

The v124 iPad run proved the suspicious blocks are not a sparse-signature false
positive:

- 14 exact consecutive non-zero full-buffer PCM duplicates;
- all 14 reused the exact same guest buffer address;
- all 14 occurred when host queue depth was 0;
- animation: 13 exact repeats, guest frames 1295..1468, overlapping the user
  reported crackle apex ~1400;
- late stress: 1 exact repeat at guest frame 11204, close to the reported apex
  ~11100;
- no different-buffer exact duplicate was observed.

This strongly indicates stale guest-buffer replay at the Wwise/OpenSL producer edge.

## v125 question

Which guest execution context is actually calling OpenSL Enqueue when the stale
buffer is replayed?

For each exact repeat (bounded to 64 event lines), record:

- guest frame;
- execution context: raw OpenSL callback / identified CAkAudioThread worker /
  main / other worker;
- guest tid;
- PC/LR;
- guest buffer address and byte count;
- host queue depth;
- callback deliveries / host-consumed / pending callbacks;
- identified audio-worker tid and v104 handshake count.

Terminal summary aggregates repeat counts by context.

No PCM is modified or dropped. No callback cadence, scheduler priority, BankMgr,
32 kHz source clock or AVAudioEngine behavior is changed.

## Test

Keep the animation crackle inside 800..2500 and the final-wave/input crackle inside
10000..12500, note the approximate apex frames, then Hard Stop and provide the log.