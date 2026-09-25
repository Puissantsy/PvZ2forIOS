# v122 — PCM continuity telemetry

## Result from v121

The stable v121 run reproduced crackle around guest frame ~1300 and again around
~15500, but host telemetry recorded only one underrun in the entire run:

- one empty 1024-frame underrun at guest frame 2;
- zero partial underruns;
- zero enqueue ring-full / block-full rejects;
- zero read CAS conflicts;
- host queue otherwise remained healthy.

This rules out normal CoreAudio starvation as the cause of the observed crackle.

## v122 question

Is the discontinuity already present in the PCM blocks Wwise hands to the host?

v122 preserves v121/v118 behavior exactly and adds two low-cost producer-side
measurements in PvZ2HostAudioEnqueuePCM16:

1. Inter-block edge continuity
   - compare previous block's final sample to the new block's first sample per channel;
   - count boundaries with absolute jumps >4096, >8192 and >16384;
   - record maximum jump and the guest frame where it occurred.

2. Sparse consecutive-block repeat detector
   - FNV-1a over only 16 evenly-spaced frames (<=32 PCM16 samples), not the full block;
   - count consecutive blocks with identical sparse signatures;
   - record max repeat run plus first/last guest frames.

No PCM data is modified. No per-buffer logging is performed. No guest scheduling,
OpenSL callback, BankMgr, 32 kHz clock or AVAudioEngine behavior changes.

## Test

Repeat the same route and note approximate crackle frames. Hard Stop after Day 4.
The terminal V121 HOST AUDIO SUMMARY now also contains the v122 continuity fields.