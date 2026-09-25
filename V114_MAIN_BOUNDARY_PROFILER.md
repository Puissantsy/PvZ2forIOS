# v114 — Native_onDrawFrame natural main-thread profiler

## Purpose
v113 cut CAkAudioThread cost by about 52% per frame on the real iPad and almost
halved the mapping_inverse/floor1_inverse1 cost per call. The remaining laggy
animation around frames ~770 now often spends more time on the main thread than
on tid5. v114 identifies that second bottleneck without changing runtime
semantics.

## Preserved runtime
- v113 128 MiB guest-heap Dynarmic page table remains enabled at frame 1.
- v112 audio boundary telemetry remains enabled.
- pinch, Android UI control, scheduler, Wwise/OpenSL and memory protections are
  unchanged.
- no __divsi3 or other guest optimization is added in v114.

## Main profiler
Only while Native_onDrawFrame is running on tid0:
- every existing main jit.Run span is timed;
- natural import SVCs record import name, exact LR/callsite, preceding guest
  execution gap and host handler cost;
- tail guest execution after the final import in each span is measured;
- spans with no imports retain natural startPC -> endPC plus total/max wall time;
- no periodic HaltExecution, SVC trap or guest code patch is introduced.

Slow/interesting frames append:
main114={runMs,guestGapMs,hostImportMs,tailMs,noImportMs,spans,calls,maxGapMs,maxHostMs}

Hard Stop emits:
- V114 MAIN BOUNDARY SUMMARY
- V114 MAIN IMPORT GAP
- V114 MAIN IMPORT HOST
- V114 MAIN CALLSITE GAP
- V114 MAIN NOIMPORT SPAN

## iPad test
Reproduce the same laggy startup/animation around ~770 frames, rapid seed
selection, and a heavy late wave. Then Hard Stop and export the full log.
The next optimization should target the highest main callsite/span class rather
than guessing.
