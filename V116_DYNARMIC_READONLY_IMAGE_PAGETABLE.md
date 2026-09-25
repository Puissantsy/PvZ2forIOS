# v116 — Dynarmic read-only image page table

## Root cause targeted

v115 validated direct Dynarmic memory for the main stack: the laggy animation improved
substantially, but remained far above the no-lag target. The v115 iPad run also showed
that remaining time is predominantly guest ARM execution rather than host import cost.

The remaining hot paths span both the main thread and CAkAudioThread, so v116 targets a
shared structural source of overhead instead of patching strlen, floorf, Vorbis, or
other callsites one-by-one.

## Exact ELF contract

For the supplied PvZ2 1.5.252752 armeabi-v7a libPVZ2.so:

- PT_LOAD[0]: vaddr 0x00000000, memsz 0x00ccaad4, flags 5 = PF_R|PF_X
- PT_LOAD[1]: vaddr 0x00ccbf90, memsz 0x0012d770, flags 6 = PF_R|PF_W

v116 validates this exact permission profile before running.

## v116 change

Preserve all validated v115 behavior:

- v113 128 MiB heap page table;
- v115 lower 255/256 main-stack pages direct;
- final main-stack page callback-backed for LR-slot/provenance;
- v114 main-boundary and v112 audio-boundary telemetry;
- existing scheduler, Wwise/OpenSL, rendering, input, VFS and allocator behavior.

At frame 1, additionally direct-map only complete 4 KiB pages fully contained in the
non-writable RX PT_LOAD:

- direct guest range: 0x10000000..0x10cc9fff
- 3274 pages / 13,410,304 bytes
- partial RX tail page at 0x10cca000 remains callback-backed
- writable PT_LOAD beginning at guest 0x10ccbf90 remains entirely callback-backed

This intentionally keeps mutable data, GOT and GNU_RELRO on the existing callback path.
No guest code, scheduler rule, audio timing rule, GLES behavior or game logic is changed.

## Why this is a batch optimization

The v115 run still showed large guest-side costs around main-thread string/math/render
paths and audio Vorbis paths. Those paths all execute from or read stable content in the
RX image. Mapping the complete RX pages attacks that shared memory-access class rather
than adding one optimization per hotspot.

## Expected log evidence

At frame 1:

- V113 HEAP PAGETABLE ACTIVE
- V115 MAIN STACK PAGETABLE ACTIVE
- V116 RX IMAGE PAGETABLE ACTIVE ... directPages=3274 ... directEnd=0x10cc9fff ...
  partialTailBase=0x10cca000 rwLoadBase=0x10ccbf90

The terminal V113 page-table summary also reports rxImageDirect.

## iPad test contract

1. Reach the same playable state as v115.
2. Confirm LR-SLOT ARM/POP and RELRO summaries remain coherent.
3. Reproduce the previously laggy animation and note its approximate frame range.
4. Continue into gameplay and a heavy final wave.
5. Repeat rapid plant selection while listening for any audio repeat/stutter.
6. Hard Stop and export the complete log.

The main success criterion is not merely “a little smoother”: the animation frame time
must move materially toward normal real-time rendering.