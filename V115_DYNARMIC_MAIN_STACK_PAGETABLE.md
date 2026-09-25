# v115 — Dynarmic main-stack page table

## Root cause targeted

v114 isolated the remaining visible slowdown on the Native_onDrawFrame main thread.

Across the profiled run, most main-thread jit.Run wall time was guest execution between
natural imports rather than host import-handler time. The ~700–770 animation is
main-bound, while the ~800 transition is a separate allocation/loading-heavy phase.
The deliberate seed-spam test around ~4800 is already healthy in v114.

Static analysis of the dominant guest path also found a large local stack frame around
libPVZ2.so+0x001890a0. v113 already proved that Dynarmic direct page-table memory can
remove callback overhead safely for the stable 128 MiB guest heap.

## v115 change

Preserve the complete v114 runtime and telemetry, including:

- v113 direct guest-heap page table;
- v114 natural main-thread boundary/import profiler;
- v95 precise LR-slot provenance;
- v96+ scheduler/wait fixes;
- validated audio, input, rendering and Android UI control paths.

At frame 1, additionally map the lower 255/256 pages of the fixed 1 MiB main guest
stack directly through Dynarmic:

- direct: `0x20000000..0x200fefff` (255 pages / 1,044,480 bytes);
- callback-backed: `0x200ff000..0x200fffff` (final 4 KiB page).

The final page is intentionally excluded because all LR-slot addresses observed in the
v114 run were in `0x200ff000`. Keeping it callback-backed preserves the v94/v95
write/provenance observation path instead of trading diagnostics for speed.

No guest code is patched. No scheduler, Wwise, GLES, input, UI-package, allocator or
gameplay behavior is changed.

## Expected log evidence

At frame 1:

- `V113 HEAP PAGETABLE ACTIVE ... mainStackLower=PAGE_TABLE mainStackHigh4K=CALLBACK`
- `V115 MAIN STACK PAGETABLE ACTIVE ... directPages=255 ... callbackTailBase=0x200ff000 callbackPages=1`

The terminal V113 page-table summary also reports the stack-direct state.

## iPad test contract

1. Confirm the game reaches the same playable state as v114.
2. Confirm `LR-SLOT ARM/POP` traces still appear and remain coherent.
3. Reproduce the ~700–770 laggy animation and compare frame/main114 timings with v114.
4. Continue through the ~800 transition; treat it separately from the animation.
5. Reach Day 4, first zombie, and a heavy late wave.
6. Repeat fast seed selection; it should not regress from the ~24.5 ms v114 result.
7. Hard Stop and export the complete log.

A strong reduction in the ~700–770 main-thread cost with intact LR telemetry validates
stack callback overhead as a structural bottleneck and justifies considering other
carefully bounded direct-memory regions later.
