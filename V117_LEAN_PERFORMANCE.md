# v117 — Lean performance pass

## Root cause targeted

The real iPad v116 test validates normal gameplay performance: rapid plant selection
and the Day 4 final wave are perceptually smooth. The remaining severe issue is the
specific animation sequence, still around hundreds of milliseconds per frame.

v116 frame 1966 recorded roughly 545 ms total, including about 331 ms main and 214 ms
worker time, while the main boundary profiler observed 67,613 imports in that single
frame. Across the full run V114 recorded 39,170,080 main imports.

v117 therefore removes observational hot-path work before adding another game-specific
patch. This determines how much of the remaining slowdown is instrumentation-induced.

## Preserved functional runtime

v117 keeps v116 functional behavior:

- 128 MiB guest heap and indexed first-fit allocator;
- GNU_RELRO enforcement;
- cooperative scheduler / mutex / semaphore / condition-variable fixes;
- OpenSL/Wwise audio bridge and timing fixes;
- touch, pinch, keyboard and Android UI package behavior;
- ETC1/GLES/direct presentation;
- v113 heap direct page table;
- v116 complete RX-page direct mapping.

## Removed hot diagnostics

v117 disables:

- V112 per-import audio boundary profiler;
- V114 per-import main boundary profiler;
- V110 per-AddTicks audio bucket profiler;
- V90 allocator profiling;
- V90 host-cost profiling;
- V93 return provenance;
- V94 caller-return watch;
- V95 precise caller-return watch.

V90 lightweight frame/worker timing remains enabled so the iPad log still gives
guestMs/mainApproxMs/waitWorkerMs and periodic frame samples.

## Full main-stack direct mapping

V115 intentionally kept 0x200ff000..0x200fffff callback-backed for V94/V95.
Those watches are disabled in v117, so the entire fixed 1 MiB stack is now direct:

- direct: 0x20000000..0x200fffff
- pages: 256/256
- callback pages: 0

## Expected startup evidence

- V117 LEAN PERFORMANCE
- V113 HEAP PAGETABLE ACTIVE ... mainStack=PAGE_TABLE(256/256)
- V117 FULL MAIN STACK PAGETABLE ACTIVE ... directPages=256 callbackPages=0
- V116 RX IMAGE PAGETABLE ACTIVE ... directPages=3274

There should be no V112 AUDIO BOUNDARY SUMMARY or V114 MAIN BOUNDARY SUMMARY at Hard
Stop because those profilers are deliberately disabled.

## iPad test contract

1. Reach the same playable state.
2. Reproduce the problematic animation and note its approximate frame range.
3. Observe whether the lag changes materially; the target remains roughly 15–20 ms.
4. Sanity-check rapid plant selection and audio.
5. Hard Stop and provide the complete log.

If the animation collapses from hundreds of milliseconds toward real-time, profiling
overhead was a major remaining bottleneck. If it stays similarly slow, the next pass
must target the actual high-frequency guest/import workload rather than instrumentation.