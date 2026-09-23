# PvZ2 v90 — Direct Presentation + Deterministic Performance Profiler

Date: 2026-09-23

## Evidence used

The real iPad reproduces the same fast and slow regions in v88 and v89. The
slowdown geography is therefore deterministic and tied to game work/state
transitions rather than being created by v89's profiler.

v89 also separated two independent costs:

- some guest frames are genuinely enormous before presentation begins (for
  example the ~89.8 s frame around frame 273);
- other guest frames are only a few milliseconds, while the old live path can
  spend tens of milliseconds reading a 2048x1536 RGBA framebuffer back to the
  CPU.

Static Android/iOS comparison identified the dominant v89 main-thread HOTPC
cluster inside EAText/FontFusion cmap lookup. The Android routine at
libPVZ2.so+0x00a4d954 contains a complete 0..65535 character/glyph scan. The
historical iOS 1.5 executable contains the equivalent algorithm, so v90 times
that real behavior instead of bypassing it.

The historical iOS renderer uses an EAGL drawable/renderbuffer presentation
path. v89 instead streamed one frame out of three through:
glReadPixels -> CPU flip/unpremultiply -> NSData -> CGImage/UIImage ->
UIImageView.

## Root causes targeted

v90 deliberately combines one proven presentation correction with
low-overhead measurements for the remaining deterministic stalls:

1. remove the one-in-three visible-frame decimation;
2. remove glReadPixels/UIImage from the live path;
3. replace unconditional post-frame sleep(16 ms) with a 16.666667 ms total
   frame budget;
4. time the verified complete cmap scan at lib+0x00a4dc30..0x00a4dc78;
5. measure synthetic heap first-fit fragmentation without logging every malloc;
6. separate worker wall time from the enclosing guest-draw wall time;
7. retain aggregate ETC1/VFS/zlib/GLES host-cost buckets;
8. do not inherit v89's ~1.8M-event BLX/quantum profiler in v90.

No allocator algorithm, font algorithm, scheduler policy, resource mapping or
audio backend is changed in this version.

## Files changed

- platform/ios/src/host_gles.hpp
- platform/ios/src/host_gles.mm
- platform/ios/src/main.mm
- platform/ios/src/pvz2_apk_probe.hpp
- platform/ios/src/pvz2_apk_probe.cpp

## Direct presentation

PvZ2 still renders into the validated 2048x1536 offscreen default framebuffer.

A second EAGLContext in the same sharegroup samples the existing color texture
and draws it directly into a CAEAGLLayer-backed renderbuffer. The drawable is
cleared black and the 4:3 game texture is aspect-fit. The presenter uses a
separate GL context so the guest GLES state remains untouched.

Every successfully completed guest frame is presented. Live display no longer
copies framebuffer bytes to UIKit. The old CPU readback code remains available
for explicit screenshots/terminal diagnostics only.

The old post-frame 16 ms sleep is also removed in v90. v90 sleeps only the
remaining portion of a 16.666667 ms target frame period. This is intentionally
a conservative pacing approximation rather than a rewrite of the whole guest
loop around CADisplayLink.

## Font probe

Static analysis verified a full 0..65535 cmap scan. v90 patches only two ARM
instructions:

- lib+0x00a4dc30: scan begin; the original MOVW r6,#0xffff is emulated;
- lib+0x00a4dc78: scan end; the original MOV r0,r4 is emulated.

This produces two SVC transitions per complete scan, not 65,536 probes.

## Allocator probe

The allocator algorithm is unchanged. v90 records:

- allocation/free counts;
- exact number of free-list entries examined by first-fit;
- average/max scan depth;
- scan-depth histogram;
- current/peak free-block count;
- alloc/free wall time sampled once per 1024 calls.

## Worker probe

Both existing worker execution sites are timed without changing when a worker
is run:

- worker execution inside a concrete lifecycle wait;
- one fair boundary-worker slice after a completed frame.

Per-frame lines separate approximate main-thread draw time, wait-worker time,
boundary-worker time, font scan time and presentation time.

## Useful log markers

- V90 FRAME
- V90 FRAME SUMMARY
- V90 FONT SUMMARY
- V90 ALLOC SUMMARY
- V90 HOSTCOST SUMMARY
- V90 PRESENT FAIL
- V90 TERMINAL

## iPad test

Use **V90 Direct**, which is the default mode.

1. Measure Run -> first visible frame.
2. Verify that the visible frame counter advances one by one rather than
   270 -> 273 -> 276.
3. In the sections that were already relatively fast in v88/v89, note whether
   motion now feels substantially smoother.
4. Follow the same interaction path as v88/v89 and note where the known slow
   regions begin and end.
5. Do not change the path just because one region is slow: reproducibility is
   useful for comparing the v90 counters with v88/v89.
6. If a stall becomes extremely long, Hard Stop remains available.
7. Export the complete log.

The log should tell us whether each deterministic stall is dominated by the
font cmap scan, a guest worker (including audio/Vorbis), allocator
fragmentation, host resource work, or residual main-thread guest execution.
