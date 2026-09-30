# V150 — guest-native qsort compatibility

## Root cause

v149 proved that the Power Up BoardTimerColor radial polygon is correct before
Sexy::Graphics::DrawPoly. The compatibility layer still handled POSIX qsort as
a no-op, while DrawPoly relies on qsort both for Y ordering and active-edge/X
ordering. That makes the rasterizer start at the center Y for the observed
Power Up polygons and corrupts scanline pairing.

This is a class-wide libc compatibility issue, not a Power Up-specific geometry
bug. libPVZ2.so has multiple qsort callsites, including both DrawPoly rasterizers.

## V150 change

- Install a guest-native ARMv7 qsort shim at trampoline arena +0x90000.
- The shim performs an in-place generic heapsort and calls the original PopCap
  comparator with BLX inside guest execution, so ARM/Thumb comparators and
  comparators that call other guest code/imports remain valid.
- Keep the v145/v149 radial probes enabled for direct before/after comparison.
- For repeated Power Up testing only, signature-patch the PowerupManager ctor
  store at guest +0x45e0ec and set m_ignoreCost (+0x30) to 1.
- pp.dat persistence remains normal; the old profile-wide sandbox is not
  reintroduced.

The sorting algorithm is POSIX-qsort compatible but is not intended to emulate
the historical Bionic Bentley-McIlroy comparison order. Code must not depend on
qsort's unspecified ordering of equivalent elements.

## iPad validation

1. Startup must report V150_GUEST_QSORT_COMPAT.
2. Import setup must report the guest-native qsort shim.
3. PowerupManager creation must report V150 POWERUP ignoreCost=1.
4. Activate Pinch and let the timer cross roughly 0.75 / 0.50 / 0.25.
5. Compare v149 source-polygon records with the final GLES draw. At ~0.50 the
   rendered sector must no longer begin at y=center; the upper half must survive.
6. At ~0.25 the final draw must no longer collapse into the center horizontal band.
7. Briefly exercise menus/gameplay because qsort is fixed globally, not only for
   DrawPoly.
8. Quit/relaunch once to confirm normal profile persistence still works.
