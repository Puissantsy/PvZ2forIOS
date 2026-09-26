# v133 — Exact Android UIFlickEvent ABI

Video comparison (real iPad vs BlueStacks) confirmed that Android keeps the
Almanac carousel moving for roughly 1–1.6 seconds after several fast releases,
while v132 still stops with the finger.

v132 had the correct semantic event and ordering but the wrong payload layout.
Android GestureDetector.OnGestureListener.onFling has float velocityX and
float velocityY. The exact 32-byte UIFlickEvent record is:

- +0x00 int type = 4
- +0x04 int X
- +0x08 int Y
- +0x0c float velocityX
- +0x10 float velocityY
- +0x14 0xDEADBEEF
- +0x18 0xDEADBEEF
- +0x1c 0xDEADBEEF

v132 incorrectly encoded velocity as two doubles, shifting the second velocity
and sentinels. v133 corrects only this ABI. Flick-before-UP ordering, release
fallback, v131 RNG, v130 launcher, v129 board scale, v128 persistence and v127
audio remain unchanged.

Validation: fast Almanac flick should continue after release with gradual
deceleration and tabs must remain immediately clickable.
