# v134 — Exact Android onFling routing

## Evidence

Exact classes.dex inspection resolves AndroidUIEventManager.onFling:

- method registers show e1 is the first MotionEvent argument;
- X = (int)e1.getX();
- Y = (int)e1.getY();
- GestureDetector velocityX/velocityY arrive as float arguments;
- UIFlickEvent constructor stores those floats into DOUBLE fields;
- UIFlickEvent.Serialize uses ByteBuffer.putDouble for both velocities;
- event is enqueued before HandleTouchEvent processes ACTION_UP.

Exact serialized record remains 32 bytes:

- +0x00 int type=4
- +0x04 int startX
- +0x08 int startY
- +0x0c double velocityX
- +0x14 double velocityY
- +0x1c 0xDEADBEEF

v132 had the correct double layout but incorrectly used release/end X/Y.
v133 changed the velocity layout to float and is superseded.

## Why this matters

World Map covers a broad interaction region, so start/end routing differences can
be invisible. The Almanac carousel is a narrow ScrollWidget: Android routes the
flick to the widget where the gesture BEGAN. Using release coordinates can route
the type-4 event to a different child/card/empty area and lose inertia while
ordinary touch UP still works.

## v134

- restore exact double/double UIFlickEvent payload;
- route type 4 using stored gesture-start guest coordinates;
- keep FLICK before UP atomically;
- keep v132 release fallback;
- keep v131 rand48 fix and all prior validated runtime work.

Validation: fast horizontal Almanac carousel flick should continue after release
with gradual deceleration; tabs remain immediately clickable.
