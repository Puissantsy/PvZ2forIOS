# v136 — exact touch timestamp seconds

## Root cause

v135 proved that the Almanac fast swipe already produced a valid UIFlickEvent:
the host generated it, serialized type 4 before the terminal touch UP, and the
ProcessEvents queue was empty on the next frame.

Static inspection then showed that UIFlickEvent velocity is not the kinetic
timebase used by scrolling. The Android native type-4 decoder reads the two
velocity doubles, reduces them to a dominant-axis direction, and dispatches the
shared app swipe virtual (+0x1c0). The velocity magnitude is not forwarded.

The normal touch path carries the temporal information used by shared touch
consumers. Exact classes.dex inspection shows:

- AndroidUIEventManager.GetTimeStamp() calls System.nanoTime();
- it converts the long to double;
- it divides by 1,000,000,000.0;
- UITouchTracker stores that result;
- UITouchEvent copies it into its timestamp double and Serialize() writes it
  unchanged with ByteBuffer.putDouble.

Therefore the Android/shared-engine Touch timestamp unit is **seconds**.
The legacy iOS 1.5 binary independently agrees: its iPhoneOSAppDriver stores
UITouch.timestamp directly in the shared Touch structure, and UIKit timestamps
are seconds.

The port had been doing `touch.timestamp * 1000.0`, so consecutive ~8 ms
hardware samples reached libPVZ2.so as ~8.0 seconds apart. Any ScrollWidget
velocity/inertia derived from Touch timestamps therefore appeared about 1000x
slower than reality.

## v136 correction

- Send raw `UITouch.timestamp` seconds for every guest UITouchEvent:
  begin, move, end, cancel and end-with-flick.
- Rename the C++ guest queue field/parameter to `timestamp_seconds` so this
  unit cannot silently regress.
- Keep v132's host-only coalesced velocity history in milliseconds; its
  `dtMs` estimator and UIFlickEvent generation are separate and already
  correct.
- Keep v134 exact type-4 routing and v135's one-shot Almanac recorder.
- Recorder touch lines now label the guest value as `tsSec` /
  `timestampSec`.

## iPad validation

In Almanac, perform the same fast horizontal release as v135.

Expected primary result: the carousel continues moving after release and
decelerates naturally instead of stopping with the finger.

Also verify ordinary taps, slow dragging, tab changes, pinch and gameplay input
still behave normally. If inertia is still absent, export the full persistent
log: v136 retains the v135 recorder and the next investigation should instrument
the guest touch/ScrollWidget consumer, not the already-validated host queue.
