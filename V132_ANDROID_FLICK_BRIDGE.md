# v132 — Android GestureDetector / UIFlick bridge

## Static root cause

The Android classes.dex path is:

AndroidSurfaceView$1.onTouch(MotionEvent)
1. ScaleGestureDetector.onTouchEvent
2. GestureDetector.onTouchEvent
3. AndroidUIEventManager.HandleTouchEvent

AndroidUIEventManager.onFling(e1,e2,velocityX,velocityY) constructs a dedicated
UIFlickEvent. Its exact serialized ABI is 32 bytes:

- int type = 4
- int X
- int Y
- double velocityX
- double velocityY
- int 0xDEADBEEF

Because GestureDetector runs before HandleTouchEvent on ACTION_UP, UIFlickEvent
is queued before the terminal UITouchEvent.

The port previously bypassed GestureDetector entirely and therefore never sent
type 4. Extra MOVE/coalesced samples cannot replace this semantic event.

## v132 correction

- Preserve one Android-style MOVE per UIKit touchesMoved callback.
- Use UIKit coalesced samples only for a recent release-velocity estimate.
- On a real single-touch fling, atomically attach UIFlickEvent to the terminal
  touch queue item.
- ProcessEvents serializes type 4 immediately before that touch UP.
- Require movement >=12 guest units and speed >=50 units/s; clamp velocity
  magnitude to 8000 units/s.
- If UIKit ends a captured touch marginally outside the rendered rectangle,
  still emit UP at the last valid guest point so capture cannot remain stuck.
- v131 srand48/lrand48 fix remains inherited unchanged.

## Validation

Almanac horizontal zombie/plant carousel:
- drag follows finger;
- fast release continues scrolling with momentum proportional to release speed;
- after the gesture, tabs such as Plants/Zombies/Upgrades respond normally;
- taps/slow drags do not spuriously fling.
