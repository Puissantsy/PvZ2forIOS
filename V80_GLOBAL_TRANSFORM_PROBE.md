# PvZ2 v80 — Global Transform + Keyboard Provenance Probe

Date: 2026-09-22

## Root cause / question targeted

Real-iPad observation now establishes the same oversized/cropped symptom on
three distinct startup surfaces:

1. the EA logo is much larger than expected;
2. the "Plants vs. Zombies 2 — It's About Time" title/loading image is enlarged
   enough to crop content and hide the loading bar underneath;
3. the first-run Profile/name screen is also enlarged/cropped.

Therefore the localized Android/iOS TextEntry difference found by static v2.5
(x=26,width=373 versus historical iOS x=110,width=289) is real but cannot be
the primary explanation for the global visual fault.

v79 also proved that V77 reaches the intended historical 2048x1536 pixel /
1024x768 point geometry and the expected 2.56 Profile scale. v80 does **not**
patch resolution, FBO size, contentScaleFactor, UI package, widget rectangles
or that scale.

The question is now: where does the common enlargement enter this chain?

    guest/layout coordinates
      -> vertex positions
      -> screenMatrix
      -> GLES viewport/FBO
      -> copied framebuffer
      -> UIKit ScaleAspectFit presentation

## What v80 records

### screenMatrix provenance

Every GLES glUniformMatrix4fv upload is retained per program/location. For a
uniform named screenMatrix, bounded change logs contain frame/program/location,
viewport, all 16 matrix values and an inferred orthographic canvas from
2/abs(m00) and 2/abs(m11).

Marker: `V80 SCREENMATRIX`.

### Pre-transform draw geometry

Bounded frame windows cover early EA, title/loading, and Profile. For sampled
glDrawArrays calls on non-default guest FBOs, v80 records active
program/FBO/viewport, raw pre-transform x/y bounds, texture IDs/dimensions, and
the active screenMatrix/inferred canvas.

Markers: `V80 TRANSFORM DRAW` and `V80 TRANSFORM SUMMARY`.

No matrix or vertex is modified.

### Host presentation

Selected live frames record source framebuffer size, UIView/ImageView bounds
in points, UIImageView contentMode, UIScreen scale and nativeScale.

Marker: `[V80 HOST PRESENT]`.

### Keyboard/focus provenance

The Profile keyboard opens automatically. The reported repro is: manually
dismiss keyboard, interact until the default/placeholder text is visible, then
tap the visible TextEntry; the keyboard does not reopen.

v80 leaves keyboard behavior unchanged but separates guest
Device_ShowKeyboard/Device_HideKeyboard/Device_IsKeyboardShowing activity from
the actual UIKit UITextField first-responder state and its begin/end delegate
transitions.

Markers: `V80 KEYBOARD` and `[V80 HOST KEYBOARD]`.

This tells us whether a failed reopen is because PvZ2 never issues another
ShowKeyboard, or because it does and UIKit fails to reactivate.

## Preserved behavior

V80 inherits the validated V77 historical-iPad contract, including:

- 1024x768 points / 2048x1536 pixels;
- UI_IPAD remap;
- touch + keyboard bridges;
- zlib / ETC1 rendering path;
- natural GameState progression;
- all existing V79 Profile provenance traps.

No resource, GameState, scale, geometry, viewport, FBO or widget state is
forced by v80.

## iPad test

1. Leave **V80 Transform** selected (default).
2. Run the original PvZ2 1.5.252752 APK + matching OBB.
3. Observe EA and the PvZ2 title/loading screen normally.
4. On Profile, confirm the keyboard appears automatically.
5. Dismiss it.
6. Interact until the default/placeholder name text is visible again.
7. Tap the visible TextEntry once or twice and note whether the keyboard
   reappears.
8. Press Stop after that interaction and export the complete log.

Useful markers:

- `V80 SCREENMATRIX`
- `V80 TRANSFORM DRAW`
- `[V80 HOST PRESENT]`
- `V80 KEYBOARD`
- `[V80 HOST KEYBOARD]`
- `V80 TRANSFORM SUMMARY`
- inherited `V79 PROFILE`

## How to read the result

- Wrong inferred canvas/matrix across EA + title + Profile => common guest
  projection/transform fault.
- Matrix/canvas sane but already oversized raw position bounds => common fault
  earlier in layout/coordinate generation.
- Guest draw/framebuffer values sane but host presentation inconsistent =>
  final UIKit presentation fault.
- No new guest ShowKeyboard after tapping TextEntry => focus/hit/UI logic is
  the next keyboard target.
- New guest ShowKeyboard but UIKit never becomes first responder => host
  keyboard reactivation bridge is the next target.
