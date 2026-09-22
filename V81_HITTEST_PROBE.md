# PvZ2 v81 — Hit-Test Pixels/Points Probe

Date: 2026-09-22

## Root cause targeted

v80 proved that keyboard reactivation itself works: when the guest issues
Device_ShowKeyboard, UIKit becomes first responder. The iPad test also showed
that tapping the visually displayed TextEntry does not reopen the keyboard,
while tapping lower on the visible FACEBOOK title does.

Git history adds a strong causal candidate:

- v39 (62af4810) proved Native_onSurfaceChanged consumes height,width. That
  fix stays untouched.
- v72 introduced touch mapping when framebuffer and logical coordinates were
  both 1180x820.
- v74 changed the framebuffer to 2360x1640 Retina pixels while keeping
  1180x820 logical points, but mapTouch remained based on framebuffer
  sourceWidth/sourceHeight.
- v77 changed the contract to 2048x1536 pixels / 1024x768 points, with the
  same touch mapper.

v81 therefore tests whether touch delivery remained in pixel space after the
guest UI/hit-test moved to logical point space.

## Modes in the same IPA

- **V80 Transform**: exact pixel-coordinate control. No input behavior change.
- **V81 HitTest**: default. Same rendering as V80/V77, but touches delivered to
  UI_ProcessEvents are scaled from 2048x1536 framebuffer pixels to 1024x768
  logical points.

No framebuffer, viewport, screenMatrix, UI package, GameState, widget rectangle
or Native_onSurfaceChanged argument is changed.

## New logs

Host mapping:
`[V81 TOUCH MAP]`

Each entry includes:
- UIKit point coordinate;
- corresponding framebuffer-pixel coordinate;
- logical 1024x768 candidate;
- coordinate actually delivered;
- source/guest sizes, aspect-fit scale and offsets.

Guest serialization:
`V81 TOUCH DELIVER`

This logs each bounded touch record actually written to AndroidUIEventManager,
rather than only the first event of each batch.

Summary:
`V81 HITTEST SUMMARY`

All V79/V80 Profile, transform, presentation and keyboard markers remain
enabled in V81.

## iPad test

Leave **V81 HitTest** selected.

1. Start APK + OBB and reach Profile.
2. Let the keyboard open automatically.
3. Dismiss it and make the placeholder/default text reappear.
4. Tap directly on the visible TextEntry.
5. Note whether the keyboard reopens.
6. Also tap the visible FACEBOOK title once for comparison.
7. Press Stop and export the complete log.

A direct TextEntry tap reopening the keyboard in V81, while v80 required a tap
near FACEBOOK, would strongly confirm the v74 pixels-vs-points regression.
