# PvZ2 v84 — Render Contract / Final Blit A/B

Date: 2026-09-23

## Root cause targeted

v83 proved the first-run controls can be activated even while the visible
framebuffer is globally oversized/cropped. The same visual fault affects the
EA logo, PvZ2 title/loading image and Profile, so widget-specific geometry is
not the primary target.

The v83 log shows two screen projection spaces in the same frame:

- ordinary offscreen rendering uses a 2048x1536 inferred canvas;
- immediately before PvZ2 rebinds guest FBO 0, it uploads a screenMatrix whose
  inferred canvas is 1024x768 while the GLES viewport remains 2048x1536.

v80 deliberately excluded guest FBO 0 from TRANSFORM DRAW sampling, so the
actual final composite vertex bounds were never recorded.

## APK Java reference verified from classes.dex

Original class:
`com/popcap/SexyAppFramework/AndroidSurfaceView`

Verified behavior:

- `Graphics_CanSetGLViewScaleFactor`: returns true.
- constructors initialize `mViewScaleFactor` to 0.5f.
- `Graphics_GetGLViewScaleFactor`: directly returns that field.
- `Graphics_SetGLViewScaleFactor(float)`: directly stores that field; it does
  not resize the SurfaceView, framebuffer or renderbuffer.
- `Graphics_GetScreenSizeInPixels`: returns `mOrigAppWidth/Height`.
- `Graphics_GetScreenSizeInPoints`: obtains DisplayMetrics but then loads
  1.0f as the effective divisor before using view getWidth/getHeight. In other
  words, for this APK the returned point dimensions are the actual Android
  view dimensions, not Retina-style width/2 and height/2.
- `Graphics_GetPointSizeInPixels`: returns DisplayMetrics.density. The iPad
  host analogue remains 2.0 in all v84 modes.

This means the current v77-v83 bridge is a hybrid contract:
pixels=2048x1536, points=1024x768, pointSize=2.0, CanSet=false, GL scale=1.0.

## Modes in one IPA

### V84 Blit

Exact v83 graphics behavior. No JNI geometry/scale mutation.

New passive trace includes guest FBO 0 and logs:

- raw pre-transform position bbox;
- source texture IDs and dimensions;
- viewport;
- active screenMatrix;
- inferred projection canvas.

Marker: `V84 FINAL BLIT DRAW`.

### V84 P=PX — default

Smallest causal experiment.

Only:
`Graphics_GetScreenSizeInPoints -> 2048x1536`

Everything else stays at v83 behavior:
- pixels/FBO/viewport = 2048x1536;
- point size = 2.0;
- CanSet = false;
- GLViewScaleFactor = 1.0;
- v39 Native_onSurfaceChanged height,width ordering unchanged;
- UI_IPAD unchanged;
- touch remains pixel-space;
- no GameState/widget/resource is forced.

### V84 Android

Includes P=PX and reproduces the APK scale-field contract:

- CanSet = true;
- initial GLViewScaleFactor = 0.5;
- Get reads the stored field;
- Set stores the requested float only;
- no host GLES resize is performed.

## Decision logic

1. If V84 P=PX immediately fixes EA/title/Profile proportions and the final
   projection becomes 2048x1536, the root cause is the synthetic
   GetScreenSizeInPoints=1024x768 bridge.
2. If P=PX does not fix it but V84 Android does, the missing Android
   mViewScaleFactor contract is causal.
3. If neither fixes the visual fault, V84 FINAL BLIT DRAW still tells us
   whether the final guest-FBO-0 composite itself has doubled geometry or
   whether the bad scale entered earlier.

## iPad test

Start with **V84 P=PX** (default).

Watch the EA logo and PvZ2 title screen before doing anything else. A fix should
be obvious there: the artwork should no longer be globally enlarged/cropped,
and the loading bar should become visible in its expected area.

If P=PX is still wrong, stop/export the complete log, then rerun the same IPA
with **V84 Android** selected. There is no need for another build.

Useful markers:
- V84 FINAL BLIT DRAW
- V84 RENDER CONTRACT SUMMARY
- V80 SCREENMATRIX
- V39 GLES VIEWPORT
- V80 HOST PRESENT
- Graphics_GetScreenSizeInPoints
- Graphics_GetGLViewScaleFactor
- Graphics_SetGLViewScaleFactor
