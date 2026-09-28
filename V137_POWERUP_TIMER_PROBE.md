# v137 — Power Up radial timer geometry probe

## Observed bug

The Power Up border is correct on iPad, but the translucent BoardTimerColor fill
is mostly absent at activation and only becomes visible around mid-timer as a
rotating sector. The reference behavior starts fully tinted and removes that
tint continuously with a radial clock-like wipe.

## Static findings before v137

- POWERUPTYPES.RTON defines BoardTimerColor and TotalTime for each Power Up.
- libPVZ2.so contains PowerupTimeUI plus all eight IMAGE_UI_POWERUPS_*_BORDER_*
  assets: border and timed fill are separate pieces of the effect.
- The APK imports no glStencilFunc/glStencilOp/glClearStencil, so this is not a
  missing stencil API in the host bridge.
- sin/cos/atan2/fmod imports used by radial geometry are functionally bridged.
- Both Android GL11 and GL20 renderers translate the engine primitive type 6 to
  GL_TRIANGLE_FAN. A small fan is the natural primitive for the radial wipe.

## Instrumentation

v137 is capability-identical to v136. It changes no guest geometry, matrix,
Board field or GL state.

For glDrawArrays(GL_TRIANGLE_FAN) with 3..16 vertices it records frame/program,
FBO, raw position bounding box, active screenMatrix and inferred canvas,
viewport, scissor, blend state and bound textures. The trace budget is separate
from old v80 startup tracing, so it survives until the Power Up is activated.

## iPad test

Activate one Power Up, let its full timer finish, Hard Stop, then export the
complete pvz2forios-probe.log. V137 POWERUP FAN lines should distinguish a bad
guest fan from a correct fan projected/clipped in the wrong coordinate space.
