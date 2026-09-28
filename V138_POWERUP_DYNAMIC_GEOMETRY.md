# v138 — Power Up dynamic geometry recorder

## Why v137 was insufficient

A real iPad v137 run selected several Power Ups, activated one, let the timer
finish, then exited. The complete log contained zero V137 POWERUP FAN lines.
Therefore the BoardTimerColor path is not a small non-indexed
glDrawArrays(GL_TRIANGLE_FAN) as initially hypothesized.

## v138 scope

v138 remains runtime/capability-identical to v136/v137 and changes no draw,
matrix, Board field, touch path or GL state.

After the first real v129 Board-scale write, it observes BOTH:
- glDrawArrays
- glDrawElements

For blended primitives up to 256 indices/vertices, it reconstructs the actual
position bounding box from client vertex data (including indexed element
lookups). It records only spatially large/off-canvas candidates and de-duplicates
8-pixel-quantized signatures so static lawn/background geometry does not consume
the log budget while a rotating/wiping timer continues to produce new geometry.

Each V138 POWERUP GEOM record includes draw kind, program, primitive mode,
count, raw bbox/size, guest+host FBO, viewport, scissor, textures and the active
screenMatrix/inferred canvas.

## Test

Repeat one Power Up activation, let its timer finish, then Hard Stop and export
the complete log. This one probe covers the full array/elements primitive class
instead of producing one version per guessed primitive mode.
