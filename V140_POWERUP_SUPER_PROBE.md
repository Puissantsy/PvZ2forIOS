# v140 — Power Up one-run super-probe

The user has only a few paid Power Up activations left. v140 is designed so a
single activation should provide enough evidence for several downstream
hypotheses instead of requiring one IPA per probe.

It preserves v139/v138/v136 runtime behavior and does not alter game state,
currency, rendering, input or Power Up timing.

For every plausible large blended full-board primitive after Board activation it
captures, at timer-scale temporal resolution:

- arrays/elements, primitive, program, count and full bbox
- blend enable + src/dst + color mask
- viewport, scissor, FBO context inherited from v138
- texture units 0..3 with dimensions/format/type/pixel presence
- every enabled vertex attribute by semantic name
- decoded samples for positions, UVs, colors and other streams
- latest tracked int/vec4/mat4 uniforms for the active program
- all prior v139 targeted tex15/16 tint detail and v138 geometry tracing

Trigger is deliberately broader than tex15/16: near-fullscreen blended draws
are included so different Power Up types/phases cannot evade the capture.

One iPad test: enter a level, activate ONE Power Up, let the timer finish,
Hard Stop, export the complete log.
