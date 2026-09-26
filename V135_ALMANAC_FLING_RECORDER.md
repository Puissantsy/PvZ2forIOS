# v135 — Almanac fling flight recorder

Diagnostic-only build inherited from v134.

It keeps a 160-line rolling prehistory and auto-triggers on the first horizontal
UIFlickEvent with gesture-start Y >= 900 on the validated 2048x1536 surface.
This targets the lower Almanac carousel without requiring frame synchronization.

The trace records:
- trigger frame and UI_ProcessEvents caller LR;
- DirectByteBuffer handle/capacity and queue depths;
- every touch item with phase/id/current/previous/timestamp;
- exact UIFlickEvent start coordinates and velocity;
- raw serialized double bit patterns and byte offsets;
- FLICK-before-UP ordering;
- ProcessEvents event count / bytes written / backlog flags;
- ~120 frames after trigger.

The host persistent log also records the release velocity estimator inputs.

Test once: navigate to Almanac without horizontal lower-screen flings, perform
one fast swipe in the zombie/plant carousel, wait ~3 seconds, then copy/export
the log. One gesture is enough.
