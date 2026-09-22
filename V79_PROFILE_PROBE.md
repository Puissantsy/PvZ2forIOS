# PvZ2 v79 — First-Run Profile Provenance Probe

Date: 2026-09-22

## Root cause / question targeted

Static v2.4/v2.5 eliminated a broad Android-only scale explanation for the
oversized-looking first-run Profile/Facebook/EULA screen. Android 1.5.252752
and the historical iOS 1.5.252123 binary share:

- the 600-unit base-height model;
- the historical 1536 -> 2048x1536 contract;
- MainMenu/Profile scale 1536/600 = 2.56;
- matching checkbox, Facebook-button and Facebook-container geometry;
- matching generic Profile layout.

The first confirmed localized geometry difference is the text-entry subpath:
Android x=26,width=373 versus historical iOS x=110,width=289.

v79 therefore does **not** try another resolution or scale. It observes the
live dynamic values fed into the already-identified layout paths.

## Same-build controls

The existing modes are reused directly; no new mode semantics are invented:

- V75 iPad UI = modern native geometry control
- V77 Legacy iPad = 1024x768 pt / 2048x1536 px historical-geometry control

The exact same V79 instrumentation is enabled in both.

## Instrumented Android sites

- SetWidthHeight guard: guest 0x102b8494
- broader Profile entry: 0x103095b4
- acceptance checkbox: entry 0x103082d8, rect call 0x103083e8
- Facebook button: entry 0x103085f8, rect call 0x103087a8
- Facebook container: entry 0x10308b80, rect call 0x10308c5c
- name text-entry: entry 0x1030aea8, computed rects 0x1030b03c and 0x1030b0b0
- generic Profile layout: entry 0x1030f930, rect call 0x1030fa50

Every replaced ARM instruction has an exact opcode signature and is emulated
unchanged in the SVC callback. Signature mismatch aborts before guest startup.

## Captured values

Bounded to the first eight hits at each site:

- object pointer;
- object/parent +0x30 / +0x34 width and height;
- +0xa0 and +0xc8 state fields;
- root LawnApp pointer known by the existing diagnostics;
- LawnApp +0x6a8 scale bits/value (expected 2.56 in V77);
- frame and caller LR;
- raw integer call arguments at checkbox/Facebook/container/generic layout;
- text-entry computed x/y/w triple from stack+40/+44/+48;
- second text-entry computed quad from stack+24..+36.

## What the iPad test must decide

1. Does V77 actually reach scale 2.56 at the first-run layout sites?
2. What is the live parent width/height for the Profile screen?
3. Are checkbox/Facebook/container rectangles the same between V75 and V77?
4. Does the Android text-entry naturally compute approximately 26/91/373 * 2.56?
5. If computed rectangles are sane but the framebuffer still looks enlarged,
   the next target becomes downstream projection/presentation rather than
   layout geometry.

No global scale, m_contentResolution, widget rectangle, resource ID, GameState
or branch is forced in v79.
