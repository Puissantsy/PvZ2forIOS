# PvZ2 v83 — Profile Button Dispatcher + Pixel Touch

Date: 2026-09-22

## Root cause targeted

v82 delivered 1622/1622 touch records, but its logical guest touch space was
1024x768. The only Profile button candidate actually constructed on that run
was candidate5 with rawXYWH=(360,1158,368,110). Its Y range therefore begins
390 pixels below the largest possible v82 logical touch Y.

The rotation test also showed that UIKit correctly changes the view from
1180x820 to 820x1180 while continuing to aspect-fit the same 2048x1536 guest
framebuffer. The visible crop/oversize is already present in the guest frame;
v83 does not alter host presentation.

## v83 behavior

- historical iPad rendering stays 2048x1536 px / 1024x768 pt;
- UI_IPAD, v39 height,width surface order, FBO, viewport and screenMatrix stay
  unchanged;
- v82 Profile radar remains active;
- touch delivery returns to the V80 pixel-space control: 2048x1536;
- v81/v82 logical /2 touch delivery is NOT active in v83;
- no widget, state, resource or GameState is forced.

## Verified native dispatcher

Static ARM analysis of Android 1.5.252752 identifies the Profile button
dispatcher at libPVZ2.so+0x0030b8f0. It receives the button ID in r1 and
immediately switches on ID-5.

The passive v83 trap is at +0x8:

- guest 0x1030b8f8
- original opcode 0xe1a09000 = MOV r9,r0
- the SVC handler reproduces MOV r9,r0 exactly, then logs r1.

The jump table resolves to:

- ID 5  -> 0x1030b958
- ID 6  -> 0x1030ba88
- ID 7  -> 0x1030bbc4
- ID 8  -> 0x1030be34
- IDs 9..17 -> common return/no dedicated action path
- ID 18 -> 0x1030bf40
- ID 19 -> 0x1030bf60
- ID 20 -> 0x1030bf80

These are static IDs/cases only. v83 does not assign semantic names such as
Continue, Facebook or EULA until the real iPad runtime correlates them.

## Logs

New marker:

- V83 BUTTON DISPATCH

It records frame, buttonId, static switch target, this/profile pointer equality,
caller LR, last delivered touch and the inherited v82 Profile/candidate radar.

Final marker:

- V83 BUTTON DISPATCH SUMMARY

Inherited markers remain available:

- V81 TOUCH MAP / V81 TOUCH DELIVER (v83 should report PIXEL_CONTROL)
- V82 TOUCH RADAR
- V82 ACTION KEYBOARD
- V82 PROFILE STATE
- V82 ACTION GAMESTATE
- V82 PROFILE RADAR SUMMARY
- V79/V80 rendering provenance

## iPad test

Leave **V83 Buttons** selected.

1. Reach the first-run Profile.
2. Enter at least one character in the name.
3. Dismiss the keyboard if useful.
4. Tap around normally.
5. Specifically try the v82 candidate5 area. On the known 1180x820 landscape
   presentation, raw guest rect (360,1158,368,110) maps approximately to
   host-view x=236..432 pt, y=618..677 pt.
6. If an action fires, note the visible result, but the log is the source of
   truth: V83 BUTTON DISPATCH will reveal the native button ID.
7. Press Stop and export the complete log.

A dispatch with buttonId=5 after a touch inside candidate5 proves candidate5
is a real actionable button and lets the resulting native behavior identify
its semantic role without guessing.
