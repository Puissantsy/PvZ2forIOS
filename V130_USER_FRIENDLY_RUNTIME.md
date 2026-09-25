# v130 — User-friendly runtime launcher

## Goal

Keep the validated v129/v128/v127 gameplay runtime unchanged while removing the
development-probe workflow from normal use.

## First launch

The user selects the original PvZ2 1.5.252752 APK and matching OBB once.
v130 copies them into:

Application Support/PvZ2Runtime/

The IPA does not embed or redistribute those game files.

## Later launches

1. If runtime files are missing, show the one-time importer.
2. If files exist but CS_DEBUGGED is not set, automatically open
   stikdebug://enable-jit for this bundle.
3. StikDebug relaunches the app under the debugger.
4. v130 sees CS_DEBUGGED and immediately starts PvZ2 with the cached files.
5. If JIT is already active, tapping PvZ2forIOS goes straight to the game.

LocalDevVPN/Wi-Fi requirements remain those of StikDebug; Dynarmic itself is
unchanged.

## Presentation

Normal flow uses a minimal black "Preparing" launcher then full-screen PvZ2.
The old step buttons/status/log UI are not shown. The live caption and Stop
button are hidden. A four-finger triple tap copies the persistent diagnostic log
to the clipboard without interrupting gameplay.

## Diagnostics/performance

v130 keeps the functional v127 audio worker-drain scheduler but disables the old
v124-v126 exact-repeat/flight-recorder windows (800-2500 and 10000-12500) and
their per-worker recorder overhead. Persistent crash/runtime logging remains.

## Inherited validated behavior

- v129 historical iOS Board scale
- v128 persistent USERFS/config
- v127 Wwise audio worker drain
- v118 production performance path
- direct GLES Points=Pixels presentation
- touch/pinch/keyboard bridges
