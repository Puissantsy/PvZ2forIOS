# pvz2_apk_probe single-translation-unit split

Starting with v110, the former ~39k-line `pvz2_apk_probe.cpp` is stored as ordered
`.inc` fragments and included by the small root `.cpp`.

This is intentionally a **mechanical source-layout refactor**, not an ABI or runtime
architecture change:

- CMake still compiles only `pvz2_apk_probe.cpp`.
- All fragments are preprocessed into that same translation unit.
- Anonymous namespaces, private class members, globals, scheduler state and Dynarmic
  callbacks therefore keep the same linkage/lifetime model.
- Fragment boundaries are storage boundaries only; they may fall inside a class or
  function. Do not compile a fragment separately.
- Keep the include order in `pvz2_apk_probe.cpp`.

The purpose is to keep each source object small enough for GitHub connector reads and
future targeted edits without forcing a risky multi-translation-unit rewrite.

v110 also adds, without changing v109 scheduling semantics:
1. exact Android UIPinchEvent type=3 delivery;
2. low-overhead CAkAudioThread/tid5 attribution by Wwise function family;
3. UI_ANDROID vs UI_IPAD package-selection A/B in one IPA.

Persistent USERFS/save work is deliberately deferred to a later isolated version.

## KEYOBS isolated research-only build

On `research/world-key-conversion` only, diagnostic entry zero launches `KEYOBS`, a read-only triple-instruction probe at `AddWorldKeys` and the original key-gate update boundary. It inherits v151 production runtime and does not change any award, save or wallet behavior. This **separate research build** has bundle ID `com.puissantsy.pvz2forios.keyobs` so normal v170/production app data is not replaced. See `docs/WORLD_KEY_RUNTIME_KEYOBS.md`. Do not merge this diagnostic-entry ordering into production.
