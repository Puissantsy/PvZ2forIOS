# KEYCONV -> functional v170 Probe, staged / no IPA
Date: 2026-10-14. Base: `v170-targeted-global-isolation-staging`, not the KEYOBS research line (they have diverged). Target branch: `integration/probe-keyconv-egypt`.

## Device evidence (KEYOBS, not Probe)
The physical iPad log `pvz2forios-probe(20261014-142209).log` shows at 14:20:54 UTC:
`[KEYCONV AUTO] completed=YES profiles=1 keys=1 coinsDelta=1000 scope=EGYPT_ONLY`.
At 14:21:08 UTC the guest reported Egypt five gates state 3, `eligible=YES`, `wsk={egypt:0}`; it reached 1,200 frames by 14:21:39 UTC. User confirms +1000 coins and persistence through a second actual app start (not present in that one captured log). This validates KEYOBS's one-key happy path, NOT the Probe integration.

## Root cause and implementation
Original KEYOBS was research-only and blocked in the production bundle via marker and CMake identity. Its journaled pre-guest converter cannot just be renamed because the Probe's v170 tree includes extra entitlement, reset and restore changes that KEYOBS doesn't include. Transferred the vetted C++ RTON preview, stopped-guest SHA-256 per-profile journal, Objective-C++ adapter and a narrow startup hook onto the **v170** Probe launcher.

- Only Egypt saved key stock with all five verified gate states, and only if matching `pp.dat` / `snapshot2.dat` / `local_profiles` identities and stock. Stock=0 or gates closed => zero writes.
- New opt-in file **in the Probe Documents root**, `PvZ2ProbeKeyconvRequest.txt`, must contain exactly `ENABLE_EGYPT_AUTOMATIC_KEYCONV_PROBE_V1\n`. This is deliberately DIFFERENT from KEYOBS. Absent token: no automatic conversion; normal v170 path unchanged, except pending-journal recovery safety gate.
- Recovery first (before v163 restore/reset prompts); existing v170 restore and reset flows preserved. Conversion only after APK+OBB imported and StikDebug/JIT attached; never while JNI/V128 active.
- Verified v165 prelaunch snapshot BEFORE transaction; preserves production backup container. Fatal filesystem/journal errors fail-closed, read-only preview mismatches offer explicit one-shot game launch **without** migration; never silently reconcile diverged stocks.
- Probe Info.plist ID remains `com.puissantsy.pvz2forios`; specific compile+plist marker is required. KEYOBS's app ID and sandbox are not reused. Research crash laboratory is **not** included.
- The native reward hook is now staged as a separate opt-in flag in the **unchanged V151** runtime: the single AddWorldKeys+8 MOV r10,r0 site is signature-checked and replaced by a guarded SVC only when explicitly authorized. The recovered KEYOBS policy is restricted to Egypt, checks all five saved gate events before tail-calling the exact original SetCoins native function for 1–4 new keys. Missing/unsafe state falls back to native key award. Pirate/Cowboy/Future/Dark remain untouched. Physical validation is pending on Probe; no new grant tested yet.

## Source changes
`platform/ios/src/main.mm`, `platform/ios/src/keyconv_prelaunch_ios_adapter.mm/.hpp`, `platform/ios/CMakeLists.txt`, `platform/ios/Info.plist.in`, the five unmodified transaction/RTON headers from KEYOBS and related synthetic C++ test files. Use exact historical Dynarmic c97c525e via its proven staged source/patch; do not modify allocator or guest store entitlement hooks. GitHub policy runs Linux/macOS synthetic interruption tests and iOS arm64 object compile **without producing an IPA**. Build workflow only on an explicit marker after ALL checks.

## Next iPad test (NOT YET DONE)
1. Verify the Probe's current full external backup and preserve the previously working Probe IPA.
2. Build exactly ONE unsigned IPA after CI is green and review of feature parity. **Update** existing Probe with identical app identifier and signing identity, never uninstall. Keep KEYOBS installed separately.
3. With token **absent**, confirm normal v170 startup, store entitlements, v163 restoration, v166 reset UI, profiles and combat. No KEYCONV writes.
4. Only on an isolated disposable copy with a surplus Egypt key and all five gates open, place the exact Probe token and cold-launch. Verify `[KEYCONV PROBE] completed=YES profiles=1 keys=1 coinsDelta=1000`, stock 0, +1000 coins and gates untouched in-game.
5. Kill and restart twice, check persisted coins and no second credit. Test closed gates => no conversion; divergent image pair => read-only warning, no writes; interrupted journal => recover or hard block.
6. Remove token to disable experiment. Never import KEYOBS's active save or overwrite a real 10010-coins profile as a fixture.

STATUS: Source integration staged; NOT built as IPA, NOT validated on iPad, NOT merged into working Probe. The reported KEYOBS success does not establish production safety.


## Native one-off hook safety gate
- Explicit opt-in is mandatory; the exact Probe startup token gates both saved-stock conversion and new in-game awards.
- V151 full feature path remains selected, including the v170 boutique/entitlement feature code; do not substitute research diagnostic modes.
- Program bytes at AddWorldKeys+8 must match the exact original ARM `MOV r10,r0` signature; mismatch fails before any guest execution when enabled.
- The handler emulates the original instruction if any precondition fails, including mismatched frame/LR, missing profile, unknown world, closed gates or currency overflow.
- On a read-only RTON preview incompatibility, live reward interception is disabled for that entire launch; no writes were performed by the attempted prelaunch migration.
- The historical KEYOBS runtime decoder/policy tests were copied into this branch and added to the no-IPA CI matrix.
