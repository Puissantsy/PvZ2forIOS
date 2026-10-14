# v170 — A/B Store QA isolated on iPad (NO IPA YET)

Branch: `research/offline-store-qa`. Its gameplay/store engine derives from
`v170-targeted-global-isolation-staging`, not production `main` or KEYOBS.
The original v170 unsigned IPA from 2026-10-02 was **not** tested on iPad
and used the main production bundle identifier. **Do not install that old IPA
onto a production app to test premium purchasing.**

## Why the split

The original PvZ2 GlobalSaveData persisted Snow Pea catalog ID 21 in a
SHARED global native save after player A's replacement-Store debit.
Player B then saw the original free CLAIM but lacked the per-profile
host entitlement and could not actually plant Snow Pea. An incorrect
purchase can debit 10,000 coins without delivery. Simply hiding CLAIM
or erasing global ID21 would destroy legitimate historical EA purchases.

The staged v170 handler uses an original native saver to regenerate BOTH
`global_save_data` and its proprietary `.hash`, transaction-owned
bounded full-vector preimages, a persistent v2 receipt and a fail-closed
journal. Those safeguards have compiled, **not yet been shown to work
on the physical iPad**, and the source must not be merged into main
until a real two-profile A/B acceptance succeeds.

## Side-by-side safety

- Unsigned bundle ID: `com.puissantsy.pvz2forios.storeqa`.
- Display name: **PvZ2 Store QA**.
- Custom Info.plist research marker and source identity must be valid.
  Even if a signer rewrites the standard bundle identifier, the launcher
  refuses *exact* production/KEYOBS/Android identifiers before inspecting
  player saves, showing a reset dialog, requesting JIT or importing APK/OBB.
- Normal KEYOBS (`com.puissantsy.pvz2forios.keyobs`) and the main game
  (`com.puissantsy.pvz2forios`) MUST remain installed and untouched.
- STOP if the signer offers to uninstall/replace either existing app:
  refuse the installation, do not restore its data.
- The isolated app has its own empty sandbox, so it must import the user's
  locally provided matching 1.5.252752 APK + OBB again. No originals
  or extracted proprietary assets go to public GitHub or a build artifact.

## Device acceptance (after one isolated QA build and review)

1. First confirm a NEW, independent **PvZ2 Store QA** icon and its own
   empty Files/Document directory, not an update/replacement.
   Sign with the normal sideloading method and verify the installed ID.
2. In this QA app ONLY: choose the explicit protected fresh-test reset
   if needed. Create TWO disposable profiles A and B.
3. Confirm B Snow Pea **BUY** 10,000 coins BEFORE any purchase. On A
   accept a single 10,000-coin Snow Pea BUY using disposable coins.
   Immediately verify A's coins, native playable Snow Pea, and
   `V170 GLOBAL CLEANUP SAVED` along with real USERFS saves of
   `global_save_data` and `.hash`. If absent, stop and collect log.
4. Switch to B in the SAME app process. Expect independent 10,000-coin
   BUY, **NOT** the historical free CLAIM. Do not press CLAIM.
5. The explicit one-time `Crédit PvZCoins de test (profil actif)…`
   can raise **only disposable B** to at least 60,000 coins. B buys
   Snow Pea once; verify playable plant and independent wallet.
6. Save/export full log, hard close, relaunch, confirm both masks and
   wallet balances persist without second charge. Preserve native log
   and .ips for any crash; the real iPad is ground truth.

Original historic same-SKU entitlements remain ambiguous unless verified
on a separate baseline. Never delete or rewrite historic global catalog bits
blindly. No bulk repairs to other SKUs without provenance evidence.

## Build control

Dynarmic exact historical commit
`c97c525ec1432b1e5404ebf091027738005ec168` and tree
`fd5b3ab282948fcdacc202ee11ee6d7aec339125`, with the existing
spinlock patch (not allocator/JIT changes), are checked by the CI build.
QA policy + Apple arm64 launcher object compilation must pass first.
The iOS build workflow runs only when `platform/ios/.storeqa-build-request`
is changed, or when manually dispatched. Build **once** for the grouped
QA baseline, not one IPA per unsupported import.

## First isolated QA build request

Both the portable safety test and actual iPadOS arm64 launcher compilation passed: [Actions #38547531549](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38547531549). One explicit marker-based unsigned Store QA build is requested on this branch. Do not infer physical-device purchase success merely from the build passing. Retain the existing v170 original-global fail-closed interlock and v165 protected snapshot/restore; no user save is used in CI.
