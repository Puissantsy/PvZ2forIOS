# v166 — protected fresh-test reset and A/B CLAIM experiment (no speculative guest purchase patch)

## Verified iPad/runtime baseline

User confirmed on October 1, 2026 that v165 creates portable full save snapshots and successfully restores them using PvZ2RestoreInbox on the physical iPad. An external iCloud Drive baseline exists with about 60,000 PvZCoins on test1. Preserve that working recovery mechanism throughout later code changes. Snapshot folders include ALL player profiles plus per-profile purchase config, not one profile per folder.

Prior v164 full log proves the existing v162 per-profile audit works, but covers only a single observed active profile (ID 1790838014) with both native and host sidecar premium masks at zero before AND after catalog refresh. There is no A-purchase to B-switch sequence in the available uploaded log. This does NOT establish a specific root cause for the historical CLAIM symptom.

## Code-grounded suspect classes (do not treat as proved)

1. v162/v165 `OfflineStoreApplyProfileEntitlements` in part_01 manages six plant IDs and four game-upgrade IDs in the player-specific vectors at offsets 0x18 and 0x34, keyed by `offline_store_profile_v1_<id>_*` in the V128 config. Current `part_09` logs BEFORE/APPLY/before-refresh/after-refresh and purchase commits; use those, do not reinvent the instrumentation.
2. Original PvZ2 1.5 has separate native `PurchaseBroker` and `GlobalSaveData` state. `part_09` refresh sends synthetic `SkuDetails` for ten supported SKUs through the real native FireDidRefresh. `part_05` synthetic Java SkuDetails exports SKU, price, title, description; it does not synthesize any per-profile purchased flag. Therefore CLAIM could come from native/global purchase state or an in-memory broker cache.
3. On detected account switch, `part_09` currently reapplies profile vectors, but it does not explicitly invalidate a native purchase broker cache; whether this is relevant depends on a real A-to-B probe.
4. An old migrated global purchase or legacy QA tree might contaminate a particular test profile. Never blanket-delete or rewrite GlobalSaveData before establishing its exact native layout and relationship to campaign progress.

## Controlled A/B experiment using v166 fresh-reset build

0. First install v166 IN PLACE over v165. Keep the complete 60k baseline externally on iCloud Drive or PC. At the one-time startup prompt, choose **Réinitialiser mes données locales**. This creates verified normal and protected prereset copies, resets all UserData* plus config-v1.txt, preserves imported APK/OBB, and re-enables the existing one-time 60k test grant when a new profile is created. Do not accidentally restore your protected 60k reference into the live app before the fresh A/B test. The poststop `⋯` menu also offers a repeatable test reset, followed by an app cold relaunch.
1. Create a NEW account A (e.g. `A_Fresh60k`) after reset and confirm its 60k test credit; create account B (`B_NoPurchases`) and first record its starting shop states. Neither new account should inherit the old reference's premium entitlements.
2. Within the SAME APP SESSION, switch to account A. Purchase ONE previously unowned target: Snow Pea (10k), Squash (15k) or Jalapeno (20k). If A still has all three unowned and the wallet really contains 60k, buying all three once costs 45k and covers three store entries. Record before/after coins and actual unlocks. Do NOT restore between A and B.
3. Switch to B in the SAME SESSION and reopen the shop. For each A-purchased target record BUY or CLAIM (screenshot preferred) BEFORE touching CLAIM. Check native rights and any unexpected immediate unlock; do not redeem on B during this initial trace.
4. Tap top-left ellipsis > Sauvegarder et arrêter. Preserve/export the FULL log from this exact session, containing `[OFFLINE STORE PROFILE BEFORE/APPLY]`, `[OFFLINE STORE CATALOG AUDIT before/after]`, `[OFFLINE STORE purchase commit / PROFILE PURCHASE]`, `[V128 USERFS]`, and the profile IDs. Copy the log BEFORE launching again if the launcher resets it. This is the key evidence.
5. Relaunch with B still selected. Without restoring the baseline yet, reopen B shop and record whether the surprise CLAIM (if any) survives process restart. Stop, preserve the SECOND full log. This separates an in-memory broker cache (disappears on restart) from persistent global/transaction state (survives). If A or B does not persist account selection, record that too.
6. Restore the external test1 60k baseline after BOTH logs are preserved (or perform a separate fresh-reset experiment without modifying the reference). Confirm coins, progression and v165/v166 backup/restore still work. Never uninstall.

## Decision tree to minimize future rebuilds

- B native/sidecar premium masks are zero but B displays CLAIM only before restart: investigate native `PurchaseBroker` catalog/payment cache invalidation on switch, and verify no phantom payment/CLAIM action.
- B native/sidecar masks are zero and CLAIM survives restart: inspect the original `GlobalSaveData`/persistent purchase-status representation and separate only the ten offline SKUs per account, leaving unrelated global campaign state intact.
- B native vectors are nonzero but sidecar zero: fix rehydration/timing at profile switch and catalog boundaries; this class is already scoped by v162 instrumentation.
- B sidecar itself became nonzero due to an A purchase: correct purchase commit profile resolution, migration or sidecar-key mapping.
- B BUY displays correctly but CLAIM action allows free redemption or other mismatched ownership, inspect the separate redemption path rather than painting UI labels.

## Preconditions for a future v167 CLAIM functional build

Once both logs plus observed UI states disambiguate these classes, implement the relevant root-cause correction with per-SKU/profile invariants, rollback on failure, and bounded probes in ONE version. Build once after collecting the fixes; validate on physical iPad, then restore baseline. The v166 IPA adds only the explicitly requested guarded QA reset and leaves guest purchase semantics and instrumentation from v162 unchanged; reserve the eventual CLAIM root-cause patch for v167 after this experiment.

Related tracked PRs: #7 CLAIM provenance (base), #8 v163 backups, #9 v164 host stop menu, #10 v165 inventory recovery.
