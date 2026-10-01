# v167 — Static root-cause investigation: CLAIM / unlock leakage between local profiles

Status: STATIC ANALYSIS ONLY. The v166 opt-in reset IPA was compiled (GitHub Actions run #430) and the user has saved a reference snapshot. **This branch does not change gameplay, store state, save files, or build an IPA**. The native code is the 2013 Android armeabi-v7a `libPVZ2.so` extracted from the project-supplied APK v1.5.252752. ARM offsets below are offsets within this exact ELF, not stripped-symbol names inferred from nearby unrelated weak symbols.

## 1. Important difference: actual rights vs shop's CLAIM vs cached items

Define three independently observable conditions for A purchases plant X then B opens the shop:

- Native rights / gameplay: can B actually use X, or does only the button display CLAIM?
- Per-profile host rights: the ten offline SKU entitlements are in `config-v1.txt` keys `offline_store_profile_v1_<profile_id>_plants|features`, and projected into the active profile's vectors at `+0x18` and `+0x34`.
- Native purchase/catalog state: original PvZ2 `PurchaseBroker` and saved or cached state can carry transaction and purchase knowledge independently of the vectors above.

Never treat a CLAIM label alone as proof B owns or can use the plant; never patch the label alone if the purchase query/global state would still be shared.

## 2. Confirmed source-level flow in v166 (inherited from v162)

Source: `platform/ios/src/pvz2_apk_probe_parts/part_01.inc` near lines 2375-2390, 2454-2459, 2462-2661, 2664-2864. The offline catalog defines six premium plants (Snow Pea, Squash, Imitater, Jalapeño, Torchwood, Power Lily) and four game upgrades. It deliberately keeps ONLY those IDs in per-profile masks, reads/writes profile-owned vectors, retains unrelated IDs and saves ownership to V128 `config-v1.txt`.

Source: `part_05.inc` near lines 516-636: synthetic Java SkuDetails provides `getSku`, `getPrice`, `getTitle`, `getDescription`; `Refresh` queues requested SKUs; `RequestPayment` queues an `OfflinePurchaseRequest` holding SKU, price, serial and error, with NO initiating `profile_id` field. If selected profile changes between request and delayed completion, the callback currently resolves and charges whichever profile is active at delivery time. This race is statically visible, though a real occurrence has NOT been observed.

Source: `part_09.inc` near lines 2610-2644, 2802-2935, 2938-3120. It detects account switches by `ProfileManager +0x14` and rewrites premium profile vectors with per-account sidecar masks. At catalog refresh it audits before/after against sidecar, repairing mismatched vectors for tracked profiles. But it does NOT invalidate or rewrite the original `PurchaseBroker`'s cached product purchase state.

**Critical order**: for an accepted payment, the host computes and charges coins from the *currently selected* profile, then delivers `OfflineStore_FirePaymentComplete` to the REAL native driver (`part_09.inc` about 3024-3080), then calls `OfflineStoreRecordPurchasedEntitlement` to set host per-profile ownership (`part_09.inc` about 3091-3103). The native callback receives the driver and transaction details, not the host-specific sidecar `profile_id`. It dispatches into the original guest broker, whose internal global state is NOT rolled back or isolated just because the host later sets another profile's mask.

Another confirmed robustness bug: if `OfflineStoreRecordPurchasedEntitlement` returns false after native payment succeeded, `part_09.inc` logs a critical message but continues rather than treating this as an atomic entitlement persistence failure. This creates a possible inconsistency among charged coins, native delivered purchase, and host sidecar. It is NOT proved to explain the reported cross-profile symptom.

## 3. Findings independently checked in the supplied Android ELF

ELF `.rodata` (file offset equals RVA for this range) contains one group of strings at:

```text
0x00c78c35  global_save_data
0x00c78c46  local_profiles
0x00c78c65  m_unlockedPlants
0x00c78c76  m_unlockedGameFeatures
0x00c78c8d  m_unlockedMapGates
0x00c78ca0  m_unknownSkus
0x00c78ce5  PurchasingSkus
```

The game really has distinct named global and local-profile persistence and serialized concepts for unlocked plants/features and unknown/purchasing SKUs. Their adjacency in `.rodata` alone **does not prove which exact file owns each field or which method computes the CLAIM label**. Earlier real v164 log shows V128 loading `UserData/No_Backup/global_save_data`, `local_profiles`, `pp.dat` and `snapshot2.dat` successfully; `global_save_data` is not an invented filename.

The same ELF contains purchase-broker state labels around `0x00c7a0a3`: `PurchaseBrokerState`, `RefreshingPurchases`, `RefreshingPurchasesWaitingForResponse`, `RefreshingPurchasesWaitingForReceipts`, **`RetrieveGlobalPurchase` at `0x00c7a14e`**. This is concrete evidence the original broker has a global-purchase retrieval state distinct from our newly invented per-profile V128 masks. It strongly supports, but does not by itself prove, the shared-native-state hypothesis.

Important false leads: `SKUPurchased` at ELF `0x00c726e7` appears in a contiguous analytics event-key group (`NumTransactions`, `EntrySource`, `CartType`, `PurchaseSuccessful`, `TransactionID`). It should not be treated as an ownership flag without instruction-level cross-references. `IMAGE_UI_CLAIM_SMALL` at `0x00c682c6` names a visual asset, not a business-logic branch.

The native ARM callback at `0x009ff9e0` (known from v164 `FireDidRefresh` logs) dispatches a refresh event through a virtual call rather than being a simple synchronous, sidecar-aware product overwrite. `FirePaymentComplete` callback starts at `0x009ffa84`; the host delivers a synthetic receipt to it. We still need an instruction-level xref to identify the exact internal purchase-state reader feeding CLAIM and the actual unlock path.

Metadata cross-check: project `PvZ2_METADATA(1).zip` `PACKAGES/PLANTTYPES.RTON` includes premium plant type names, but contains no `SKU`, `Purchased` or `Premium` field strings for shop purchase status. RTON plant definitions do not substitute for tracing native broker/ownership decisions.

## 4. Diagnostic ranking — hypotheses, not verified root-cause conclusions

**H1: global native purchase state (primary)**. v166's sidecar makes profile A/B ownership appear separate only in explicitly rewritten profile vectors; the real broker also records native transaction/global-purchase state. Changing the active profile does not change the original global owner, and even a catalog refresh reuses the same synthetic broker driver, so B may see CLAIM or gain the unlock from global/native state. This fits both the original `RetrieveGlobalPurchase` state and the host's real native purchase callback sequence. Distinguish whether B actually has the plant, not just the label.

**H2: in-memory cached catalog/CLAIM state**. Even if the native rights vectors are correctly cleared on switch, the same Java/native broker may reuse product-state objects or cached claimability from A. The host replays `SkuDetails`, but does not explicitly invalidate the native purchased-item cache on profile switch. If the issue vanishes when relaunching directly into B, prioritize this rather than rewriting global save data.

**H3: wrong account credited during async purchase**. `OfflinePurchaseRequest` lacks the initiating profile ID. The delivery callback resolves `GetCurrentProfile` again and charges/grants to that then-active account. To prevent this entire class, bind pending request to initiating stable profile ID AND verify it before debit and delivery. If profiles differ, fail safely rather than charging another profile. This is a definite code design weakness, not an established occurrence.

**H4: legacy migration/reload contamination**. A single global `offline_store_profile_scope_migrated_v1` flag migrates the current profile's initial premium vectors once, regardless of which old profile's pre-existing global save originally owned the premium rights. In a non-reset older save, opening B first on the migration run may assign B A's former rights. Later `GlobalSaveData` rehydration may also repopulate native vectors after a switch. v166's fresh reset eliminates old QA trees for a cleaner experiment.

## 5. The decisive evidence to collect from the already-built v166 IPA (NO NEW BUILD)

Keep the user's verified reference save EXTERNALLY in iCloud Drive/PC (an ordinary local backup's three top-level items may naturally be `UserData`, `config-v1.txt`, `snapshot-info.plist`; `UserData` contains ALL profiles). On freshly reset v166, before buying anything open B's shop; then switch to A, buy one premium plant, switch immediately to B in the SAME process and record both the SHOP text BUY/CLAIM and whether the plant is actually selectable/usable. Hard Stop and export full log #1; compare per-profile `OFFLINE STORE PROFILE BEFORE/APPLY`, `CATALOG AUDIT before/after`, `purchase commit` and `PROFILE PURCHASE` lines. Cold-relaunch directly into B WITHOUT restoring, record its shop AND actual plant access, Hard Stop and save full log #2. Only then restore cloud baseline. Do not install anything else to run this test.

Interpretation:

| B sidecar/native masks | B display | Plant usable on B? | Survives cold restart? | Action |
|---|---|---|---|---|
| 0 / 0 | CLAIM | No | No | Inspect per-process broker/cache state before touching persistent global data. |
| 0 / 0 | CLAIM | No | Yes | Trace persistent native purchase flag read by the UI and reset/scope just ten offline SKUs. |
| 0 / 0 | CLAIM | Yes | Either | Native global gameplay entitlement remains authoritative; isolate shared unlock reader/writer as well as UI. |
| B vectors nonzero, B sidecar zero | CLAIM | Either | Either | Rehydration or missed profile switch; current vector overlay timing is incomplete. |
| B sidecar incorrectly nonzero | CLAIM | Either | Either | Investigate migration or asynchronous purchase owner mismatch; do NOT patch UI. |

The v164 uploaded log only covered one profile ID 1790838014 with raw premium vectors AND sidecar masks at zero before and after catalog refresh. It did NOT contain the controlled A-purchase → B-switch sequence, so it cannot single out H1 vs H2 today. User's report of cross-profile access motivates the investigation but does not substitute for those two logs.

## 6. Scope of ONE subsequent functional patch (after disambiguation)

- Maintain a single per-profile source of truth for **only the ten offline SKUs**, preserving all normal plants, features and campaign progression. Do not clear whole `global_save_data` on every switch, and do not paint the BUY label over incorrect native status.
- If H1 is confirmed, identify the ARM-level purchase/claimability query and legitimate global writer (native transaction callback or deserialization), then interpose the correct per-profile purchased state in BOTH shop and gameplay entitlement paths. Explicitly reset appropriate broker caches only at account switch, with a safe transaction boundary.
- Bind pending transaction to initiating profile, prevent cross-account fulfillment, audit sidecar write after native callback and handle failure/rollback without double-charge or free claims.
- Preserve existing V166 reset, V165 verified backup/restoration, V164 diagnostics UI, V162 bounded transaction/entitlement probes, and all guest scheduler/audio/render/memory improvements. Instrument only changed event boundaries, not per-frame. Implement the full identified class of fixes before ONE new IPA build.

Current decision: no speculative native patch and no additional IPA on this static-analysis branch. The next meaningful input is the already-planned v166 A→B real-iPad observation and the two complete logs.
