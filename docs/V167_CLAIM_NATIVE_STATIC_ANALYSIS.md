# v167 — Static root-cause investigation: CLAIM / unlock leakage between local profiles

Status: STATIC ANALYSIS ONLY. The v166 opt-in reset IPA was compiled (GitHub Actions run #430) and the user has saved a reference snapshot. **This branch does not change gameplay, store state, save files, or build an IPA**. The native code is the 2013 Android armeabi-v7a `libPVZ2.so` extracted from the project-supplied APK v1.5.252752. ARM offsets below are offsets within this exact ELF, not stripped-symbol names inferred from nearby unrelated weak symbols.

## New decisive physical-iPad observation (reported by user)

**CONFIRMED visual/interaction behavior**: after account A buys a premium plant, another account B can press `CLAIM`, obtains the plant for real, and that item disappears from B's shop. This falsifies the narrow hypothesis that the problem is only a stale button label. The second account is genuinely able to redeem a shared original purchase. The report does NOT yet show whether the availability of CLAIM persists in B after a cold restart *before B redeems it*, or identify the exact native function/state granting it.

**Design context, hypothesis not independently proven as historical product contract**: Google Play purchase entitlements are naturally global to the store purchaser even when a game has multiple local player profiles. The old PvZ2 purchase broker's `RetrieveGlobalPurchase` state and this observed behavior are consistent with intentionally sharing one permanent IAP across profiles, with a per-profile `CLAIM` to materialize each local unlock. Our newer desired behavior (spend separate PvZCoins and own a plant independently on each local profile) diverges from that possible original purchase model. Merely clearing B's `m_unlockedPlants` vector still allows the native global purchase/CLAIM restoration path to append the plant on B.

**Revised implementation priority**: scope the *right to claim/redeem the original purchase* and the subsequent *grant* to the purchasing local profile for the TEN custom coin-backed offline SKUs, preserving all other original/free progression and native assets. An account-switch cache reset alone cannot be considered sufficient even if it removes a transient CLAIM: unauthorized redemptions must be blocked at the logical entitlement decision, not just UI. Verify no cross-profile deducible/global transaction history leaks through `RetrieveGlobalPurchase`; audit the actual claim callback/restore transaction path with the ELF and logs. Prevent the initiating-profile race before sending FirePaymentComplete.

**Critical test sequencing refinement**: B has now clicked CLAIM and genuinely unlocked the item, so simply restarting B NOW cannot distinguish the original global claimability leak from B's legitimate newly saved unlock. For a restart comparison, restore the pre-purchase/fresh-reset test state or pick ANOTHER premium plant not yet claimed on B: buy it only on A, first inspect B's unexpected CLAIM without redeeming, cold restart on B STILL BEFORE REDEMPTION, then inspect again. Preserve both full logs; only after these controls test claim redemption separately.
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

**H2: in-memory cached catalog/CLAIM state (can coexist with H1, insufficient alone after confirmed B redemption)**. Even if the native rights vectors are correctly cleared on switch, the same Java/native broker may reuse product-state objects or cached claimability from A. The host replays `SkuDetails`, but does not explicitly invalidate the native purchased-item cache on profile switch. If the issue vanishes when relaunching directly into B, prioritize this rather than rewriting global save data.

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

User explicitly confirmed that B pressing CLAIM actually grants the premium plant and removes the item from the shop. Therefore a purely cosmetic stale-label fix is ruled out. The v164 uploaded log only covered one profile ID 1790838014 with raw premium vectors AND sidecar masks at zero before and after catalog refresh. It did NOT contain the controlled A-purchase → B-switch sequence, so it cannot single out H1 vs H2 today. User's report of cross-profile access motivates the investigation but does not substitute for those two logs.

## 6. Scope of ONE subsequent functional patch (after disambiguation)

- Maintain a single per-profile source of truth for **only the ten offline SKUs**, preserving all normal plants, features and campaign progression. Do not clear whole `global_save_data` on every switch, and do not paint the BUY label over incorrect native status.
- If H1 is confirmed, identify the ARM-level purchase/claimability query and legitimate global writer (native transaction callback or deserialization), then interpose the correct per-profile purchased state in BOTH shop and gameplay entitlement paths. Explicitly reset appropriate broker caches only at account switch, with a safe transaction boundary.
- Bind pending transaction to initiating profile, prevent cross-account fulfillment, audit sidecar write after native callback and handle failure/rollback without double-charge or free claims.
- Preserve existing V166 reset, V165 verified backup/restoration, V164 diagnostics UI, V162 bounded transaction/entitlement probes, and all guest scheduler/audio/render/memory improvements. Instrument only changed event boundaries, not per-frame. Implement the full identified class of fixes before ONE new IPA build.

Current decision: no speculative native patch and no additional IPA on this static-analysis branch. The next meaningful input is the already-planned v166 A→B real-iPad observation and the two complete logs.

## 7. Instruction-level and cross-platform verification after user confirmed real CLAIM grant

Re-extracted and disassembled the actual project APK `lib/armeabi-v7a/libPVZ2.so` with LLVM ARM tooling. These are genuine ARM `LDR` literal references resolved through the position-independent C++ base, not mere neighboring ASCII strings:

| Purpose | Android string address | ARM instruction loading relative reference |
|---|---:|---:|
| `PurchasingSkus` | `0x00c78ce5` | `0x0043c058` (literal `0x0043c2b8`) |
| `m_unlockedPlants` | `0x00c78c65` | `0x0043c3c8` (literal `0x0043c774`) |
| `m_unlockedGameFeatures` | `0x00c78c76` | `0x0043c464` (literal `0x0043c788`) |
| `m_unknownSkus` | `0x00c78ca0` | `0x0043c59c` (literal `0x0043c7a4`) |
| `local_profiles` | `0x00c78c46` | `0x0043e988` (literal `0x0043ea94`) |
| `global_save_data` | `0x00c78c35` | `0x0043faf8` (literal `0x0043fc04`) |
| `PurchaseBrokerState` | `0x00c7a0a3` | `0x0049aa80` (literal `0x0049ab44`) |
| `RetrieveGlobalPurchase` | `0x00c7a14e` | `0x0049ac3c` (literal `0x0049ac5c`) |

Note: ARM `LDR` to metadata strings is proof of a real serialized/enum reference, **not proof the loader itself implements the claim decision**. The unrelated weak `std::*` symbol labels displayed by disassemblers often span much larger ranges and must NOT be treated as precise user-function names.

Real v164 iPad USERFS loader evidence: `UserData/No_Backup/global_save_data` loaded **196 bytes** and `local_profiles` **1061 bytes**; `pp.dat` and `snapshot2.dat` both **7241 bytes**. These are actual distinct on-disk resources. Their formats and premium purchase contents have NOT been decoded from a real A/B save here.

Independent check against the project-supplied original 2013 iOS 1.5.252123 `PvZ2` ARMv7 Mach-O confirms ALL nine exact metadata/enum names above (including `global_save_data`, `local_profiles`, `m_unlockedPlants`, `PurchasingSkus`, `RetrieveGlobalPurchase`). This means the global-purchase architecture predates our Android-on-iOS bridge and is shared across original platforms. It remains inference, not a verified EA design statement, that global store purchases were intentionally claimable on multiple local profiles.

Native `Sexy::IPurchaseDriver::Product` lookup: Android ARM `0x00a006c0` calls `std::map<std::string, Product>::find` at `0x00a006f8`, then copies four values from offsets 0, +4, +8, +12 in the retrieved record. Adjacent product update code near `0x00a00c3c` inserts or replaces through `map::operator[]`. This supports that **catalog/product-details lookup differs from native entitlement/redemption handling**; it does not disclose the separate purchase-ownership structure. No justified `SkuDetails` field alteration can be inferred as a direct fix for CLAIM.

The Android `classes.dex` also includes Google Play billing names `getAllOwnedSkus`, `getAllPurchases`, `getPurchases`, `queryPurchases`. Presence of these library API names does not show which ones the original game actually calls for CLAIM; no unobserved JNI call should be invented.

Consequence of actual B CLAIM→plant grant: global/native entitlement read and the resulting per-profile unlock writer must BOTH obey our custom coin-backed profile scope for only ten offline SKUs. Cache invalidation or masking a label alone is insufficient. Existing v166 cannot answer whether the global flag is deserialized at cold startup or maintained only in broker RAM because the available full probe log has no A→B claim event.

Companion unbuilt implementation work: branch `v168-claim-redemption-fix-staging` pins `RequestPayment` to its **initiating** profile and aborts on later selection mismatch before debit/native transaction completion. This proactively fixes a distinct confirmed race but does NOT claim to fix free cross-profile CLAIM; do not ship an owner-only IPA as if it did.

### Native `RetrieveGlobalPurchase` state dispatch: narrowed instruction path

Further analysis of ARM control flow (not just strings): the enum-label function at `0x0049ab50` has a 7-case jump table indexed by `r2` values 0..6; index **6** resolves the literal string `RetrieveGlobalPurchase` through its `0x0049ac38` case. The broker processing function at `0x0049ba40` reads its state from `[r4 + 0x1c]`, tests for state **6** at `0x0049ba50`, and enters the `0x0049bb20` branch.

That branch invokes the known `GetCurrentProfile` function at `0x0049bb54` → `0x0047f8b0` (the same address the host's v166 `kGetCurrentProfile` already calls), takes the resulting native profile pointer into `r5`, and at `0x0049bb8c` calls `0x0042feec` with `r0 = active profile`, `r1 = broker+0x20`, `r2 = 1` and another argument. On the main return path it calls `0x0049aa70` to return the broker to state 0. Thus the original **global purchase retrieval state processes data in the context of whichever local profile is active**.

Caveat essential to safe patching: `0x0042feec` has **another caller at `0x004a0e28`** and appears to be a more general native profile/DB helper, not a dedicated "CLAIM" permission function. Do not patch this callee globally or force state 6 to bypass the routine; both could corrupt unrelated profile/campaign behavior. Further inspection of its return values, source data, and caller-dependent parameters is needed before introducing a narrow interception.

This is an exact state-machine path and practical candidate for an EVENT-ONLY dynamic ownership probe at the call boundary, but it is not yet independent proof that this specific call makes B's store item claimable, or that the plant grant uses the same branch.

### Native FirePaymentComplete is deferred: full verified ARM listener chain

A further instruction-level trace of the reference Android ELF changes an earlier timing assumption. The JNI entry at `0x009ffa84` does **not** synchronously grant ownership: it prepares a **56-byte** purchase event (`0x009ffd20` allocates 56 bytes), then calls event enqueue routine **`0x009e5ed0` at `0x009ffddc`**. That queue routine manipulates a global container under locking, rather than directly writing the profile's unlocked vector.

When the queued event is processed, its callback **`0x00a01614` calls `0x00a00e24` at `0x00a01650`**. This function resolves a listener pointer at native driver offset **`+0x0c`** (`0x00a00e60`) and invokes the listener's vtable method **slot 0** through `blx r11` (`0x00a00ed8`). Thus the exact purchase handoff is: host-generated `FirePaymentComplete` -> native JNI 56-byte event queue -> deferred event callback -> purchase driver's native listener -> *yet-to-be-resolved original broker method that updates purchased/granted state*. Tracing THAT listener registration/vtable target is a more precise next step than editing arbitrary GlobalSaveData keys.

This timing matters: `part_09.inc` calls the native `FirePaymentComplete` entry, then immediately writes our V128 per-profile sidecar, but **the original game's listener may consume the event only later**. We must not claim the original broker already wrote its global purchased state before the host sidecar; the verified code establishes order of JNI enqueue before V128 commit, not order of native entitlement mutation versus sidecar persistence.

Consequently, the staged v168 `initiating_profile_id` check prevents an A→B switch that occurs **before host delivery of FirePaymentComplete**. It may be insufficient for a later A→B switch occurring **after native JNI enqueue but before native listener dispatch**, depending on actual event-queue drain timing. The final grouped patch must preserve owner identity across that second asynchronous boundary as well (either validate at listener consumption, or establish a proven same-account synchronous drain), and then isolate the underlying global claim permission for ten custom SKU only. Do not represent the staged fix as a fully verified race remedy.

The `RetrieveGlobalPurchase` broker state branch was independently rechecked at `0x0049ba50` (compare state 6) → `0x0049bb20`, selecting current profile via `0x0047f8b0` at `0x0049bb54` and invoking helper `0x0042feec` at `0x0049bb8c`. Helper `0x0042feec` performs generic RtDb/RtObject field handling and is also called at `0x004a0e28`; it is NOT an isolated exclusive CLAIM-authorization function. Editing it globally would be unsafe.

**Safe next native boundary candidates (event-only probes, if static vtable recovery remains inconclusive)**: the `0x00a00ed8` native driver listener invocation, the state-6 `0x0049bb20` branch and `0x0049bb8c` helper call, plus profile selector before and after those events. Capture SKU, initiator profile ID, selected profile ID, native profile rights vector and host sidecar mask without dumping arbitrary per-frame guest memory. The only reliable proof of blocking unauthorized redemption is that B does NOT receive the plant at CLAIM or from the entitlement path, not a changed button label.

### 2026-10-01 deeper ARM trace: definitive broker listener and per-product global retrieval entry

**Proven native listener connection, removing the prior virtual-dispatch uncertainty:** broker constructor `0x0049a8ac` writes vtable address `0x00ccddb8` to `broker+0`, creates native purchase driver via `0x009ff218` at `0x0049a904`, and registers the broker as driver's listener using driver's virtual slot `+8` at `0x0049a914`. Driver's slot `+8` resolves to `0x00a002e4`, which is literally `str r1, [r0, #0xc]; bx lr`: the broker pointer is stored in native driver `+0x0c`. When deferred payment event reaches the driver, `0x00a00e24` reads that pointer and dispatches listener vtable slot0 at `0x00a00ed8`. Broker slot0 resolves to **`0x0049ccf0`**. The event chain is therefore definitively `JNI FirePaymentComplete 0x009ffa84 → 56-byte event queue 0x009e5ed0 → callback 0x00a01614 → driver dispatch 0x00a00e24 → broker listener 0x0049ccf0`.

**Transaction operation at `0x0049ccf0`:** creates a 40-byte native `PurchaseTransaction`, populates several fields, appends it to the broker's `PurchaseTransaction*` vector at broker offset `+0x2c` (ARM `0x49ce44..0x49ce7c`), then calls helper `0x0049ff08` (from `0x49ce84`). This is a verified **receipt-to-broker pending-transaction handoff**; it is NOT proof that the plant was already unlocked in this listener, because subsequent transaction processing may happen later.

**New narrow global-retrieval *submission* path:** at **`0x0049ac98`**, a broker function accepts `r0=broker` and `r1=item/product ID` (saved as `r9` and `r8`). After validation/UI work, its convergent branch **`0x0049afb8`** copies the item identifier (`r8`) to **`broker+0x20`** using `0x00b74be8`; **`0x0049afc8` sets broker state to `6`** by branching to `0x0049b160` (`0x0049aa70` state setter). The state-6 consumer at `0x0049bb20` then reads **whichever profile is currently selected** with `GetCurrentProfile` and passes it and this queued item identifier to the generic helper `0x0042feec` at `0x0049bb8c`. This links a SPECIFIC requested product with later `RetrieveGlobalPurchase` processing on CURRENT (not transaction-originating) profile; it is substantially narrower than editing all `global_save_data` or all `RtDb` operations.

That submission method has at least seven literal BL callers in the reference APK (`0x151d14`, `0x153020`, `0x3545dc`, `0x4b75f0`, `0x4ff994`, `0x503958`, `0x5ad9d8`); do not assume all represent a `CLAIM` click. Its classification helper **`0x0049df38`** compares the submitted product category against literal strings `plant` (`0xc682e2`), `bundle` (`0xc7170a`), `gameupgrade` (`0xc716ed`), and `coin` (`0xc7231f`). A condition on this helper controls presentation/animation along one path, but BOTH paths converge at the same item-specific state-6 setup `0x49afb8` (as evident from the conditional branch at `0x49aeb8`). Thus merely bypassing that category check would NOT be a valid CLAIM fix.

**Boundary of proof:** it is now verified that the original native broker has a per-product state-6 global retrieval request, subsequently resolved against the *current* local profile, and real payment receipts reach a shared broker transaction vector through a queued event. Combined with the real iPad observation B can genuinely redeem A's purchased item, this strongly supports a cross-profile store purchase/redemption route. The exact BOOLEAN permission check distinguishing `BUY` from `CLAIM` has still not been proved from a single instruction; the actual item grant may occur in downstream `0x42feec` or later transaction processing. `0x42feec` is also used at unrelated `0x4a0e28` and must not be globally patched.

**Functional patch design gate:** for only the six offline plant SKUs plus four game-upgrade SKUs, use a single stable per-profile entitlement/transaction mapping. On request (`0x49ac98`) AND eventual state-6 processing (`0x49bb20`), record owner and desired SKU action and distinguish explicit paid purchase from global restore; reject nonowner restore without suppressing B's ordinary BUY. Recheck owner at the deferred listener (`0x49ccf0`), since the JNI callback itself is asynchronous. Guard the real unlock writer too, not the shop text alone. First recover exact request type and SKU representation at the callsites or with **event-only** register/sidecar probes; no speculative ARM patch at these addresses or new build is justified yet.

### Scope check: state-6 handoff calls a shared profile-item update/insert helper, not a safe global hook

Further disassembly of `0x42feec` shows the callee takes `r0=profile-like owner`, `r1=requested item RtId`, `r2=mode`, `r3=auxiliary ID`, traverses an RtDB table/list, compares each entry's item ID to the requested ID (ARM `0x430070..0x430098`), follows an existing-item branch at `0x4304cc`, and follows another path after exhausting the list (`0x4300b4..0x430274`) that constructs/updates related records. This strengthens the interpretation that state 6 directly **applies a requested item to the active profile** rather than simply looking up text for the shop. **However**, the exact semantic meaning and all side effects of the helper's data fields are not independently verified; do not label `0x42feec` exclusively `GrantPremiumPlant`.

The second call site `0x4a0e28` invokes that same helper with `r0` from `0x483950`, a different item argument and `r2` varying with another internal condition. Therefore bypassing `0x42feec` outright would also affect other game/item flows. Only a conditional interception at the verified **broker state-6 caller** (`0x49bb8c`) for the ten injected SKU IDs, using the locally selected profile and host-side profile-specific ownership, is a plausible narrow candidate; test against both B ordinary BUY and B unauthorized CLAIM before adopting it.

**Extra useful distinction:** The item-specific submission `0x49ac98` calls helper `0x49df38` for product-category identification. Literal ARM references prove four tested category strings: `plant` at ELF `0xc682e2`, `bundle` at `0xc7170a`, `gameupgrade` at `0xc716ed`, `coin` at `0xc7231f`. The state-6 setter at `0x49afb8..0x49afcc` is reached both through the direct branch when classification result is not 1 and through the alternate animation/presentation path. Thus filtering the category check is NOT a method to stop cross-profile redemption, and changing the broker class globally would interfere with noncustom products.

At current proof level the most precise chain is: item-specific submission `0x49ac98` → state6 entry `0x49afb8` → item ID at broker+0x20 → current-profile lookup `0x49bb54` → shared profile-item update `0x49bb8c` → GUI/gameplay updates as determined by native engine. Independently, native FirePaymentComplete enqueues and later dispatches its transaction via registered broker listener slot0 `0x49ccf0`. We know the user actually received the item on B, but we have not yet demonstrated, for THAT exact input trace, whether B claim used this state6 call or a second callback path. A targeted, event-driven ARM entry/exit trace of `0x49bb20`, `0x49bb8c` and `0x49ccf0` on the **already-built v166** can close that remaining causal gap with one iPad experiment, without probing every frame.
