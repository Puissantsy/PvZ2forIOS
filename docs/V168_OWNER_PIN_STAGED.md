# v168 staging — offline purchase owner pin (NO IPA YET)

## Why this code exists

Original v166 offline JNI `RequestPayment` stored `{sku, price, serial}` but NOT the account where the user clicked BUY. The later async frame-boundary callback called `GetCurrentProfile` again, then debited coins and delivered the real native `FirePaymentComplete`. If A requested an item and switched to B before delivery, B could be charged/credited. This was a source-level race, independent of the already-reported B→CLAIM→real free grant.

## Exact staged source changes

- `part_01.inc`: `OfflinePurchaseRequest` now has `initiating_profile_id` (invalid default `0xffffffff`) and `OfflineStoreCurrentSelectionId()`, reading the exact `kGuestBase + 0x00d4e960` profile-manager selector (`manager + 0x14`) already consumed by the production callback path. The address is tied to the reference APK v1.5.252752 and is not fabricated from account labels.
- `part_05.inc`: capture initiating selector synchronously at JNI `RequestPayment`. If catalog SKU is unsupported OR the initial profile is unavailable, queue a payment failure code rather than an unowned payable transaction. Include initiator and immediateError in the event log.
- `part_09.inc`: before reading/debiting coins or entering real `FirePaymentComplete`, compare the deferred resolver's current selector with the request's initiating profile. On mismatch, call existing `FirePaymentIncomplete`, clear pending request and log both IDs; no coin debit or native global transaction. Preserve existing lifecycle and original JNI format.

## Static pass/fail matrix

| Scenario | Expected result |
|---|---|
| A requests a known SKU, A still selected on delivery | Normal one-time coin debit followed by real native completion and host sidecar commit |
| A requests a known SKU, B selected on delivery | Incomplete result, NO debit to A or B, NO native completion, NO entitlement change |
| No valid account when RequestPayment occurs | Queue incomplete result, no purchase |
| Unknown SKU | Same incomplete handling, no purchase |
| Existing pending transaction | Preserve old single-purchase guard (reject second request) |
| A purchases, later switches to B and B presses already-visible CLAIM | **NOT FIXED HERE**; requires identifying and isolating native global purchased/claim-redeem path |

## Strong native evidence, and remaining limit

`docs/V167_CLAIM_NATIVE_STATIC_ANALYSIS.md` now includes Android ARM instruction-level string cross-references to `PurchasingSkus`/`m_unlockedPlants`/`global_save_data`/`RetrieveGlobalPurchase`, plus the matching strings in the original 2013 iOS ARMv7 executable. This cross-platform agreement suggests, but does not directly prove, that a non-consumable IAP is intentionally available to each local player via CLAIM. Our custom PvZCoins model, however, must scope only ten offline purchase SKUs per account. The exact native getter/writer authorizing B's redemption has NOT yet been isolated via verified xrefs or a full A-buy→B-claim iPad trace. **Do not rewrite original `global_save_data`, invent an ARM patch address, or release an owner-only IPA as a claimed CLAIM fix.**

## Future grouped patch gate

After identifying the native purchase-status/claim path, complete source-of-truth isolation for the ten supported SKUs, stop unauthorized claim redemption, and audit failure rollback. Add minimal event-driven probes for ownership checks. Preserve v165 verified backup/restore, v166 intentional reset + one-time QA grant, v162 per-profile mask logs and all validated guest runtime changes. Make ONE new iOS build only when the entire identified class is covered. Do not merge uncompiled staged runtime changes into the validated v166 baseline.

## Verified second asynchronous boundary — remains UNSOLVED by owner pin

Further native disassembly verifies `FirePaymentComplete 0x009ffa84` only queues a 56-byte native event. Its deferred callback `0x00a01614` calls driver dispatcher `0x00a00e24`, which consults driver listener `+0x0c` and dispatches the registered purchase-broker slot0 `0x0049ccf0`. The actual broker listener appends a 40-byte pending `PurchaseTransaction` to vector at broker+0x2c, then delegates further processing.

Consequently, this branch's initiating-profile guard protects **only the host RequestPayment -> FirePaymentComplete enqueue boundary**. It does not pin the owner through native event consumption or later `RetrieveGlobalPurchase` and is NOT a complete solution for free cross-profile CLAIM. A follow-on grouped patch must (i) bind native event/transaction to initiating profile throughout its lifetime, and (ii) restrict the genuine claimability and grant of only ten offline SKU entitlements to that owner; B must still be able to pay for a new legitimate purchase.

The real native item-specific submission `0x0049ac98` receives broker + requested product, stores product at broker+0x20 then sets state6 `RetrieveGlobalPurchase` via `0x49afc8 -> 0x49b160`. State6 later retrieves current profile and passes it with pending item data into a GENERIC helper `0x42feec`. This is a narrow observation point, NOT permission to patch the state or generic helper until BUY and CLAIM cases are distinguished. See accompanying v167 analysis.

## Confirmed historical product contract: shared non-consumable purchases

Source: project `PvZ2_METADATA(1).zip` -> UTF-16 `PvZ2_METADATA/LOCALES/{EN-US,FR-FR}/PROPERTIES/LAWNSTRINGS.TXT`. Relevant exact keys:

- `PURCHASE_CROSS_PROFILE_PLANT`: *Purchased Plants can be claimed by any of your additional profiles!*
- `PURCHASE_CROSS_PROFILE_UPGRADE`: *Purchased Upgrades can be claimed by any of your additional profiles!*
- `PURCHASE_RECLAIM_ITEM_BODY`: *Item has already been purchased on another profile. Claim for current profile at no cost!*
- `FORCE_RESTORE_PURCHASES_BODY`: *Restore Purchases will allow you to claim all of your past purchases in any profile.*
- `INGAME_RESTORE_PURCHASE_ITEM_BUTTON`: `CLAIM`.

The original game's cross-profile CLAIM is **confirmed intentional**, not a bug in native `global_save_data` deserialization, not necessarily our JNI implementation defect, and not merely a stale label. The iPad user confirmed pressing CLAIM on B actually grants the A-purchased plant for free and removes it from B's shop.

**New desired semantics apply ONLY to the 10 custom coin-backed offline entries defined in part_01:** original global nonconsumable entitlements must remain untouched for unrelated items, but a custom plant bought with profile A's own PvZCoins must NOT be redeemable for free on B. B must get its own ordinary BUY option and may purchase X using B's coins. This is a deliberate change of original game's ownership policy for the custom offline store, not a general corruption fix.

Acceptance invariants before releasing ANY runtime IPA:

1. Fresh A/B after v166 reset. A BUY X decreases ONLY A coins once, grants usable X to A, persists after restart.
2. Before B buys, B store offers BUY (not free CLAIM) for X. Any stale native CLAIM attempt on B must be denied at the real entitlement grant, not just hidden in UI.
3. B BUY X decreases ONLY B coins once, grants X to B without modifying A's wallet, plants or sidecar. After process restart both retain independent ownership.
4. Rapid account switch before host payment delivery AND between native queue and listener consumption must not charge/grant wrong profile or create global claimability for the other account.
5. Reinstall is NEVER necessary: v165 full snapshots/restore and v166 explicit reset remain byte-for-byte compatible. Existing other item categories are not swept or globally cleared.

**Static design decision:** do not make the original native global broker itself fully per-profile for everything. Instead introduce an authoritative narrow per-profile ownership/claimability adapter that recognizes the ten synthetic offline SKUs, injects correct purchasing eligibility into the store and guards the native state-6 grant path plus deferred purchase listener. When reconstructing the native broker/product layout, distinguish product-request UI event from paid receipt and unsolicited global restore; `0x49ac98` is called from at least seven callsites and cannot be unconditionally blocked. The existing `part_01` V128 masks provide one candidate persistent authority; inspect its migration interactions before using as a final canonical record.

## New staged metadata for the native deferred transaction boundary (still unbuilt)

The pending host `OfflinePurchaseRequest` is already pinned to the initiating local profile. However, JNI `FirePaymentComplete` enqueues a separate 56-byte C++ event that later becomes broker transaction data; the native listener can execute after another local account is selected. We have now added an opaque synthetic transaction marker that **travels with the guest event**: token `pvz2-offline:v2:<initiatingProfileId>:<serial>:<sku>`, order `pvz2-offline-order:v2:<initiatingProfileId>:<serial>`, receipt `pvz2-offline-receipt:v2:<initiatingProfileId>:<serial>`. `original_json.purchaseToken` uses the same v2 token, and the host continues comparing the exact generated token when `ConfirmDelivery` occurs.

The next native listener/claim hook will be able to extract and verify that stable owner directly from transaction data, not infer it from `GetCurrentProfile` at consumption time. **This addition preserves evidence, not enforcement**: no native event hook has yet been implemented, and original intentional cross-profile CLAIM is not fixed in this staged branch. For strict parsing, recognize only the exact host-generated `pvz2-offline:v2:` prefix and a valid finite decimal profile ID plus serial, then match the known 10-SKU catalog; never apply this custom policy to genuine non-v2 original store receipts.

Future physical-iPad acceptance: when the grouped native hook build is ready, verify normal A BUY still gets successful `ConfirmDelivery` with the exact v2 token, A retains the item and charged coins, B's independent BUY and a rejected stale unauthorized CLAIM do not result in any free grant; verify fast A→B switches before host enqueue and after native enqueue, failure/rollback and cold restart. The existing v166 IPA contains NONE of these new uncompiled runtime changes.

## Important compatibility edge case: an original receipt can reuse the SAME canonical SKU

Our ten offline catalog entries intentionally use the old original `com.popcap.pvz2.android...nonconsume` product identifiers. A real historical purchased SKU imported through an authentic original save/receipt could therefore have EXACTLY the same SKU string as a new custom v2 coin purchase. Filtering **all** claims of those ten SKU strings would silently revoke an authentic original purchased entitlement and diverge from the original restore contract.

Staged source now exposes `OfflineStoreLocalOwnershipForSku(profileId,sku)` with five **informational states**: `NotOfflineSku` (never override unrelated SKU), `NoProfile` (fail closed/defer), `SidecarNotReady` (wait for tracked migration/projection), `Owned`, `Unowned`. This helper intentionally does NOT by itself authorize or block original free CLAIM. It is usable by a future adapter only AFTER purchase provenance is distinguished (host v2 token/receipt versus genuine original legacy receipt). Never interpret `Unowned` as evidence that an authentic original global entitlement did not exist.

Explicit next research gate: confirm which original native saved purchase records retain receipt/token origin after cold restart and how to recognize existing authentic global purchases. For new v2-only custom transactions, keep an independent profile-scoped host ledger and avoid adding reusable original global entitlement; project per-profile purchase visibility and grant authority for custom origin only. If the original purchase database discards provenance, resolve conflicting original+custom same-SKU cases with a migration/preservation policy backed by actual save tests, not an unconditional SKU filter.

The helper and v2 receipt marker are deliberately unbuilt preparations for that adaptation, not a speculative guest patch. A single future IPA must test BOTH clean fresh v166 profiles and restoration of existing legacy/global-paid saves without altering campaign progression.

## Offline proof without another iPad IPA: two manifest-verified save diffs

New read-only helper `tools/compare_store_snapshots.py` takes TWO complete, intact `save-...` directories from v165/v166 (not individual `pp.dat` or `config-v1.txt`). It validates `snapshot-info.plist` and SHA-256 of every listed file and refuses unexpected paths, symlinks and altered files before reporting which file path/hash changed. It never modifies or extracts user data. This can distinguish the set of files written by PAID A purchase versus FREE B CLAIM without claiming that a changed binary file alone identifies a particular field.

Suggested controlled setup (after protecting the complete 60k baseline OUTSIDE the app):

1. Use an A/B test state with at least one target SKU still unclaimed on B. The fact that B has already redeemed A's first test plant means comparing that SAME already-claimed item after cold restart is no longer a clean unclaimed control.
2. For A purchase: copy the `prelaunch` snapshot from the session into a private analysis folder, buy one new plant ONLY on A, `⋯ > Sauvegarder et arrêter`, copy its `poststop` snapshot and full log. Compare:

```sh
python3 tools/compare_store_snapshots.py 'A-prelaunch-save-folder' 'A-poststop-save-folder'
```

3. For B claim: cold-relaunch without restoring, allow the automatic `prelaunch` snapshot, switch to B and record existing `CLAIM`, then claim that SAME plant ONCE (after capturing the UI evidence). Save+stop and copy `poststop` and full log. Compare:

```sh
python3 tools/compare_store_snapshots.py 'B-prelaunch-save-folder' 'B-poststop-save-folder'
```

4. Compare affected resource sets, prioritizing `config-v1.txt` (host per-profile masks/one-shot marker), `UserData/No_Backup/global_save_data` (original shared), `local_profiles`, `pp.dat`, `snapshot2.dat`. For minimal privacy, transfer only the generated changed-path/size summary; for true field decoding we may later need the specific changed binary save files from BOTH before and after, with the user's approval.
5. Finally restore the untouched reference via `PvZ2RestoreInbox`, as already validated on iPad.

Independent reproducible contract verifier (works with original project APK + metadata, optionally part_01 catalog) is `tools/verify_original_claim_contract.py`:

```sh
python3 tools/verify_original_claim_contract.py --metadata 'PvZ2_METADATA(1).zip' --apk 'original-android-reference.apk' --catalog platform/ios/src/pvz2_apk_probe_parts/part_01.inc
```

No user data should be sent to public GitHub. The test logs and snapshots may contain account/progression info; keep any shared analysis private. No new IPA is necessary to produce these existing v166 snapshots.

## Strict v2 receipt contract now isolated and unit-testable (still staging)

The parser/serializer lives in pure, dependency-free C++20 header `platform/ios/src/offline_receipt_v2.hpp`, included once from `pvz2_apk_probe.cpp`. `part_09.inc` now calls `MakeReceiptTokenV2` rather than hand-assembling the token; token remains byte-for-byte `pvz2-offline:v2:<initiatingProfileId>:<serial>:<sku>`, with the same v2 owner/serial retained in order and receipt strings. An invalid serializer result causes rollback before JNI native event enqueue. **No deployed native listener calls the parser yet; this is a safe future prerequisite, not CLAIM enforcement.**

`ParseReceiptTokenV2` accepts a known-SKU predicate to reuse the existing 10-entry catalog instead of maintaining a second independent SKU allowlist. It rejects original `pvz2-offline:<serial>:<sku>` legacy tokens, unrelated/noncatalog strings, `v3` or malformed version, leading-zero aliases, signed/negative IDs, invalid `0xffffffff` owner, empty/zero serial, 32/64-bit numeric overflows, oversized tokens and appended garbage. On rejection it leaves its output entirely unchanged. The namespace `pvz2offline` is side-effect-free; an authentic original receipt without v2 provenance must follow original shared-purchase handling rather than this custom path.

A standalone host-side regression test is committed at `tests/test_offline_receipt_v2.cpp` (without iOS dependencies); equivalent source run locally with Clang 17 / `-std=c++20 -Wall -Wextra -Werror -pedantic` passed two valid/boundary cases and 13 invalid/legacy cases. To rerun the committed test on a development machine:

```sh
clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Iplatform/ios/src tests/test_offline_receipt_v2.cpp -o /tmp/receipt-v2-test
/tmp/receipt-v2-test
```

Read-only project source validation also confirmed eight bilingual localization keys (four each EN-US and FR-FR), all ten custom SKUs byte-for-byte in the ORIGINAL binary `MAGENTO.RTON` resource and all six version-locked ARM state/purchase opcodes in the reference `libPVZ2.so`. These tests establish provenance-collision risk and trace integrity, NOT safe authorization semantics for real legacy receipts. Keep PR as draft and do not build/release an owner-only IPA.

## New work: original transaction offsets, purchase preflight, and decoded snapshot diagnostics

**Precise ARM event mapping**: see v167 analysis for the complete guest instructions. `FirePaymentComplete`'s 56-byte native queued event passes six original JNI strings through its deferred callback and driver bridge. At the registered broker listener (`0x49ccf0`), the guest allocates a **40-byte** `PurchaseTransaction` and writes canonical SKU `+0x0c`, receipt `+0x10`, order ID `+0x14`, token `+0x18`, JSON `+0x1c`, signature `+0x20`, with broker state/status `+0x04` and processing flag `+0x08`. On the known reference APK, **17/17** ARM instruction anchors for original global state and this layout passed exact-byte verification. For a NEW synthetic v2 payment, `tx+0x18` contains the host `pvz2-offline:v2:<profileId>:<serial>:<sku>` token. These offsets are guest ARM32 and strictly version-locked; they must not be applied as native host std::string structs or to arbitrary builds.

Staged **non-enforcing** `platform/ios/src/offline_native_purchase_probe.hpp` captures these offsets and classifies the token into five provenance outcomes: original/unknown receipt (leave legacy untouched), malformed v2 token, valid v2 owner is selected, valid v2 owner differs from selected, and selected profile unavailable. The discriminator invokes our canonical strict parser and reuses the existing 10-SKU catalog predicate. Do NOT use a mismatched currently selected profile to drop an enqueued purchase until exact retry/replay semantics are established; the event itself cannot protect against global CLAIM later.

New `offline_purchase_policy.hpp` gives a pure fail-closed admission matrix for fresh paid offline `RequestPayment`: `Unowned→Allow`, `Owned→RejectAlreadyOwned`, `NotOfflineSku→RejectUnsupportedSku`, `NoProfile→RejectMissingProfile`, `SidecarNotReady→RejectSidecarNotReady`. The existing five-state source helper in `part_01.inc` now reuses this enum and `part_09.inc` executes the policy BEFORE GetCoins, SetCoins or native FirePaymentComplete. This prevents accidental repeat coin debits if a native BUY button becomes stale and postpones transactions until the sidecar is ready. Genuine original receipts do not pass through our `RequestPayment` gate. Local isolated host C++20 static assertions for five cases passed; committed test `tests/test_offline_purchase_policy.cpp` reproduces them.

Native provenance classifier isolated C++20 equivalent passed six scenarios: real original unknown receipt, old pre-v2 synthetic receipt (unclassified), malformed spoofed v2 receipt, matching selected profile, different selected profile, and NO selected profile. Committed `tests/test_offline_native_purchase_probe.cpp` reproduces it; this is not a full iOS guest build or proof of runtime native hook correctness.

**Actionable no-IPA diagnostics**: decompiled exact `V128LoadConfigOnce` / `V128FlushConfig` in `part_02.inc` verifies that saved `config-v1.txt` uses TAB-separated `I/B/S` records with UTF-8 keys encoded as hex. `tools/compare_store_snapshots.py` now provides `--premium-diff`, which verifies BOTH manifests + SHA256 files first, then decodes and outputs **only** the whitelisted `offline_store_profile_v1_<id>_plants/features` masks and global `offline_store_profile_scope_migrated_v1` flag. It prints readable names for six plants/four upgrades but never prints other configuration values or raw USERFS data. It reports `ABSENT` separately from a `0x00000000` mask; that distinction is relevant for first-profile migration.

Example on TWO complete local snapshots (the user confirmed their actual backup has three root elements, as expected when UserData is a directory):

```sh
python3 tools/compare_store_snapshots.py 'save-...-prelaunch-...' 'save-...-poststop-...' --premium-diff
```

Use this separately for A's paid BUY and B's free CLAIM, with a still-unclaimed B test item and an externally protected baseline. After B CLAIM, if the B sidecar mask stays **zero** but the plant becomes playable, guest/native ownership or its grant path bypassed host sidecar; if B's sidecar changes, inspect migration timing or an unexpected host callback. A changed `global_save_data` hash is correlation, NOT proof of a specific premium field without safe decoding of that exact before/after binary pair.

Five **synthetic** fixture tests passed locally: known paid A mask difference without leaking unrelated `config-v1.txt` data, mock B global-file change with B sidecar unchanged, duplicate premium key rejection, altered SHA256 file rejection and unlisted file rejection. Committed reproducible QA: `tests/test_snapshot_premium.py`. The existing v166 uploaded full probe log covers two store refreshes, four native/sidecar audits for ONE profile and **ZERO** purchase commits or JNI RequestPayment events. Consequently this log by itself cannot prove the A-buy/B-claim runtime route. No actual paired user A/B snapshots have been supplied during this static pass.

**Release gate remains OPEN**: exact native BUY/CLAIM permission check and original global-entitlement publisher have not been isolated; a guest read hook at pending `PurchaseTransaction+0x18` is not installed. Staged parser, classifications and paid-BUY idempotency do NOT themselves prevent B's intentionally supported original free CLAIM. Keep this PR draft and create NO new IPA until per-profile custom transaction isolation is genuinely enforced while keeping authentic legacy same-SKU receipts restorable.
