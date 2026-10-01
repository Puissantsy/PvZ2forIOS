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
