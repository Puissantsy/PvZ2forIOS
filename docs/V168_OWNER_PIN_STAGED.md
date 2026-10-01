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
