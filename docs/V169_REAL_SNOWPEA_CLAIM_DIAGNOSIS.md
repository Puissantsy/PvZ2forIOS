# Real physical-iPad Snow Pea A purchase / B CLAIM: corrected root-cause investigation

**Date:** 2026-10-01. **Evidence:** two user-provided complete verified v166 snapshot ZIPs, each also containing its session log, plus one standalone third-session full log. **Sensitive raw saves and full logs remain local to the user's ChatGPT Project and MUST NOT be committed to this public repository.** Snapshot manifests and SHA256 file inventories were validated after extracting their extra log files separately.

## Crucial correction to previous diagnosis

The earlier statement that B “can actually use the plant” was contradicted by the user's subsequent **gameplay test**: pressing CLAIM makes Snow Pea disappear from the shop, but B CANNOT select/use Snow Pea in an actual level. After cold restart, B can press CLAIM again. The prior claim that an independent native purchase/ownership was confirmed is **withdrawn**. The original game supports free cross-profile reclaim by design, but our v162/v166 per-profile host entitlement overlay prevents the native B grant from surviving and being usable.

This is **not a purely cosmetic label problem**: the real native CLAIM path temporarily marks B's native premium plants vector as owning Snow Pea, and this appears to persist into the original native serialized save. Our intentionally separate V128 host sidecar remains zero for B and overwrites B's original vector later. Meanwhile A's global ownership marker remains present and produces CLAIM again. This explains the UI lock-out from normal PvZCoin BUY.

## Verified A paid purchase (first ZIP)

- The only custom JNI `RequestPayment` is in A's session. The native callback is `FirePaymentComplete`, the host debits **10,000 PvZCoins** (balance 60,310 → 50,310), and the host commits the per-profile Snow Pea plant bit (`plants=0x00000001`) for A. `ConfirmDelivery` follows.
- Verified A snapshot contains one profile's custom host plants mask `0x00000001` and feature mask `0`.
- A's ORIGINAL RTON `UserData/No_Backup/global_save_data` is 190 bytes and contains **`m_unlockedPlants = [21]`**. Element 21 is Snow Pea. The other inspected original global RTON arrays, `m_unlockedGameFeatures`, `m_unlockedMapGates`, `m_unknownSkus`, are **empty**.
- **New timing evidence in the FULL A session log:** at the SAME timestamp as A's synthetic Snow Pea `RequestPayment`, 10k coin debit, `FirePaymentComplete` and V128 sidecar commit, the native guest explicitly **flushes `global_save_data` AND `global_save_data.hash`** via USERFS; `ConfirmDelivery` follows in the next second. The complete B-CLAIM log and separate third B session have NO global-data USERFS flush. Therefore the original global marker was published/serialized as part of the A purchase transaction, NOT as a B claim event. This time correlation directly pinpoints the native original payment/global persistence path as the high-priority intervention site.
- Important remaining limit: we do not have a `global_save_data` copy captured *before* the A purchase, and no instruction-level breakpoint identifies the exact native writer. The post-buy global ID21, native A-time flush and B-time no-flush jointly provide strong source-grounded attribution to A's synthetic purchase, but do not prove which original function added that ID.

## Verified B free CLAIM (second ZIP)

- B's log shows a separate newly selected profile with target host plant and feature masks BOTH zero (`0x00000000`) at account switch and initial store refresh.
- **There is NO custom JNI RequestPayment, purchase commit, FirePaymentComplete, or ConfirmDelivery associated with B's free CLAIM.** Thus the previous v168 owner-pinned payment and v2 receipt parser are orthogonal to the actual FREE CLAIM path and cannot fix it by themselves.
- Near the observed CLAIM action, the same B profile's native premium vector changes from `rawPlants=0x0` to `rawPlants=0x1` while the host sidecar remains `sidecarPlants=0x0`. At the subsequent catalog refresh, existing `OfflineStoreApplyProfileEntitlements` correctly restores the guest vector to `0x0`, and the audit confirms `rawPlants=sidecarPlants=0`. B therefore cannot use the plant after projection.
- B's verified host snapshot still has A `plants=0x1` and B `plants=0x0`; its second profile/loot entries and overall `pp.dat`/`snapshot2.dat` grew as expected. A/B `global_save_data` and its companion hash file are **byte-for-byte identical**: no new global purchase was recorded *by B's CLAIM*.
- Parsing B's same 190-byte original global RTON also yields `m_unlockedPlants=[21]`. The global flag already present after A's purchase is a concrete explanation for B being offered original free cross-profile CLAIM.

## Independent cold-relaunch and re-CLAIM (third log)

- At guest startup, B's **unmodified guest** premium vector is again `rawPlants=0x1` while the loaded V128 B entitlement mask is `0x0`. The first profile-overlay invocation rewrites raw to `0x0`; catalog after-refresh audit verifies zero.
- On a later store refresh after the next user-triggered native CLAIM, B's native raw plants vector AGAIN becomes `0x1` with B sidecar still zero, and the overlay resets it to zero AGAIN. This corroborates the report of repeatable CLAIM but no playable Snow Pea.
- The cold-start native `rawPlants=0x1` combined with a changed binary `pp.dat` and unchanged global RTON is **strong evidence** that original per-profile native save persisted the free claim, even though the host mask overrides it. We have not decoded the internal B field inside `pp.dat`; do not claim exact on-disk byte locations.

## Root cause and why previous v168 work does not fix the real issue

There are TWO conflicting ownership models:

1. Original PvZ2 uses a SHARED global nonconsumable marker; its official EN/FR localizations explicitly promise free CLAIM on other profiles. The actual A/B saves both contain global Snow Pea ID 21, so B's store legitimately offers original CLAIM.
2. Our experimental replacement shop debits profile-LOCAL coins and records a profile-LOCAL V128 right; it projects that sidecar onto the guest's per-profile vectors. A's sidecar=1 and B's sidecar=0 remain correctly isolated. But we currently also call ORIGINAL `FirePaymentComplete` for A's new synthetic purchase; the original game's global purchase/restoration semantics are engaged. When B uses its original free CLAIM, it bypasses our synthetic RequestPayment and never writes B's host sidecar, making the apparent claim unusable. The “persistent” report is about effective **gameplay**, not necessarily the original game's native B save.

**The primary new fix is the source/global publication of synthetic offline ownership**, not just clearing B's vector, checking queued v2 receipts, or hiding a CLAIM string. Original genuine receipts may have EXACTLY the same ten SKU IDs, so blindly removing all global IDs 21 etc. would destroy authentic legacy purchases.

## Narrow grouped implementation requirements

- **Before any new synthetic A purchase**, capture/persist a versioned **legacy global ownership baseline** for the exact canonical six plants/four upgrades; never classify an unknown existing original global bit as synthetic just because its SKU matches one of ten entries.
- **For a new synthetic v2 transaction only**, preserve its initiating profile and host local purchase right, but prevent **NEW synthetic-only additions** from persisting into the original global ownership marker. Test both immediate same-process B store and cold relaunch B store: both should offer B independent BUY, never original CLAIM.
- Do not merely strip `global_save_data` on disk after the native event: the native broker may cache global state in memory during the same session. Recover/validate the live original global object read/write boundary or adapt the store's eligibility decision for custom synthetic provenance, observing original runtime behavior first.
- **Save integrity requirement from actual files:** the original native purchase writes **both** `global_save_data` and `global_save_data.hash` immediately after A payment; both remain identical during B CLAIM. The 24-character uppercase companion hash is NOT the raw-file MD5, SHA-1, or SHA-256 in our current comparison. Never propose a byte-level raw RTON file rewrite or omit native hash regeneration. Prefer an original in-memory GlobalSaveData/provenance intervention and let the original save serializer write BOTH matching files, or establish a separately verified native checksum routine before any file migration. Preserve validated full v165/v166 snapshots atomically.
- Preserve legitimate original purchased global bits on restored historical saves. Because original global RTON has just an ID array and no receipt provenance, ambiguous existing bits require an explicit conservative migration/preservation rule; they are NOT safely distinguishable by ID alone.
- Maintain host sidecar isolation as-is, do not turn B's temporary CLAIM into a real free unlock, and do not charge users through a UI still promising “CLAIM at no cost.” The proper B UI for a new A synthetic-only purchase must show the PvZCoin BUY price.
- Existing v168 staged initiating-profile pin, v2 receipt token/parser and duplicate-charge preflight can remain separate safety work but are **not** fixes for B's free CLAIM path. Avoid shipping an owner-only IPA as if solved.
- **One future grouped build**, only after identifying the live native global owner/eligibility mechanism and preparing targeted event probes across the initial A purchase / B store / B attempt / restart. Do not modify user's validated v165 backups, v166 reset, or external cloud baseline.

## Exact discriminating test matrix (physical iPad)

| Stage | ORIGINAL global Snow Pea | V128 A | V128 B | Expected UI/gameplay after FIX |
|---|---|---|---|---|
| Fresh reset baseline | absent (unless a genuine restored legacy purchase) | 0 | 0 | Both see paid BUY |
| A buys with A's coins | **synthetic must NOT publish globally** | 1 | 0 | A owns/uses; B still sees paid BUY |
| B opens shop without buying | synthetic globally absent | 1 | 0 | B sees paid BUY, no free CLAIM |
| B buys using B's own coins | synthetic globally absent | 1 | 1 | Both independently own/use |
| Cold restart | synthetic globally absent | 1 | 1 | Independent ownership preserved |
| Restored LEGACY authentic global purchase | genuine original bit preserved | any | any | Original genuine cross-profile restore remains available by original design |

**QA wallet pitfall already visible in the THIRD log:** B had only **270 PvZCoins**, versus the 10,000 PvZCoins price of Snow Pea. Therefore a successful next probe must distinguish "B correctly sees BUY" from "B can afford a fresh independent BUY". To test BOTH without modifying the protected A save or automatically granting everyone coins in release builds, use an explicitly QA-gated and profile-targeted temporary ≥10k credit on a disposable B profile, then assert exactly one 10k deduction and B host mask 0→1. This is a planned optional QA facility, NOT yet implemented. Never interpret B's insufficient 270 coins as evidence that the CLAIM patch failed.

**No new iPad test is needed to re-prove the existing failure**: the supplied three real logs and two ZIPs conclusively show the state split and locate the actual global RTON marker. The next request, if any, should concern a SINGLE grouped instrumented/fixed build and preserve external backups.
