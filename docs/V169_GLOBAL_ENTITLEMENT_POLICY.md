# v169 — original global entitlement versus new PvZCoin purchase: guarded policy (STAGING ONLY)

**Status: verified STATIC DESIGN, not installed runtime patch, not an IPA.** Base: v168 staged provenance work; physical runtime truth remains the v166 iPad ZIPs and three full logs described in `docs/V169_REAL_SNOWPEA_CLAIM_DIAGNOSIS.md`.

## Correction based on real user evidence

The native original `global_save_data` serializes `m_unlockedPlants=[21]` in BOTH A's purchase and B's free-CLAIM snapshots. Both exact 190-byte files have the same SHA-256 and byte content. A's custom JNI RequestPayment debits A and calls original `FirePaymentComplete`, which is followed by native USERFS writes of **both** `global_save_data` and its proprietary `.hash` in A's full log. B's free original CLAIM uses **no** host RequestPayment, flips B's native raw plant bit from 0 to 1, but never updates B's custom sidecar. Existing per-profile overlay later resets B native raw to 0. On cold launch B raw starts at 1 before host masking, explaining CLAIM repeatability and inaccessible plant in gameplay. Never describe B as having truly usable Snow Pea.

The original EN/FR resource strings explicitly permit global cross-profile CLAIM for authentic purchases. However, our new 10-PvZCoin-SKU replacement shop explicitly requires different local-coin ownership. The ten custom SKU identifiers overlap exactly with the original `MAGENTO.RTON`; therefore product ID alone cannot distinguish synthetic from real historical global entitlements.

## Newly recovered global schema: exact Android ARM instructions

At original `libPVZ2.so` **1.5.252752 ARMv7** schema registration routine, independent property-name literal references immediately precede setting the offsets passed to the original RtDB property registrar (ARM32 `mov r3,#imm`). The verified member offsets in the **schema's GlobalSaveData object** are:

| Name | ARM literal-loading instruction | ARM offset-setting instruction | Schema field offset |
|---|---|---|---:|
| `m_unlockedPlants` | `0x43c3c8` | `0x43c418: e3a03004` | `+4` |
| `m_unlockedGameFeatures` | `0x43c464` | `0x43c4b4: e3a03010` | `+16` |
| `m_unlockedMapGates` | `0x43c4d4` | `0x43c550: e3a0301c` | `+28` |
| `m_unknownSkus` | `0x43c59c` | `0x43c5ec: e3a03028` | `+40` |

Thus all four original properties occupy successive 12-byte slots consistent with ARM32 `std::vector` layouts. **The object instance / global singleton POINTER is NOT established by this schema registration**; applying the offsets to an unverified heap address would corrupt guest memory. All eight exact instruction words are now checked by optional `--apk` mode in `tools/inspect_global_premium_rton.py`. This read-only tool also reports all four typed arrays in known-format original RTON, intentionally rejecting nonempty `m_unknownSkus` until its element type is decoded. Equivalent parsing against the user's actual A/B original 190-byte files independently returned `plants=[21]` with every other inspected array empty and the exact same SHA-256.

## Safe original-rights policy staged NOW

New pure C++20 `platform/ios/src/offline_global_entitlement_policy.hpp`, committed tests `tests/test_offline_global_entitlement_policy.cpp`:

- Input is **verified original legacy baseline** captured BEFORE any NEW synthetic offline transaction can pollute shared global ownership, current original global bits, and separately **verified v2 transaction-published bits**; six plant/four game feature bits are independently processed.
- `SyntheticChangeCanBeRemoved` is returned **only** for original-global new bits absent from legacy baseline AND attributable to a successful new v2 synthetic native payment. The planner never writes guest memory, disk data or host sidecar.
- If original baseline is absent/untrusted, genuine old bit is inexplicably missing, or any new bit lacks matching v2 provenance, return a **PRESERVE/DEFER** decision, not a speculative removal.
- Genuine historical global purchase remains original-global; in addition, effective gameplay projection for each profile should OR the verified historical global mask with that profile's new custom paid sidecar. This avoids the previous v166 overlay mistakenly removing B's genuine ORIGINAL claim.
- Native raw vectors may also include noncatalog IDs: per-category masks and eventual field-specific mutations must leave unrelated IDs untouched. **No raw on-disk rewrite:** `global_save_data.hash` is an original proprietary 24-character hash; the original native serializer must write both files itself.

### Host-side check already performed

An exact-byte copy of the committed `offline_global_entitlement_policy.hpp` was compiled locally using Clang C++20, `-Wall -Wextra -Werror -pedantic`. Its Git **blob SHA-1** matches the GitHub file (`7eba849eb8cd73213d2c7e4b215ef76299f64eaf`). The local compile-time harness passes **10 global delta cases and 4 local gameplay projection cases**, including legacy Snow Pea preservation, new synthetic Snow Pea removal, mixed legacy+synthetic entitlements, missing baseline, unattributed updates, old original bit disappearance, upgrades and unrelated out-of-catalog IDs. The full committed standalone regression suite is in `tests/test_offline_global_entitlement_policy.cpp`.

Independent static examination of the two existing original iPad global RTON blobs confirms the A/B matching four original property arrays; verification of the eight exact schema instruction words also passed on the supplied original APK. Python synthetic RTON parser regression tests in `tests/test_global_save_schema.py` are committed for repeatability. **There is no full iOS compile and no real guest live-object test of this v169 branch yet.**

## What remains before ONE grouped iOS IPA

1. Locate and validate the actual *live* original `GlobalSaveData` instance, and independently trace the original purchased-global update after deferred broker listener `0x49ccf0`; the schema alone is insufficient. Instrument only entry/exit of source-confirmed native changes, not all guest memory per frame.
2. Capture trustworthy untouched ORIGINAL legacy baseline while a user-controlled fresh reset is explicitly established. For older snapshots already containing Snow Pea bit 21 and no previous baseline, **origin is AMBIGUOUS**: preserve it until provenance can be established, never assume it was our synthetic purchase.
3. Apply policy **only when a new, validated synthetic v2 transaction** adds a catalog bit not present in trusted legacy baseline, before same-process profile B store eligibility calculation, and ensure original serializer saves the resulting original-global data together with the correct native `.hash` after successful host sidecar commit. Never prevent native genuine IAP/global rights. If live pointer, transaction status, save order or checksum path is unverified, **defer mutation** and add bounded diagnostics instead.
4. Preserve the original genuine-rights gameplay overlay, profile-local PvZCoin paid BUY on B, and rollback/replay safety after native 56-byte queued event. Do not confuse the native B CLAIM event with JNI synthetic RequestPayment; B claim bypasses the latter in all supplied real logs.
5. iPad acceptance with untouched external baseline: new disposable A buys Snow Pea once for 10k, A can use it; new disposable B sees 10k BUY, NOT CLAIM, and can buy independently after **explicit QA-only profile-targeted credit** (third log showed B had only 270 coins); A and B independent unlocks survive cold restart. A separate **pre-existing authentic original** global Snow Pea save must still allow original cross-profile recovery/playability. No downgrade in v165 external backup/restore, v166 guarded reset and existing first-frame/gameplay probes.

**This branch contains safe policy and verification, not the missing live native hook.** Do not merge into stable v166 or release an IPA until the complete native publisher + in-memory UI + native paired-file persistence is implemented and source/physical tests pass.

## New native breakthrough: verified global getter, global HAS/ADD primitives, and original save route

Extended ARM disassembly of the exact original Android ELF now yields the actual runtime entrypoints, not only serialization member offsets. The original live GlobalSaveData getter is **`0x0043ebd0`**. Original `HasGlobalPlant` at **`0x0043efec`** calls it with `r0=0` and checks the live vector at GlobalSaveData offsets `+4/+8` for the plant ID in input `r0`; it returns boolean `0` or `1`. Original `HasGlobalGameFeature` at **`0x0043f220`** calls the SAME getter with `r0=0`, checks `+16/+20`, and returns the same boolean. This pair is a verified, bounded **read-only** observation interface for global eligibility.

Original `AddGlobalPlant` at **`0x0043eaa4`** calls the getter with `r0=1`, checks the plant list at object offsets `+4/+8/+12`, appends an absent ID, then immediately calls original global serializer **`0x0043ee24`** at `0x0043ebc4`. Original `AddGlobalGameFeature` at **`0x0043f0f4`** similarly uses `+16/+20/+24` and calls original serializer at `0x0043f214`. The original saver at `0x0043ee24` obtains the `global_save_data` filename through `0x0043fadc` at `0x0043ee30`, then uses original native persistence machinery. Real A payment log shows the original game flushes BOTH `global_save_data` and its paired proprietary `.hash` immediately after original synthetic purchase completion. Don't call the saver speculatively or rewrite raw disk RTON.

**Important corrected vector interpretation:** Schema members are 12-byte ARM32 `std::vector<int>` slots and the stored rights IDs are **4-byte integers**. The native search loops are **unrolled four elements per iteration**, which explains their `>>4` and `+16` instructions; fallback code compares the remaining one to three DWORD elements at `+0/+4/+8/+12`, and original `AddGlobalPlant` uses the `std::vector<int>` 4-byte-element growth routine at `0x43ebc0`. DO NOT interpret the loop's 16-byte stride as a 16-byte RtId item, a misreading of optimized unrolling. The current host `OfflineStoreReadTargetMask` already understands the identical scalar DWORD-vector layout, so it can safely read the original global object with **object+4** for plants and **object+16** for upgrades once a valid live guest object pointer has been obtained and bounds checked. It MUST NOT use those offsets on an arbitrary unverified pointer or use profile sidecar masks as a substitute for original global rights.

Full original ARM BL caller map established by scanning every ARM32 direct branch in the reference ELF:

| Primitive | Native entry | Verified direct caller addresses |
|---|---|---|
| `GetGlobalSaveData(create=false/true)` | `0x43ebd0` | `0x43eabc`, `0x43effc`, `0x43f10c`, `0x43f230`, `0x43f334`, `0x43f3b4`, `0x43f3f8`, `0x43f474` |
| `HasGlobalPlant(id)->bool` | `0x43efec` | `0x16154c`, `0x3036f8`, `0x303a8c`, `0x34387c` |
| `HasGlobalGameFeature(id)->bool` | `0x43f220` | `0x16183c`, `0x3037c8`, `0x303b58`, `0x3466c0` |
| `AddGlobalPlant(id)` | `0x43eaa4` | `0x162420`, `0x304dac` |
| `AddGlobalGameFeature(id)` | `0x43f0f4` | `0x162048`, `0x304e8c` |
| `SaveGlobalOriginal()` | `0x43ee24` | `0x43ebc4`, `0x43f214`, `0x43f39c`, `0x43f460`, `0x43f73c` |

Nearby native caller sets (`0x161xxx`, `0x303xxx/0x304xxx`, `0x343xxx`) appear across purchase/reward/UI flows and have NOT been proved exclusive to the new synthetic `FirePaymentComplete` or exclusive to B free CLAIM. **Never patch these primitive functions globally** or globally change `HasGlobalPlant(21)` to false: that would break genuine original same-SKU entitlements. Use the now verified read-only global HAS functions as event-only probes around the known host synthetic `RequestPayment`/deferred broker and profile-switch catalog refresh. Observed `HasGlobalPlant(21)` before A synthetic payment vs after event flush distinguishes exact live eligibility. For future NEW verified v2-only global additions, the planner can propose a scoped removal in live guest DWORD vector and the ORIGINAL saver, but only after confirming caller/event timing, baseline trust and transactional rollback; original authentic global IDs remain intact.

**No runtime hook/build yet:** this is static verification of named-behavior inference from actual control flow. The profile-select-sensitive native callsite driving the UI BUY-versus-CLAIM remains to be connected to an exact original UI action. The original global primitives above provide a much safer path to that final proof than generic `RtDb` helper patches.
