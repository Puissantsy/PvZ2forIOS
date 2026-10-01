# v162 — Offline-store CLAIM / per-profile provenance

## Baseline (2026-10-01)

Base: main @ ab5f2de2bf2ad07d0259549814db322827172587.
The prior patch scopes six plant and four upgrade entitlement IDs to the V128
sidecar keyed by local profile ID. The original guest still writes
`global_save_data` and `local_profiles` during a normal session.

**iPad observation:** Squash, Snow Pea and Jalapeño may display CLAIM on
another, otherwise fresh, account. A displayed CLAIM is not proof that
the other account has the plant entitlement or can redeem it.

**Instrumentation gap:** the V85/V86 production log filter discarded regular
`OFFLINE STORE ...` lines (including migration, profile overlay,
catalog refresh and purchase callbacks). Absence of those lines in the
2026-10-01 probe log did not establish that these paths were inactive.

## Batched v162 changes

- `part_02.inc`: whitelist event-driven OFFLINE STORE log lines in
  production; no per-frame register/guest-memory dump.
- `part_01.inc`: audit premium vector masks before and after the
  profile-specific overlay. Validate the written vectors, preserving
  unrelated plant/feature IDs and the existing purchase sidecar.
- `part_09.inc`: log a bounded sample of invalid current-profile
  resolutions. Audit native vs V128 premium masks immediately before
  and after native FireDidRefresh. If an already-tracked profile's native
  premium vectors were overwritten from the shared save, restore only
  its known premium IDs *before* the catalog is refreshed.

**Not yet claimed fixed:** PvZ2 may have a separate global
purchase/catalog/CLAIM status independent of both native profile vectors
and the V128 sidecar. This build observes native vector state at the
broker refresh boundary; it does not blindly overwrite global_save_data,
forge purchase responses or change button text.

## Expected log markers

- `OFFLINE STORE PROFILE BEFORE id=... migration=... rawPlants=... targetPlants=...`
- `OFFLINE STORE PROFILE APPLY id=... plantsMask=... featuresMask=...`
- `OFFLINE STORE CATALOG AUDIT event=before-refresh ... rawPlants=... sidecarPlants=...`
- `OFFLINE STORE CATALOG restoring native premium vectors ...` (only on divergence)
- `OFFLINE STORE CATALOG AUDIT event=after-refresh ...`
- `OFFLINE STORE purchase commit profileId=... sku=... coinsBefore=... coinsAfter=...`
- `OFFLINE STORE PROFILE PURCHASE id=... sku=... mask=...`
- `OFFLINE STORE PROFILE RESOLVE unavailable ...` (max six samples)

If raw and sidecar masks are both zero for account B at
`after-refresh` yet CLAIM remains visible, the next patch must
target the *separate* native purchase-status/CLAIM query; changing
the premium vectors or painting BUY on top would be insufficient.

## One-build QA (real iPad)

1. Preserve an app-data backup if important. Avoid deleting existing
   valid profiles; use new accounts for this controlled experiment.
2. Open account A, buy Snow Pea, Squash, Jalapeño with PvZCoins.
   Capture the coins before/after and the resulting entitlement state.
3. Switch to a newly created account B and open the premium plants shop.
   Record BUY/CLAIM for each of those three items *before tapping CLAIM*.
4. If a surprise CLAIM is visible on B, do not redeem it until screenshot
   and Hard Stop log have been saved. If deliberately testing redemption,
   separately note whether B really obtains the plant at zero cost.
5. Restart the app. Check account A still owns all three, B does not
   inherit them and each profile retains its own coin balance.
6. Provide the full v162 probe log and any unexpected visual behavior.
   Compare BEFORE/APPLY/before-refresh/after-refresh by profile ID.

A successful GitHub Actions build checks compilation and packaging only;
cross-account shop behavior must be confirmed on the real iPad.
