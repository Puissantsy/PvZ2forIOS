# v170 — disposable iPad A/B acceptance (do not use original baseline)

**State:** grouped source integrated, iOS native build requested. No real iPad fix verified. Real previous bug was: A buys Snow Pea for 10,000 PvZCoins, guest writes original global ID 21; B sees free CLAIM but local V128 sidecar=0 and cannot play Snow Pea. Preserve unknown original historic same-SKU bits.

## 0. Safety / installation

1. Verify the **entire** original v165 `save-...` folder is already copied and opens in **iCloud Drive or PC outside the app sandbox**. A folder inside Files > On My iPad > PvZ2forIOS Probe is NOT uninstall-proof. Do **not** delete/uninstall the app.
2. Install the v170 unsigned IPA **in place** only after GitHub build and checksum inspection. An unsigned artifact still needs the user's normal iPad sideload/signing setup.
3. For reproducible ownership attribution, select the **explicit v166 protected fresh test reset**, not either supplied A/B snapshot already contaminated with `global_save_data.m_unlockedPlants=[21]`. First use `⋯ → Sauvegarder et arrêter`, make sure poststop snapshot worked, reset and ensure `PvZ2ProtectedResets/save-...` contains a verified copy. Fully quit and relaunch. Imported APK/OBB are not reset.

## 1. First synthetic A payment

- Create disposable A and B, confirm distinct native profile IDs. A should obtain the existing v128 one-time initial 60k floor; B need not have 10k yet.
- **Before A BUY**, confirm no global original Snow Pea (ID21) is present. If the new v170 full-vector preflight refuses a first purchase, capture log; DO NOT bypass the preflight or keep repeatedly tapping.
- On A buy Snow Pea 10,000 PvZCoins exactly once. Expected: full-vector BEFORE journal checkpoint precedes debit/native FirePaymentComplete; owner/token match in deferred ConfirmDelivery and paid V128 sidecar. V170 exact full-vector decision must be synthetic-only. Compact/readback and ORIGINAL native saver should produce `V170 GLOBAL CLEANUP SAVED`. Both global original RTON and `.hash` fingerprints must have changed with zero new USERFS failures. A's native premium plant mask and persisted sidecar bit0 remain 1, A's wallet decreases by 10k.
- If `V170 GLOBAL CLEANUP SAVED` is absent, or there is a journal/checkpoint/saver error, **stop the experiment** and export full log. Do not assume a visual shop refresh means ownership is correct. Native saver ambiguity may require restoring only the protected disposable baseline.

## 2. Independent B ownership in the SAME process

- Switch to B and fully open the store. **Snow Pea must offer a paid 10,000 PvZCoins BUY**, not the original free CLAIM. B sidecar and playable native premium mask should remain 0 before its own purchase. A's bit remains 1.
- While B is still selected, open `⋯ → Crédit PvZCoins de test (profil actif)…`; confirm **only on a disposable B**. At the next guest boundary expect `V170 QA CREDIT explicit one-time profileId=<B>` and B wallet floor to 60k, without crediting A. A second click and a cold restart must not grant again. If the log shows A's ID or an unresolved transaction, stop instead of proceeding.
- B buys Snow Pea for its own 10k. Expect its separate exact token and locally persisted sidecar bit0=1; then open an actual level, select/plant Snow Pea and confirm it is usable. Verify B spent 10k once, without charging A.

## 3. Cross-restart check / restoration

- Use `⋯ → Sauvegarder et arrêter` and export the **full log** before testing a clean cold app launch. Confirm A/B profiles persist. B must retain its purchased playable Snow Pea; A must remain independently owned. If B was inspected before buying, the cold-launch shop must continue to show independent BUY, never a resurrected CLAIM.
- Confirm the v170 monotonic v2 receipt serial persists and both original global premium masks stay free of NEW synthetic-only bits. The one-time original 60k grant and explicit B grant must not silently re-run.
- After QA, restore the complete external original reference via the already tested guarded `PvZ2RestoreInbox` procedure. If you encounter any partial/ambiguous native save state, keep the disposable backup, don't experiment on the original reference.

## 4. What evidence to supply

A complete probe log for the A buy/B store/B buy session and the cold-launch session, exact screenshot or description of B's BUY/CLAIM and A/B playable plant status, observed balances before/after, and iOS `.ips` if it crashes. Useful markers: `V170 GLOBAL TXN`, `V170 GLOBAL EXACT`, `V170 GLOBAL CLEANUP SAVED`, `V170 QA CREDIT`, `OFFLINE STORE PROFILE`, `V128 USERFS`, `V163 SAVE`.

All 10 SKU mappings passed isolated C++ tests, **not all 10 real-iPad purchases**. Original old EA same-SKU purchase sharing must be tested separately with a verified protected legacy baseline and must **never** be inferred merely from a preexisting global plain-ID bit. Do not merge the draft PR or mark the CLAIM bug fixed on compiler success alone.
