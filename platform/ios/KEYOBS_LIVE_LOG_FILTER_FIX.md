# KEYOBS live log filter correction — isolated iPad test build

## Original iPad evidence (private log not committed)

- Test: Egypt Day 3 completed, one Egyptian key obtained, then an Egyptian key gate opened.
- Session selected `RESEARCH_WORLD_KEYS_READ_ONLY`, started successfully and wrote the isolated `pp.dat` throughout play.
- The full supplied log contains **no** `KEYOBS READ ONLY installed`, `KEYOBS GRANT_PRE` or `KEYOBS GATE_*` events.
- This is **not** evidence that the game failed to award a key or open the gate: v151 inherits v85's production log filter. Our original instrumentation incorrectly used `Append` (`ProbeLogClass::Legacy`), so all KEYOBS lines were discarded by the Vxx/error allowlist.

## Grouped source fix

- `part_04.inc`: seven award/gate messages use `AppendDiagnostic`, which is retained independently of the production Legacy allowlist.
- `part_08.inc`: initial installation signature also uses `AppendDiagnostic`. Only under this research mode, suppress verbose unrelated `V144 SELECTION DRAW` lines so the user's next log is compact; no runtime graphics behavior is changed.
- `main.mm`: one-time, verified v165 prelaunch snapshot of the existing separate KEYOBS app's current `UserData` and `config-v1.txt`, **after** any explicitly confirmed restore and **before** JIT/guest execution. The user can export this copy to confirm the already-opened gate without replaying Day 3.
- Regression checks in `tools/verify_world_key_probe_wiring.py` and `tools/verify_keyobs_restore_wiring.py` enforce the log channel and the private prelaunch snapshot ordering. Standalone policy and native-event-view tests remain unchanged.
- **No rewards, keys, coins, map events, save hash or nonresearch app data are modified**. Reuse exact separate bundle ID `com.puissantsy.pvz2forios.keyobs`.

## Physical iPad acceptance after the single grouped build

1. Install the corrected IPA **in place over the same KEYOBS research app**. Do not uninstall KEYOBS or restore the older Snow Pea ZIP over the new test progress.
2. On first launch, the host must emit `[KEYOBS SAVE] prelaunch VERIFIED snapshot=save-...` and `[FULLLOAD] KEYOBS READ ONLY installed...`. If either fails, share the complete log before further gameplay.
3. Copy the complete new `On My iPad/PvZ2 Keys Research/PvZ2Backups/save-...-prelaunch-...` directory to external Files/iCloud/PC. Share the backup privately for independent pre/post `W/E/S` and currency verification, NOT via public GitHub.
4. Obtain another **new** Egyptian key through normal progression (not necessarily a Day 3 replay). The log should contain `KEYOBS GRANT_PRE ... world=egypt amount=1` and five gate states. Optionally open another gate for the paired before/after event trace.
5. Key→1,000-coin recycling is **still not active**; this release validates native call provenance before any economy changes.

Offline preflight: isolated GitHub validation https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37064853929 passed all checks. Build triggered only after all grouped fixes.
