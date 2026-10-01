# v165 — fix verified backup inventory and expose precise failures

## Evidence from real v164 iPad log

Uploaded probe dated 2026-10-01 10:46:31 UTC shows `[V164 SAVE MENU] user confirmed safe stop`, `V151 HARD STOP frame=5683` and `V90 TERMINAL reason=user-hard-stop`. Guest progression was loaded from the current production `Library/Application Support/PvZ2forIOS/UserData/No_Backup` tree and there were regular V128 USERFS flushes. At the very end: `[V163 SAVE] poststop skipped/failed: Unsafe path or too many save files`.

**Fact:** Guest stop succeeded and the exporter failed in save tree inventory; this is not a guest persistence failure. In v164 source `Inventory` combines two unrelated cases (`!IsSafeRelativePath(relative)` or `files.count >= 512`) into one generic error. The log alone cannot tell which of these cases occurred. Existing multi-profile/QA folders are one plausible source of excessive file count, but this remains a hypothesis until the next full log.

## Grouped changes

- `platform/ios/src/save_backups.mm`: increase per-snapshot file count from 512 to 16,384 while preserving existing **64 MiB per-file**, **128 MiB per-snapshot**, SHA-256 inventory, no traversal/symlink and atomic publication restrictions. Avoid weakening path safety.
- Separate diagnostics for escaping root, unsafe relative path, and legitimate file-count overflow. Include affected root and count or relative path in the error message. Validate manifest root element types and retain bounded max 128 distinct roots.
- `platform/ios/src/main.mm`: save and re-emit the *prelaunch* automatic snapshot result after the diagnostic logger resets on launch. On success, log snapshot basename and manifest root/file counts; on failure, expose the exact reason in the post-stop `⋯` menu instead of implying success.
- Preserve existing v162 CLAIM diagnostics, v163 snapshots/restore, v164 host `⋯` stop menu and guest runtime behavior without modification.

## iPad acceptance

1. **Update in place** without uninstalling current v164; do not delete `test`/`test2` or their progression.
2. On boot, do not assume an automatic prelaunch snapshot is valid until `[V163 SAVE] prelaunch SUCCESS` appears with nonzero roots/files.
3. Tap the v164 upper-left `⋯` → `Sauvegarder et arrêter`. Confirm that the poststop menu now reports success or the **exact** error. Copy the full log.
4. In Files → On My iPad → PvZ2forIOS Probe → PvZ2Backups, confirm at least one complete `save-...` snapshot, with `snapshot-info.plist`, `config-v1.txt` when present, and `UserData` / `UserData-*` trees.
5. Copy the **entire** snapshot folder into iCloud Drive or a PC; confirm it exists outside the app's sandbox.
6. Only with an optional disposable profile, copy the external snapshot back to `PvZ2RestoreInbox`, confirm explicit restore and check profile/progression/premium isolation. Never uninstall until this full round trip succeeds.

Recovery if v165 still fails: its new error identifies which limit/path is responsible. Do not strip safety checks or discard old QA folders blindly.

CLAIM store bug is independent, tracked by PR #7; a verified portable snapshot is the immediate priority.
