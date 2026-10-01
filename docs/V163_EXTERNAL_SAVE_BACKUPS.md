# v163 — Safeguarded external save backups (iPad)

## Confirmed storage layout / why earlier profiles can reappear

The V128 guest USERFS mapping stores persistent game data in the application's **private** iOS container:

- \`Library/Application Support/PvZ2forIOS/UserData/\` — current production save tree.
- Existing diagnostic runs may have also used \`UserData-QA-Keyboard-TestProfiles-v2/\` — the 2026-10-01 v151 log shows this exact QA path. It is separate from production. The return of earlier \`test\` / \`test2\` profiles on v162 is consistent with switching trees; this is a **hypothesis until the v162 log is checked**.
- \`Library/Application Support/PvZ2forIOS/config-v1.txt\` — host-side configuration, including offline premium per-profile masks. **Never back up profiles without this file**.

This is **not external** merely because an IPA update can preserve it. Uninstalling the app can delete its data container.

## Implemented on v163 branch

Files: \`platform/ios/src/save_backups.mm\`, \`save_backups.hpp\`, \`main.mm\`, \`CMakeLists.txt\`.

- Save before guest launch and after completed guest run / Hard Stop. Do not snapshot during active gameplay.
- Capture \`config-v1.txt\` and **every existing** \`UserData\` / \`UserData-*\` root without combining test and production saves.
- Keep each date-stamped copy in app \`Documents/PvZ2Backups/save-.../\`; Apple Files exposes Documents because \`UIFileSharingEnabled\` and \`LSSupportsOpeningDocumentsInPlace\` already exist in Info.plist.
- Each snapshot carries \`snapshot-info.plist\` containing root names and every file's size and SHA-256. The copy is hashed and compared with the source, verified before publication, and local snapshots rotate after 12 copies.
- **External durability requires a user action:** use Files to copy a full snapshot folder from "On My iPad > PvZ2forIOS Probe > PvZ2Backups" to **iCloud Drive**, a connected external drive or a PC. Local Files is only staging; it can be deleted with the app.
- Explicit offline restore: while the app is fully stopped, copy that same complete snapshot folder into "On My iPad > PvZ2forIOS Probe > PvZ2RestoreInbox", relaunch, and confirm the **Restore** prompt. Restore verifies every file and refuses symlinks, path traversal, unsupported roots and mismatching SHA-256 before any live mutation. A separate pre-restore safety snapshot is created and directory moves retain rollback data on failure. Cancel keeps the current game.
- The restore inbox copy is renamed \`Restored-...\` after success so it does not prompt on every launch.

Neither the APK nor OBB is exported: these remain user-provided and can be reimported on a fresh installation. The live runtime/guest layout is unchanged.

## Acceptance tests: REAL iPad only

1. Install/update v163 **without deleting current app data**.
2. Confirm game boots and previous progression exists. Hard Stop.
3. In Files, locate \`PvZ2Backups\`; inspect a complete \`save-...\` folder (manifest, \`config-v1.txt\`, save tree(s)). Copy the entire folder to iCloud Drive and **verify it appears there**. Do not uninstall yet.
4. Test a harmless change in a disposable profile, Hard Stop and save again.
5. For an isolated restore test, copy the chosen snapshot back to \`PvZ2RestoreInbox\`, force close, reopen, accept Restore and confirm the same profile and coin/premium ownership returned.
6. Export complete runtime logs with lines \`[V163 SAVE]\` and relevant \`V128 USERFS\` paths. Do not declare backup/restore validated until successful iPad round trip.

## Scope and limitations

- The automatic copies are LOCAL safety copies, not cloud sync or live autosaving; user must copy them outside the app to survive uninstall.
- Only profiles plus config are included, not cache, logs, APK/OBB or game assets.
- Restoring a snapshot resets the complete saved state from that date (including all included production and QA trees and premium sidecar), not just one profile.
- Never uninstall the current installation or delete \`test\`/\`test2\` before a successful external export AND verified restore on iPad.
- This release does not fix the separate "CLAIM" shop bug. Keep PR #7 open; use the new backup facility to make that experiment reversible.
