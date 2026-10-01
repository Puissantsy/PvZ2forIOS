# v164 — Accessible Save & Stop, verified portable saves

The production UI had hidden the old UIKit Stop button. v163 implemented verified snapshots, but the user could not request the poststop snapshot. v164 restores an unobtrusive 44×36 pt upper-left ellipsis (⋯) host button and retains all v163 backup work.

## Gameplay controls

- Tap the upper-left ⋯ during play and select **Sauvegarder et arrêter**.
- The existing PvZ2RequestInteractiveStop() requests a guest stop. The button is disabled while stopping. The v163 poststop snapshot only runs once the guest execution has ended.
- After stopping, tap ⋯ to **Copier le journal** or **Fermer**.
- During gameplay, the same menu offers **Copier le journal** without stopping and **Continuer à jouer**.
- The old four-finger triple-tap diagnostics copy gesture is unchanged.

## Real durability

v163/v164 snapshot all existing UserData and UserData-* save roots together with config-v1.txt, including per-profile premium purchase records. Copies are SHA-256 verified, timestamped, and staged locally in Files > On My iPad > PvZ2forIOS Probe > PvZ2Backups. The automatic rotation retains the newest twelve local snapshots. Never confuse local On My iPad staging with an external backup: copy an entire save-... folder to iCloud Drive or a PC while the app is installed.

To restore, copy a complete external snapshot folder into Files > On My iPad > PvZ2forIOS Probe > PvZ2RestoreInbox while the game is stopped. At the next launch, explicitly confirm. Before replacing live saves the app checks all files and prepares a separate verified safety snapshot; a cancelled restore leaves current data untouched. APK and OBB are intentionally not part of a save snapshot.

## First real iPad test

1. Update in place to v164; DO NOT uninstall the app or remove profiles.
2. Open test and test2, then tap ⋯. Verify the menu appears and gameplay still works.
3. Tap Sauvegarder et arrêter. Once stopped, use ⋯ to copy the complete log and close.
4. Check local PvZ2Backups for a save-... folder with snapshot-info.plist, config-v1.txt and UserData roots. Copy the full folder to external iCloud Drive or PC, then verify it is really present there.
5. Test restoration only with a disposable profile after a successful external copy; check all save data and purchases after reopening. A successful compile alone is not a successful backup test.
6. Share the full v164 log, focusing on [V164 SAVE MENU], [V163 SAVE], and V128 USERFS. Resume the CLAIM investigation only after a verified external-backup/restore round trip.

Source docs: https://github.com/Puissantsy/PvZ2forIOS/blob/v163-external-save-backups/docs/V163_EXTERNAL_SAVE_BACKUPS.md
v162 CLAIM investigation: https://github.com/Puissantsy/PvZ2forIOS/pull/7


## v165 correction after first real v164 iPad run

At 10:12:15 UTC in the user's 2026-10-01 v164 log, the ellipsis menu requested a safe stop, guest Hard Stop completed at frame 5683, and only the backup exporter failed: `Unsafe path or too many save files`. The old error combined invalid path with an arbitrary 512-file inventory ceiling. The exact triggering condition cannot be recovered from v164's ambiguous log.

v165 supports up to 16,384 files while retaining the 64 MiB per-file and 128 MiB total snapshot limits. It computes each relative path using canonical paths under its own UserData root (handling iOS /var and /private/var aliases), refuses any escape/symlink, and emits distinct, actionable path/count errors. The prelaunch snapshot outcome is now retained after the diagnostic logger reset. A successful snapshot logs its root and file counts; the poststop ellipsis menu displays success or the exact failure instead of a generic possibly-successful description.

**Update the app in place.** Tap ⋯ → Sauvegarder et arrêter, then open the same menu to read the outcome. If it says SUCCESS, confirm a complete `save-...` folder under Files → On My iPad → PvZ2forIOS Probe → PvZ2Backups. Copy the entire folder externally to iCloud Drive or PC and verify the external copy before trying a restore on a disposable profile. If it fails, supply the full v165 log: its new message should pinpoint which path or limit caused the failure. Never uninstall before export AND restore were verified on the real iPad.

Detailed diagnosis: https://github.com/Puissantsy/PvZ2forIOS/blob/v165-save-inventory-recovery/docs/V165_SAVE_INVENTORY_RECOVERY.md
