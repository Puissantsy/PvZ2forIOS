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
