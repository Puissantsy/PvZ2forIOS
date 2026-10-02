# KEYOBS — importing an existing save without restarting

This file marks the single grouped build of the isolated KEYOBS restore update after the non-iOS checks passed. The KEYOBS bundle ID is com.puissantsy.pvz2forios.keyobs, separate from production com.puissantsy.pvz2forios. Do not replace the production installation.

1. Obtain a complete v165/v170-style save-... folder containing snapshot-info.plist, UserData and config-v1.txt. Retain the original externally.
2. Update only the separate KEYOBS app with the new unsigned research IPA.
3. Open KEYOBS once to create its Files-visible PvZ2RestoreInbox, then force-quit.
4. Extract your saved ZIP in iPad Files if needed. Copy, never move, the inner save-... folder into On My iPad > PvZ2 Keys Research > PvZ2RestoreInbox. The snapshot-info.plist, UserData and config-v1.txt must be directly inside save-..., not in an extra wrapper directory.
5. Launch KEYOBS; explicitly confirm Restaurer before guest launch. Its original v165 restorer validates every size and SHA-256 before installing anything and backs up existing KEYOBS data if present.
6. Confirm profile, doors and coins, then reproduce one key reward and export KEYOBS logs.

The APK and OBB still need to be imported separately. Original production saves are untouched. Never commit saves or game files to the public repository.

Technical notes: docs/WORLD_KEY_RUNTIME_KEYOBS.md on this research branch.