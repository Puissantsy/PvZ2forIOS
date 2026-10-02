#!/usr/bin/env python3
"""KEYOBS isolated save-restore source invariants; no private saves, no IPA."""
from pathlib import Path

root=Path(__file__).resolve().parents[1]
main=(root/"platform/ios/src/main.mm").read_text()
engine=(root/"platform/ios/src/save_backups.mm").read_text()
header=(root/"platform/ios/src/save_backups.hpp").read_text()
cmake=(root/"platform/ios/CMakeLists.txt").read_text()
plist=(root/"platform/ios/Info.plist.in").read_text()

def check(condition, label):
    if not condition: raise AssertionError(label)

check('#include "save_backups.hpp"' in main, "restore API missing")
check("src/save_backups.mm" in cmake, "restore engine not compiled")
check("com.puissantsy.pvz2forios.keyobs" in cmake and
      "com.puissantsy.pvz2forios.keyobs" in plist, "restore would collide with production app")
check("<key>UIFileSharingEnabled</key>" in plist and
      "<key>LSSupportsOpeningDocumentsInPlace</key>" in plist,
      "restore inbox not exposed via Files")
check("PVZSavePendingRestores" in header and "PVZSaveRestoreSnapshot" in header,
      "missing existing v165 safe API")
check('static NSString *const kManifest = @"snapshot-info.plist"' in engine,
      "missing versioned snapshot manifest")
check('@"pvz2forios-save-v1"' in engine and "ValidateSnapshot(snapshot, &manifest, error)" in engine,
      "restore must validate exact snapshot")
check('kMaxSaveFiles = 16384u' in engine and
      'CC_SHA256' in engine and 'IsSafeRelativePath(relative)' in engine,
      "v165 inventory/hash/path protections missing")
check('PVZSaveCreateSnapshot(@"prerestore", error)' in engine,
      "must protect any existing KEYOBS progression before replacement")
check("PVZSavePendingRestores();" in main and
      "BOOL keyobsRestoreChecked;" in main and
      "BOOL keyobsRestorePromptActive;" in main,
      "inbox and startup guard missing")
start=main.index("- (void)v130ContinueLaunch {")
end=main.index("- (void)appendUI:",start)
prelaunch=main[start:end]
check(prelaunch.index("PVZSavePendingRestores()") <
      prelaunch.index("if (!V130RuntimeInstalled())") <
      prelaunch.index("if (!IsDebugged())"),
      "restore must precede APK/JIT/guest launch")
check('@"Restaurer"' in prelaunch and '@"Ignorer"' in prelaunch,
      "restore must be explicit, with cancel")
check("PVZSaveRestoreSnapshot(snapshot,&restoreError)" in prelaunch,
      "not using verified engine")
check("strongSelf.keyobsRestorePromptActive=NO;" in prelaunch,
      "startup must be released after accepted or declined")
check("Restauration refusée" in prelaunch and
      "ne démarrera pas automatiquement" in prelaunch,
      "restore failure should block guest startup")
# After the first iPad run already consumed a key/opened a gate, the
# in-place log-channel update must preserve that current profile BEFORE any
# other guest execution, with a verified local v165 prelaunch snapshot.
check("BOOL keyobsPrelaunchSnapshotTaken;" in main,
      "missing once-per-launch save evidence guard")
check("PVZSaveHasLocalSave()" in prelaunch and
      'PVZSaveCreateSnapshot(\n                @"prelaunch", &snapshotError)' in prelaunch,
      "current KEYOBS save must be snapshotted with v165 engine")
check(prelaunch.index("PVZSavePendingRestores()") <
      prelaunch.index("PVZSaveCreateSnapshot(") <
      prelaunch.index("if (!V130RuntimeInstalled())"),
      "current-state snapshot must follow any user-confirmed restore, before JIT")
check('[KEYOBS SAVE] prelaunch VERIFIED' in prelaunch and
      '[KEYOBS SAVE] prelaunch FAILED' in prelaunch,
      "must explicitly report verified snapshot or actionable failure")
print("PASS: isolated KEYOBS app, v165 manifest/hash/bounds, explicit pre-JIT restore and fail-closed launch")
