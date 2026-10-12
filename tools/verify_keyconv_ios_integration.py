#!/usr/bin/env python3
"""Check isolated KEYCONV startup order and opt-in code paths (no IPA)."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/"platform/ios/src/main.mm").read_text()
cmake=(root/"platform/ios/CMakeLists.txt").read_text()
adapter=(root/"platform/ios/src/keyconv_prelaunch_ios_adapter.mm").read_text()
start=main.index("- (void)v130ContinueLaunch {")
end=main.index("\n- (void)appendUI:",start)
launch=main[start:end]
def location(snippet):
    assert snippet in launch, snippet
    return launch.index(snippet)
assert location("PVZKeyconvRecoverBeforeRestore(&recoveryError)") < location("PVZSavePendingRestores()")
assert location("PVZSaveRestoreSnapshot(snapshot, &restoreError)") < location('PVZSaveCreateSnapshot(')
assert location("PVZSaveCreateSnapshot(") < location("PVZKeyconvEligibleSlots(&previewError)")
assert location("PVZKeyconvEligibleSlots(&previewError)") < location("PVZKeyconvSettleSelectedSlot(")
assert location("PVZKeyconvSettleSelectedSlot(") < location("[self v130StartStoredRuntime]")
assert "self.keyconvPrelaunchBackupVerified = YES" in launch
assert "self.keyconvRecoveryWasClean &&" in launch
assert "strongSelf.jniRunning ||" in launch
assert "v130KeyconvStopLaunch" in launch
assert "self.keyconvFatalBlocked" in launch
assert "style:UIAlertActionStyleCancel" in launch
assert "self.keyconvStartupNote.length" in main
assert "keyconv_prelaunch_ios_adapter.mm" in cmake
assert "tests/staging" in cmake
assert "com.puissantsy.pvz2forios.keyobs" in adapter
assert "native::Recover(root,true)" in adapter
assert "native::Settle(root," in adapter
assert "if (!ResearchBundle())" in adapter
assert "PVZKeyconvEligibleSlots" in adapter
assert not (root/"platform/ios/src/world_key_prelaunch_native.hpp").exists()
print("PASS: recovery-before-restore, verified backup, explicit profile opt-in, fail-closed guest barrier, retained log")
