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
assert location("PVZSaveRestoreSnapshot(snapshot,&restoreError)") < location('PVZSaveCreateSnapshot(')
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
info=(root/"platform/ios/Info.plist.in").read_text()
policy=(root/"tests/staging/keyconv_research_identity_policy.hpp").read_text()
assert "com.puissantsy.pvz2forios.keyobs" in adapter
assert "PVZ2KeyconvResearchBuild" in info
assert "PVZ2KeyconvOriginalIdentifier" in info
assert "PVZ2KeyconvResearchBuild" in adapter
assert "PVZ2_KEYCONV_RESEARCH_BUILD=1" in cmake
assert 'Evaluate(' in adapter and 'Result::Allowed' in adapter
assert "ProductionIdentifier" in policy
assert "CFBundleIdentifier" in info
assert "native::Recover(root,true)" in adapter
assert "native::Settle(root," in adapter
assert "if (!ResearchBundle())" in adapter
assert "PVZKeyconvEligibleSlots" in adapter
assert not (root/"platform/ios/src/world_key_prelaunch_native.hpp").exists()
# The crash test is opt-in through a Files-visible exact request, never
# triggered by the normal launcher or by automatic recovery.
lab_bridge=(root/"platform/ios/src/keyconv_disposable_lab_ios_adapter.mm").read_text()
lab_core=(root/"tests/staging/keyconv_disposable_crash_lab.hpp").read_text()
request=(root/"tools/PvZ2CrashLabRequest.txt").read_text()
assert request=="ENABLE_PVZ2_KEYCONV_DISPOSABLE_LAB_V1\n"
assert "keyconv_disposable_lab_ios_adapter.mm" in cmake
assert "PVZKeyconvLabRecoverOnLaunch(&labError)" in launch
assert "PVZKeyconvLabHasExplicitRequest(&requestError)" in launch
assert location("PVZKeyconvLabRecoverOnLaunch(&labError)") < location("PVZKeyconvRecoverBeforeRestore(&recoveryError)")
assert location("PVZKeyconvLabHasExplicitRequest(&requestError)") < location("PVZSavePendingRestores()")
assert "self.keyconvLabPromptActive" in launch
assert "self.keyconvLabStartupNote.length" in main
assert main.count("PVZKeyconvLabKillOnlySynthetic(")==1
assert main.index("PVZKeyconvLabKillOnlySynthetic(") < main.index("- (void)v130ContinueLaunch {")
assert "v130KeyconvLabConfirmCrash" in main
assert "PVZKeyconvLabConfirmationPhrase()" in main
assert "UIAlertActionStyleDestructive" in main
assert "PVZKeyconvLabHasExplicitRequest" in lab_bridge
assert "PvZ2CrashLabRequest.txt" in lab_bridge
assert "tx::ReadRegular(request,128)" in lab_bridge
assert "typedConfirmation" in lab_bridge
assert "PVZKeyconvResearchIdentityIsAllowed()" in lab_bridge
assert "PVZ2_KEYCONV_RESEARCH_BUILD" in lab_bridge
assert "Root(const fs::path& support)" in lab_core
assert "tx::Working(root)/\"pp.dat\"" in lab_core
assert 'Directory=".pvz2-keyconv-disposable-lab"' in lab_core
assert "UserData" in lab_core and "No_Backup" in lab_core
assert "LAB_SYNTHETIC_RTON_V1_ONLY" in lab_core
assert "USER_CONFIRMED_SYNTHETIC_CRASH" in lab_core
assert "RecoverAndVerify" in lab_core
assert "PrepareOrRearm" in lab_core
assert "lab::PrepareOrRearm(SupportPath())" in lab_bridge
assert "REARMED_VERIFIED_OLD_OLD" in lab_core
assert "RECOVERY_ROLLED_BACK" in lab_core
assert "lab::Prepare(SupportPath())" not in lab_bridge
print("PASS: KEYCONV live-save startup gates and opt-in Files request + typed fake-RTON SIGKILL lab verified")
