#!/usr/bin/env python3
from pathlib import Path
main=Path('platform/ios/src/main.mm').read_text()
cmake=Path('platform/ios/CMakeLists.txt').read_text()
plist=Path('platform/ios/Info.plist.in').read_text()
adapter=Path('platform/ios/src/keyconv_prelaunch_ios_adapter.mm').read_text()
workflow=Path('.github/workflows/build-ios-probe.yml').read_text()
tests={
 'Probe identity preserved': '<string>com.puissantsy.pvz2forios</string>' in plist and 'PvZ2forIOS Probe' in plist,
 'No KEYOBS id in Probe plist': 'com.puissantsy.pvz2forios.keyobs' not in plist,
 'Separate signed Probe marker': 'PVZ2KeyconvProbeBuild' in plist and 'PVZ2KeyconvOriginalIdentifier' in plist,
 'Adapter build gate': 'PVZ2_KEYCONV_PROBE_BUILD=1' in cmake and 'PVZ2_KEYCONV_PROBE_BUILD' in adapter,
 'Lab never shipped': 'keyconv_disposable_lab_ios_adapter.mm' not in cmake,
 'Recovery before restore': main.index('PVZKeyconvRecoverBeforeRestore(') < main.index('if (!self.v163RestorePromptShown) [self v163OfferPendingRestore]'),
 'JIT before settlement': main.index('if (!IsDebugged()) {\n        [self v130RequestJIT];') < main.index('PVZKeyconvSettleAllEligible('),
 'Opt-in before mutation': main.index('PVZKeyconvAutoResearchRequested(') < main.index('PVZKeyconvSettleAllEligible('),
 'Backup before mutation': main.index('PVZSaveCreateSnapshot(@"prelaunch",&backupError)') < main.index('PVZKeyconvSettleAllEligible('),
 'Explicit read-only bypass': 'READONLY_BYPASS_ACCEPTED no_conversion=YES' in main and 'migrationError.code==2' in main,
 'Fail closed transaction': 'TRANSACTION_OR_FILE_FAILURE fail_closed=YES' in main,
 'Probe-only token': 'PvZ2ProbeKeyconvRequest.txt' in adapter and 'ENABLE_EGYPT_AUTOMATIC_KEYCONV_PROBE_V1' in adapter,
 'No automatic IPA build': 'branches: [integration/probe-keyconv-egypt]' in workflow and 'platform/ios/.probe-keyconv-build-request' in workflow,
 'Stable old v170 reset flow': 'v166OfferResetIntro' in main and 'PVZSaveResetForTest' in main,
 'Existing v170 store controls': 'v164PresentBackupMenu' in main
}
cpp=Path('platform/ios/src/pvz2_apk_probe.cpp').read_text()
parts=[Path(f'platform/ios/src/pvz2_apk_probe_parts/part_{i:02d}.inc').read_text() for i in range(10)]
tests.update({
 'Original V151 mode selected': 'PvZ2DiagnosticMode::V151ProductionQsortCompat' in parts[0] and 'kSelectableDiagnosticModes[]' in parts[0],
 'Opt-in passed to live runtime': 'keyconv_egypt_reward_opt_in' in Path('platform/ios/src/pvz2_apk_probe.hpp').read_text() and 'self.keyconvRewardOptIn == YES' in main,
 'Single exact ELF site trapped': '0x0042ccd0u,0xe1a0a000u,kJniProbeSvcWorldKeyAddObserve' in parts[8],
 'No research-mode replacement': 'ResearchWorldKeyConvert' not in parts[0],
 'Egypt-only reward policy': 'world=="egypt" && decision.convert()' in parts[4],
 'Bounded native gate event decoder': '#include "world_key_event_view.hpp"' in cpp,
 'Read-only incompatible state disables live hook': 'self.keyconvRewardOptIn=NO;' in main,
 'Opt-in before live interception': 'self.keyconvRewardOptIn=self.keyconvRecoveryWasClean' in main,
})
for label,ok in tests.items():
 print(('PASS' if ok else 'FAIL')+': '+label)
assert all(tests.values()),'Unsafe/incomplete Probe KEYCONV integration'
