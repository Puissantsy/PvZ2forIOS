#!/usr/bin/env python3
"""Prevent accidental production/KEYOBS replacement by the v170 QA app."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
plist=(root/"platform/ios/Info.plist.in").read_text()
cmake=(root/"platform/ios/CMakeLists.txt").read_text()
launcher=(root/"platform/ios/src/main.mm").read_text()
build=(root/".github/workflows/build-ios-probe.yml").read_text()
assert "<string>PvZ2 Store QA</string>" in plist
assert "<string>com.puissantsy.pvz2forios.storeqa</string>" in plist
assert "PVZ2StoreQAResearchBuild" in plist
assert "PVZ2StoreQAOriginalIdentifier" in plist
assert 'XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.puissantsy.pvz2forios.storeqa"' in cmake
assert "PVZ2_DYNARMIC_SOURCE_DIR" in cmake
assert "https://github.com/LiveContainer/dynarmic.git" not in cmake
assert "research/offline-store-qa" in build
assert "platform/ios/.storeqa-build-request" in build
assert "c97c525ec1432b1e5404ebf091027738005ec168" in build
assert "fd5b3ab282948fcdacc202ee11ee6d7aec339125" in build
start=launcher.index("- (void)viewDidLoad {",launcher.index("@interface ProbeViewController"))
end=launcher.index("- (void)dealloc",start)
view=launcher[start:end]
guard=view.index('PVZ2StoreQAResearchBuild')
identity=view.index('if(!qaMarked || qaBlocked)')
startGame=view.index('V130RuntimeInstalled()')
assert guard<identity<startGame
assert 'com.puissantsy.pvz2forios.production' in view
assert 'com.puissantsy.pvz2forios.keyobs' in view
assert 'com.ea.game.pvz2_row' in view
assert 'NSLog(@"[STOREQA] IDENTITY_REFUSED")' in view
assert 'return;' in view[identity:startGame]
assert 'v130ContinueLaunch' in view[startGame:]
assert '"PvZ2forIOS-v170-OfflineGlobal-unsigned"' not in build
print("PASS: Store QA separate bundle, fail-closed startup before V128, exact historical Dynarmic, single build marker")
