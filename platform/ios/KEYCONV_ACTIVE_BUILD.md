# Active world-key conversion build marker

All grouped source changes are complete before this build trigger.

Pre-build validation succeeded:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37226104553

This experimental child branch preserves the existing KEYOBS app bundle ID and
save sandbox, but launches `RESEARCH_WORLD_KEYS_CONVERT` first. Eligible
1..3-key awards are replaced immediately by the game's native SetCoins using
1000 coins/key only when every verified gate for that world is already state
>=3. Unknown/incomplete/future/dark/overflow/ABI failures preserve normal keys.

No APK, OBB or private save is included.


## Exact iOS Dynarmic build dependency

The active IPA workflow now clones the exact public Dynarmic gitlink used by
Applesauce `ios-host`:
- repository: `https://github.com/johnny901901901/dynarmic.git`
- revision: `f488f760c69c42a97331961e8e6c359b46ccc9e9`

Its standalone clone/API/spin-lock compatibility probe passed:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37227502915

The complete active conversion policy + ARM tail-call + save wiring + exact
Dynarmic source wiring validation also passed:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37228382759

This commit intentionally triggers the **single grouped IPA build** after all
source and dependency changes were staged.
