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
