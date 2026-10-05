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


## Startup compatibility rebuild after first device crash

Physical iPad log `pvz2forios-probe(20261004-194529).log` ended immediately
after `V91 RELRO ARMED`, before constructors and before any `KEYCONV GRANT_PRE`
or `KEYCONV APPLY`. Therefore the economy mutation did not execute.

The inaccessible historical Dynarmic archive could not be recovered (public
codeload returned 404). The replacement public Dynarmic revision compiles with
the expected API but differs from the historical runtime. For this active
research mode only, V113/V115/V116's direct page-table optimization is disabled
at JIT construction; all guest memory stays on the already-supported callback
path. Parent KEYOBS and production modes retain their previous mapping behavior.

This build adds explicit `KEYCONV JIT CONSTRUCT BEGIN/END` markers. Full
offline validation passed:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37230188057

This commit triggers one grouped corrected IPA build.


## A14 / pre-TXM Dynarmic constructor fix — 2026-10-05

Physical iPad log `pvz2forios-probe(20261005-101846).log` now proves the
V113/V115/V116 fallback itself works: runtime reaches
`KEYCONV DYNARMIC COMPAT...` and
`KEYCONV JIT CONSTRUCT BEGIN pageTable=OFF`, then dies before
`KEYCONV JIT CONSTRUCT END`. Therefore the direct guest page table is not the
startup root cause.

The pinned public Dynarmic revision
`f488f760c69c42a97331961e8e6c359b46ccc9e9` changed physical-iOS Oaknut
CodeBlock allocation to enter an external JIT broker through
`BRK #0xf00d`. That is not the established A14/pre-TXM StikDebug path used by
this project. The isolated KEYCONV build now applies
`dynarmic-ios-a14-nontxm-codeblock.patch` and compiles Dynarmic with
`PVZ2_DYNARMIC_FORCE_NONTXM_JIT=1`, restoring the historical iPhone
mmap(RX) <-> mprotect(RW) W^X code-cache path and compiling the f00d broker
branch out.

The IPA workflow performs `git apply --check`, applies the patch, runs
`verify_world_key_dynarmic_compat.py`, and only then configures/builds.
KEYCONV's callback-backed guest memory remains enabled for this acceptance
build; parent KEYOBS/production V113 behavior remains unchanged.

This commit intentionally triggers the single grouped corrected IPA build.


### Successful grouped build

- Source commit: `643562becdd8387bb89959e640365d8b7e85d3f8`
- GitHub Actions: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37296757464
- Artifact: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37296757464/artifacts/11340660787
- IPA SHA256: `c6806917e0a7c2f31b67fbe10a99784de0f2bfc6154cb986517682b01a9c5388`
- Bundle ID: `com.puissantsy.pvz2forios.keyobs`
- Display name: `PvZ2 Keys Research`

CI confirmed:
- pinned Dynarmic patch applied;
- A14/pre-TXM compatibility regression test passed;
- CMake reported the f00d broker disabled;
- iOS arm64 build, inspection, IPA package and artifact upload all passed.

Physical acceptance remains intentionally startup-only first. Expected sequence:
`KEYCONV JIT BACKEND: A14/pre-TXM legacy W^X forced; BRK #0xf00d broker disabled.`
then `KEYCONV JIT CONSTRUCT BEGIN pageTable=OFF`, then
`KEYCONV JIT CONSTRUCT END`.
