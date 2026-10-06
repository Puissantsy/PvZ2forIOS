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


## First guest-dispatch crash after fixing JIT construction — 2026-10-05

Physical iPad log `pvz2forios-probe(20261005-194047).log` proves the previous
broker-removal change fixed JIT construction itself. Runtime now reaches:

- `KEYCONV JIT BACKEND: ... BRK #0xf00d broker disabled.`
- `KEYCONV JIT CONSTRUCT BEGIN pageTable=OFF`
- `KEYCONV JIT CONSTRUCT END`
- `V88 STARTUP BEGIN phase=constructors count=618`

and then the process dies before any later retained startup diagnostic.

Inspection of pinned Dynarmic f488 identifies the next incompatibility. Its
generated A32 dispatcher executes from the code cache and, on a cache miss,
calls `GetOrEmit()`. `AddressSpace::Emit()` calls `UnprotectCodeMemory()`
while that dispatcher is still executing. The previous compatibility patch
used one mapping and changed it RX -> RW -> RX, so the first guest translation
removed EXEC from the mapping underneath the currently executing host PC.
That explains why JIT construction succeeded but the first `jit.Run()`
faulted immediately.

The active A14/pre-TXM correction now uses one persistent anonymous RWX code
mapping after StikDebug has attached / `CS_DEBUGGED=YES`. The f488
`BRK #0xf00d` broker remains compiled out only under
`PVZ2_DYNARMIC_FORCE_NONTXM_JIT`; normal upstream/TXM behavior remains
available outside this isolated build. Dynarmic `protect()/unprotect()` stay
no-ops for the forced physical-iOS path, so `GetOrEmit()` cannot revoke EXEC
from its live dispatcher.

KEYCONV also now exempts `CHECKPOINT constructor[...]` lines from the v85
performance log filter. If any guest constructor remains incompatible, the
next device log will identify the exact last constructor entered instead of
collapsing the failure to the generic constructors phase.

All changes are staged with `[skip ci]`; no new IPA build has been launched
yet. One grouped build will be triggered only after source/wiring review.


### Grouped A14 RWX acceptance build trigger

Source/wiring review against pinned Dynarmic f488 passed before this trigger:
the upstream CodeBlock has the expected six physical-iOS guards, one broker
allocation guard and one legacy iPhone allocation fallback. The staged patcher
matches all three contracts, the unsafe same-map RX<->RW toggle is rejected by
regression checks, and KEYCONV constructor breadcrumbs are retained.

This commit intentionally triggers the single grouped IPA build for the
persistent A14/pre-TXM RWX correction.


## A14 dual-map correction after 2026-10-05 19:40 device log

Physical log `pvz2forios-probe(20261005-194047).log` proves the previous
broker-removal build now reaches `KEYCONV JIT CONSTRUCT END` and enters the
constructors phase. The visible crash therefore moved past JIT construction.

The subsequently staged single-map persistent-RWX experiment was **not**
accepted as the final fix. Its GitHub Actions run 37366344076 ended without an
artifact, so no physical iPad result exists for that path. Static review also
recovered the more important historical contract from this repository's
original Dynarmic wiring: the working LiveContainer fork was selected
specifically for its dual-mapped executable-memory path.

This grouped correction therefore recreates that historical contract on the
pinned public f488 source for KEYCONV only:
- permanent anonymous RW mapping for Oaknut writes;
- `vm_remap` alias of the same pages;
- permanent RX protection on the executable alias;
- physical-iOS `protect()/unprotect()` remain no-ops;
- f488's `BRK #0xf00d` broker stays compiled out only for the forced A14 path;
- callback-backed guest memory remains enabled for KEYCONV only;
- KEYOBS/production V113 behavior remains unchanged.

The first constructor `jit.Run()` is additionally bracketed by non-filterable
`KEYCONV FIRST CONSTRUCTOR RUN BEGIN/END` diagnostics, and constructor
checkpoints are exempt from the V85/V118 performance log filter.

This commit intentionally triggers one grouped IPA build after all source,
workflow and regression changes were staged.


### Successful grouped dual-map build

- Source commit: `75c3bde796f6dc0a526da7250acc3ebd5be7863e`
- GitHub Actions: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37372393069
- Artifact: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37372393069/artifacts/11370583418
- IPA SHA256: `085395ed0fa3920e34fac6bba9cb8f7d4c8eee00ebd6863b2af1ffd24d269832`
- Bundle ID: `com.puissantsy.pvz2forios.keyobs`
- Display name: `PvZ2 Keys Research`

CI confirmed the exact f488 source was patched to the A14/pre-TXM permanent
RW/RX dual-map path, the KEYCONV regression contract passed, CMake configured,
the arm64 iOS target built, and the IPA artifact uploaded successfully.

Physical acceptance remains startup-only first. Expected decisive markers are:
`KEYCONV JIT CONSTRUCT END`,
`CHECKPOINT constructor[0] begin ...`,
`KEYCONV FIRST CONSTRUCTOR RUN BEGIN ...`, and, if the first guest dispatch
returns, `KEYCONV FIRST CONSTRUCTOR RUN END ...`.


## Exact historical Dynarmic restoration — 2026-10-06

Physical log `pvz2forios-probe(20261006-183744).log` proves the reconstructed
f488 dual-map path still dies inside the first `jit.Run()`:
`CHECKPOINT constructor[0]` and
`KEYCONV FIRST CONSTRUCTOR RUN BEGIN addr=0x100e96c0` are present, while
`KEYCONV FIRST CONSTRUCTOR RUN END` is absent.

The decisive change is that the original dependency became publicly accessible
again:
`LiveContainer/dynarmic@c97c525ec1432b1e5404ebf091027738005ec168`.
That is the exact revision referenced by the already-working PvZ2/KEYOBS
runtime. Its Oaknut allocator:
- maps the executable alias RX first;
- detects TXM at runtime;
- on non-TXM A14 skips JIT26PrepareRegion;
- vm_remaps the RX pages to a distinct writable alias;
- mprotects only the writable alias RW.

The active branch now restores that exact source and the project's historical
`dynarmic-ios-nontxm.patch` spinlock fix. All f488 allocator patching and
`PVZ2_DYNARMIC_FORCE_NONTXM_JIT` overrides are removed.

The temporary KEYCONV callback-memory workaround is also removed. V113 direct
page-table behavior is restored exactly as in the first active KEYCONV commit
and the physically proven KEYOBS/production runtime.

The first-constructor BEGIN/END diagnostics and constructor checkpoints remain
so physical acceptance can prove the first guest dispatch immediately.

This commit intentionally triggers one grouped IPA build after all restoration
changes were staged with [skip ci].


### Successful exact-runtime build

- Source commit: `22ec02c6e921a053b20920d82688587e8c5fa900`
- GitHub Actions: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37513543303
- Artifact: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37513543303/artifacts/11435824843
- IPA SHA256: `ffdfd9027ea3d7488f9a66af63beb7f5eee422accd6cd9be770fc30bf757440f`
- Bundle ID: `com.puissantsy.pvz2forios.keyobs`
- Display name: `PvZ2 Keys Research`

CI confirmed `DYNARMIC_HEAD=c97c525ec1432b1e5404ebf091027738005ec168`,
the historical iOS spinlock patch applied, the allocator remained unmodified,
the V113 direct page table was restored, and the full arm64 build/package
succeeded.

Physical startup acceptance should now show
`KEYCONV DYNARMIC RESTORE...`, `JIT CONSTRUCT BEGIN pageTable=ON`, then
the first-constructor BEGIN/END markers. No Day 3 reward should be triggered
until startup reaches the menu/map.


### Physical startup acceptance — 2026-10-06

Physical log `pvz2forios-probe(20261006-185231).log` validates the exact-runtime
restoration on iPad:
- `KEYCONV JIT CONSTRUCT BEGIN pageTable=ON` / `END`;
- first constructor enters and returns;
- all 618 constructors complete;
- JNI_OnLoad and application/surface lifecycles complete;
- V113/V117/V116 direct page tables activate at frame 1;
- runtime remains stable through frame 6000+ and reaches the normal menu;
- no `KEYCONV GRANT_PRE` or `KEYCONV APPLY` occurs during startup.

Startup acceptance is therefore PASS. Next acceptance step is the noneligible
Egypt key-award control: while at least one verified Egypt key gate is not
opened, a real 1-key reward must remain a key, log
`KEYCONV GRANT_PRE ... decision=GateNotOpen`, and produce no
`KEYCONV APPLY`. Only after that control passes should an all-gates-open
disposable profile test actual key-to-coin conversion.
