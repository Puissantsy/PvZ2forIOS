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


### Physical noneligible award acceptance — 2026-10-06

Physical log `pvz2forios-probe(20261006-190700).log` validates the fail-open
noneligible path:
- real Egypt award observed at original caller LR `0x10176408`;
- `world=egypt amount=1 coinsBefore=890`;
- decision `GATE_NOT_OPEN`;
- Egypt gate states `{13:1,23:1,33:1,39:1,41:2}`, therefore not eligible;
- no `KEYCONV APPLY` occurred;
- physical UI confirmed +1 Egypt Key and unchanged coin balance.

Noneligible award acceptance is PASS. Next safe device check is opening the
currently available one-key Egypt gate and confirming the native gate path still
spends the key and transitions that gate from state 2 to state 3 under the
active KEYCONV build.


### Physical key-gate spend/state acceptance — 2026-10-06

Physical log `pvz2forios-probe(20261006-191241).log` validates normal gate
opening under active KEYCONV:
- Egypt gate event 41 is observed at state 2 before the native open path;
- native path requests `desiredState=3`;
- after the path returns, event 41 is state 3;
- other Egypt gates remain state 1, so the world remains noneligible;
- no `KEYCONV APPLY` occurs during gate opening;
- physical test opened the gate using the previously earned Egypt key.

Gate-spend/state acceptance is PASS. The remaining functional acceptance target
is an all-Egypt-key-gates-open disposable profile followed by a fresh real
Egypt key award, which must skip key credit and add exactly 1,000 coins.


### Physical eligible conversion and grouped multi-key/stock probe — 2026-10-11

Physical iPad `pvz2forios-probe(20261011-200804).log` proved:
- `KEYCONV GRANT_PRE sourceLR=0x10176408 world=egypt amount=1 coinsBefore=7800 decision=CONVERT`;
- all Egyptian key gates `13,23,33,39,41` have native state 3;
- `KEYCONV APPLY world=egypt keys=1 coinsDelta=1000 coins=7800->8800 via=SetCoins@0x1042e5ac`;
- physical UI showed +1000 coins and unchanged Egypt keys.

Eligible 1-key conversion is now physically PASS.

A single grouped *research* follow-up:
- support incoming 4-key AddWorldKeys awards (4,000 coins after verified completed gates); legacy >4, especially the statically catalogued 100-key callers, remain fail-open into original native award;
- add bounded read-only `wsk={...}` stock snapshot from the original profile's WorldSpecificKeys vector at +0x7c, included in active reward/gate diagnostics;
- do NOT migrate or write preexisting keys, since the exact live stock layout and native save/notify semantics still require device validation;
- pure policy tests cover 4 and rejection of 5/100; static verifier enforces nonmutating stock probe.

Next iPad probe: preserve the existing KEYCONV app and save; trigger a normal Egyptian key reward and check that the log shows `wsk={egypt:...}` with expected stock. No Yeti needed for testing pure 4-key policy, but live Yeti award provenance remains unproven. If logs show INVALID/UNKNOWN, do not interpret stock values or enable migration. No production changes.


### Build blocked by historical dependency availability — 2026-10-11

Single grouped build attempt: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38171726047
on source `c1b71edf54b883c822f4aeb00d96e9c2fd4f407f`.
GitHub Actions failed in `Checkout exact proven LiveContainer Dynarmic revision`
BEFORE source verification, CMake configuration or compilation.
Git printed `fatal: could not read Username for 'https://github.com':
terminal prompts disabled` while cloning
`https://github.com/LiveContainer/dynarmic.git`.
The original repository/commit now returns 404 via GitHub API again.
No new IPA was produced. Do not fall back to f488: that alternate allocator
failed physical device tests before first guest dispatch.
The existing successful c97c KEYCONV IPA remains the last device-proven build.
The four-key/stock-witness changes remain on the isolated research branch,
UNBUILT and UNTESTED on device. Standalone policy tests may run independently.


### Guarded stock-reconciliation policy and CI — 2026-10-11

User reports a separate iCloud backup at **6 Egypt Keys with one 5-key gate
remaining**, and another backup with **10,000 PvZCoins** for repeated premium
purchase tests. These cloud backups are NOT embedded in this repository or
visible to this CI, and no data migration has been attempted.

Staged read-only policy `tests/staging/world_key_stock_reconcile.hpp` plans
previously stranded keys (range 1..99) into 1000 coins each, only if all
verified key gates for the target world are open, native saved stock is valid,
and signed wallet addition is safe. It returns a PLAN only and never calls
native guest functions or writes pp.dat. Unit tests exercise idempotence at
zero stock, 1/6/99 keys, overflow, closed/duplicate/missing gates,
unknown/future worlds, and invalid 100-key stock.

Bounded KEYCONV inventory logs now validate native COW string size headers at
char pointer -12, readable count, bounded string memory, and reject duplicate
world entries rather than giving a misleading stock snapshot.

Exact historical Dynarmic dependency is now cached by immutable SHA through
actions/cache@v4. The source cache will be seeded on the NEXT successful
checkout, not retroactively; current Dynarmic upstream 404 can still block
the first restored build. Git reset to pinned SHA removes previous spinlock
patch from a restored cache before fresh application. No alternate backend
is introduced.

Standalone CI is green:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38175096127
- 33 key-award policy assertions;
- 7 read-only native event-view assertions;
- 26 pure existing-stock reconciliation assertions;
- source-wiring/ARM tail-call/fail-open/save-isolation checks all pass.
This does NOT prove actual native stock mutation or device behavior.
The working prior KEYCONV IPA remains the recommended device installation.

The first future device validation must inspect `wsk={...}` on a verified
backed-up profile and confirm original gate/key stock readings.
Do not activate old-stock mutations without a native transaction design and
device evidence. Premium purchase failure has not recurred; continue
instrumentation-only investigation instead of speculative changes.


### Native stock ARM verification + crash-safe staged planner — 2026-10-11

Original reference APK was read locally (not committed): extracted
`libPVZ2.so` SHA256 matches the exact expected
`f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f`.
Direct native disassembly confirms GetWorldKeys/SpendWorldKeys COW world
string `chars-12` length and `profile+0x7c/+0x80` 8-byte WorldSpecificKeys
entries; spend subtracts requested count, clamps to zero, and writes via
native notify path. Extended `tools/verify_world_key_arm.py` with exact
opcodes for these witnesses.

Active KEYCONV now includes one-time read-only `KEYCONV STOCK_PROFILE`
snapshot after `OfflineStoreApplyProfileEntitlements` resolves the active
native profile. It can observe iCloud-restored surplus keys at startup
without a new key award or gate opening. This is NOT built/tested on device.

Added pure `InspectSettlement` safety classifier: NotYetApplied,
FullyApplied, PartialKeyDebit, PartialCoinCredit, UnexpectedState,
InvalidPlan. Partial cases never imply automatic retry. Added precise
backup regression: Egypt=6 with one state-2 gate => noneligible; after
native 5-key spend to Egypt=1 and all gates=3 => exactly 1000-coin plan.
No runtime stock mutation nor host checkpoint transaction exists yet.

New green policy-only CI:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38175743041
- 33 award policy tests;
- 7 native event decoder tests;
- 37 stock-reconcile/interrupt classification tests under UBSan;
- all related static/wiring verification steps pass.
A new IPA still cannot be produced until exact proven Dynarmic c97c
checkout is available/cached. Do not switch to a different allocator.


### Shared stock decoder integration — 2026-10-12

The host-only stock parser is now the same code unit-tested on CI and
instantiated by the active KEYCONV runtime.
`tests/staging/world_key_stock_view.hpp` decodes bounded
`[world:COW string pointer,count:u32]` entries; runtime
`WorldKeyReadOnlyStockSnapshot` performs native COW header, readable
terminator, vector bounds and profile checks before producing `wsk={...}`.
The pure reader rejects duplicate, unknown and inconsistent native entries.
No guest save or key balance mutation was enabled.

Green no-IPA CI: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38205300169
(33+7+13+37=90 unit assertions plus all static integration checks).
The V128 save audit confirms that a native spend and native coin setter
can independently trigger durable pp.dat flushes via guest close/fsync.
Atomic file rename alone DOES NOT make both operations a transaction.
A WAL/backed-up crash-safe commit remains necessary before active
existing-key migration. No new IPA is built because the proven
LiveContainer c97c dependency checkout is still unavailable.


### October 12 — 3-file save-journal proof of concept (research only)

Private snapshots (2026-10-01) show `pp.dat` and `snapshot2.dat`
byte-identical within each snapshot, at 3,620 and 7,080 bytes
respectively; `local_profiles` differs between snapshots. Real
2026-10-11 KEYCONV log has 307 `pp.dat` V128 flushes and additional
`snapshot2.dat`, `local_profiles`, loot and draper writes.
The old `pp.dat`-only rollback design is insufficient as a general
game-save transaction.

Added bounded, research-only durable multi-file staging / journal with
atomic per-file rename and an atomic published committed marker.
On a startup recovery barrier, interrupted batches roll back all
affected files; fully committed batches keep their new images.
Unknown/concurrent states are CONFLICT, never overwritten or retried.
Tested interruption before manifest, between three replacements,
mid-rollback and after commit marker.

Source files:
- `tests/staging/world_key_save_journal.hpp`
- `tests/staging/world_key_save_bundle_journal.hpp`
- `tests/staging/test_world_key_save_journal.cpp`
- `tests/staging/test_world_key_save_bundle_journal.cpp`
- `tools/verify_world_key_save_isolation.py`
- `docs/WORLD_KEY_SAVE_TRANSACTION.md`

CI https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38208306965
is GREEN: 180 isolated unit checks and all static/integration checks.
No iOS build attempted, no code activated that spends stock keys, no
changes to the original stable Probe, and no user save modifications.

Next physical acceptance after restoring exact Dynarmic checkout:
1. Boot KEYCONV read-only profile and confirm `KEYCONV STOCK_PROFILE`
   includes `wsk` even when gate vector is invalid.
2. Restore disposable 6-key profile, observe 6 -> 1 keys on native
   5-key gate opening, collect complete V128 save write-set and identify
   which files the exact transition edits.
3. Only then integrate a quiescent guest save-serialization barrier
   and a prelaunch journal recovery barrier, with fail-closed
   process-kill tests before enabling automatic surplus settlement.


### October 12 — Key stock + exact V128 write-set diagnostic preflight

KEYCONV research-mode-only instrumentation:
- a shared, standalone-tested whitelist of three native profile files:
  `pp.dat`, `snapshot2.dat`, `local_profiles`;
- baseline bytes loaded only after a successful V128 disk read, capped at
  1 MiB/file; exact byte comparison after successful native V128 flush;
- log line adds frame, sameAsPrior=YES/NO/UNKNOWN and flushUs; a
  separate summary records changed/unchanged/unknown counts, total and
  maximum flush time;
- preserves the original guest VFS flush ordering, fsync, rename, and
  all non-KEYCONV modes; does not change saves or automatic key settlement;
- even with an invalid native gate event vector, `KEYCONV STOCK_PROFILE`
  still logs the bounded `wsk` inventory observation.

Off-device C++ unit tests: **197 checks** pass
(33+7+13+37+31+59+17); static wiring checks also PASS.
CI: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38208827380

Exact historical Dynarmic recovery was tested separately without
starting another IPA build. Source probe:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38208937421
on GitHub Actions macOS returned:
`remote: Repository not found.`
`fatal: repository 'https://github.com/LiveContainer/dynarmic.git/' not found`
when attempting an **anonymous git ls-remote**.
The source cache is therefore still empty. Only the previously installed
device-proven KEYCONV IPA is currently suitable for physical testing.

Full next-device acceptance plan:
`docs/WORLD_KEY_WRITESET_PROBE.md`.


### October 12 — offline native RTON save-edit research route

The original October 1 user save snapshots were analyzed LOCALLY,
without committing their private contents. Original PlayerInfo saved
objects are RTON with `objdata.c` (coins), `objdata.wsk` (world
keys), `objdata.wm` (gate event state) and `objdata.i` (native
profile index). Both archives contain byte-identical pp.dat and
snapshot2.dat; their snapshot-info.plist SHA-256 inventories pass (9/9
and 10/10). `local_profiles` also contains the corresponding
PlayerInfoLocalSaveData ProfileIndex for each saved player slot.

Added:
- `tools/inspect_pvz2_rton_save.py`: read-only RTON parser + manifest
  SHA-256 verifier, no player names/UIDs in emitted JSON;
- `tools/experimental_keyconv_rton_memory.py`: pure exact numeric-token
  mutation in memory only, only for all-open Egyptian gates, with full
  post-edit reparse/structural diff and signed-wallet overflow guards;
- `tools/experimental_keyconv_rton_archive.py`: **explicitly opted-in
  disposable-output ZIP experiment only**, never overwrites source,
  requires identical profile mirror, valid inventory and matching
  PlayerInfo.i / local_profiles.ProfileIndex, refreshes both RTON
  profile images and their manifest checksums, verifies the output;
- isolated tests `test_readonly_rton_save.py`,
  `test_keyconv_rton_memory.py`,
  `test_keyconv_rton_archive.py`.

Green CI:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38212259281
197 C++ checks + 23 read-only Python + 9 in-memory token edits
+ 10 disposable ZIP tests = **239 checks** plus static safeguards.

IMPORTANT: neither original private snapshot contains a NONEMPTY wsk,
so the actual live six-key world-vector serialized schema is still
unproven. The experimental archive **must not be imported into a
primary profile** until a disposable backed-up real world-key
sample and actual iPad save restore/restart verification pass.
The stable iPad app is unchanged. This offline research does NOT remove
the historical Dynarmic c97c source 404 for future IPA builds.
See `docs/WORLD_KEY_OFFLINE_RTON_INSPECTOR.md`.


### October 12 — PRIVATE native surplus-key save finally inspected

The user supplied `Save clé excédentaire.zip` to private project
Sources. Local read-only inspection verifies `PlayerInfo.wsk` is exactly
`[{wn:"egypt",kc:1}]` in the relevant player slot; all five Egypt
gate events are state 3. Source manifest's 11 entries pass SHA-256
verification. `PlayerInfo.i` equals matching local_profiles.ProfileIndex.
The original backup remains unmodified and is NEVER uploaded to GitHub.

Important correction to the previous identical-mirror assumption:
native `pp.dat` and `snapshot2.dat` differ in nine other decoded
fields and represent distinct original progression snapshots.
A safe OFFLINE experiment must preserve that difference, patching
each snapshot's own `c` and `kc` numeric fields separately,
then rebuilding two distinct manifest checksum records.

Modified offline tools and synthetic tests:
- `tools/inspect_pvz2_rton_save.py` exact wn/kc reader;
- `tools/experimental_keyconv_rton_memory.py` strict two-token edits;
- `tools/experimental_keyconv_rton_archive.py` distinct pp/snapshot2
  edits and validated local_profiles native profile identity;
- three synthetic Python test suites with specific diverged-fallback
  regression and fail-closed tests.

A PRIVATE disposable converted ZIP has been produced in the conversation
container, with independent read-back and checksum validation. It has
NOT been loaded into the iPad and is NOT considered a validated game save.
Actual restore/restart acceptance remains required on a disposable test
installation; stable research/production iPad IPA files are untouched.
