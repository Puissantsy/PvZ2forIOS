# KEYCONV prelaunch two-image settlement — staged research implementation

Status 2026-10-12: **offline transaction prototype in Python, 13/13 new
synthetic tests PASS on GitHub Actions; NOT wired into iOS and NOT yet
accepted by a physical iPad as an automatic operation.**

## Why the existing experiment is not sufficient on its own

The user has now confirmed the *separately edited* disposable RTON backup
survives a true iPad app process restart with 0 Egyptian keys and 10,010
PvZCoins, rather than 1 key and 9,010 coins. A second +1,000 credit was
not observed. The original iPad FULLLOAD trace shows subsequent guest
flushes of `pp.dat` and `snapshot2.dat`.

That establishes persistence of **offline** conversion, not safety of doing
`SpendWorldKeys` and `SetCoins` independently while the Android guest
executes. Such a runtime hook can be interrupted between two independent
V128 writes. Existing `SaveBundleJournal` remains a C++ research-only
prototype; it is deliberately not linked to the guest.

## New files

- `tools/experimental_keyconv_prelaunch.py`: offline, opt-in,
  stopped-guest research prototype; never imported by iOS sources.
- `tests/staging/test_keyconv_prelaunch.py`: 13 synthetic tests with
  interrupted preparation, first image replacement, second image
  replacement, committed-marker recovery, repeated load, divergent
  fallback values, closed gates, identity mismatch and corrupt journal.
- `.github/workflows/verify-world-keys.yml`: runs the new tests and
  Python syntax check, without building an IPA.

GitHub CI (SUCCESS, latest after installing-byte verification and the
pre-commit-marker interruption test):
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38224910870

The prototype also passed local interruption tests using *copies* of the
private Oct 12 reference source, never using actual save bytes as public
fixtures.

## Contract of the offline prototype

The caller supplies a **copy** of an isolated research live-root directory,
a zero-based player slot and `guest_stopped=True`. The function is not
connected to an executable iOS startup path.

1. **Mandatory recovery barrier**: before any game reads the profile,
   recover an interrupted `.pvz2-keyconv-prelaunch-journal` transaction
   or refuse launch if journal/content is inconsistent.
2. Require `UserData/No_Backup/{pp.dat,snapshot2.dat,local_profiles}`
   as bounded regular, non-symlink and non-hardlinked files.
3. Decode every selected `PlayerInfo.objdata.i` in both images and verify
   against `PlayerInfoLocalSaveData.objdata.ProfileIndex` at that slot.
   Reject divergent `wsk` stock and all ambiguous records.
4. Reuse the already-validated **exact numeric token** editor. Require
   the same eligible original key count in both files, the verified five
   Egyptian gate states >=3 in each RTON, and signed coin overflow safety.
   Preserve each file's own non-coin/non-key historical state.
5. Save full old/new byte images outside `UserData`, with SHA-256
   digests and a profile-bound manifest. Use exclusive create, fsync,
   atomic rename and directory fsync. Verify each current image still
   equals its expected old bytes immediately before replacement.
6. Only after **both** new images have been installed is a durable
   `committed` marker published. Interrupted *uncommitted* conversions
   roll both files back; a committed operation requires exact new-image
   matches. Mismatches block further launch instead of guessing.
7. Rename the completed journal directory to `.done` atomically
   before cleanup, so interrupted cleanup can resume. The next startup
   sees `kc=0` and becomes a no-op: no extra PvZCoins credit.

This is not a claim of formal transactional atomicity on APFS: directory
fsync/rename durability, interruption behavior and multi-profile races
must all be validated for the concrete iOS implementation.

## Exact future iOS integration seam (source audit, NOT IMPLEMENTED)

`platform/ios/src/main.mm`, method `v130ContinueLaunch`:

- before startup, the KEYOBS branch already asks the user to **Restaurer**
  or **Ignorer** an integrity-validated snapshot. Failed restores stop
  launch. Preserve that behavior.
- once restoration has completed, it creates a `prelaunch` snapshot
  via `PVZSaveCreateSnapshot` while `jniRunning` and
  `v130LaunchStarted` are false.
- only afterwards can `v130StartStoredRuntime` invoke the guest
  `documentPicker`/full-load pipeline.

The migration **settlement** must run after the confirmed restore and
successful prelaunch snapshot but **before** guest/JIT. A separate
**journal-recovery gate must run before even presenting a new restore**;
see sequencing correction below. It must have an explicit one-shot/opt-in gate and
a recovery barrier even when an experiment is disabled. The current
Python prototype cannot run inside the compiled iOS app as-is; it must
be ported to tested Objective-C++/C++ code, not simply linked.

## Remaining gates before a single new IPA build

- Implement the equivalent bounded RTON reader/precise token mutation and
  durable journal in an iOS-compilable isolated module. Avoid duplicated
  schema assumptions; reuse the exact observed `wn/kc` fields.
- Define how the app chooses profiles. Current prototype deliberately
  requires an explicit slot; automatic selection/all-profiles processing
  is **not** proven safe. Keep every native profile identity independent.
- Confirm the current v165 restore implementation and the prelaunch
  migration cannot overlap or fight over disk roots; journal and
  disposable backups remain outside the inventoried `UserData` root.
- Verify exact native startup/before-V128 barrier, iOS filesystem
  semantics and crash recovery; prohibit guest file writes until complete.
- Run simulated kill/corruption/profile-switch/relaunch/regression cases
  in a separate research app with untouched iCloud originals.
- Only then group changes and attempt **one** iOS IPA build using the
  exact previously verified Dynarmic backend; never substitute an
  unverified allocator merely to get a build.
- Keep production/v170, working KEYCONV IPA, and read-only KEYOBS parent
  unchanged. Do not enable this automatic migration by default.

## Physical iPad acceptance, when ready

Test an isolated profile holding one Egyptian surplus key with all five
Egypt gates opened. Expect `KEYCONV_PRELAUNCH ...` bounded diagnostics,
0 keys, original wallet +1,000 and no change to the five gate states.
After a complete app restart **without restoring again**, expect 0 keys,
the same wallet and no extra `APPLY`. Also test deliberately interrupted
prelaunch/forced-kill/restart and confirm old **or** new state, never
partial debit/credit or lost unrelated progression. Keep full logs and
an iOS `.ips` on any crash.


## Native converter staged — C++20 byte-exact parity and profile pairing (2026-10-12)

A platform-neutral native RTON parser/converter has been staged under the
**test-only** directory, not linked into `platform/ios`:

- `tests/staging/world_key_rton_native.hpp` decodes the original 1.5.252752
  RTON token tags, string caches and nested objects, remembers the precise
  numeric token spans, writes only `objdata.c` and Egyptian `wsk[].kc`,
  reparses the entire document and rejects unrelated semantic differences.
  Unrecognized token types fail closed. Supports signed/unsigned varints
  and fixed integer encodings.
- `tests/staging/world_key_rton_native_pair.hpp` requires the explicit
  selected PlayerInfo slot and `local_profiles` registry, validates native
  ID matches in both images and equality of old key stock, while preserving
  different fallback wallet/progression values. Mismatched gate eligibility,
  slot count or native IDs are rejected.
- `tests/staging/keyconv_rton_native_cli.cpp` is a synthetic-fixture runner
  only; the final iOS runtime must call a library function directly.
- `tests/staging/test_keyconv_rton_native.py` verifies **byte-for-byte
  equality** of C++ output with the previously iPad-validated Python
  prototype across numeric-width changes, zero keys, closed gates,
  malformed tags, overflow, invalid slot and fallback wallet difference.
- `tests/staging/test_world_key_rton_native_pair.cpp` tests two-image
  pairing, identical stock, different coin totals, native registry binding,
  idempotence and fail-closed cases.

Separately, `experimental_keyconv_prelaunch.py` now uses a **version 2**
recovery manifest bound to the exact `local_profiles` SHA-256, explicit
profile slot and native ID. If the profile registry changes across an
interrupted conversion, recovery stops rather than touching the wrong
profile. The research-only Python crash suite now has **15 passing tests**.

**Latest green CI:** https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38226303428
(15 Python prelaunch tests, 8 new Python/C++ byte-parity cases, native
paired C++ checks, all existing world-key/RTON/backup tests and static
wiring guards). No iOS build was triggered and no personal backup file was
published. Native converter parity is proven for the tested synthetic RTON
cases, not yet the user's complete private iPad save.

### Required prelaunch sequencing correction

A crash-recovery journal needs to be checked **before offering a new v165
restore**. A previous interrupted prelaunch migration may still refer to
live old/new player images; importing another backup while recovery is
pending would destroy the checkpoint invariant.

Future KEYCONV research-only iOS control flow:

1. With the guest stopped, recover or fail closed on ANY pending journal.
   Even if automatic conversion is disabled, a pending journal must not
   be bypassed.
2. Then offer existing explicit v165 restore/ignore and verify inventory,
   preserving current fail-closed restore semantics.
3. Capture a complete verified `prelaunch` backup after any approved
   restoration, BEFORE attempting migration. A failed checkpoint must
   prevent an opted-in migration.
4. After explicit research-only opt-in, decode and check native identity
   and both original RTON images; settle them via a native crash-durable
   two-file journal; verify both images and commit before guest load.
5. If any step fails, block guest launch rather than run on a partial or
   ambiguous save. Continue to JIT/guest launch only on clean recovery,
   no-op or completed atomic settlement.

**Status update:** a SHA-256-based, stopped-guest **research-only C++20
journal** now exists under `tests/staging/world_key_prelaunch_native.hpp`.
Its synthetic file-system crash/recovery tests run on Linux and macOS;
the same source is syntax-checked for iPadOS arm64. It is still **NOT linked**
into the iOS runtime or proven power-loss-atomic on iPad. The older
`SaveBundleJournal` uses FNV-1a and remains research-only; do not substitute
it for the new journal. The remaining blocker is the controlled native iOS
prelaunch integration, opt-in UI, recovery-before-restore barrier and real
iPad failure injection.


## Native SHA-256 transaction with Apple toolchain gate — 2026-10-12

The branch now stages the platform-neutral journal
`tests/staging/world_key_prelaunch_native.hpp` and synthetic fault tests
`tests/staging/test_world_key_prelaunch_native.cpp`. These are NOT
included in `platform/ios/CMakeLists.txt` and cannot mutate a real app.

The native flow uses the existing tested C++20 exact-token RTON pairing
planner and an explicit **stopped guest + research opt-in** gate. It
checks the `local_profiles` native ID, preserves distinct primary/fallback
coin balances, stages both before/after bytes in a separate journal directory
OUTSIDE `UserData`, verifies SHA-256/lengths and uses exclusive create,
`fsync`, same-volume `rename` and parent-directory sync. A durable commit
marker appears only after both new images have been re-read and checked.

Recovery refuses missing/mismatched registry identity, symlinks, unknown
journal files, tampered old/new images, and concurrent/unexpected saves.
With no commit marker it restores BOTH old images; with a verified commit
marker it preserves BOTH new images. Partial cleanups resume from
`.done`. An interrupted recovery does **not** automatically start another
conversion in that same launch; an explicit later clean-start attempt is
required. On first installation without `UserData`, an empty journal
correctly yields `NoJournal` before any restore prompt.

**Security limitation:** SHA-256 checks here detect byte corruption,
not hostile rewriting of both an image and its unauthenticated manifest.
This is a stopped-process, single-sandbox research protocol; without
a verified startup lock and real iOS-kill tests it does NOT guarantee
atomicity against simultaneous guest writes, hostile filesystem actors
or device power failure.

### Apple-specific crash found and repaired

Adding a macOS native smoke job exposed a real AddressSanitizer
**heap-use-after-free** inside the RTON nested array decoding path during
`ConvertEgypt`. The failing frame was the vector's element relocation
when parsing a nested array; the subsequent complete Value-tree copy
reached stale storage. `Reader::Read` now preallocates bounded array
storage using the parser-verified element count. The guarded converter
then completed the same crash suite with Apple AddressSanitizer/UBSan.

### Green cross-platform checks

- GitHub Actions: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38239442677
- Ubuntu: complete existing world-key/RTON tests and the native SHA-256
  filesystem crash test under AddressSanitizer and UBSan.
- macOS 15 (Apple arm64): same native recovery/transaction test with
  CommonCrypto SHA-256 under AddressSanitizer and UBSan.
- Xcode iPhoneOS SDK: `clang++ -fsyntax-only` targeting
  `arm64-apple-ios17.4` succeeded, without any link/app/IPA build.
- Existing real-iPad offline ZIP conversion still validated separately;
  this new native journal has NOT run on the iPad.

### Next research-only integration batch

Before changing `platform/ios`: specify a journal-recovery gate that
runs once before **any** v165 restore prompt, a distinct
post-restore/pre-guest explicit opt-in for migration, a mandatory successful
verified prelaunch backup, strict selected-profile confirmation, and
fail-closed startup UI on conflicts. Confirm all guest/JNI/V128 threads
remain stopped through the whole transaction. Only then stage an iOS
adapter and its source-wiring tests. Do not trigger multiple IPA builds:
consolidate all changes and build the research IPA once after CI checks.


## KEYCONV iOS startup integration + full Apple object compilation — 2026-10-12

Research branch now wires the native stopped-guest journal into the **isolated**
KEYOBS app. This is NOT an automatic/background modification of the original
production PvZ2 installation.

**Changed runtime components:**
- `platform/ios/src/main.mm`: a guarded recovery barrier runs before the
  existing v165 restore prompt. After user-approved restore, a verified
  `prelaunch` snapshot is required before any migration offer. Read-only
  eligibility is restricted to a specific native PlayerInfo slot, and the
  user must choose either "Ignorer" or an explicit "Convertir uniquement le
  profil N" action. An interrupted transaction is not re-applied in the
  same startup; a conflicted journal blocks guest launch rather than
  risking a partial save. The bounded prelaunch result is replayed after
  the existing probe-log reset so iPad test evidence survives.
- `platform/ios/src/keyconv_prelaunch_ios_adapter.{hpp,mm}`: explicit
  KEYOBS bundle-ID gate, stopped-guest native journal recovery,
  read-only native slot discovery, selected-slot settlement, bounded
  user-facing errors, and no disclosure of native profile identifiers or
  raw player data in diagnostics.
- `platform/ios/CMakeLists.txt`: compiles the research Objective-C++
  adapter with the staged C++20 RTON/journal headers. Existing Dynarmic
  allocator/JIT remains UNMODIFIED.
- `tools/verify_keyconv_ios_integration.py`: checks the ordering
  recovery -> v165 restore -> backup -> preview -> selected-slot settle
  -> guest startup, plus explicit opt-in and failed-transaction barriers.

**Failure discovered and fixed in an independent Apple SDK check:**
some pre-existing v165 and newly added Objective-C++ blocks used GNU-only
`typeof(self)` declarations. The full `main.mm` arm64 iOS syntax check
caught these; all were replaced with the explicit
`__weak ProbeViewController *` /
`__strong ProbeViewController *` types, preserving callback behavior.

**Latest green CI, with real iPadOS arm64 object code (not merely syntax):**
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38252464672

- policy-only Linux/Ubuntu: passed.
- Apple CommonCrypto native transaction/sanitizers: passed.
- Apple iPhoneOS arm64 syntax checks: passed.
- `clang++ -target arm64-apple-ios17.4 -c` built `main.mm`,
  `save_backups.mm` and `keyconv_prelaunch_ios_adapter.mm`
  into arm64 object files: passed.
- **NO IPA produced**. The full IPA workflow failed *before compiling*
  the app when the runner could not anonymously clone
  `https://github.com/LiveContainer/dynarmic.git` at the exactly validated
  `c97c525ec1432b1e5404ebf091027738005ec168`.
  Its Git fetch reported `could not read Username ... terminal prompts
  disabled`. No alternate Dynarmic revision has been substituted.

The research branch's full IPA workflow now has an explicit manual
`workflow_dispatch` gate; push-triggered IPA builds are limited to
`main`. This prevents another IPA attempt on every research edit.
Do not claim iPad runtime acceptance of the new KEYCONV flow until the
full IPA can be built using the **identical** historically proven Dynarmic
source and tested in the isolated app on the real device.

**Next hard gate:** recover an independently verified copy of the exact
historical Dynarmic commit (e.g. a trustworthy retained local checkout
with matching full Git SHA, including submodules) or regain access to
the original repository. If unavailable, do NOT silently select an
alternative JIT. Once the exact source exists, run one manual IPA build,
then test recovery/opt-in/profile selection and cold-restart persistence
on disposable KEYOBS saves only.

## Exact Dynarmic dependency recovered from original upstream — 2026-10-12

The discontinued/missing clone endpoint `LiveContainer/dynarmic` is
**not needed**: the exact physically proven commit is publicly available in
the upstream repository `lioncash/dynarmic`, to which the former fork
belonged. The public GitHub commit API resolves the **identical immutable
Git SHA** `c97c525ec1432b1e5404ebf091027738005ec168`, with immutable **tree SHA**
`fd5b3ab282948fcdacc202ee11ee6d7aec339125`, message `oaknut: fix a rare case to avoid hitting
JIT26PrepareRegion`. GitHub also exposes the precise iOS RX-first,
TXM/A14 and `vm_remap` implementation at that commit.

The repository origin in the research build workflow and optional CMake
fallback has been changed from the unreachable fork to its public upstream;
**the Git commit SHA, full tree, original iOS spinlock patch, guest page-table
wiring, and Dynarmic allocator logic are unchanged**. The workflow now
requires SHA and tree identity before proceeding. A separate NO-IPA Linux
preflight anonymously clones the upstream origin, checks both identities,
verifies all historical memory-allocation markers and runs
`git apply --check` against the existing patch. If any check fails, no IPA
build may be dispatched.

This is a transport/origin correction, not a Dynarmic update or
recompilation of the JIT. A full IPA must still pass one explicit manual
build and physical-iPad acceptance. DO NOT alter production.

### Upstream Git fetch correction and single-build gating

The **first** no-IPA preflight proved that a normal clone of
`lioncash/dynarmic` does **not** download c97c's older object; `git
checkout c97c...` therefore failed. The **second**, fully green
[no-IPA preflight](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38254071471)
added an explicit `git fetch origin c97c525ec1432b1e5404ebf091027738005ec168`
and then verified `HEAD`, full tree SHA
`fd5b3ab282948fcdacc202ee11ee6d7aec339125`, JIT/TXM
signatures, vendored externals and patch applicability. Its Linux
source preflight, Apple object tests and original policy tests all passed.

The full IPA workflow now uses the **same explicit fetch** and refuses
a cache whose remote origin is not the verified upstream. Research
branch source commits never trigger it. A one-time commit of
`platform/ios/.keyconv-build-request` will request exactly one
IPA build after this preflight; normal manual `workflow_dispatch`
remains an alternative.


## Single exact-source research IPA build — 2026-10-12 (SUCCESS)

**Full iPadOS arm64 release build succeeded**, rather than only the
isolated Objective-C++ compilation and syntax tests.

- GitHub Actions run:
  https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38254470277
- Exact build commit:
  `b398de49b1e42adf8c1cba39ced4ee87f71173e9`
- Artifact: `PvZ2forIOS-JIT-Probe-unsigned` (ZIP containing
  `PvZ2forIOS-JIT-Probe-unsigned.ipa` and matching
  `.ipa.sha256`).
- GitHub artifact ID: `11750330187`
- Dynarmic source: original c97c525e Git SHA and exact
  `fd5b3ab282948fcdacc202ee11ee6d7aec339125` source tree, fetched
  explicitly from the public `lioncash/dynarmic` origin. The proven
  project iOS spinlock patch was applied. No guest/JIT allocator redesign
  or revision substitution.
- Build steps `Configure iOS project`, `Build unsigned arm64 app`,
  `Inspect build`, `Package unsigned IPA` and
  `Upload unsigned IPA`: **all SUCCESS**.
- Prerequisite no-IPA security policy, source provenance, Apple sanitizer,
  and iPadOS object compilation checks:
  https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38254346034
  **all SUCCESS**.

**Important:** building successfully does not prove runtime correctness.
No automatic migration or crash-recovery scenario in this build has yet
been physically accepted on the user's iPad. Keep main/production
unchanged and test only with disposable research profiles.

### Physical iPad acceptance plan for this artifact

1. Preserve the known-good research IPA, the *original unconverted*
   disposable `Save clé excédentaire.zip`, and the current converted
   save separately. Do not overwrite the production app or personal
   iCloud baseline.
2. Sign/install the *research* IPA as usual. If it is installed as an
   update, remember the existing isolated sandbox may already contain
   the **converted** (0 key / 10,010 coin) state. It is deliberately not
   an eligible source for an additional award.
3. Unpack the untouched disposable original `save-...` snapshot
   directory into the isolated Files-visible
   `PvZ2 Keys Research/PvZ2RestoreInbox`. Force quit/restart,
   explicitly accept the existing v165 `Restaurer` dialog.
4. Confirm an integrity-verified `prelaunch` snapshot precedes any
   migration prompt. For a *fresh unconverted* Egyptian profile 2 with
   all five gates open, expect explicit
   `KEYCONV — sauvegarde expérimentale` choices `Ignorer` and
   `Convertir uniquement le profil 2`. Test Ignore first if desired:
   startup must preserve the original wallet/key state.
5. Restore the untouched original again for the conversion test;
   choose only experimental **profil 2**. Expect 1→0 Egyptian keys,
   9,010→10,010 PvZCoins, all five gates still unlocked and the
   research gameplay/map rendered normally.
6. Force quit/relaunch **without restoring** and check persistent
   0 keys / 10,010 coins and no second +1,000 award or conversion prompt.
   Check bounded `[KEYCONV PRELAUNCH]` log lines in
   `pvz2forios-probe.log`. If any crash occurs, preserve the full
   log plus iOS `.ips` report.
7. **Later/isolated safety suite only:** controlled prelaunch process
   interruption and journal-recovery tests on disposable saves. Avoid
   force-killing a real account while a two-image write is underway.

If the restore/preview is refused on-device, do not work around the
fail-closed guard; inspect the full log, profile identity/slot and
unmodified original archive before proposing any code changes.


## iPad initial launch failure — re-signed KEYOBS bundle identity (2026-10-12)

**Physical-device observation:** the first KEYCONV research IPA
(`b398de49b1e42adf8c1cba39ced4ee87f71173e9`,
[Actions #38254470277](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38254470277))
immediately displayed:

> KEYCONV — démarrage interrompu / KEYCONV réservé à l'application de
> recherche / KEYCONV : sauvegarde non vérifiée. Lancement bloqué.

Source-level root cause: `ResearchBundle()` in
`platform/ios/src/keyconv_prelaunch_ios_adapter.mm` compared the
*runtime* `NSBundle.mainBundle.bundleIdentifier` to exactly
`com.puissantsy.pvz2forios.keyobs`. GitHub build's unsigned
`Info.plist` carried that exact ID, but the runtime check returned false
on the physically installed/signed IPA. A signing/hosting-time bundle
identity change is the leading explanation; the exact post-sign
identifier has not been recovered from a device log. No recovery, native
save load or conversion was entered by this rejected launch, based on
the displayed branch path.

**One grouped correction** (no production change):
- Explicit research-only compiler definition
  `PVZ2_KEYCONV_RESEARCH_BUILD=1` on the research CMake target; adapter
  emits a compile error if built without it.
- An independent Info.plist research marker
  `PVZ2KeyconvResearchBuild=true` and immutable logical original
  identifier `PVZ2KeyconvOriginalIdentifier` baked into the
  **unsigned KEYOBS IPA**. These nonstandard plist fields survive
  ordinary bundle-ID re-signing without relying on the installation ID.
- A pure C++ identity policy that accepts the canonical KEYOBS bundle,
  a signer-appended suffix, or a wholly replaced runtime ID only when
  the verified build marker is present. Explicitly refuses known
  production PvZ2 IDs even with a marker. The existing prelaunch
  backup, consent, native profile identity and stopped-guest transactional
  checks remain unchanged.
- Privacy-safe `NSLog` diagnostic for missing marker or re-signed
  bundle ID. No raw user profile, coins, RTON, or device IDs are printed.
- New C++ synthetic policy test and additional static UI/CMake checks.
  Original save ZIP was inspected **read-only** on the assistant side:
  two native profile slots; the second holds Egyptian `kc=1`,
  `pp.dat.c=9010`, and independent `snapshot2.dat.c=7750`.
  All five Egyptian gates have the open state in both copies.
  These original images remain strictly private and untouched.

**Gate before next IPA:**
[GitHub Actions #38263388274](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38263388274)
PASS — all Ubuntu native/RTON/policy suites, Apple/CommonCrypto
crash tests, full arm64 iPadOS launcher/backup/adapter object compilation,
and exact historical Dynarmic source preflight. The prior CI error
came only from missing `-DPVZ2_KEYCONV_RESEARCH_BUILD=1` in the standalone
object-test command and was corrected. No additional IPA build before
the complete set passed.

**On-device retest:** signed research IPA only, do not remove old
research sandbox or touch production, first open without restoring.
If the KEYCONV prompt now appears after restoring a fresh **original**
unconverted experimental snapshot, select only profile 2.
Confirm +1000 coins/zero keys and second cold start. If the marker is
stripped by the signing tool, the launch must continue to fail closed;
preserve the complete probe log and signing method before changing
identity rules again. Never disable the runtime isolation entirely.
