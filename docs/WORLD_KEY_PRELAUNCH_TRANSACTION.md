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
