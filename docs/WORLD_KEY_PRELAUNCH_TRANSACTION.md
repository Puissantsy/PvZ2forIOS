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

A native research-only prelaunch settlement hook would belong **after**
the confirmed restore and successful prelaunch snapshot but **before**
starting the guest/JIT. It must have an explicit one-shot/opt-in gate and
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
