# KEYCONV multi-file save settlement — 2026-10-12

## Why the single-file prototype must NOT ship

Two *private, user-supplied* October 1 Snow Pea save snapshots were inspected
locally, without uploading any save or personal data:
- Snapshot 1: `No_Backup/pp.dat` and `No_Backup/snapshot2.dat` are
  byte-identical (3,620 bytes each).
- Snapshot 2: those two files are again byte-identical (7,080 bytes each).
- `No_Backup/local_profiles` also differs between the snapshots
  (228 vs 284 bytes). These captures span more than a single transaction.
  Therefore they do NOT prove exactly which file each individual award edits.

The physical KEYCONV run `pvz2forios-probe(20261011-200804).log`
records 307 V128 flushes of `pp.dat` in that session, plus observed
flushes of `snapshot2.dat`, `local_profiles`, loot and draper files.
Constant file *size* does not prove identical serialized content.
This rules out shipping an `pp.dat`-only journal as general crash safety.

## What is implemented (research / off-device only)

`tests/staging/world_key_save_journal.hpp` and
`tests/staging/world_key_save_bundle_journal.hpp` are file-system
prototypes; **neither is included by the iOS runtime**.

`SaveBundleJournal` stages 1..8 *existing regular files from the same
folder* into a private journal directory. It rejects symlinks, path
traversal and duplicate names, caps each file to 64 MiB, and verifies
bounded pre/post images (FNV-1a: accidental-corruption detection only,
not a cryptographic or malicious-tampering guarantee).

It writes and fsyncs the old and target images, publishes a manifest,
and fsyncs their parent directories before beginning file replacement.
Each replacement writes an exclusive temporary image, fsyncs, renames
over its destination and fsyncs the parent directory. An explicit,
fsynced commit marker is published atomically only after all new files
have been installed. The transaction journal is then cleaned up.

Recovery MUST run before allowing the original game to load any
profile, and before any V128 guest write. It handles:

- No journal: proceed normally.
- Journal without manifest and only recognized staging files:
  preparation was interrupted before any write; remove staging files.
- Manifest without committed marker: verify every live file matches
  exactly either its old or new image; restore **all** pre-images,
  with durable rename and retry if another crash interrupts recovery.
- Valid committed marker: require **all** target images to match;
  retain those images and clean the journal.
- Unknown filename, corrupt checkpoint/marker, wrong profile,
  unexpected file state or symlink: **CONFLICT, NO AUTO-REPAIR**.

A completed transaction is never automatically replayed.

## Why this is not an iPad-ready feature yet

This is a file-system recovery prototype, NOT an implementation of the
native game operation or a claim of atomic multi-file guest saves.
Future integration needs all of the following device evidence:

1. Exact native profile reading and key stock `KEYCONV STOCK_PROFILE`
   on the restored 6-key/last-door research profile.
2. A bounded V128 write-set capture between a key spend and all
   subsequent wallet/save notifications. Its complete set must include
   *every* written/created/deleted file, not only `pp.dat`.
3. A quiescent guest boundary: suspend guest threads and all V128
   flushes before calling the two original native APIs, then serialize
   target files into staging without leaking partially converted files.
4. An app-startup recovery barrier before any original save can be
   loaded, and an unambiguous profile-id association.
5. An on-device process-crash and iOS-kill test on a disposable profile
   proving old-or-new consistency, correct key/coin amounts, no
   double settlement, no broken cloud snapshots, and no entitlement
   regressions.
6. Integrity checks robust enough for production needs; the current
   noncryptographic FNV-1a checks are laboratory-only.
7. Any new/deleted files or cross-folder writes require a generalized
   manifest; the current bounded prototype only handles existing
   regular files within a single directory.

Only after these pass should migration be enabled. It must stay off in
the production Probe and in the current physically working KEYCONV
installation. The user retains untouched iCloud backups at six Egypt
keys before the last five-key gate and at 10,000 PvZCoins.

## Build and tests

`.github/workflows/verify-world-keys.yml` compiles the isolated
C++ bundle/journal tests with AddressSanitizer + UBSan. Simulated
interruption points include every installed file, interrupted rollback,
crash during preparation, wrong profile, checksum failure, path
traversal and unexpected concurrent save state.

The Dynarmic historical source `LiveContainer/dynarmic@c97c525e`
is still not accessible via the current GitHub API, and the previous
successful IPA artifact contains neither that source nor its build
tree. No iOS IPA build was attempted with a substituted backend.
