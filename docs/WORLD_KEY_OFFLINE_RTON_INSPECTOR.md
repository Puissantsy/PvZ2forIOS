# PVZ2 1.5.252752 original-save RTON inspector (read-only)

## Why this unblocks a separate experiment

The current physically working KEYCONV iPad IPA already converts *new*
Egypt key awards into +1,000 PvZCoins when all five native key gates are open.
Old world keys stored *before* opening the last gate remain stranded.

The exact proven LiveContainer Dynarmic c97c commit is now missing from
anonymous GitHub access, so we cannot build another safe KEYCONV IPA yet.
There is nevertheless an **independent offline route** for investigation:
the game's `No_Backup/pp.dat` and `snapshot2.dat` are unencrypted
`RTON\x01\x00\x00\x00` containers. They serialize the native
`PlayerInfo.objdata` profile including:

- `c`: native coin balance;
- `wsk`: saved world-specific key vector;
- `wm`: saved map events (W/E/S: world/event/state).

These are confirmed by decoding the two real user-provided Snow Pea save
archives from 2026-10-01 in the current project Sources. This discovery
does **not** require a new Dynarmic build or a device runtime change.

## Real private snapshot observations (do not commit the source archives)

| Snapshot | PlayerInfo objects | Balances | `wsk` |
| --- | ---: | --- | --- |
| Test 1 Snow Pea | 1 | profile slot 0: 50,310 | empty |
| Test 2 claim Snow Pea | 2 | slot 0: 50,310; slot 1: 270 | empty for both |

Both files' `pp.dat` and `snapshot2.dat` were **byte-identical within
each snapshot**, and both archives passed all checksum checks in their
`snapshot-info.plist` inventories: 9/9 and 10/10 files respectively.

These originals provide reliable evidence for RTON syntax, coin and gate
metadata, and backup integrity validation. **They do not validate the
layout of a nonempty `wsk`** because none of the three test player
profiles carried a saved world key in those archives.

## New tool

`tools/inspect_pvz2_rton_save.py` accepts a local PvZ2forIOS snapshot
ZIP containing one `No_Backup/pp.dat` and optionally `snapshot2.dat`.
It performs only reads. It:

1. rejects invalid RTON framing, malformed token streams, overly large
   arrays/strings, duplicate object keys, bad cache indices and unsupported
   tags;
2. decodes the native `PlayerInfo` without emitting player names or UID;
3. reports coins, saved known key-gate states and guarded key vector data;
4. compares `pp.dat` and `snapshot2.dat` byte-for-byte;
5. verifies the optional `snapshot-info.plist` inventory: path safety,
   per-file sizes, SHA-256 digests, duplicate names and 128 MiB total cap;
6. never modifies the ZIP, `pp.dat`, `snapshot2.dat`, files in iCloud,
   or the original game.

A nonempty key vector with an unfamiliar schema is reported as
`unknown_schema`, **not** guessed into an editable field.

Run locally against a **copy** of an existing private backup:

```bash
python3 tools/inspect_pvz2_rton_save.py "/private/path/to/snapshot.zip"
```

It emits a JSON **inspection**, not a patched save.
The supplied backup should remain private; avoid pushing personal
save contents, archive names or profile names to the public GitHub repo.

## Candidate offline surplus conversion (not yet enabled)

The user's untouched iCloud reference profile has **six Egypt keys** and
the final Egypt gate costs five keys. A disposable restore should
allow observing:
- before: Egypt=6, last gate still closed;
- after original gate purchase: Egypt=1, all Egypt gates state 3;
- hypothetical one-time conversion: Egypt=0 and coins +1000.

A safe experimental *offline* converter would need:
1. decode and validate the actual **nonempty `wsk`** layout and
   profile identifier from that backed-up profile (not available yet);
2. preserve *all unrelated fields and exact token/cache references*;
3. construct a full verified target image for both `pp.dat` and
   `snapshot2.dat`, accounting for expected game save semantics;
4. update snapshot manifests and SHA-256 inventories if the backup
   format is used for restoration;
5. retain an immutable original copy and require explicit disposable
   profile restoration/testing;
6. prove after iPad restart that coins/keys persist and that rerunning
   the migration does nothing.

We have **not** met these prerequisites; no offline patching tool is
activated or recommended for real player saves yet.

## Independent tests

`tests/staging/test_readonly_rton_save.py` contains synthetic fixtures
and failure cases (six-key and post-gate examples, bad cache, duplicate
mapping, malformed framing, wrong arrays, mirror mismatch, corrupted
SHA-256 manifest, traversal paths and unsupported schemas). No
real save files are part of the public CI.

RTON token definitions cross-checked with RETON's public format
documentation. The authoritative runtime evidence is still the original
PvZ2 ELF and physical iPad logs.


## Further progress — in-memory edit and disposable archive prototype

The research branch now includes two new components:

- `tools/experimental_keyconv_rton_memory.py`: indexes the original RTON
  integer-token byte spans, then changes **only** the selected PlayerInfo
  `objdata.c` and Egyptian `objdata.wsk` count **in memory**. It
  requires verified W2 gate states 13/23/33/39/41 >=3, a single
  unambiguous Egyptian key entry, saved keys 1..99, a wallet amount that
  cannot overflow signed 32 bits, and a supported original numeric token
  type. It redecodes the entire resulting RTON and checks every
  unrelated field is unchanged. A second attempt after count 0 is a no-op.
- `tools/experimental_keyconv_rton_archive.py`: exports to a **new,
  explicitly named disposable ZIP** only. It requires a fully verified
  `snapshot-info.plist`, an identical `pp.dat`/`snapshot2.dat`
  pair, a unique original PlayerInfo path, an explicit zero-based
  profile slot, and an explicit `--ack-disposable-only` flag. The
  exporter updates both copies of the same RTON and their manifest
  SHA-256/size entries. It then reparses the output, validates the
  entire inventory, and compares all unrelated archive bytes. It
  refuses pre-existing output paths and never overwrites the source.

**Warning:** this is a research utility. Although it generates a
structurally validated ZIP under synthetic tests, it has **not**
been used on the user's live six-key snapshot or accepted/rebooted on
the physical iPad. The actual saved layout of a NONEMPTY `wsk`
is not yet confirmed. Do NOT import the generated experimental ZIP
into the primary game profile or replace your untouched iCloud backups.

Syntax of the guarded experimental invocation, for future work on
a **disposable, separately restored test profile only**:

```bash
python3 tools/experimental_keyconv_rton_archive.py \
  /private/path/to/COPIED_AFTER_GATE_OPEN.zip \
  --profile-slot 0 \
  --output /private/path/to/EXPERIMENTAL-key-conversion.zip \
  --ack-disposable-only
```

Even this command will REFUSE conversion if the key gate is still
closed (the original six-key/five-key-door backup is a PRE-gate fixture),
if the manifest/mirror differs, if the key layout is ambiguous, or if
the result cannot be verified. It remains an *experiment*, not a
recommended production migration.

### New green tests

https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38211868074
successfully executed:

- 197 existing C++ checks across award policies, native stock,
  recovery journals and V128 profile write-set paths;
- 23 Python tests of read-only RTON inspection and manifest integrity;
- 9 Python tests of exact in-memory two-token currency transformation;
- 9 Python tests of disposable mirrored ZIP export, manifest rebuild,
  refusal to overwrite, closed gates and repeated conversion.

**238 combined test cases/checks**, plus static ARM/runtime wiring
verifiers, all pass. No iOS build or device test occurred.
