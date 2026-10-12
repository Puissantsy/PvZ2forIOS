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

**239 combined test cases/checks** (including the strict native profile-ID regression), plus static ARM/runtime wiring
verifiers, all pass. No iOS build or device test occurred.


### Native PlayerInfo identity binding — 2026-10-12

A further source investigation decoded `No_Backup/local_profiles` in
both original user-provided private snapshots. Each `PlayerInfo`
contains a native integer `objdata.i`, while
`PlayerInfoLocalSaveData` at the corresponding slot contains
`objdata.ProfileIndex`. Both user snapshots show the IDs matching for
each of the 1 and 2 player slots, respectively.

The experimental archive exporter now REFUSES output unless:

- both `pp.dat` and `local_profiles` are valid full RTON documents;
- the selected zero-based slot exists in both and has the expected
  PlayerInfo/PlayerInfoLocalSaveData classes;
- the selected `PlayerInfo.objdata.i` is a positive integer and equals
  the selected `local_profiles.objdata.ProfileIndex`;
- the preexisting backup inventory is valid and all previous safety
  conditions pass.

The current synthetic archive tests explicitly include a negative
profile-ID mismatch case. This guards against an archive containing
multiple unrelated user profiles; the exporter still requires that
the operator deliberately choose the intended disposable slot.

**Last green CI:**
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38212259281

- 197 existing native/host C++ checks;
- 23 read-only RTON inspection/manifest tests;
- 9 exact in-memory RTON numeric patch tests;
- 10 disposable separate-ZIP backup export tests.

**239 validations/checks** plus static checks pass, no iOS IPA was
built and no real player file was modified.


## Validated against the private October 12 native-key snapshot

The user has supplied the preserved private `Save clé excédentaire.zip`
through Project Sources. We inspected it **locally only**; this file,
its names, profile IDs, hashes and bytes are not uploaded to this public
repository, tests or GitHub Actions.

The saved-key structure is no longer hypothetical:
`PlayerInfo.objdata.wsk` is an array of exact `{wn, kc}` records;
the supplied active player has one Egyptian key, all five Egyptian gate
events are in native state 3, and the selected PlayerInfo native ID
matches the corresponding local_profiles registry entry. The separate
primary and fallback RTON images both confirm this key state.

CRITICAL: `pp.dat` and `snapshot2.dat` are **different valid game
states**, not duplicate images. The latter is an older progress snapshot:
the two decoded trees differ in nine leaf fields, including the wallet
and some native progression events. Both files are checksum-valid in the
11-entry original snapshot manifest. Making them identical would erase
the game's historical fallback state.

Therefore the experimental exporter now:
- parses and validates each RTON separately and requires the same
  intended native profile ID, key quantity and fully opened Egypt gates;
- patches precisely **each original image's own c and kc numeric tokens**,
  preserving its prior wallet/progression difference;
- updates each image's **own** manifest SHA-256 and size entry;
- verifies all 11 original inventory files, all untouched ZIP files,
  both patched RTON documents, and correct distinct mirror state;
- refuses differing native key stock, missing/open-gate evidence, wrong
  profile ID, unexpected token types or output overwrites.

A private disposable ZIP was generated in the conversation workspace and
verified after writing. Its original source was preserved byte-for-byte.
This demonstrates an OFFLINE file transformation and does **NOT**
establish that iPad's live runtime accepts/reloads the modified balance.

**No real/private backup is committed or used as a CI fixture.**
Standalone tests use fake profile names, fake native IDs, and synthetic
RTON values. This feature remains *research-only*.

On-device acceptance still requires a disposable research app profile,
a preserved original iCloud backup, and a complete iPad restart+logs.
Verify the Egyptian key is 0 and the +1000 coins persist; do not
restore the experiment over the user's only good save.


### Confirmed final isolated verification — 2026-10-12

A private, disposable native snapshot was generated from the user's
supplied project-only ZIP on a local container **without committing any
save bytes**. The original package's SHA-256 is unchanged after export.
Both RTON PlayerInfo documents were independently re-parsed after the
precise Egyptian stock/count and wallet transformation, 11/11 manifest
inventory SHA-256 entries passed, and all unrelated files matched
their original bytes. The original primary/fallback divergence remains
deliberately preserved. This is OFFLINE verification only, not an iPad
runtime acceptance result.

The strict public synthetic regression run is green:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38214199959

- 197 isolated C++ checks;
- 23 read-only RTON parsing / manifest tests;
- 9 exact numeric token replacement tests;
- 12 experimental ZIP export, diverged fallback and fail-closed tests;
- static native saved-key ABI, no-overwrite, isolated journal,
  V128 observer, guest JNI and Dynarmic configuration checks.

That is **241** passing isolated checks/tests plus static verifiers.
The research iOS application and original source archives are unchanged.
The next meaningful acceptance is restoration of the *disposable copy*
into a separate iPad test profile, verifying coins and keys before
and after a full process restart.
