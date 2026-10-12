# KEYCONV: unused original world-key stock reconciliation (staged, NO MUTATION)

## Device-proven baseline

The physical iPad log `pvz2forios-probe(20261011-200804).log` proves new
one-key Egypt rewards become +1000 coins once five gate events are state 3.
It does **not** prove conversion of keys already saved in the native profile.
The existing working KEYCONV IPA must remain installed until a new probe is
built and tested.

User-protected iCloud snapshots:
- pre-last-gate Egypt profile: **6 keys**, last gate requires **5 keys**;
  restore into an isolated research profile, spend 5 through the original game,
  leave 1 unused key and all Egypt gates open;
- second profile: 10,000 PvZCoins, kept for repeated premium-store regression.
Neither backup is included in this repo. Neither is to be modified in place.

## Exact original ARM source witnesses

Compared to user-supplied APK's `lib/armeabi-v7a/libPVZ2.so`, SHA256
`f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f`.
The `tools/verify_world_key_arm.py` source verifier now asserts exact
instructions at these RVAs:

| Native helper | RVA | Validated behavior |
| --- | --- | --- |
| GetWorldKeys | `0x42CC54` | Looks up bounded per-world vector `profile+0x7c/+0x80` |
| AddWorldKeys | `0x42CCC8` | Adds counts by native world-string lookup, caps at 99 and notifies |
| SpendWorldKeys | `0x42CEEC` | Finds native 8-byte `WorldSpecificKeys` entry, subtracts amount, clamps to 0 and notifies |
| SetCoins | `0x42E5AC` | Previously proven native coin setter/notifications |
| Native world strings | e.g. `0x42CC74`, `0x42CF0C` | libstdc++ COW string length stored at `chars-12` |
| Original gate-open | `0x5B8454`, `0x5B8470` | Native key spend and event state transition to 3 |

The source evidence establishes layout **in the original ELF**. The on-device
pointers and saved values still need active KEYCONV instrumentation verification.
The new `wsk={egypt:N,...}` logger is read-only and bounds/checks vector
stride, COW length, world name, count 0..99 and duplicate worlds. It runs at
native active-profile initialization (once per profile apply), and also during
genuine gate and award events.

## Explicit conversion policy, no native writes yet

`tests/staging/world_key_stock_reconcile.hpp` returns a `StockPlan`, not an
action. For each world, it must verify:

1. Current world is one of the verified active worlds (Egypt/Pirate/Cowboy).
2. ALL exact unique native key gates are state >= 3.
3. Bounded native existing stock is 1..99; 0 is a no-op.
4. `coinsBefore + stock * 1000 <= 0x7fffffff`.
5. Current profile, wallet and world-key entries are actually readable.

Desired disposable-account test: backup precondition Egypt=6,
gate not open => no conversion; native 5-key door spend => Egypt=1,
all gates open; planned conversion => Egypt=0, coins increase by 1000.

`InspectSettlement` classifies observed *persisted* post-restart state into:
- NotYetApplied: original key count and coin balance;
- FullyApplied: no remaining keys and full target coins;
- PartialKeyDebit: keys are gone but coins unchanged (UNSAFE);
- PartialCoinCredit: coins credited but keys still present (UNSAFE);
- UnexpectedState: any intermediate/mismatched balance (UNSAFE);
- InvalidPlan: never act.

No branch under this planner writes guest memory, calls guest native APIs,
edits `pp.dat`, or changes the main Probe/production mode.

## Native migration preconditions, not yet shipped

**Do NOT** implement a naive pair of calls
`SpendWorldKeys(profile,world,N); SetCoins(profile,C+1000N)`
across normal independent game saves: an interruption can persist only one
side, losing keys or duplicating coins on retry.

Before enabling native migration:
1. Physically verify `KEYCONV STOCK_PROFILE ... wsk={egypt:N,...}` for the
   *actual* iCloud restored profile, plus exact save state before/after gate.
2. Define an isolated, durable, profile-id-bound backup/journal in the host;
   refuse to start without a complete valid original checkpoint.
3. Identify native save notifications and all V128 `pp.dat` flush/backup
   behaviors, and provide a single durable profile-level commit barrier
   across guest native spend+credit operations.
4. Before/during/after the transaction verify native keys, native coins,
   current profile identity and exact original save, not UI counters alone.
5. On interrupted restart, inspect the durable snapshot and journal. Do not
   blindly retry partial or diverged states. Retain the original backup for
   explicit rollback rather than performing undocumented raw-save changes.
6. Ensure repeat loads, profile switches and app reinstall do not replay a
   completed conversion. Preserve the original guest notification paths.
7. Keep read-only KEYOBS parent and production Probe untouched.

## Unit test and device status

The isolated world-key tests (eligibility, event decoder, stock plan, crash
outcome classification) run in `.github/workflows/verify-world-keys.yml`.
They are **not** proof of a crash-atomic save transaction.

The first proposed IPA with a read-only stock log and multi-key policy still
cannot be built while the historical `LiveContainer/dynarmic@c97c525e`
source is unavailable. The workflow now caches the exact historical git
checkout after a successful fetch, checks SHA and leaves allocator unchanged;
it does not claim a cache exists before one is actually created.


## Latest no-IPA regression

https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38175743041
passed **33** reward policy checks, **7** read-only event decoder checks and
**37** stock settlement checks under UBSan, along with ARM tail-call and
Dynarmic source-wiring verifications. The runtime now logs a bounded
`KEYCONV STOCK_PROFILE` at native active-profile initialization, but the
change has not yet been compiled to an IPA or verified on the physical iPad.
The original APK's exact hash and the native stock/spend ARM words have
been checked locally; native save transaction atomicity is still unknown.


## October 12, 2026: shared decoder and source-save audit

The KEYCONV runtime no longer owns a separate ad-hoc WorldSpecificKeys
record decoder. `tests/staging/world_key_stock_view.hpp` provides the
read-only bounded 8-byte LE `[chars, count]` native record decoder used
both by the runtime and standalone unit tests:
- 0..16 records; 0..99 keys; reject short/unaligned vectors;
- original native COW world string length from `chars-12`; readable
  terminator at exactly `chars+len`;
- whitelist Egypt/Pirate/Cowboy/Future/Dark; reject unknown/duplicate names;
- no calls to SpendWorldKeys, SetCoins, or raw save writes.
`WorldKeyReadOnlyStockSnapshot` keeps all guest pointer checks and provides
a string-reader callback only, while the shared decoder verifies every
entry. `KEYCONV STOCK_PROFILE` still logs at the native active profile
initialization, without requiring the user to win another key.

V128 host persistence source audit:
`v128_flush_file` serializes the writable guest user file into
`host.tmp`, fflush/fsyncs the temp, and renames it over the host path.
Guest fflush/fsync/fclose/close can independently trigger this operation.
These are per-file atomic replacements, NOT a transactional bundle of
SpendWorldKeys and SetCoins. Furthermore, the source does not fsync the
containing directory after rename. Therefore crash/power-loss atomicity
of a multi-operation migration is NOT established. Stock settlement
remains strictly observation/planning-only pending a durable recovery
protocol and iPad validation.

CI: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38205300169
succeeded:
- 33 award policy assertions,
- 7 gate-event snapshot assertions,
- 13 read-only native stock decoder assertions (UBSan),
- 37 existing stock reconciliation/interrupt assertions (UBSan),
- source-wiring, ARM tail-call and fail-open regression checks.
90 unit assertions + integration/static checks pass, no IPA produced.
