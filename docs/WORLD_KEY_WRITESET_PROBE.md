# KEYCONV iPad acceptance — native profile V128 write-set observer

## Purpose / source of truth

The original physical iPad `pvz2forios-probe(20261011-200804).log`
already proved an **incoming** Egypt key is converted into +1000 coins
after all Egypt gates become native state 3.

**Existing saved keys** remain unconverted. The iCloud save at **six
Egypt keys with one five-key gate still closed** is the authoritative
future regression fixture. This note does not claim to have accessed,
restored or changed that cloud backup.

The active KEYCONV branch has a new, read-only V128 write-set observer.
It is **not yet built into a new IPA** because historical Dynarmic is
unavailable from the anonymous GitHub Actions runner.

## Changes staged

- `tests/staging/world_key_save_write_observer.hpp` strictly matches
  only three historical guest save paths ending in:
  `/No_Backup/pp.dat`, `/No_Backup/snapshot2.dat`, and
  `/No_Backup/local_profiles`. No other VFS paths are instrumented.
- `part_01.inc` stores the last observed bytes for only these profile
  files, at most 1 MiB per file, and counts changed, unchanged and
  unknown-baseline writes; disabled in non-KEYCONV modes.
- `part_06.inc` captures initial bytes after successful disk load and
  compares the **entire byte vectors** on each successful V128 flush.
  The existing temporary-file, fsync and rename save path is preserved.
  No new host IO and no save writes occur from the observer.
- Existing `V128 USERFS FLUSH` diagnostic lines gain
  `frame=<n> sameAsPrior=YES|NO|UNKNOWN flushUs=<microseconds>` for
  those three files in active KEYCONV mode. A first write without a
  loaded baseline is UNKNOWN, **not** automatically classified changed.
- `part_02.inc` also prints
  `KEYCONV V128 PROFILE WRITESET SUMMARY flushes=... changed=...
  unchanged=... unknown=... totalMs=... maxUs=...`.

This directly distinguishes repeated identical saves from actual
changes and gives flush latency without assuming writes cause a game
FPS drop. It does not claim durable atomicity across multiple files.

## Future device sequence — do not overwrite original iCloud backups

1. Install the **next successful KEYCONV research IPA** over the same
   isolated research app, preserving its distinct bundle ID. Do not
   replace the validated production Probe.
2. Restore a *copy* of the six-key pre-last-door profile. At startup,
   capture `KEYCONV STOCK_PROFILE ... wsk={egypt:6,...}`, or capture
   the explicit INVALID status without interpreting it as six keys.
3. Open the existing five-key gate via the game's original UI. Confirm
   native state 2 -> 3 and world stock 6 -> 1 from the complete log.
4. Record each `V128 USERFS FLUSH` for the three profile files with its
   frame number, exact prior comparison, elapsed microseconds and
   ordering relative to `KEYOBS GATE_BEFORE/GATE_AFTER`.
5. Restart the research app to verify the same stock and gate states
   persisted; save its complete log and iOS .ips if a crash occurs.
6. Only then integrate a bounded, pre-guest-load recovery barrier for
   `world_key_save_bundle_journal.hpp`, with deliberate native guest
   quiescence and complete file write-set proof, before enabling any
   old-key coin settlement. Multiple original save files may be
   relevant; no `pp.dat`-only shortcut is allowed.

## Test status and blocker

Pure unit tests: 33 awards + 7 gate events + 13 native stock decoding +
37 saved-key reconciliation + 31 single-file journal + 59 multi-file
journal + 17 write-set path filter = **197 checks**.
The static host-wiring verifiers also PASS:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38208827380

Source recovery workflow:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38208937421
MacOS runner tested the anonymous upstream and received:
`remote: Repository not found.`
`fatal: repository 'https://github.com/LiveContainer/dynarmic.git/' not found`.
Therefore no exact source was cloned or cached and **no new IPA** was
built. A public search index may still list the repository, but the
live macOS git check is the relevant build evidence.
