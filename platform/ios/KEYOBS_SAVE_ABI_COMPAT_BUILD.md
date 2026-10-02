# KEYOBS corrected native build — complete grouped source state

The first native attempt of the read-only KEYOBS log/snapshot fix failed to
compile because the reused v165 restore engine did not export the v166 helper
`PVZSaveHasLocalSave`. No IPA was uploaded. This follow-up adds its exact
non-mutating existing-root test to both `save_backups.hpp` and
`save_backups.mm`, and the offline wiring check now rejects missing
definitions before Xcode.

Pre-build checks passed:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37065319048

Bundled changes from the first, failed build and this ABI correction:
- All KEYOBS award/gate/installation markers go to the unfiltered
  `AppendDiagnostic` path;
- the verbose irrelevant `V144 SELECTION DRAW` lines are omitted in KEYOBS
  mode only;
- the current **isolated** KEYOBS profile is SHA-256-snapshotted on the next
  launch before JIT starts, so the already-opened gate may be verified from
  this saved copy without replaying Egypt Day 3;
- v165 snapshot engine plus v166 presence-check helper compile together.

Never bundle APK/OBB/user-save bytes; never overwrite the ordinary PvZ2 app.
The experimental IPA still only observes keys, never credits coins.
