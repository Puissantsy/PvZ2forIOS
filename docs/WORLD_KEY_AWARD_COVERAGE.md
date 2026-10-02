# Native key-award coverage and read-only iPad instrumentation contract

Scope: **exact** supplied PvZ2 Android 1.5.252752 ELF, SHA256 `f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f`. Local tests, NOT observed live iPad award execution. This branch is deliberately separate from the concurrently staged v170 synthetic offline-store entitlement correction. No game binaries, saves, or assets belong in GitHub.

## Newly discovered: 13 DIRECT AddWorldKeys callers, not two

A full ARM-mode `.text` scan finds **13** direct `BL 0x42CCC8` callsites. Static register-setup witnesses:

| Caller RVA | Quantity source | Preliminary classification |
|---|---|---|
| 0x161E60 | register r11 | generic award dispatcher, key case |
| 0x176404 | immediate 1 | independent one-key grant |
| 0x357128, 0x357170, 0x3571B8, 0x357200, 0x357248 | immediate 100 | repeated five-world bulk grant paths, **possibly debug/QA; not proven** |
| 0x35AAD8, 0x35AB20, 0x35AB68, 0x35ABB0 | immediate 1 | four other one-key paths, **proven static quantity only** |
| 0x479620 | object +0x1C | strong `PresentTypeKey`-style grant candidate: object+0x18 supplies world-string address, object+0x1C quantity |
| 0x796540 | immediate 1 | separate one-key path |

**Do not blindly replace every call to `AddWorldKeys`.** These paths may represent different game semantics; the generic dispatcher and type-specific method could represent the *same logical award at different moments*. Actual caller order must be established on the real iPad to prevent double-conversion. The scan covers direct ARM-mode `BL` only, not indirect `BLX`, virtual dispatch, Thumb code or arbitrary guest instruction patching.

The generic dispatcher beginning at `0x161AA4` uses an ARM table, indexed by `discriminator - 3`. The statically verified table routes discriminator **11** to `0x161C70` (native coins at `0x161CAC`) and discriminator **13** to `0x161E20` (world keys at `0x161E60`). These are numerical native discriminators; do not assert `PresentType`'s source enum declarations without a runtime trace.

## Native saved world-map events: fixed-width prefix

The original key-gate opening at `0x5B8454` spends a map gate's key cost and `0x5B8470` calls the event-state writer with value **3**. The original writer `0x42D270`:

- looks up the event through profile+`0x24` (vector begin), with end at +`0x28` and capacity at +`0x2C`;
- when an entry exists, advances by index times **24** bytes and compares/monotonically raises the DWORD at record+`0x04`;
- when inserting, writes a BYTE at record+`0x00`, a HALFWORD at +`0x02`, and a DWORD state at +`0x04`, then advances by 24 bytes.

This is strong static evidence for a **read-only candidate** `[W:u8, reserved:u8, E:u16 LE, S:u32 LE, ... 16 more bytes]` (interpretation of W/E as map-event IDs should be compared to an iPad pre/post gate opening before enabling conversion). Do not assume all other 16 bytes are understood. The helper `tests/staging/world_key_event_view.hpp` accepts only a trusted, already bounded copy of the native vector, caps records at **1,024**, never accesses live pointers and never writes guest memory. Feed its result to the separately tested fail-closed `Evaluate()` policy.

## Preferred ONE grouped opt-in read-only iPad probe (after ongoing v170 acceptance)

1. Validate the **exact ELF hash**, that all 13 registered callsites have expected BL destinations, and that the active profile and any vector pointers are mapped/readable (begin <= end <= capacity, 24-byte alignment, <=1,024 records). Never call another native function from an unsafe nested guest callback.
2. At the normal stable guest boundary, log a bounded copy of the active profile's gate records **once on each meaningful change only**. For each known gate ID, emit world, event, candidate state, and missing/duplicate flags; log every unrecognized or ambiguous case *without* treating it as completed.
3. At any verified callsite reached during an actual new key reward, capture callsite guest PC, LR, world argument pointer/string **with length cap**, key quantity, profile identity, current keys and current coins **read-only**. Correlate the 13 callsites to actual chest/quest/level actions instead of assuming all are player drops.
4. At one **paid key-gate opening** on a backed-up disposable profile, capture pre/post candidate vector state plus the ordinary native `pp.dat` after the game writes it. Confirm that the correct gate transitions **1→3** and that the corresponding world-key amount decreases by its RTON cost.
5. Correlate the original `PresentRecord` UI type and display timestamp with native award dispatch/type-specific grant to choose an interception **before** both the award and visual presentation. Do not ship post-credit coin grants displaying a key icon as a finished fix.
6. Replay the same chest-close, level-restart, cold-launch and profile-switch scenarios, checking that each award is counted **exactly once** and that an unresolved/inactive world retains the original key reward.

Suggested one-line bounded trace: `KEYOBS phase=pre_award site=0x00161e60 profile=<local> world=egypt quantity=2 gates=13:3,23:3,33:3,39:3,41:3 keysBefore=<n> coinsBefore=<n> originalReward=<name> decision=ELIGIBLE_READ_ONLY`. No personal profiles, original raw saves or APK in public build artifacts.

## Reproducible offline preflight (does not build IPA)

```sh
python3 tools/verify_world_key_arm.py --elf /YOUR/OWN/libPVZ2.so
python3 tools/verify_world_key_award_coverage.py --elf /YOUR/OWN/libPVZ2.so
clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Itests/staging \
  tests/staging/test_world_key_conversion_policy.cpp -o /tmp/keypolicy && /tmp/keypolicy
clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Itests/staging \
  tests/staging/test_world_key_event_view.cpp -o /tmp/keyevents && /tmp/keyevents
```

Original snapshot tests are **not** proof that the next unmodified iPad save has the same live layout. No IPA, original runtime patch, asset change or user-save mutation is included here.
