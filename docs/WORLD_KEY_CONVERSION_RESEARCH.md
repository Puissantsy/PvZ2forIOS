# World-key recycling research — PvZ2 1.5.252752

**Research-only branch; no runtime hooks and no IPA.** Based on the project owner's locally supplied APK/metadata. Never commit the APK, OBB, `libPVZ2.so`, original assets or user saves.

## Contract

For a **new** world-key reward, if **every** known `key_gate` in that world is already open, convert each newly awarded key into **1,000 PvZCoins**, without granting keys. Do not refund old keys. Unknown/incomplete worlds or states preserve normal keys. The `future` world is `ComingSoon` in the inspected RTON and must be explicitly confirmed active.

| World | W | key_gate event ID (cost) |
|---|---:|---|
| egypt | 2 | 13 (3), 23 (4), 33 (5), 39 (4), 41 (1) |
| pirate | 3 | 15 (4), 23 (4), 28 (3), 32 (5) |
| cowboy | 4 | 14 (4), 22 (5), 28 (4), 36 (3) |
| future | 5 | 13 (5), 14 (4), 15 (3), 16 (4) |

The user's original metadata contains each world's 1/2/3-key `PresentTypeKey` variants plus `coinpack_large=1000`. Observed saved `PlayerInfo.objdata.wm` has `W,E,S`; available private profiles have **closed** Egyptian gates (`S=1`), so a physical-device pre/post gate opening differential still matters.

## Verified ARM32 evidence (exact Android ELF only)

Local exact ELF SHA256: `f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f`.

| BL callsite | Native destination | Static interpretation |
|---|---|---|
| 0x161CAC | 0x42CB20 | Present handling: add coins with native notifications |
| 0x161E60 | 0x42CCC8 | Same present handler: add named-world keys (dynamic quantity) |
| 0x176404 | 0x42CCC8 | Additional key grant path, quantity one |
| 0x5B8454 | 0x42CEEC | Key gate spends key cost read from map item +0x2C |
| 0x5B8470 | 0x42D270 | Same gate open sets saved map event state to **3** |
| 0x375A74 | 0x42E680 | Read profile's original coins |
| 0x375A80 | 0x42E5AC | Write profile's original coins |

Other original native helpers: `GetWorldKeys=0x42CC54`, `AddWorldKeys=0x42CCC8`, `SpendWorldKeys=0x42CEEC`, `UpdateWorldMapEvent=0x42D270`. Profile's per-world key vector is at `+0x7C/+0x80`; each entry is a world-string pointer plus DWORD count, clamped to **99** by the native add routine. The event updater monotonically raises `S`; the actual gate-opening call supplies `S=3`. Thus `S>=3` is a **static candidate** for an opened key gate, subject to the physical-iPad save differential before a live patch.

The native present handler has separate coin and key calls: this is a promising narrow award-level interception, but additional `0x176404` awards must also be covered. The earlier `PresentRecord` choice and chest animation remain to trace. A hook at the generic key accumulator alone risks incorrectly displaying keys when awarding coins; no such hook is shipped here.

## Safe integration sequence

1. Keep research isolated from concurrent v170 offline-store and backup experiments.
2. Add one grouped **read-only** guest probe to the last physically validated branch: track actual new key grants at both paths, original reward identity, active profile/world, every gate state, old/new key count, old/new coins, `pp.dat` persistence and guest PC/LR.
3. Verify a **single key-gate opening** with a protected disposable profile: compare the original pre/post `wm[W,E].S`, `wsk` and `c`.
4. Locate reward selection/presentation to show actual coins when recycling; only enable mutation once source and animation are consistent.
5. Preserve native persistence, original untouched modes, exactly-once reward attribution, and all unmodified legacy save/profile behavior. Unknown/ambiguous data must fall back to the game's existing key award.

The staged standalone `world_key_conversion_policy.hpp` contains **only** an isolated non-mutating eligibility/amount decision, not the runtime interception.

## Standalone regression

```sh
clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Itests/staging \
  tests/staging/test_world_key_conversion_policy.cpp -o /tmp/test_keys &&
/tmp/test_keys
```

Locally, **21 pure eligibility tests passed**. Passing these does not establish iPad runtime behavior.