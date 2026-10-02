# KEYOBS read-only runtime integration (isolated research branch)

## Source status

**Source staged; one optional diagnostic mode, not a key→coin patch.**
The normal production `main` and the concurrent v170 offline-store/save branches have **not** been changed. In particular this branch does not modify a key balance, award, coin total, `pp.dat`, or the proprietary save hash.

This branch is deliberately opt-in *at build level*: its first selectable diagnostic entry is `ResearchWorldKeyReadOnly` (`KEYOBS`), because the v130 launcher always chooses entry 0. It inherits the validated v151 production qsort/runtimes via `V151Enabled()`; it does not install the v150 cost override. **Do not cherry-pick its diagnostic-mode ordering into main or v170.** The eventual finished feature should have separate configuration and tests.

### Files changed in the existing iOS source

- `platform/ios/src/pvz2_apk_probe.hpp`: distinct diagnostic mode value 200.
- `platform/ios/src/pvz2_apk_probe_parts/part_00.inc`: three unique SVC identifiers, mode descriptor, research-branch first-launch routing.
- `part_02.inc`: research mode inherits the v151 production behavior.
- `pvz2_apk_probe.cpp`: includes the independently tested nonmutating native-event decoder.
- `part_01.inc`: bounded native profile snapshot at +0x24/+0x28/+0x2C, event stride 24, up to 1,024 entries; world-name cap 16; strictly read-only.
- `part_08.inc`: exactly **three** SVC instruction replacements, and only in KEYOBS mode, each guarded by the original 32-bit opcode:
  - `0x42CCD0 MOV r10,r0`: observe ALL direct/indirect `AddWorldKeys` entries;
  - `0x5B846C MOV r3,#3`: snapshot the gate state immediately before the original purchase/opening operation;
  - `0x5B8474 LDR r0,[pc,#0x88]`: snapshot the gate state immediately after the **original** update returns.
- `part_04.inc`: each SVC reproduces the replaced original ARM instruction, preserving the normal native execution; logs the award caller LR/world/quantity/current coins and all known gate states, or snapshots the paired pre/post gate state. First 64 grants and 16 gate pairs maximum, then suppressed.
- `platform/ios/CMakeLists.txt` and `Info.plist.in`: research-only app ID `com.puissantsy.pvz2forios.keyobs` and display name `PvZ2 Keys Research` ensure a **separate iOS data sandbox**, avoiding overwriting production/v170 saves. This separate app needs its own user-supplied APK+OBB and AltStore signing slot.

All 3 original ELF instructions and the LDR target were rechecked against the exact supplied `libPVZ2.so`. The existing 13-direct-BL scan is retained. The common native function entry can also capture **indirect** callers, which a static direct BL scan cannot guarantee to enumerate.

## Root cause targeted

We have not yet seen an iPad grant/open transition with every gate opened. The original binary shows the relevant API and memory layout, but native reward visual selection and possible duplicate grant semantics still need runtime provenance. Any speculative in-place conversion before this observation could double-award or display a key while paying coins.

## Expected log evidence

- `KEYOBS READ ONLY installed AddWorldKeys+0x8 and gate-before/after`
- `KEYOBS GRANT_PRE sourceLR=0x... tid=... world=egypt amount=... coinsBefore=... eventCount=... W2={13:...,23:...,33:...,39:...,41:...} eligible=...`
- `KEYOBS GATE_BEFORE eventPtr=... desiredState=3 ...`
- `KEYOBS GATE_AFTER ... W2={...}`

These are **read-only CANDIDATE states** based on the static ARM field layout. `eligible=YES` merely reports hypothetical policy eligibility for one additional key. **The build will not actually convert anything.** Unknown/incomplete/unmapped event vectors yield UNKNOWN or NO, never a false conversion.

## Protected physical-iPad verification sequence

**Only if a research IPA has passed iOS compilation, and only on a disposable separate keyobs app sandbox:**

1. On the separate `PvZ2 Keys Research` app, import the local original 1.5.252752 APK and matching OBB. Its app ID differs, so it cannot overwrite the v170 app sandbox; still retain your existing external backups.
2. With one Egyptian gate closed and sufficient legitimate keys, capture the keyobs log baseline and an optional separate research-app save backup.
3. Open just that gate ONCE; record visual effects and verify one `GATE_BEFORE/GATE_AFTER` pair. The target `W2` event should transition from recorded state 1 (or another closed state) to exactly 3; all other `W2` key gates should be unchanged.
4. Collect ONE new normal Egyptian key-present award: verify `GRANT_PRE world=egypt amount=1/2/3`, `sourceLR`, coin balance and all five `W2` states. Run a similar test in Pirate/Cowboy when convenient.
5. Hard Stop and export the full keyobs log and the optional **private**, pre/post `pp.dat` saved inside that separate app only. Never post raw saves/ELF/OBB on the public repository.
6. Test normal key behavior while at least one gate is closed. An all-open case can be tested later on a separate deliberately completed world. Cold restart and profile switching are required before enabling an actual crediting patch.

**Accept** the research probe only if no crash, gate pre/post transitions and award sourceLR are coherent, original key rewards/coins are unmodified, original save behavior persists, and both iOS app sandboxes remain separate. If observations disagree with `W/E/S` assumptions or save data, stop; do not enable conversion.

## Independent checks, no IPA

```sh
python3 tools/verify_world_key_probe_wiring.py
python3 tools/verify_world_key_arm.py --elf /path/to/YOUR/libPVZ2.so
python3 tools/verify_world_key_award_coverage.py --elf /path/to/YOUR/libPVZ2.so
clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Itests/staging tests/staging/test_world_key_conversion_policy.cpp -o /tmp/keypolicy && /tmp/keypolicy
clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Itests/staging tests/staging/test_world_key_event_view.cpp -o /tmp/keyevents && /tmp/keyevents
```

The separate `verify-world-keys.yml` workflow compiles the **pure C++ tests** and checks source wiring, without invoking an iOS/IPA build or accessing game files.

## First grouped research IPA — October 2, 2026

**One iOS arm64 CI build succeeded** from source commit `6611b9cdd558e9a940c54b27c8f7a57d3154dea7`:
- Build: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/36973103978
- Artifact (unsigned IPA inside a GitHub ZIP): https://github.com/Puissantsy/PvZ2forIOS/actions/runs/36973103978/artifacts/11212556001
- IPA SHA256 as emitted by CI: `848c621b46fa78e09d48a53444f9bd5eeee51d57e84f2a950f520a2d0af5fbad`
- Installed bundle ID inspected from compiled `Info.plist`: `com.puissantsy.pvz2forios.keyobs`; display name `PvZ2 Keys Research`.
- No APK/OBB/user saves in this artifact. It is unsigned and requires the user's normal local signing/test setup.
- Non-IPA checks all succeeded: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/36973037696 (21 eligibility, 6 decoder, 3 opt-in SVC emulation/wiring checks).
- **NOT tested on real iPad yet.** No original gameplay economy change or key-to-coin conversion is included. Keep original port/v170 saved-state backups intact.

GitHub docs appended here only **after** the one grouped iOS build: no further iOS source modifications or second build are introduced.

## KEYOBS private save import (staged follow-up; grouped new build required)

The first KEYOBS IPA (run 36973103978) lacked restore UI, so it cannot import a save just by putting `pp.dat` in the Files-visible Documents folder; the live USERFS directory is privately under `Library/Application Support/PvZ2forIOS/UserData`.

This branch now reuses the **existing v165** SHA-256 verified, traversal-safe, manifest-validated `save_backups.mm/.hpp` restore engine with NO rewrite of any save or proprietary hash. KEYOBS creates its own Files-visible `PvZ2RestoreInbox` at first launch. Before starting JIT or the guest it offers an explicit Restore/Ignore prompt for the newest complete `save-...` snapshot folder. A failed restore blocks launch in that session with a visible error. If the separate KEYOBS app already contains test progress, the engine creates a verified pre-restore safety backup in its own `PvZ2Backups` folder. Neither app's data is automatically read from the other app.

**The private project attachments** `Save test1 achat snowpea.zip` and `Test2 claim snowpea.zip` both contain v165-compatible `pvz2forios-save-v1` `snapshot-info.plist`, whole `UserData` and `config-v1.txt`. Their manifest files and SHA-256 inventory were checked in the private Project environment (9 and 10 files, respectively), but *neither* should be committed or incorporated into a public GitHub build. The latter archive is a CLAIM diagnostic snapshot, not necessarily the player's desired everyday progress. A fresh, verified export from the intended existing profile is preferable when available.

### Transfer using iPad Files (after restoring-capable KEYOBS IPA is built)

1. Keep the original PvZ2 app installed and retain a separate copy of the desired **complete** snapshot in iCloud Drive or a PC. For a current v165/v170 app, with gameplay safely stopped, `⋯ → Sauvegarder et arrêter` generates `PvZ2Backups/save-...`. Copy the whole `save-...` folder externally.
2. Install/update the separate KEYOBS IPA **over KEYOBS only**, never the normal PvZ2 app. Open KEYOBS once and stop/force-quit; its Documents folder `PvZ2RestoreInbox` will exist. Its original locally selected APK/OBB remain unaffected if upgrading in place.
3. In Files, extract the backed-up ZIP first (if zipped), then **copy**, never move, the **inner `save-...` directory itself** with its `snapshot-info.plist`, `UserData` tree and `config-v1.txt` to **On My iPad → PvZ2 Keys Research → PvZ2RestoreInbox**. Do not place the ZIP alone inside that directory; do not include an extra wrapper directory above `save-...`.
4. Force-quit KEYOBS and reopen it. Answer **Restaurer** to the confirmation. Wait for confirmation before running any game. On success the separate app starts with the copied progression and records `[KEYOBS RESTORE] verified snapshot restored into isolated app`. The imported folder is renamed `Restored-save-...`.
5. Verify profile, opened gates, existing key count, coins and gameplay. Then test ONE new key reward and export the full KEYOBS log. If the copied snapshot has all Egyptian gates already open, only the `GRANT_PRE` observation is needed; it still does **not** convert keys yet.

**Do not** uninstall the original app, migrate only `pp.dat`, modify `global_save_data.hash`, or put any of these private archives on public GitHub. The restore function imports the snapshot atomically within the separate KEYOBS app, including the profile-specific `config-v1.txt`.

## Verified restore-capable KEYOBS build — 2026-10-02

The single grouped **save-import** native iOS arm64 build passed. This is source/compiler/IPA validation, NOT yet a physical-iPad import acceptance result.

- GitHub Actions run: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37057610625
- Ready-to-download GitHub artifact ZIP (contains the new unsigned IPA): https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37057610625/artifacts/11250110316
- Build source commit: `9798a3c9ec2b9cdd893ebf55cf685ad87fc77bbe`.
- SHA-256 of unsigned IPA as reported by build: `c6a2fd3b48ec5a3a32a074eceebeaa548f7c6e3714f1b1a3d72f0ff45f379018`.
- Compiled Info.plist verified: display name `PvZ2 Keys Research`, bundle ID `com.puissantsy.pvz2forios.keyobs` (distinct from production).
- Pre-build non-iOS validation passed: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37057527822 . All 21 world-key policy tests, 6 event decoder tests, native probe wiring checks and explicit pre-JIT v165 restore-flow static checks passed.
- Private archive manifests were independently inspected in the user's project: `Save test1 achat snowpea.zip` (9 manifest entries) and `Test2 claim snowpea.zip` (10 entries) had matching SHA-256 contents. They were NOT bundled or uploaded to GitHub.

The game does **not** automatically convert keys to coins yet. After installing the new IPA over the SEPARATE KEYOBS app and importing a snapshot in its Files-visible `PvZ2RestoreInbox`, the next real-iPad test should confirm the restored profile/world-map states and capture one real key-award trace.

## October 2 iPad follow-up — key award + gate-open performed, but evidence filtered

The user ran KEYOBS using a copied test profile, completed Egypt Day 3 and obtained a key, then opened an Egyptian gate. The private full device log `pvz2forios-probe(20261002-205820).log` proves the app selected `RESEARCH_WORLD_KEYS_READ_ONLY` and loaded/rewrote its own `No_Backup/pp.dat` repeatedly, including save-size changes. **It has zero emitted `KEYOBS GRANT_PRE` / `GATE_BEFORE` / `GATE_AFTER` / installation lines.** Therefore this log does *not* prove the actual native award caller or the gate's saved transition; do not invent those fields from the file-size changes.

Root cause established in our own source: `part_04.inc` and `part_08.inc` used the ordinary `Append("KEYOBS ...")` API, which maps to `ProbeLogClass::Legacy`; the inherited v151 performance capabilities include v85, whose `KeepLegacyPerformanceLogLine()` allowlist suppresses any non-Vxx / non-error strings. Every KEYOBS line was silently discarded, including the initial install marker. This is an **observability-only** bug, not evidence that the original reward/gate gameplay failed.

Grouped fix on this isolated research branch:
- Route ALL native KEYOBS award, gate-before, gate-after, caps and initial installation markers through `AppendDiagnostic`. In this codebase that class bypasses the old v85 Legacy filter and the v118 hot-line prefix filter does not match KEYOBS.
- Suppress only the unrelated several-kilobyte `V144 SELECTION DRAW` debug strings *in KEYOBS diagnostic mode*, retaining their original behavior everywhere else. That makes the next diagnostic much smaller and easier to analyze.
- Add strict source regressions in `tools/verify_world_key_probe_wiring.py` that refuse all future `Append("KEYOBS` calls and verify every marker uses the unfiltered diagnostic channel.
- Preserve the independently stored test progression under the same `com.puissantsy.pvz2forios.keyobs` app ID; **update in place, never delete KEYOBS** and do not restore the older test1 ZIP over the newly earned key/gate state.

Next iPad acceptance once grouped CI passes: first read the `KEYOBS READ ONLY installed` signature near startup. A new legitimate Egyptian key reward OR opening another Egyptian gate should then produce its matching `KEYOBS` evidence; replaying Day 3 is not necessary if its one-time key has already been claimed. The earlier door state should remain in the separate KEYOBS profile; a private current save snapshot can also independently establish which event is open without replaying the first test. This release still does **not** award 1,000 coins per key.

### Recover the ALREADY-opened Egyptian gate without replaying the level

The corrected KEYOBS research app now creates a **local v165 verified prelaunch snapshot** once at the next launch, after any explicit restore and **before** JIT or guest execution. Update the **existing** KEYOBS app in place (same isolated bundle ID; do not uninstall or restore the old Snow Pea test ZIP over the new progress). Open it once, then look in **Files → On My iPad → PvZ2 Keys Research → PvZ2Backups → latest save-...-prelaunch-...**. Copy that entire folder to an external drive/iCloud before sharing a copy privately. Its `UserData/No_Backup/pp.dat` can be compared with the earlier **private** reference snapshot to confirm which Egyptian gate now has state 3, even though the first run's KEYOBS evidence was filtered. This is *not* a live reward-call trace; obtaining the award caller still requires a future real key acquisition and a fresh KEYOBS log.

The next fixed IPA must show `KEYOBS READ ONLY installed` at startup and then the relevant `KEYOBS GRANT_PRE` / `KEYOBS GATE_*` events. The client preserves the existing 64-grant/16-gate log caps; unrelated verbose `V144 SELECTION DRAW` strings are suppressed only in research mode.

**Visibility note:** the original launcher resets its persistent session logger before entering the full-load probe. Therefore `[KEYOBS SAVE] prelaunch VERIFIED` (emitted before JIT) may **not** appear in the subsequently exported full-load log. For the current research IPA, the concrete `PvZ2Backups/save-...-prelaunch-...` directory and its `snapshot-info.plist` are authoritative evidence of the snapshot. The `[FULLLOAD] KEYOBS READ ONLY installed` marker is emitted after the reset and must appear in the exported log. Absence of the save marker alone is NOT a failed snapshot; absence of the Files directory or a verified manifest is.
