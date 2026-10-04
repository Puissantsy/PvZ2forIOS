# Live Egypt key/gate evidence -> active conversion design

## Physical iPad evidence (2026-10-04)

Private project log: `pvz2forios-probe(20261004-184031).log`.

The corrected read-only KEYOBS run performed Egypt Day 2 + Day 3, received the
Day 3 key, then opened the newly available one-key gate.

Confirmed live events:
- KEYOBS installed successfully.
- Exactly one key grant was observed:
  `sourceLR=0x10176408 tid=0 world=egypt amount=1 coinsBefore=680`.
  Since LR is callsite+4, this confirms exact original BL `0x176404 ->
  AddWorldKeys(0x42CCC8)` for this Day 3 reward.
- Before the gate open, known Egypt states were
  `13:1,23:1,33:1,39:1,41:2`.
- The native open path requested state 3, and immediately after it returned the
  states were `13:1,23:1,33:1,39:1,41:3`.
- Therefore state **2 is available-but-not-open** for this real gate, and state
  **3 is opened**. The conversion predicate `state >= 3` for every known
  `key_gate` is now backed by both exact static ARM and physical iPad evidence.
- The profile was correctly reported NON-ELIGIBLE before/after because four
  other Egypt key gates remained state 1. No false conversion occurred.
- No duplicate grant/open callbacks were observed in this scenario.

## Active child branch

`research/world-key-conversion-active` is forked from the proven read-only
branch. The read-only branch remains intact.

The active mode still traps the single common `AddWorldKeys` entry at exact
original instruction `0x42CCD0 MOV r10,r0`. For a 1..3-key award:

1. Decode the bounded native event vector and map the original world string.
2. Require every verified gate in Egypt/Pirate/Cowboy to have exactly one saved
   entry with state >=3. Future remains disabled; Dark is unknown and therefore
   never converts.
3. Calculate exactly `1000 * key_count`; reject overflow beyond signed
   `0x7fffffff`.
4. If eligible, restore the already-executed AddWorldKeys ARM prologue frame
   (`push {r4-r11,lr}` + `sub sp,#20` = 56 bytes), verify the saved LR still
   matches live LR, then **tail-call the game's original SetCoins at
   0x42E5AC** with the old coin balance + delta. AddWorldKeys itself is skipped,
   so the key is never credited.
5. If profile/event/stack/LR/wallet verification fails for any reason, restore
   the original `MOV r10,r0` path and let native AddWorldKeys run normally:
   fail-open means the player keeps the original key rather than losing a
   reward.

The original SetCoins performs the game's native wallet notifications after
writing profile+0x14; no raw coin write is used.

## Known remaining acceptance item

The economy behavior can be validated independently from presentation. A source
that visually announces a key may still show the original key artwork even
when the native wallet receives coins. Do not call the feature visually
finished until an all-gates-open physical test confirms both the wallet/key
balances and the reward presentation. If needed, reward-type presentation will
be intercepted separately after the mutation path is proven.

No production/v170 branch is changed.


## Successful active conversion IPA build — 2026-10-04

The first complete active conversion IPA build succeeded after replacing the
dead historical Dynarmic source path with the exact public iOS revision already
proven by Applesauce.

- Source commit: `3872e63662fe28b3ded81412fa51c24b0fe007e5`
- Build: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37228455841
- Artifact ZIP containing unsigned IPA:
  https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37228455841/artifacts/11312587258
- IPA SHA256:
  `d999ac5455b4a78ec06594194417c322fda8801495ddef4d447b93c690cced4f`
- Compiled display name: `PvZ2 Keys Research`
- Bundle ID: `com.puissantsy.pvz2forios.keyobs`
- Exact Dynarmic source used:
  `johnny901901901/dynarmic@f488f760c69c42a97331961e8e6c359b46ccc9e9`
- Pre-build policy/ARM/save/Dynarmic wiring checks:
  https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37228382759

This IPA launches `RESEARCH_WORLD_KEYS_CONVERT`. It is still an isolated
research build using the same separate KEYOBS sandbox. Incomplete worlds,
missing/duplicate gate entries, Future/Dark, invalid quantities, coin overflow
or ARM frame/profile verification failures preserve the original key award.

Physical acceptance remains required. The most important first acceptance test
is a **noneligible** award on the current Egypt profile: it must still grant the
key exactly as before and log `KEYCONV GRANT_PRE ... decision=GateNotOpen`
without `KEYCONV APPLY`. Only after that control succeeds should an
all-Egypt-gates-open disposable profile be used to prove 1 key -> 1,000 coins,
2 -> 2,000 and 3 -> 3,000 while key balance stays unchanged.


## KEYCONV callback-memory compatibility IPA — 2026-10-04

The first active conversion IPA launched on the physical iPad but its private
log ended immediately after `V91 RELRO ARMED`, before the constructor phase.
There was no `KEYCONV GRANT_PRE` or `KEYCONV APPLY`; therefore no key/coin
mutation executed before the crash.

The exact historical Dynarmic archive used by the working KEYOBS build could
not be recovered: GitHub/codeload returned 404 for
`LiveContainer/dynarmic@c97c525ec1432b1e5404ebf091027738005ec168`.
The public replacement revision has the expected API but is not yet physically
proven equivalent for PvZ2's V113 direct page table.

Targeted compatibility change, active mode only:
- do not attach V113/V115/V116's direct page table when
  `ResearchWorldKeyConvert` is active;
- retain Dynarmic callback-backed guest memory for that experiment;
- retain the original page-table behavior for parent KEYOBS/production modes;
- bracket JIT creation with `KEYCONV JIT CONSTRUCT BEGIN/END` markers.

All policy/ARM/save/dependency/startup-fallback checks passed:
https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37230188057

Corrected iOS arm64 build:
- Build: https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37230228110
- Artifact ZIP:
  https://github.com/Puissantsy/PvZ2forIOS/actions/runs/37230228110/artifacts/11312564471
- IPA SHA256:
  `610b38bdc452bdec6b611c8b4cad1792ac9a2507009b4240ca0fe24120ec1a42`
- Bundle ID remains `com.puissantsy.pvz2forios.keyobs`
- Display name remains `PvZ2 Keys Research`.

Physical acceptance step 1 is deliberately minimal: update the existing KEYOBS
install in place and only confirm that startup reaches the normal map/menu.
If startup still fails, the new BEGIN/END marker pair will isolate whether
replacement Dynarmic JIT construction itself is the failure. Do not replay
Day 2/Day 3 until startup is accepted.
