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
