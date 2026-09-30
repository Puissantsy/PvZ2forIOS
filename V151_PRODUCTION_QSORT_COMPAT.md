# V151 — production qsort compatibility

v151 is the cleaned functional build after the successful real-iPad validation
of v150.

## Confirmed on iPad

v150 fixed the Power Up selection effect: the board tint/radial now appears with
the correct geometry when a Power Up is selected and disappears at the correct
time. This confirms the root cause was the missing qsort semantics in the
Android/Bionic compatibility layer.

## What v151 keeps

- the guest-native ARMv7 qsort bridge introduced by v150;
- normal guest comparator execution through BLX;
- all previously validated runtime, rendering, input, audio, persistence and
  iPad Board-scale fixes;
- normal pp.dat persistence.

## What v151 removes from normal execution

- no PowerupManager m_ignoreCost override: coins/costs behave normally again;
- the temporary v149 source-polygon hook is not inherited by v151;
- the temporary v145 Board radial hook is not installed in v151.

The historical v145/v149/v150 modes remain in source for reproducibility, but
the selectable runtime mode is V151_PRODUCTION_QSORT_COMPAT.

## Expected validation

- startup: V151_PRODUCTION_QSORT_COMPAT;
- qsort setup: V151 installed guest-native qsort shim;
- no V150 POWERUP ignoreCost log;
- selecting a Power Up keeps the now-correct tint/radial behavior;
- Power Up coins are consumed normally;
- save/profile persistence remains normal.
