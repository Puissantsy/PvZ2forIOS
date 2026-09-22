# PvZ2 UI Scale Static Investigation v2.4

Date: 2026-09-22

## Scope

Static comparison of:

- Android PvZ2 1.5.252752 `libPVZ2.so` (ARMv7)
- historical decrypted iOS PvZ2 1.5.252123 ARMv7 Mach-O
- v78 real-iPad runtime log as the geometry/content-resolution reference

No runtime mutation and no v79 build were performed.

## 1. LawnApp geometry contract is historically correct

Android exact `LawnApp::SetWidthHeight` function:

- ELF `0x002b848c`
- guest runtime `0x102b848c`
- direct callers: `0x002b8280` from `0x002b7efc`, and `0x002be64c` from `0x002be120`

Verified Android fields/math:

- `this+0x74` = active height
- `this+0x70` = active width
- `this+0xb34` = content-resolution height as float
- `this+0xb30` = content-resolution width as float
- constructor baseline height `this+0x6b8 = 600`
- scale field `this+0x6a8 = activeHeight / 600`
- 0.2f rounding bias in neighboring scale/rounded-scale fields

Historical iOS counterparts:

- LawnApp constructor: `0x000de095`
- SetWidthHeight: `0x000de55c`
- constructor baseline height `this+0x764 = 600`
- homologous scale field `this+0x754 = activeHeight / 600`

The historical iOS function has an explicit 1536-height branch producing width=2048, height=1536, content width=2048.0f, content height=1536.0f.

Therefore v78's `2048x1536` content-resolution contract matches the historical iOS executable. A different global `m_contentResolution` should not be the next experiment.

## 2. MainMenu/Profile layout function is now identified

Cross-binary semantic matching found a high-confidence pair:

- Android: ELF `0x0030f924` / guest `0x1030f924`
- historical iOS: Thumb function `0x002ce449` (code start `0x002ce448`)
- shared semantic-string Jaccard = 1.0 (8/8)

Opcode analysis shows this is not merely audio registration: the function directly constructs/positions UI children.

Immediate profile/menu callers also match structurally:

- Android `0x0030f6ec` (calls layout at `0x0030f7e0`)
- Android refresh/ensure path `0x0030ff40` (calls layout at `0x0030ffd8`)
- historical iOS `0x002ce314` (calls layout at `0x002ce3b8`)
- historical iOS refresh/ensure path around `0x002ce8c0` (calls layout at `0x002ce918`)

## 3. The layout scale formula is the same on Android and historical iOS

Android `0x0030f924` loads LawnApp `this+0x6a8`.
Historical iOS `0x002ce448` loads homologous LawnApp `this+0x754`.

Both fields are written by their verified SetWidthHeight paths as `activeHeight / baseHeight`, where `baseHeight = 600` in both constructors.

For the historical Retina-iPad/v78 height of 1536:

`1536 / 600 = 2.56`

So **both binaries use scale 2.56** in this MainMenu/Profile path.

## 4. Exact layout constants also match

The matched layout functions multiply the same constants by the same scale field:

- 144
- 522
- 270
- 45
- 464
- 46
- 148

At scale 2.56 these become approximately 368.64, 1336.32, 691.20, 115.20, 1187.84, 117.76, 378.88.

The immediate callers also share exact layout constants 425, 73 and 500.

The profile layout functions on both platforms use the parent/widget field at `+0x30` in the same horizontal-centering arithmetic.

On Android, common Widget helper `0x009d79b8` independently confirms the semantics: it reads object `+0x30` as width and `+0x34` as height and constructs a zero-origin rectangle from them.

Thus the next unknown is the **runtime value of the MainMenu/Profile parent width and branch/object state**, not the meaning of the field.

## 5. Other useful cross-binary landmarks

Strong semantic matches:

- HotUI virtual-layout parser: Android `0x0053a9dc` <-> iOS `0x00167ac1`
- Profile schema: Android `0x0043bce4` <-> iOS `0x002f491d`
- NewUser schema: Android `0x0031cae0` <-> iOS `0x000f41c5`
- position-offset HotUI path: Android `0x00533040` <-> iOS `0x001ae4c1`
- profile/edit event path: Android `0x0030b8f0` <-> iOS `0x002cbb21`
- add-player/settings event path: Android `0x0030ea54` <-> iOS `0x002cdbd5`
- GameState MainMenu anchor: Android `0x00273344` <-> iOS `0x0025db39`

`IMAGE_UI_MAINMENU_*` string references mostly converge on generated resource-registration code (`0x000e96b0`) and are not by themselves layout-function evidence.

## 6. Device/tier selection

Android's resolution-tier selector around `0x002b860c` contains the `[384, 768, 1536]` tier table and a special `asus Nexus 7` path. v78 selects the 1536 tier.

Historical iOS also has the old iPad generation/device selection and an explicit 1536-height Retina-iPad path. Therefore selecting the `_1536` MainMenu atlas is compatible with the historical iOS binary.

The v78 JNI log registers `Device_IsTablet`, but no runtime call is observed. `Device_GetDeviceName` is called and returns `iPad13,18`. This remains a possible branch/cached-state input, but it is no longer the leading scale hypothesis.

## 7. High-confidence conclusion

The oversized-looking first-run Profile/Facebook/EULA UI is **not explained by an Android-only MainMenu/Profile scaling formula**.

For this path, Android 1.5.252752 and historical iOS 1.5.252123 have:

- equivalent LawnApp 1536 -> 2048x1536 geometry/content contract
- equivalent 600-unit base-height concept
- equivalent 2.56 scale at 1536 height
- the same profile-layout constants
- the same parent-width centering structure
- strongly matched surrounding profile/menu control flow

Remaining possibilities are now narrower:

1. Android and iOS reach different branch/object state before/inside the matched layout path.
2. The live MainMenu/Profile parent's `mWidth` (`+0x30`) or another dynamic object field differs.
3. A downstream renderer/presentation transform differs after the shared layout math.
4. The large 1536-tier first-run layout is actually the intended historical iPad appearance, and the perceived mismatch is not an Android-vs-iOS layout bug.

## 8. If a runtime probe is still needed

Do **not** make a broad HotUI probe and do not mutate resolution/content scale first.

A single targeted v79 should instrument only:

- `0x1030f924` MainMenu/Profile layout entry
- callers `0x1030f6ec` and `0x1030ff40`
- `0x102b848c` SetWidthHeight as a low-volume regression guard

At `0x1030f924`, capture:

- `this` / object pointers
- parent/widget `mWidth` at `+0x30`
- LawnApp scale `+0x6a8` (expected 2.56)
- branch/object state
- arguments to the first bounded widget move/resize calls

Run the same instrumentation in V75 and V77 controls in one IPA. If parent width, scale, branch and final rect arguments match, geometry can be considered non-causal for this screen and the next investigation should be final presentation/reference appearance, not another scale tweak.
