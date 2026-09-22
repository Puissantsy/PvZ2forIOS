# PvZ2 First-Run UI Static Investigation v2.5

Date: 2026-09-22

## Scope

This pass continues the static investigation **without building v79 and without changing runtime behavior**.

Compared inputs:

- Android PvZ2 1.5.252752 `libPVZ2.so` (ARMv7)
- historical decrypted iOS PvZ2 1.5.252123 ARMv7 Mach-O
- v78 real-iPad log as the runtime geometry reference
- first-frame/MainMenu resource metadata and the `UI_MainMenu_1536` atlas

Important version caveat: Android 1.5.252752 and iOS 1.5.252123 are the same historical 1.5 generation but are **not the same internal build number**. A concrete code/data difference below is therefore a confirmed Android-reference vs historical-iOS-reference difference, but cannot automatically be labelled platform-only rather than build-revision-specific.

## 1. Global geometry / scale is no longer the leading suspect

Already established by v2.4 and retained here as a regression constraint:

- Android `LawnApp::SetWidthHeight`: ELF `0x002b848c`, guest runtime `0x102b848c`
- historical iOS counterpart: `0x000de55c`
- both use a 600-unit base-height concept
- both have the historical 1536-height Retina-iPad path producing `2048x1536`
- Android MainMenu/Profile scale field: `LawnApp+0x6a8`
- historical iOS homologous scale field: `LawnApp+0x754`
- at height 1536, both produce `1536 / 600 = 2.56`

The v78 log independently confirms that the live Android guest is actually running with:

- original screen `2048x1536`
- active `mWidth/mHeight = 2048x1536`
- content resolution `2048x1536`

Therefore another global framebuffer/content-resolution tweak is not justified by the static evidence.

## 2. Exact first-run/MainMenu resource consumers were identified

The MainMenu resource descriptor table can be correlated across both binaries.

Representative Android descriptor offsets from base `0x00d55710`:

- `+0x0e0` `IMAGE_UI_MAINMENU_FB_CONTAINER`
- `+0x200` `IMAGE_UI_MAINMENU_CHECKBOX_DISABLED`
- `+0x218` `IMAGE_UI_MAINMENU_CHECKBOX_ENABLED`
- `+0x290` `IMAGE_UI_MAINMENU_FACEBOOK_BUTTON`
- `+0x2a8` `IMAGE_UI_MAINMENU_FACEBOOK_BTN_PRESSED`
- `+0x098` `IMAGE_UI_MAINMENU_TEXT_ENTRY_FIELD`
- `+0x188` `IMAGE_UI_MAINMENU_BTN_BKGD`

Historical iOS has the same logical descriptor sequence with the expected four-byte structure shift in this table.

This allowed the first-run components to be matched directly by the resources they consume, rather than by guessed C++ symbol names.

## 3. Acceptance checkbox geometry matches Android and iOS

Direct consumer pair:

- Android: `0x003082cc .. 0x003085ec`
- iOS: `0x002c91f4 .. 0x002c94e8`

The geometry-related float constants match:

`10, 14, 36, 86, 88`

No meaningful platform-specific size/position constant was found in this path.

## 4. Facebook button geometry matches Android and iOS

Direct consumer pair:

- Android: `0x003085ec .. 0x003088c8`
- iOS: `0x002c94e8 .. 0x002c9748`

Float constants match exactly:

`7, 20, 38, 90`

This is important because the large Facebook button seen in the v78 screenshot cannot currently be explained by a different Android-only constant in its direct resource-consumer path.

## 5. Facebook container geometry matches Android and iOS

Direct consumer pair:

- Android: `0x00308b6c .. 0x003092d4`
- iOS: `0x002c9848 .. 0x002c9df0`

Float constants match exactly:

`5, 14, 23, 28, 35, 40, 46, 52, 57, 88, 130`

Again, the direct container path does not expose a global Android-vs-iOS scaling discrepancy.

## 6. First concrete geometry difference: text-entry field

Direct text-entry consumer pair:

- Android: `0x0030ae9c .. 0x0030b160`
- iOS: `0x002cb494 .. 0x002cb6e0`

Shared constants:

`-10, 20, 27, 91`

But the main text-entry rectangle differs.

### Android

At `0x0030afcc / 0x0030afd8 / 0x0030afdc` the path uses:

- X-like constant: `26`
- Y-like constant: `91`
- width-like constant: `373`

### Historical iOS

At `0x002cb592 / 0x002cb59a / 0x002cb5ae` the homologous path uses:

- X-like constant: `110`
- Y-like constant: `91`
- width-like constant: `289`

The two branches preserve the same base-coordinate right edge:

- Android: `26 + 373 = 399`
- iOS: `110 + 289 = 399`

So the historical iOS field begins **84 base units farther right** and is **84 base units narrower**.

At the verified 1536-height scale `S = 2.56`:

- Android X: `26 * 2.56 = 66.56 px`
- Android width: `373 * 2.56 = 954.88 px`
- iOS X: `110 * 2.56 = 281.60 px`
- iOS width: `289 * 2.56 = 739.84 px`
- left-edge difference: `84 * 2.56 = 215.04 px`
- scaled right edge remains `399 * 2.56 = 1021.44 px`

The disassembly confirms that both paths read the same homologous LawnApp scale field (`+0x6a8` Android / `+0x754` iOS), multiply these constants by that scale, convert to integer coordinates, then pass the resulting rectangle into corresponding widget construction/layout calls.

This is therefore a **real, localized geometry difference**, not an artifact of the constant scanner.

## 7. The same text-entry difference reappears in the broader profile screen path

Broader profile/back-screen function pair:

- Android: `0x003095a4 .. 0x0030a9a0`
- iOS: `0x002c9f0c .. 0x002caef4`

Most geometry constants are shared, including:

`10, 20, 27, 30, 39, 43, 48, 77, 91, 108, 117, 143, 144, 151, 157, 172, 310, 350, 373, 400, 425, 500`

But this broader path repeats the same Android `26` versus iOS `110/289` text-field sub-layout difference.

That strengthens the interpretation that this is intentional historical code/data divergence in the text-entry subpath, not a false positive from unrelated literal pools.

## 8. Other first-run/profile component paths are overwhelmingly the same

Other exact or near-exact matched pairs include:

- external-link path: Android `0x0030aac8` ↔ iOS `0x002cb120`; constants `30,175,300,320,350` identical
- camera guide: Android `0x0030ca68` ↔ iOS `0x002cc70c`; constants `-10,20,27,90,311,332` identical
- edit button: Android `0x0030d1a8` ↔ iOS `0x002ccc18`; constant `14` identical
- highlight/divider: Android `0x0030e490` ↔ iOS `0x002cd888`; constants `4,65` identical
- close/inset: Android `0x0030ee14` ↔ iOS `0x002cdd50`; constants `-3,27,65,89,373,425,500` identical
- generic profile layout: Android `0x0030f924` ↔ iOS `0x002ce448`; constants `6,45,46,144,148,270,464,522` identical

A camera/photo-related pair (`0x0030c3d0` Android ↔ `0x002cc1c8` iOS) has additional iOS constants `90` and `187`, but that path also differs in direct photo/camera resource use. It should not be treated as evidence for the current legal/Profile overlay without runtime provenance.

## 9. Projection / final presentation remains possible, but global evidence points away from it

The historical iOS renderer has the expected Retina drawable/backing-size path and builds the screen projection from the active/content geometry. The Android renderer uses the same `screenMatrix` shader model, and v78 has content dimensions equal to its `2048x1536` surface.

Nothing found in this static pass gives a comparable global Android-only `2x` or aspect-related transform that would explain all of the first-run controls being too large while the historical iOS path stayed small.

A downstream object-specific transform is still logically possible, but it should now be tested only after the exact first-run layout values are captured, not by changing global resolution.

## 10. What the text-entry difference does — and does not — explain

The `26/373` versus `110/289` difference is the first concrete first-run geometry divergence discovered.

It can plausibly explain why the **editable name field / text-entry control** is wider and begins farther left in the Android reference.

It does **not** by itself explain the entire screenshot:

- acceptance checkbox direct geometry matches
- Facebook button direct geometry matches
- Facebook container direct geometry matches
- close/inset and generic profile layout constants largely match

Also, the visible white rounded panel in the v78 screenshot may be a parent/background panel rather than exactly the `IMAGE_UI_MAINMENU_TEXT_ENTRY_FIELD` rectangle. Static analysis alone cannot equate the visible outer panel bounds with this inner text-entry rectangle.

Therefore patching `26 -> 110` and `373 -> 289` globally would be premature as a complete “resolution fix”.

## 11. High-confidence conclusion

The static investigation now says:

1. The v78 2048x1536 LawnApp/content geometry matches the historical iOS Retina-iPad contract.
2. The generic MainMenu/Profile scale is also shared (`1536/600 = 2.56`).
3. Most first-run/Profile component geometry examined is materially identical between Android and historical iOS.
4. One **localized text-entry geometry difference** is real: Android `x=26,width=373` versus iOS `x=110,width=289`, with the same right edge.
5. Because the Facebook/legal/container paths mostly match, no static evidence currently supports a global resolution/scale correction for the whole screen.
6. Without a trustworthy historical first-run iPad screenshot, static code alone cannot prove that the overall large 1536-tier first-run overlay is visually wrong. It may be partly or largely the intended historical iPad layout.

## 12. Smallest justified runtime experiment, if needed

If runtime evidence is still required, the next build should be a **single small v79 A/B**, not a broad HotUI probe.

Keep the validated V75 and V77 controls and instrument only the identified first-run functions:

- `0x103082cc` acceptance checkbox consumer
- `0x103085ec` Facebook button consumer
- `0x10308b6c` Facebook container consumer
- `0x1030ae9c` text-entry consumer
- broader profile path `0x103095a4`
- generic layout `0x1030f924`
- `0x102b848c` SetWidthHeight only as a low-volume guard

Capture once per object/path:

- object and parent pointers
- parent `Widget+0x30/+0x34` width/height
- LawnApp scale `+0x6a8` (expected `2.56`)
- selected branch/state
- final integer rectangle arguments sent to the first widget move/resize/construction calls

Optionally include a **separate iOS-text-entry A/B mode** that substitutes only the historical iOS text-entry constants `110/289` for Android `26/373`. Do not combine that patch with any global scale/resolution change.

Decision logic:

- If all non-text-entry rectangles match the shared static formulas and the text-entry A/B only fixes the name field, keep it as a localized compatibility patch and continue investigating the apparent size of the legal/Facebook parent separately.
- If parent/widget dimensions are unexpectedly larger than the historical formulas imply, trace the dynamic parent construction path.
- If computed rectangles are correct but the captured framebuffer shows them enlarged, only then move downstream to the renderer/presentation transform.
- If computed rectangles and rendering both match the historical formulas, stop treating the whole overlay as a resolution bug unless a historical first-run iPad reference proves otherwise.
