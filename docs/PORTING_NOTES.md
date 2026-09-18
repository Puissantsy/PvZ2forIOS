# Porting notes

## Verified source game pair

Local analysis was performed on the user-supplied files; these files must remain outside Git.

### APK

- Package/build filename: `com.ea.game.pvz2_row_1.5.252752-7_...`
- Game version: `1.5.252752`
- Android versionCode: `7`
- SHA-256: `38d503ed05ab9a2711543cff1807e076b2fc7cc553e36162faa7d4106562ae9c`

### OBB

- Filename: `main.7.com.ea.game.pvz2_row.obb`
- SHA-256: `c849c0673264362f362cf0205931a5c8954c65519040a8e3631a86823dc185b0`

### Native game library

Extracted from `lib/armeabi-v7a/libPVZ2.so`.

- SHA-256: `f5ae581d56d5548ed18639aac19470cc67dab6a251c6cedff7cfd841e8ce0e9f`
- Format: ELF32, little-endian, ARM, EABI5, stripped
- Dynamic dependencies observed: `libz.so`, `liblog.so`, `libGLESv2.so`, `libGLESv1_CM.so`, `libOpenSLES.so`, `libc.so`, `libm.so`, `libstdc++.so`, `libdl.so`

## PvZ2 1.5.252752 lifecycle symbols

These addresses were recovered directly from the JNINativeMethod tables inside the supplied `libPVZ2.so`, not inferred only from the neighboring 1.6 build.

| Native | Offset |
| --- | ---: |
| `Native_GameAppInitialize` | `0x009EAF60` |
| `Native_applicationWillFinishLaunching` | `0x009EBF80` |
| `Native_applicationDidFinishLaunching` | `0x009EC0A0` |
| `Native_applicationWillBecomeForeground` | `0x009EC0BC` |
| `Native_applicationDidBecomeActive` | `0x009EC0C8` |
| `Native_onSurfaceCreated` | `0x009F1840` |
| `Native_onSurfaceChanged` | `0x009F18DC` |
| `Native_onDrawFrame` | `0x009F190C` |

The corresponding PvZ2Native 1.6.10 entries are exactly `+0x38` for all eight functions.

### Fingerprints

- `GameAppInitialize`: `0xE24DD094E92D4FF0`
- `onDrawFrame`: `0xE59F0014E92D4800`

These match the fingerprints currently used by PvZ2Native for 1.6.10.

### JNI signature

`Native_GameAppInitialize` declares the same eight legacy object arguments used by PvZ2Native's 1.6/4.5 support:

1. `AndroidSurfaceView`
2. `AndroidHttpProxy`
3. `AndroidFacebookDriver`
4. `cloud/Cloud`
5. `GooglePlayConnect`
6. `GooglePlayAchievements`
7. `GooglePlayLeaderboard`
8. `AndroidNotification`

The method returns `jboolean`.

### Surface calling convention

Disassembly of `Native_onSurfaceChanged` shows:

- `r1 <- r2`
- `r2 <- r3`

Therefore the PvZ2Native-style `surface_changed_pad` value is **2**, matching 1.6.10.

### AndroidAppDriver global

The `onDrawFrame` PC-relative load resolves to the driver pointer at:

`0x00DC8FD4`

This is also the address used by PvZ2Native 1.6.10.

### std::string constructor used by diagnostics/runtime helpers

Preliminary address:

`0x00B75528`

This is `0x38` below PvZ2Native 1.6.10's `0x00B75560`. Re-verify its exact semantic use before making it required for boot; it is not needed for the first lifecycle milestone.

## Proposed 1.5 version entry

The minimum boot-oriented entry should initially contain only verified required fields and optional fields that are independently confirmed. Do not copy all 1.6 diagnostic/input offsets merely because the binaries are close.

## iPad target

Development device:

- iPad (10th generation)
- Apple A14 Bionic / arm64
- iPadOS 26.6.1

The serial number is intentionally not recorded or needed.

## iPadOS 26 JIT strategy

StikDebug/StikJIT documents a different path for iOS/iPadOS 26 systems using TXM/SPTM: attaching a debugger alone is insufficient. The JIT allocator must cooperate with the debug connection when executable regions are created.

A public Dynarmic fork used by Applesauce contains a focused iPhone-device patch that:

- allocates/prepares executable JIT memory through a breakpoint protocol using `brk #0xf00d`;
- maintains separate executable and writable mappings of the same JIT region;
- feeds Dynarmic/Oaknut separate write and execute pointers;
- detaches the JIT server after the code-cache region is prepared;
- adds an iOS-safe ARM64 spinlock implementation.

This is a much better reference path than implementing an unrelated JIT mechanism from scratch.

References:

- PvZ2Native: https://github.com/OptiJuegos/PvZ2Native
- StikDebug: https://github.com/StikDebug/StikDebug
- StikJIT integration: https://github.com/StikDebug/StikJIT/blob/main/INTEGRATION.md
- Applesauce: https://github.com/johnny901901901/Applesauce
- Applesauce Dynarmic fork/branch: https://github.com/johnny901901901/dynarmic/tree/ios-hyperhle-experiment

## Next engineering milestone

Before touching rendering/audio, build a minimal iOS arm64 host that can:

1. start as a normal signed/sideloaded iPadOS app;
2. initialize an iOS-26-compatible Dynarmic A32 code cache;
3. load the supplied ELF32 `libPVZ2.so` from the app's Documents/Application Support area;
4. identify it as PvZ2 1.5.252752 using the two verified fingerprints;
5. execute a tiny controlled guest path and emit logs;
6. only then progress to JNI/lifecycle boot and GLES presentation.

Keeping these milestones separate will make JIT failures distinguishable from PvZ2 compatibility failures.
