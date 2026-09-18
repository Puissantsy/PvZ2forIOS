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
- ELF file size: `13,950,396` bytes
- Loadable guest image end: `0x00DF9700`
- `PT_LOAD` segments: 2
- `JNI_OnLoad`: `0x009EAD80`
- `R_ARM_RELATIVE`: 48,754
- `R_ARM_GLOB_DAT`: 13
- `R_ARM_JUMP_SLOT`: 316
- `.init_array` entries: 619

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

## Validated runtime milestones

On the physical iPad 10th generation / A14:

1. StikDebug attachment produces `CS_DEBUGGED=YES` on the Non-TXM target.
2. Dual-mapped writable/executable JIT memory works.
3. Dynarmic A32 translated and executed a controlled ARMv7 guest program and returned `R0=42`.
4. The v8 loader probe builds successfully and can import the user's APK directly from Files without bundling game data.

## Next engineering milestone

The loader now needs to move from structural ELF mapping to executable PvZ2 boot:

1. validate the real 1.5.252752 APK profile on-device;
2. resolve `R_ARM_GLOB_DAT` and `R_ARM_JUMP_SLOT` imports to guest trampolines;
3. implement the first libc/liblog/libm/zlib shims needed by startup;
4. create minimal guest-side JavaVM/JNIEnv tables;
5. enter `JNI_OnLoad` under Dynarmic and log the first unsupported Android/JNI call;
6. then advance toward `Native_GameAppInitialize`, GLES presentation, audio, input and filesystem support.

Keeping these milestones separate makes loader, JIT, JNI and rendering failures distinguishable.


## On-device v8 result

On 2026-09-18, the real PvZ2 1.5.252752 APK loader probe succeeded on the target iPad 10th generation / A14 / iPadOS 26.6.1.

Confirmed on-device:

- exact APK/ELF profile matched;
- `PT_LOAD=2`;
- guest base `0x10000000`;
- mapped image size `0x00DF9700`;
- all `48,754` `R_ARM_RELATIVE` relocations applied successfully;
- `R_ARM_GLOB_DAT=13`;
- `R_ARM_JUMP_SLOT=316`;
- dynamic symbol count `7031`;
- undefined imports `328`;
- `DT_NEEDED=9`;
- `.init_array=619`;
- `SONAME=libPVZ2.so`;
- `JNI_OnLoad=0x009EAD80` / guest `0x109EAD80`.

The preceding v7 Dynarmic probe also succeeded on the same device, returning `R0=42` from translated ARMv7 guest code.

## v9 JNI_OnLoad probe

v9 enters the real `JNI_OnLoad` under Dynarmic with a deliberately small guest runtime:

- all imported function relocations point to ARM guest trampolines;
- unknown imports halt cleanly and identify the first missing shim instead of crashing;
- `malloc`, `__aeabi_memset`/`memset`, and Android log calls have initial shims;
- a minimal guest `JavaVM` implements `GetEnv`;
- a minimal guest `JNIEnv` implements `FindClass` and `RegisterNatives`;
- `RegisterNatives` logs the native method names, signatures, and guest function pointers observed in the real PvZ2 tables;
- a controlled return trampoline captures the actual JNI version returned by `JNI_OnLoad`.

The expected successful return for this build is `JNI_VERSION_1_4` (`0x00010004`).


## On-device v9 result

On 2026-09-18, the real PvZ2 1.5.252752 `JNI_OnLoad` completed successfully on the physical iPad 10th generation / A14 / iPadOS 26.6.1 through Dynarmic.

Observed on-device:

- `JNI_OnLoad` entered at guest `0x109EAD80`;
- 329 imported relocations were patched;
- `malloc(316)` and `__aeabi_memset` shims were exercised successfully;
- `JavaVM::GetEnv(0x00010006)` returned the synthetic `JNIEnv`;
- `FindClass` was called for:
  - `com/popcap/SexyAppFramework/AndroidGameApp`;
  - `com/popcap/PvZ2/PvZ2DownloaderService`;
- `RegisterNatives` was called twice and exposed three native methods:
  - `Native_GameAppInitialize` at guest `0x109EAF60`;
  - `Native_GameAppTeardown` at guest `0x109EB4DC`;
  - `Native_getGoogleplayAPIKey` at guest `0x109EB524`;
- Android log calls were intercepted;
- `JNI_OnLoad` returned `0x00010004` (`JNI_VERSION_1_4`);
- no unsupported import was reached during `JNI_OnLoad`.

This proves that a real exported function from the 2013 ARMv7 PvZ2 binary can execute to completion on the A14 through the compatibility runtime.

## v10 full shared-library startup probe

The next probe runs the dynamic-linker initialization phase before `JNI_OnLoad`:

- the ELF contains 619 `.init_array` slots, of which 618 are non-null constructors;
- constructors execute in original order while sharing the same guest globals/heap;
- `__cxa_atexit`, memory-copy/move/set primitives, malloc/free, memalign, basic string compares and Android logging have initial shims;
- each constructor returns through a controlled guest trampoline;
- the first unsupported import or Dynarmic exception reports its constructor index and address;
- if all constructors complete, `JNI_OnLoad` is executed again in that fully initialized memory image.
