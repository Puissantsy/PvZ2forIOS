# PvZ2forIOS

Experimental compatibility project for running a legally owned copy of **Plants vs. Zombies 2 1.5.252752 (Android, 2013)** on modern iPadOS/iOS hardware.

## Target

- Device used for development/testing: **iPad (10th generation, A14 / arm64)**
- OS target: **iPadOS 26.x**
- Guest game binary: Android **ARMv7 / ELF32** `libPVZ2.so`
- Guest data: matching `main.7.com.ea.game.pvz2_row.obb`
- Host: native **arm64 iOS/iPadOS** application

The intended architecture is based on the same general model as [PvZ2Native](https://github.com/OptiJuegos/PvZ2Native): Dynarmic translates the original ARM32 game code to host ARM64, while the Android/JNI/native APIs used by the game are reimplemented by the host.

## Important: game files are not part of this repository

Do **not** commit or publish the APK, OBB, `libPVZ2.so`, saves, Apple pairing files, signing certificates, provisioning profiles, or other private/device-specific material.

The user supplies their own legally obtained game files at build/test time.

## Current investigation

The supplied 1.5.252752 APK contains:

- `lib/armeabi-v7a/libPVZ2.so`
- ELF32 little-endian ARM EABI5
- Android dependencies including GLESv1/GLESv2, OpenSL ES, libc, libm, libz, libstdc++, libdl and liblog

The essential JNI lifecycle functions for 1.5.252752 have been located and are extremely close to PvZ2Native's supported 1.6.10 release. See [docs/PORTING_NOTES.md](docs/PORTING_NOTES.md).

## iPadOS 26 JIT

The target iPad (10th generation / A14) is a **Non-TXM** device. On the actual iPad running iPadOS 26.6.1, the project has confirmed that StikDebug debugger attachment enables a dual-mapped JIT path: an RX mapping plus an RW alias can be created, written, and executed successfully. The on-device probe generated ARM64 code at runtime and returned the expected value `42`.

TXM/SPTM devices require the newer per-region StikDebug/StikJIT breakpoint protocol, but that path is not required on this A14 target.

Dynarmic A32 has now been validated on the physical A14: a tiny ARMv7 guest program was translated to generated ARM64 and returned the expected value `42`.

The current v8 loader probe lets the user choose their own APK from Files, extracts `lib/armeabi-v7a/libPVZ2.so` in memory, validates the ELF32/ARM layout, maps its `PT_LOAD` segments into a guest address space, applies `R_ARM_RELATIVE` relocations, enumerates unresolved Android imports, and locates `JNI_OnLoad`. No copyrighted game binary is bundled in the IPA or repository.

## Initial milestones

1. Add verified PvZ2 1.5.252752 symbol data to the PvZ2Native-style runtime.
2. Produce an arm64 iOS/iPadOS build of the compatibility core.
3. Implement the iOS 26-compatible Dynarmic executable-memory path.
4. Replace desktop OpenGL assumptions with an iOS-compatible GLES presentation path.
5. Boot the original 1.5 game to the first visible screen on device.
6. Bring up touch input, audio, filesystem/save handling, and stable frame presentation.

This project is independent and is not affiliated with or endorsed by Electronic Arts, PopCap Games, Apple, PvZ2Native, Dynarmic, StikDebug, or Applesauce.
