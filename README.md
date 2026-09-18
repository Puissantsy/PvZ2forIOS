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

iPadOS 26 requires more than attaching a debugger: executable JIT regions must cooperate with the iOS 26 debug/JIT protocol. The plan is to adapt the proven iOS Dynarmic approach used by modern 32-bit iOS compatibility projects and integrate with StikDebug/StikJIT rather than inventing a new JIT mechanism.

## Initial milestones

1. Add verified PvZ2 1.5.252752 symbol data to the PvZ2Native-style runtime.
2. Produce an arm64 iOS/iPadOS build of the compatibility core.
3. Implement the iOS 26-compatible Dynarmic executable-memory path.
4. Replace desktop OpenGL assumptions with an iOS-compatible GLES presentation path.
5. Boot the original 1.5 game to the first visible screen on device.
6. Bring up touch input, audio, filesystem/save handling, and stable frame presentation.

This project is independent and is not affiliated with or endorsed by Electronic Arts, PopCap Games, Apple, PvZ2Native, Dynarmic, StikDebug, or Applesauce.
