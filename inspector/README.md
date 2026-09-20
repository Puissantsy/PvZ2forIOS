# PvZ2 Inspector Lab

Auxiliary iOS/iPadOS application for the PvZ2forIOS reverse-engineering project.

This target is deliberately separate from the main `platform/ios` port. Its job is
**not** to launch Plants vs. Zombies 2. It turns raw values from probe logs into
useful evidence without risking regressions in the main app.

## Lab v1.1.1

Lab v1.1 accepts:

1. the original PvZ2 1.5.252752 APK;
2. optionally, a full `pvz2forios-probe.log` produced by the main port.

It then:

- extracts `lib/armeabi-v7a/libPVZ2.so` directly from the APK;
- parses the ARM32 ELF program headers and section table;
- lists `DT_NEEDED` libraries and the SONAME;
- enumerates dynamic symbols and undefined/import symbols;
- counts ELF REL relocations by ARM relocation type;
- parses `.ARM.exidx` to recover neutral stripped-function boundaries;
- recognizes the guest memory ranges already used by PvZ2forIOS:
  - `0x10xxxxxx` libPVZ2.so,
  - `0x20xxxxxx` guest stack,
  - `0x30xxxxxx` guest heap,
  - `0x40xxxxxx` host trampolines,
  - `0x5000xxxx` synthetic JNI,
  - `0x5100xxxx` synthetic Java/object area;
- scans every 7–8 digit hexadecimal address in the supplied log;
- separately ranks `PC`, `LR`, `returnPC`, `callerLR`, and `SP`;
- resolves code addresses to:
  - `libPVZ2.so+offset`,
  - ARM/Thumb mode,
  - nearest `.ARM.exidx` function start,
  - surviving dynamic symbol when one is trustworthy,
  - project landmarks already confirmed by earlier probes;
- emits a small ARM/Thumb disassembly window around the highest-signal
  control-flow addresses;
- validates the exact PvZ2 1.5.252752 GameState profile used by the v53 runtime
  probe and reports the confirmed landmarks:
  - GameStateMgr factory/constructor;
  - 0x460-byte manager object;
  - runtime vtable 0x10cdb7d8;
  - current GameState at +0x374;
  - transition state at +0x3c4;
  - pending/requested GameState at +0x41c;
  - RequestTransition, ApplyState, StartupLogo.Update and MainMenu.Enter;
  - exact GameState enum values 1 through 10.

No JIT, StikDebug, or guest execution is required for Lab v1.1.

## Reports

After analysis, the app creates this folder in its Documents directory:

```
PvZ2InspectorReport/
  summary.json
  report.txt
  addresses.csv
  annotated-log.txt   # only when a log was supplied
```

`UIFileSharingEnabled` and the in-app Share button make the reports easy to
return to the project chat.

## Why this exists

A stripped production binary often gives runtime evidence such as:

```
PC=0x1086fa84
LR=0x105149c8
R0=0x51001234
```

Lab v1.1 converts that into stable, comparable facts such as:

```
0x1086fa84
  -> libPVZ2.so+0x0086fa84
  -> .ARM.exidx function start +0x0086f66c
  -> +0x418 inside that stripped function
  -> known project landmark: ResourceRegistryLookup.global found-value load
```

This does **not** invent original C++ symbol names. When the binary is stripped,
the neutral function boundary remains the fallback.

## Next lab directions

The folder is intentionally isolated so later inspector versions can add
runtime-only diagnostics without disturbing the playable-port branch:

- controlled Dynarmic execution;
- break-at-address;
- register/stack snapshots;
- object before/after diffs;
- guest memory watchpoints;
- call-edge collection;
- JNI callsite cataloguing;
- VFS/resource-ID correlation with the extracted RSB metadata.

Those are future lab features; Lab v1.1 is intentionally a stable static-address
baseline.
