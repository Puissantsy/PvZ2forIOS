# PvZ2 Inspector Lab

Auxiliary iOS/iPadOS application for the PvZ2forIOS reverse-engineering project.

This target is deliberately separate from the main `platform/ios` port. Its job is
**not** to launch Plants vs. Zombies 2. It turns raw probe evidence into useful,
repeatable diagnostics without risking regressions in the main app.

## Lab v1.2

Lab v1.2 accepts:

1. the original PvZ2 1.5.252752 APK;
2. optionally, a full `pvz2forios-probe.log` from the main port.

It retains the v1/v1.1 ELF/address analysis and adds three important capabilities.

### 1. Section-aware ELF classification

Addresses inside `libPVZ2.so` are now classified by their real ELF section.
Only sections carrying `SHF_EXECINSTR` are treated as code and allowed to use
`.ARM.exidx` function ranges or automatic disassembly.

This fixes the v1/v1.1 failure mode where a vtable in `.data.rel.ro*` or a
global in `.bss` could be incorrectly described as if it were inside the last
stripped code function.

Examples now distinguish:

```
libPVZ2.so+... section=.text CODE ARM
libPVZ2.so+... section=.data.rel.ro.local DATA
libPVZ2.so+... section=.bss DATA
```

### 2. Exact StartupLogo v54 static profile

The inspector validates the exact ARM opcodes used by the passive v54
instrumentation, including:

- Gate A resource load;
- Gate A completed/total capture;
- Gate A VMOV / VCMPE / VMRS / BLT sequence;
- Gate B/C/D branch instructions;
- Gate C state load;
- Gate D `manager+0x430` load;
- after-A-D, E through J and late-flow markers;
- PatchScreen and MainMenu request-path markers.

This is tied to the exact PvZ2 1.5.252752 ARM binary. A mismatch is reported
instead of silently applying labels to another build.

### 3. Semantic v54 log diagnosis

When a supplied log contains `V54 STARTUPLOGO` evidence, Lab v1.2 creates
`startup-diagnosis.txt` and a structured `startupLogoRuntime` object in
`summary.json`.

For the reference v54 log from the real iPad, the expected diagnosis is:

```
GameState: GAME_LogoScreen
Gate A resource: present
Gate A completed/total: 0/0
Gate A result bits: 0x7fc00000 (quiet NaN)
Gate C: not reached
Gate D: not reached
PatchScreen marker: not reached
MainMenu marker: not reached

First observed blocker: Gate A
```

The report also explains the verified ARM floating-point sequence. A 0/0 result
becomes an IEEE-754 qNaN; with the verified `VCMPE.F32 -> VMRS -> BLT` sequence,
the comparison is unordered and the early-return branch is taken.

That identifies the **immediate machine-level blocker**. It deliberately does
not claim why the completed/total counters are zero.

The report separately counts nearby resource-miss, wait-object and HTTP events
under a **causality not established** heading.

### 4. Object-pointer correlation

If Gate A exposes a guest pointer, the inspector searches the supplied log for
that same pointer and links it to the V52 object graph when available. This is
the first step toward a generic runtime Object Inspector.

## Existing analysis retained

Lab v1.2 still:

- extracts `lib/armeabi-v7a/libPVZ2.so` directly from the APK;
- parses ARM32 ELF program headers and sections;
- lists `DT_NEEDED`, SONAME, dynamic/import symbols and REL relocations;
- parses `.ARM.exidx` function starts;
- recognizes the guest module/stack/heap/trampoline/JNI/object ranges;
- ranks raw hexadecimal addresses and PC/LR/returnPC/callerLR/SP values;
- validates the exact v53 GameState profile;
- produces small ARM/Thumb disassembly windows for executable addresses only.

No JIT, StikDebug, or guest execution is required.

## Reports

```
PvZ2InspectorReport/
  summary.json
  report.txt
  addresses.csv
  annotated-log.txt        # when a log is supplied
  startup-diagnosis.txt    # when v54 StartupLogo evidence is present
```

## Current boundary

Lab v1.2 can prove where StartupLogo first blocks, but it cannot yet explain
why Gate A's two progress counters remain zero. The next useful Inspector work
is to trace the resource object's fields/writers or compare object snapshots
around the code that feeds those counters.
