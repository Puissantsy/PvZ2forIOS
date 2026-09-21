# PvZ2 Inspector Lab

## Lab v2.1-alpha — v68 post-LogoScreen TaskResource lifecycle

v2.1 adds a complete-log analyzer for the current v68 run. It scans huge logs for the natural `GAME_LogoScreen` transition, real GLES texture uploads, worker-7 lifetime, pump/TaskResource growth, `IDLE_NOT_STALL` observations and the stable Task A/B substate cycle. It correlates those runtime facts with the already-verified resource worker/pump and TaskResource addresses and emits:

```
v68-resource-stall-diagnosis.txt
v68-critical-excerpt.txt
v69-plan.txt
```

The generated v69 plan batches the next missing lifecycle class in one probe: TaskResource vfn14 result, active→completed movement, vfn18 start-work, completed-task state and vfn24 finalization. It deliberately avoids restoring v67's per-token hot logging or forcing counters/readiness.

Auxiliary iOS/iPadOS application for the PvZ2forIOS reverse-engineering project.

## Lab v2.0-alpha — Dual Binary Android ↔ iOS

v2 starts using the historical decrypted PvZ2 iOS 1.5.252123 IPA as a
static reference alongside the Android 1.5.252752 APK.

Current implemented slice:

- select an optional iOS IPA next to the Android APK and runtime log;
- discover the direct `Payload/*.app` ARMv7 Mach-O executable automatically;
- parse Mach-O header/load commands, ARM subtype, dylibs/frameworks, segments,
  sections, `LC_ENCRYPTION_INFO`, minimum iOS/SDK, symbol count and
  `LC_FUNCTION_STARTS`;
- report Objective-C/string-bearing sections and important PvZ2 reference
  markers such as `RESFILE_PACKAGES_UI_IPAD`, ResStreams and iOS driver names;
- extract exact ASCII strings (>=8 bytes) from both `libPVZ2.so` and the
  Mach-O and export their intersection as `android-ios-shared-strings.csv`.
  These shared strings are the first automated anchors for future function
  matching.

Generated v2 files:

```
ios-reference-report.txt
android-ios-shared-strings.csv
```

This path is static and free: no JIT, StikDebug, IDA Pro, Hopper or external
service is required. The real iPad remains the runtime source of truth.

The inspector does **not** launch PvZ2. It consumes the original PvZ2
1.5.252752 APK plus an optional probe log and turns static ARM/ELF facts and
real-iPad traces into repeatable diagnostics.

## Lab v1.4

v1.4 adds a dedicated analyzer for the very large partial v61
`Res-Stream Pump Cooperation` log while keeping every v1.3 capability.

### v61 / TaskResource crash analysis

The inspector validates a 28-instruction static profile covering the native
resource-stream pump at `0x10868b7c`, its `manager+0x50/+0x54` task vector,
the three virtual slots used by the pump, the generic pthread wrapper at
`0x109cb6d0`, and the real resource worker entry at `0x10abd894`.

It also identifies the APK's exported
`vector<IResStreamsDriver::TaskResource*>::_M_emplace_back_aux` helper and
verifies the direct TaskResource producer vtable at `0x10cd0d88`, whose
reference pump slots are `+0x14 -> 0x10abede0`,
`+0x18 -> 0x10abf23c`, and `+0x3c -> 0x10ac0984`.

For a v61 log, `v61-crash-diagnosis.txt` reconstructs worker payloads,
per-worker slice/tick maxima, the exact number of
`res-stream-pump-boundary` observations, the first NoExecuteFault register
set, and the verified `r6 -> r7 -> [r7] -> [vtable+0x14] -> BLX r1` path.
It explicitly keeps `[r7]` as UNKNOWN when the runtime log did not capture
the actual vtable pointer.

### Huge-log safe mode

For logs above 24 MiB, v61-specific analysis still scans the complete file,
but generic address ranking uses a bounded head/tail sample and the app skips
the full annotated-log copy. `critical-log-excerpt.txt` replaces it with
worker-7 creation context, the first crash context, and the tail of the
partial run. The iOS picker also stores the log as `NSData` instead of first
building a second huge `NSString`.

### New v1.4 reports

```
v61-crash-diagnosis.txt
next-probe-plan.txt
critical-log-excerpt.txt
```

`next-probe-plan.txt` batches the next useful instrumentation: pre-BLX object
and vtable dump, TaskResource producer/provenance tracing, vptr write-watch,
and a bounded/fail-fast scheduler so a failed worker cannot generate another
75 MiB loop. Inspector itself does not modify the main PvZ2 probe.

---
## Lab v1.3

v1.3 keeps all v1.2 functionality and adds a semantic model for the v55/v56
Diagnostic Matrix so the next main-port build can test an entire failure class
instead of one symptom at a time.

### What v1.3 validates statically

The APK profile now includes:

- the v53 GameState hooks;
- the 24-point v54 StartupLogo profile;
- the v56 ResourceManager registry-builder traps;
- the two native group-name lookup calls into the compact trie;
- the compact-trie byte-normalization / compare / miss / found path;
- the Gate-C helper that returns true only when object field `+0x98 == 4`.

The v56 registry/trie/Gate-C profile is checked against exact ARM opcodes before
the inspector attaches meaning to runtime evidence.

### Imported ctype ABI audit

A new audit resolves the original APK's imported object relocations:

```
ELF 0x00d010d8  R_ARM_GLOB_DAT  _tolower_tab_
ELF 0x00d010dc  R_ARM_GLOB_DAT  _toupper_tab_
ELF 0x00d01280  R_ARM_GLOB_DAT  _ctype_
```

The compact-trie function at ELF `0x00a83ab0` is verified to dereference the
`_toupper_tab_` imported object. For each input byte it indexes a 16-bit
table at `byte + 1` before comparing the normalized byte with the trie node.

This matters because the current v56 port source gives generic non-function
GLOB_DAT imports a zero-filled synthetic object (apart from
`__stack_chk_guard`). That is not the pointer-to-character-table ABI required
by these three Bionic objects.

Inspector v1.3 therefore reports this as a **high-priority static root-cause
candidate**, not as a runtime-proven conclusion. v57 should A/B test an
ABI-correct ctype implementation before mutating the ResourceManager tables.

### v55/v56 semantic diagnosis

With the v56 FULL_MATRIX log, v1.3 reconstructs:

- the four-name Gate-A startup vector;
- total lookup/contribution counts;
- ResourceManager builder call/return/result;
- source and destination table sizes;
- all selected-key found/miss counters;
- Gate-A Scout activation;
- Gate-C object and its `+0x98` state;
- whether Gate D and later probes were reached.

For the current real-iPad v56 run the expected high-level result is:

```
startup vector: 4 names
table +0x28: 5289 entries
table +0x30: 3801 entries
builder result: 1
selected keys: all MISS
Gate-A scout: activated
Gate C: object+0x98 = 1, expected 4
Gate D: not reached

matrix diagnosis:
MANAGER_TABLES_PRESENT_BUT_STARTUP_KEYS_MISS
```

### v57 plan generator

v1.3 creates `v57-plan.txt`. The plan is deliberately designed around one
multi-mode IPA:

1. a v56-compatible baseline;
2. a CTYPE_COMPAT natural-path mode that implements the imported Bionic ctype
   data ABI without touching registry tables or GameState;
3. a CTYPE_COMPAT_DEEP_SCOUT mode that can preserve native proof, then scout
   beyond Gate A and Gate C without forcing a GameState transition.

The recommended v57 instrumentation also includes a character-by-character
compact-trie path trace and a write watch for the Gate-C object's `+0x98`
field. This lets one build distinguish bad character normalization, bad trie
data, loading-progress failure, and the next downstream startup gate.

## Reports

```
PvZ2InspectorReport/
  summary.json
  report.txt
  addresses.csv
  annotated-log.txt        # when a log is supplied
  startup-diagnosis.txt    # v54 semantic diagnosis
  matrix-diagnosis.txt     # v55/v56 + imported ctype audit
  v57-plan.txt             # generated next-build plan
```

## Existing v1.2 features retained

- APK extraction of `lib/armeabi-v7a/libPVZ2.so`;
- section-aware ELF classification;
- code/data separation for vtables and globals;
- dynamic imports, relocations and `.ARM.exidx`;
- exact v53/v54 profiles;
- raw log address ranking and annotation;
- StartupLogo 0/0 -> qNaN diagnosis;
- ResourceManager object correlation.

No JIT or StikDebug is required by Inspector itself.
