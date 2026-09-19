# PvZ2 address resolver

The iOS probe executes the original ARMv7 `libPVZ2.so` at guest base
`0x10000000`. Raw values such as `PC=0x1086fa84` are therefore useful, but
they are much easier to work with after normalization:

```
0x1086fa84
  -> libPVZ2.so+0x0086fa84
  -> .ARM.exidx function start +0x0086f66c
  -> +0x418 inside that function
  -> known port landmark: ResourceRegistryLookup.global found-value load
  -> instruction: LDR r0,[r10,#0x14]
```

## Why .ARM.exidx matters

This production binary is largely stripped, so many original C++ function
names do not exist in the dynamic symbol table. Android ARM ELF files still
carry an unwind table, `.ARM.exidx`. Its PREL31 entries identify function
starts. For the supplied PvZ2 1.5.252752 ARMv7 binary, the resolver infers about
26,000 distinct function starts. That gives stable function boundaries even
when a human-readable symbol name is unavailable.

The tool also uses surviving `.dynsym` names and
`tools/pvz2_known_addresses.json`, which contains landmarks confirmed while
bringing up the port.

## Runtime v46 output

v46 keeps the v45 compatibility behavior and adds high-signal lines such as:

```
V46 ADDRESS MAP READY: guestBase=0x10000000 ... exidxFunctionStarts=26039 ...
V46 ADDRMAP exception PC=0x... [libPVZ2.so+...] LR=0x... [...]
```

The memory ranges are classified automatically:

- `0x10xxxxxx`: mapped `libPVZ2.so`
- `0x20xxxxxx`: guest ARM stack
- `0x30xxxxxx`: guest heap
- `0x40xxxxxx`: host trampolines/shims
- `0x5000xxxx`: synthetic JNI area
- `0x5100xxxx`: synthetic Java/object area

## Analyse an old or new full log

No game binary is checked into this repository. Use a locally supplied APK:

```powershell
python tools/pvz2_address_resolver.py `
  --apk "C:\path\to\pvz2-1.5.252752.apk" `
  --log "C:\path\to\full-log.txt" `
  --report "C:\path\to\address-report.txt" `
  --annotated-log "C:\path\to\annotated-log.txt"
```

The report ranks repeated PC/LR/returnPC/callerLR values, resolves them to
module offsets and inferred function ranges, and prints nearby ARM
instructions. The annotated log retains the original log while adding the
resolved description beside control-flow addresses.

Individual addresses can also be queried:

```powershell
python tools/pvz2_address_resolver.py --apk ".\pvz2.apk" 0x1086fa84 0x105149c8
```

The script has no required third-party Python dependency. If `capstone` is
installed, it is used for richer ARM/Thumb disassembly; otherwise the built-in
minimal decoder still handles the branch/load/SVC patterns most useful to this
project.

## Updating known landmarks

Edit `tools/pvz2_known_addresses.json`. Keys are **ELF-relative offsets**, not
runtime addresses. Thus runtime `0x1086fa84` is entered as `0x0086fa84`.

Labels should describe what the port has actually verified rather than inventing
an original source-level function name. The .ARM.exidx function start remains
the neutral fallback when the binary contains no trustworthy name.
