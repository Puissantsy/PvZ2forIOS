#!/usr/bin/env python3
"""Refuse accidental live wiring of the KEYCONV filesystem journal prototypes."""
from pathlib import Path

root=Path(__file__).resolve().parents[1]
ios=root/"platform/ios/src"
source_paths=[ios/"pvz2_apk_probe.cpp", ios/"main.mm"]+list(
    (ios/"pvz2_apk_probe_parts").glob("part_*.inc"))
for path in source_paths:
    data=path.read_text()
    for forbidden in ("world_key_save_bundle_journal.hpp",
                      "world_key_save_journal.hpp",
                      "SaveBundleJournal(", "SaveJournal("):
        assert forbidden not in data, (
            "Unverified stock journal wired into shipping runtime: "+str(path))
vfs=(ios/"pvz2_apk_probe_parts"/"part_06.inc").read_text()
assert 'auto v128_flush_file =' in vfs
assert '::fsync(::fileno(file))' in vfs
assert '::rename(temp.c_str(), host.c_str())' in vfs
print("PASS: original V128 atomic-per-file path intact; journal is research-only")
