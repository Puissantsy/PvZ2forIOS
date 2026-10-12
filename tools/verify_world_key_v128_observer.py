#!/usr/bin/env python3
"""Static safeguards for KEYCONV-only, byte-exact V128 save telemetry."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=(root/"platform/ios/src/pvz2_apk_probe_parts")
state=(p/"part_01.inc").read_text()
runtime=(p/"part_06.inc").read_text()
summary=(p/"part_02.inc").read_text()
cpp=(root/"platform/ios/src/pvz2_apk_probe.cpp").read_text()
def need(ok,msg):
    if not ok: raise AssertionError(msg)
need("world_key_save_write_observer.hpp" in cpp,
     "missing shared exact save file whitelist")
need("IsObservedNativeProfileSave(path)" in state,
     "V128 observer must use standalone tested save path filter")
need("std::vector<std::uint8_t>>" in state and
     "keyconv_v128_last_profile_bytes" in state,
     "observer must compare exact previous contents, not just file sizes")
need("WorldKeyConversionEnabled()" in runtime and
     "keyconv_profile_trace =" in runtime and
     "KeyconvV128ProfilePath(guest)" in runtime,
     "profile trace must be gated to KEYCONV and known save files")
need("previous->second==bytes" in runtime,
     "profile observer needs byte-exact content equality")
need("v51_writable_files[guest] = std::move(bytes)" in runtime and
     "keyconv_v128_last_profile_bytes[guest]=" in runtime,
     "save load must initialize previous bytes baseline")
need("if (bytes.size()<=1024u*1024u)" in runtime,
     "profile observation must cap memory footprint")
need('sameAsPrior=' in runtime and 'flushUs=' in runtime and
     '" frame="' in runtime,
     "profile writes must record equality, duration, and frame")
need("KEYCONV V128 PROFILE WRITESET SUMMARY" in summary,
     "missing structured profile-write summary")
need("auto v128_flush_file =" in runtime and
     "::rename(temp.c_str(), host.c_str())" in runtime and
     "::fsync(::fileno(file))" in runtime,
     "original durable V128 flush route must remain unchanged")
print("PASS: KEYCONV-only V128 save observer, baseline, exact comparison,")
print("      flush timing, 1 MiB cap and original save path preserved")
