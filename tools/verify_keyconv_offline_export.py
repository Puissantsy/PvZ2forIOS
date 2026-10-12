#!/usr/bin/env python3
"""Static guardrails: an offline save export must not erase divergent backups."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
reader=(ROOT/"tools/inspect_pvz2_rton_save.py").read_text()
memory=(ROOT/"tools/experimental_keyconv_rton_memory.py").read_text()
archive=(ROOT/"tools/experimental_keyconv_rton_archive.py").read_text()

def need(ok,msg):
    if not ok: raise AssertionError(msg)

need('set(item) != {"wn", "kc"}' in reader and
     'item["wn"]' in reader and 'item["kc"]' in reader,
     "original nonempty native wn/kc schema validation missing")
need('set(entry) != {"wn", "kc"}' in memory and
     '("objects", player_slot, "objdata", "c")' in memory and
     '"wsk", index, count_field' in memory,
     "exact two-field native token mapping missing")
need("original_snapshot = archive.read(mirror)" in archive and
     "changed_snapshot, fallback_preview = in_memory_egypt_surplus_candidate(" in archive and
     "mirror: changed_snapshot" in archive and
     "pp: changed_pp" in archive,
     "divergent fallback must be separately parsed and edited")
need('fallback_data.get("wsk") != player_data.get("wsk")' in archive and
     'fallback_data.get("i") != original_id' in archive and
     'preview["key_count"] != fallback_preview["key_count"]' in archive,
     "native fallback identity and original key guard missing")
need('entry["sha256"] = hashlib.sha256(target_bytes).hexdigest()' in archive,
     "each snapshot needs independently recomputed manifest SHA256")
need('original.resolve() == output.resolve()' in archive and
     'output.exists()' in archive and
     'with zipfile.ZipFile(output, "x")' in archive,
     "experimental exporter must refuse source overwrite")
need('if name in updates:' in archive and
     'target.read(name) != data' in archive,
     "untouched backup byte-by-byte validation missing")
print("PASS: exact native wn/kc and two independently preserved RTON save images")
print("      SHA-256 inventory, profile identity, no-overwrite & no double-credit")
