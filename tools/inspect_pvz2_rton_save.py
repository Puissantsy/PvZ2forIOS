#!/usr/bin/env python3
"""Read-only, fail-closed inspector for the original PvZ2 RTON PlayerInfo saves.

No modification, conversion, or re-encoding of a player's saves is performed.
Only selected, non-identifying fields are returned; never upload saves to CI.
"""
import argparse
import hashlib
import json
import plistlib
import re
import struct
import sys
import zipfile

MAX_RTON = 64 * 1024 * 1024
WORLD_GATES = {2: (13, 23, 33, 39, 41),
               3: (15, 23, 28, 32),
               4: (14, 22, 28, 36)}
WORLD_NAMES = {"egypt", "pirate", "cowboy", "future", "dark"}


class RtonError(ValueError):
    pass


class RtonReader:
    def __init__(self, data: bytes):
        if (len(data) > MAX_RTON or
                not data.startswith(b"RTON\x01\x00\x00\x00") or
                not data.endswith(b"DONE")):
            raise RtonError("Invalid or oversized RTON framing")
        self.data = data
        self.pos = 8
        self.latin_cache = []
        self.utf8_cache = []
        self.tokens = 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data) - 4:
            raise RtonError("Truncated RTON body")
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def varint(self):
        result = 0
        for i in range(10):
            b = self.take(1)[0]
            result |= (b & 127) << (i * 7)
            if not (b & 128):
                return result
        raise RtonError("Overlong RTON integer")

    def number(self, kind):
        fmt = "<" + kind
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self, utf8=False):
        if utf8:
            characters = self.varint()
            if characters > 1024 * 1024:
                raise RtonError("Oversized UTF-8 character count")
        size = self.varint()
        if size > 1024 * 1024:
            raise RtonError("Oversized string")
        return self.take(size).decode("utf-8" if utf8 else "latin-1")

    def value(self, depth=0):
        if depth > 96:
            raise RtonError("Excessive nesting")
        self.tokens += 1
        if self.tokens > 1_000_000:
            raise RtonError("Excessive token count")
        tag = self.take(1)[0]
        if tag in (0, 1):
            return bool(tag)
        if tag in (9, 11, 17, 19, 33, 35, 39, 65, 67, 71):
            return 0
        fixed = {8: "b", 10: "B", 16: "h", 18: "H",
                 32: "i", 34: "f", 38: "I", 64: "q",
                 66: "d", 70: "Q"}
        if tag in fixed:
            return self.number(fixed[tag])
        if tag in (36, 40, 44, 48):
            return self.varint()
        if tag in (37, 41, 45, 49):
            n = self.varint()
            return (n >> 1) ^ -(n & 1)
        if tag in (0x81, 0x82, 0x90, 0x92):
            text = self.string(utf8=tag in (0x82, 0x92))
            if tag == 0x90:
                self.latin_cache.append(text)
            elif tag == 0x92:
                self.utf8_cache.append(text)
            return text
        if tag in (0x91, 0x93):
            cache = self.latin_cache if tag == 0x91 else self.utf8_cache
            index = self.varint()
            if index >= len(cache):
                raise RtonError("Invalid interned-string index")
            return cache[index]
        if tag == 0x84:
            return None
        if tag == 0x83:
            subtype = self.take(1)[0]
            if subtype == 0:
                return "RTID()"
            if subtype == 2:
                string = self.string(True)
                a, b, number = self.varint(), self.varint(), self.number("I")
                return f"RTID({b}.{a}.{number:x}@{string})"
            if subtype == 3:
                a, b = self.string(True), self.string(True)
                return f"RTID({b}@{a})"
            raise RtonError("Unsupported RTID subtype")
        if tag == 0x85:
            return self.object(depth + 1)
        if tag == 0x86:
            if self.take(1) != b"\xfd":
                raise RtonError("Invalid array marker")
            count = self.varint()
            if count > 100_000:
                raise RtonError("Array exceeds limit")
            items = [self.value(depth + 1) for _ in range(count)]
            if self.take(1) != b"\xfe":
                raise RtonError("Invalid array terminator")
            return items
        raise RtonError(f"Unsupported RTON tag 0x{tag:02x}")

    def object(self, depth=0):
        mapping = {}
        while True:
            if self.pos >= len(self.data) - 4:
                raise RtonError("Unterminated object")
            if self.data[self.pos] == 0xff:
                self.pos += 1
                return mapping
            key = self.value(depth + 1)
            if not isinstance(key, str) or key in mapping:
                raise RtonError("Invalid or duplicate object key")
            mapping[key] = self.value(depth + 1)

    def decode(self):
        result = self.object()
        if self.pos != len(self.data) - 4:
            raise RtonError("Unexpected data after root object")
        return result


def describe_gates(events):
    if not isinstance(events, list):
        return {"status": "invalid"}
    output = {}
    for world, gates in WORLD_GATES.items():
        result = {}
        for gate in gates:
            matches = [e.get("S") for e in events
                       if isinstance(e, dict) and
                       e.get("W") == world and e.get("E") == gate]
            result[str(gate)] = (
                matches[0] if len(matches) == 1 and
                isinstance(matches[0], int) and
                not isinstance(matches[0], bool)
                else "MISSING" if not matches else "INVALID")
        output[str(world)] = {"events": result,
                              "all_open": all(isinstance(v, int) and
                                              not isinstance(v, bool) and
                                              v >= 3 for v in result.values())}
    return output


def describe_world_keys(raw):
    # Do not guess the unknown schema of the user's six-key fixture.
    if not isinstance(raw, list):
        return {"status": "invalid"}
    if not raw:
        return {"status": "empty", "count": 0, "entries": []}
    entries = []
    for item in raw:
        if not isinstance(item, dict):
            return {"status": "unknown_schema", "count": len(raw)}
        # Report only known world-name literals and safe counts, no player info.
        names = [v for v in item.values()
                 if isinstance(v, str) and v in WORLD_NAMES]
        counts = [v for v in item.values()
                  if type(v) is int and 0 <= v <= 99]
        if len(names) != 1 or len(counts) != 1:
            return {"status": "unknown_schema", "count": len(raw)}
        entries.append({"world": names[0], "keys": counts[0]})
    if len({e["world"] for e in entries}) != len(entries):
        return {"status": "duplicate_world", "count": len(raw)}
    return {"status": "observed_unvalidated_schema",
            "count": len(entries), "entries": entries}


def summarize_player_save(data):
    document = RtonReader(data).decode()
    objects = document.get("objects")
    if not isinstance(objects, list):
        raise RtonError("Missing objects array")
    result = []
    for slot, item in enumerate(objects):
        if not isinstance(item, dict) or item.get("objclass") != "PlayerInfo":
            continue
        profile = item.get("objdata")
        if not isinstance(profile, dict):
            raise RtonError("Invalid PlayerInfo objdata")
        coins = profile.get("c")
        result.append({
            "profile_slot": slot,
            "coins": coins if type(coins) is int and
                     0 <= coins <= 0x7fffffff else "INVALID",
            "world_keys": describe_world_keys(profile.get("wsk")),
            "gates": describe_gates(profile.get("wm")),
        })
    return {"player_count": len(result), "players": result}



def inspect_snapshot_manifest(archive, pp_path):
    # The PvZ2forIOS backup system uses a SHA-256 inventory; reading only
    # pp.dat is insufficient to establish a trustworthy restorable snapshot.
    if "UserData/No_Backup/pp.dat" in pp_path:
        prefix = pp_path.split("UserData/No_Backup/pp.dat")[0]
    else:
        prefix = pp_path.split("No_Backup/pp.dat")[0]
    name = prefix + "snapshot-info.plist"
    try:
        info = archive.getinfo(name)
    except KeyError:
        return {"status": "MISSING", "file_count": 0}
    if info.file_size > 1024 * 1024:
        raise RtonError("Oversized save manifest")
    try:
        manifest = plistlib.loads(archive.read(info))
    except (ValueError, TypeError) as exc:
        raise RtonError("Malformed save manifest") from exc
    if not isinstance(manifest, dict) or (
            manifest.get("format") != "pvz2forios-save-v1"):
        raise RtonError("Unsupported save manifest format")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not (1 <= len(entries) <= 16384):
        raise RtonError("Invalid save manifest inventory")
    seen = set()
    for item in entries:
        if not isinstance(item, dict):
            raise RtonError("Invalid manifest entry")
        path = item.get("path")
        length = item.get("size")
        digest = item.get("sha256")
        if (not isinstance(path, str) or
                not re.fullmatch(r"[A-Za-z0-9_.\-/]+", path) or
                path.startswith("/") or
                ".." in path.split("/") or
                "//" in path or
                path in seen or
                type(length) is not int or
                not 0 <= length <= MAX_RTON or
                not isinstance(digest, str) or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise RtonError("Unsafe or duplicate manifest entry")
        seen.add(path)
        try:
            member = archive.getinfo(prefix + path)
        except KeyError as exc:
            raise RtonError("Missing inventoried save member") from exc
        if member.is_dir() or member.file_size != length:
            raise RtonError("Inventoried save size mismatch")
        if hashlib.sha256(archive.read(member)).hexdigest() != digest:
            raise RtonError("Inventoried save SHA-256 mismatch")
    if ("UserData/No_Backup/pp.dat" not in seen or
            "UserData/No_Backup/snapshot2.dat" not in seen):
        raise RtonError("Missing critical profile images in backup inventory")
    return {"status": "VERIFIED", "file_count": len(seen)}


def inspect_archive(path):
    with zipfile.ZipFile(path) as archive:
        matches = [info for info in archive.infolist()
                   if info.filename.endswith("/No_Backup/pp.dat") and
                   not info.is_dir()]
        if len(matches) != 1:
            raise RtonError("Expected exactly one No_Backup/pp.dat")
        info = matches[0]
        if info.file_size > MAX_RTON:
            raise RtonError("Oversized PlayerInfo archive member")
        pp = archive.read(info)
        mirror_name = info.filename[:-len("pp.dat")] + "snapshot2.dat"
        try:
            mirror_info = archive.getinfo(mirror_name)
        except KeyError:
            mirror = "MISSING"
        else:
            if mirror_info.file_size > MAX_RTON:
                raise RtonError("Oversized snapshot2.dat")
            mirror = "IDENTICAL" if archive.read(mirror_info) == pp else "DIFFERENT"
        manifest = inspect_snapshot_manifest(archive, info.filename)
        result = summarize_player_save(pp)
        result["snapshot2_comparison"] = mirror
        result["manifest"] = manifest
        result["read_only"] = True
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("snapshot_zip", help="Local saved-game snapshot ZIP")
    args = p.parse_args()
    try:
        report = inspect_archive(args.snapshot_zip)
    except (OSError, zipfile.BadZipFile, RtonError, UnicodeError) as exc:
        p.exit(2, f"Inspection refused: {exc}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
