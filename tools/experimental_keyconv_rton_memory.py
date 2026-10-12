#!/usr/bin/env python3
"""Experimental in-memory RTON numeric patch planning: NO FILE WRITES.

The real nonempty world-key schema is still unverified on iPad. This tool
deliberately does not expose a CLI or a save output path; it is only a pure
function for round-trip validation on synthetic RTON inputs.
"""
import copy
import struct

from inspect_pvz2_rton_save import (
    RtonReader, RtonError, describe_gates, WORLD_GATES
)

NUMERIC_TAGS = {8, 10, 16, 18, 32, 36, 37, 38, 40, 41,
                64, 68, 69, 70, 72, 73}


def _uvarint(n):
    if type(n) is not int or n < 0:
        raise RtonError("Unsupported negative/untyped varint")
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def encode_preserving_integer_tag(tag, number):
    if type(number) is not int:
        raise RtonError("Refuse non-integer RTON mutation")
    fixed = {8: "b", 10: "B", 16: "h", 18: "H",
             32: "i", 38: "I", 64: "q", 70: "Q"}
    if tag in fixed:
        try:
            return bytes([tag]) + struct.pack("<" + fixed[tag], number)
        except struct.error as exc:
            raise RtonError("Integer exceeds native token width") from exc
    if tag in (36, 40, 44, 48):
        if number < 0:
            raise RtonError("Negative unsigned RTON value")
        return bytes([tag]) + _uvarint(number)
    if tag in (37, 41, 45, 49):
        bits = 64 if tag in (45, 49) else 32
        if not -(1 << (bits - 1)) <= number < (1 << (bits - 1)):
            raise RtonError("Signed varint overflow")
        zigzag = (number << 1) ^ (number >> (bits - 1))
        return bytes([tag]) + _uvarint(zigzag)
    raise RtonError("Unsupported integer encoding tag")


class IndexedRtonReader(RtonReader):
    """Extend the tested RTON parser with exact primitive byte spans."""
    def __init__(self, data):
        super().__init__(data)
        self.path = []
        self.integer_spans = {}

    def _record(self, start, result):
        tag = self.data[start]
        if (tag in (8, 10, 16, 18, 32, 36, 37, 38, 40, 41,
                    44, 45, 48, 49, 64, 70) and
                type(result) is int):
            path = tuple(self.path)
            if path in self.integer_spans:
                raise RtonError("Duplicate indexed RTON field")
            self.integer_spans[path] = (start, self.pos, tag, result)

    def object(self, depth=0):
        obj = {}
        while True:
            if self.pos >= len(self.data) - 4:
                raise RtonError("Unterminated indexed object")
            if self.data[self.pos] == 0xff:
                self.pos += 1
                return obj
            key = self.value(depth + 1)
            if not isinstance(key, str) or key in obj:
                raise RtonError("Duplicate/invalid indexed object key")
            self.path.append(key)
            start = self.pos
            value = self.value(depth + 1)
            self._record(start, value)
            self.path.pop()
            obj[key] = value

    def value(self, depth=0):
        if self.pos < len(self.data) - 4 and self.data[self.pos] == 0x86:
            if depth > 96:
                raise RtonError("Excessive array depth")
            self.tokens += 1
            if self.tokens > 1_000_000:
                raise RtonError("Excessive indexed token count")
            self.take(1)
            if self.take(1) != b"\xfd":
                raise RtonError("Bad indexed array marker")
            count = self.varint()
            if count > 100_000:
                raise RtonError("Oversized indexed array")
            result = []
            for index in range(count):
                self.path.append(index)
                start = self.pos
                item = self.value(depth + 1)
                self._record(start, item)
                self.path.pop()
                result.append(item)
            if self.take(1) != b"\xfe":
                raise RtonError("Bad indexed array terminator")
            return result
        return super().value(depth)


def in_memory_egypt_surplus_candidate(original, player_slot):
    """Produce edited *bytes in memory* only after strict gates and key checks.

    The result is not validated for importing to PvZ2. An unchanged original
    is returned when there is no eligible stock, and errors fail closed.
    """
    if type(player_slot) is not int or player_slot < 0:
        raise RtonError("Invalid profile slot")
    reader = IndexedRtonReader(original)
    root = reader.decode()
    objs = root.get("objects")
    if not isinstance(objs, list) or player_slot >= len(objs):
        raise RtonError("Profile slot not found")
    obj = objs[player_slot]
    if not isinstance(obj, dict) or obj.get("objclass") != "PlayerInfo":
        raise RtonError("Selected object is not PlayerInfo")
    data = obj.get("objdata")
    if not isinstance(data, dict):
        raise RtonError("Invalid PlayerInfo fields")
    coins = data.get("c")
    if type(coins) is not int or not 0 <= coins <= 0x7fffffff:
        raise RtonError("Invalid coin balance")
    event_view = describe_gates(data.get("wm"))
    if event_view.get("2", {}).get("all_open") is not True:
        return original, {"status": "GATES_NOT_ALL_OPEN", "changed": False}
    entries = data.get("wsk")
    if not isinstance(entries, list):
        raise RtonError("Invalid saved key vector")
    selected = []
    seen_worlds = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RtonError("Unknown saved key entry layout")
        names = [(key, value) for key, value in entry.items()
                 if isinstance(value, str) and
                 value in {"egypt", "pirate", "cowboy", "future", "dark"}]
        numbers = [(key, value) for key, value in entry.items()
                   if type(value) is int]
        if len(names) != 1 or len(numbers) != 1:
            raise RtonError("Ambiguous world-key entry layout")
        world = names[0][1]
        if world in seen_worlds:
            raise RtonError("Duplicate native world-key entry")
        seen_worlds.add(world)
        amount = numbers[0][1]
        if not 0 <= amount <= 99:
            raise RtonError("Native key amount outside expected bounds")
        if world == "egypt" and amount:
            selected.append((idx, numbers[0][0], amount))
    if not selected:
        return original, {"status": "NO_ELIGIBLE_OLD_KEYS", "changed": False}
    if len(selected) != 1:
        raise RtonError("Ambiguous Egyptian key record")
    index, count_field, amount = selected[0]
    credit = 1000 * amount
    if credit > 0x7fffffff - coins:
        raise RtonError("Native coin-wallet overflow")
    coin_path = ("objects", player_slot, "objdata", "c")
    key_path = ("objects", player_slot, "objdata",
                "wsk", index, count_field)
    patches = []
    for path, expected_old, new_number in (
            (coin_path, coins, coins + credit),
            (key_path, amount, 0)):
        span = reader.integer_spans.get(path)
        if span is None or span[3] != expected_old:
            raise RtonError("Target integer lacks exact RTON token span")
        start, end, tag, _ = span
        patches.append((start, end,
                        encode_preserving_integer_tag(tag, new_number)))
    # Apply in descending offset order. All unrelated RTON bytes are
    # preserved verbatim, including interned strings and RTID instances.
    changed = bytearray(original)
    for start, end, replacement in sorted(patches, reverse=True):
        changed[start:end] = replacement
    changed = bytes(changed)
    after = IndexedRtonReader(changed).decode()
    expected = copy.deepcopy(root)
    expected["objects"][player_slot]["objdata"]["c"] = coins + credit
    expected["objects"][player_slot]["objdata"]["wsk"][index][count_field] = 0
    if after != expected:
        raise RtonError("Full RTON comparison failed after targeted edit")
    return changed, {
        "status": "IN_MEMORY_CANDIDATE_NOT_DEVICE_VERIFIED",
        "changed": True,
        "key_count": amount,
        "coins_before": coins,
        "coins_after": coins + credit,
        "modified_token_count": len(patches),
        "note": "DO NOT import into the game without on-device validation",
    }
