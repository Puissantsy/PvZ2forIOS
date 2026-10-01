#!/usr/bin/env python3
"""Verify the exact *original* shared-CLAIM contract and native anchor bytes.

Uses only LOCAL, user-supplied project sources. It does NOT modify an APK,
touch a save, identify the unproven BUY-vs-CLAIM predicate, or patch guest ARM.
Offsets apply exclusively to the PvZ2 Android 1.5.252752 armeabi-v7a ELF.
"""
from __future__ import annotations
import argparse
import re
import struct
import sys
import zipfile
from pathlib import Path

LOCALES = {
    "EN-US": {
        "PURCHASE_CROSS_PROFILE_PLANT": "Purchased Plants can be claimed by any of your additional profiles!",
        "PURCHASE_CROSS_PROFILE_UPGRADE": "Purchased Upgrades can be claimed by any of your additional profiles!",
        "PURCHASE_RECLAIM_ITEM_BODY": "Item has already been purchased on another profile. Claim for current profile at no cost!",
        "INGAME_RESTORE_PURCHASE_ITEM_BUTTON": "CLAIM",
    },
    "FR-FR": {
        "PURCHASE_CROSS_PROFILE_PLANT": "Vous pouvez récupérer les plantes que vous avez achetées depuis n'importe lequel de vos profils supplémentaires",
        "PURCHASE_RECLAIM_ITEM_BODY": "Cet objet a déjà été acheté avec un autre profil. Récupérez-le gratuitement pour le profil que vous utilisez actuellement.",
        "INGAME_RESTORE_PURCHASE_ITEM_BUTTON": "RÉCUPÉRER",
    },
}
# ARM opcode anchors validated against EXACT Android 1.5.252752 libPVZ2.so.
# An offset mismatch means a different ELF or another build: STOP analysis.
ARM_WORDS = {
    0x0049BA50: 0xE3500006,  # broker state == 6
    0x0049AFB8: 0xE2890020,  # broker + 0x20 per-item field
    0x0049AFC8: 0xE3A01006,  # set broker state 6
    0x0049BB54: 0xEBFF8F55,  # call GetCurrentProfile
    0x0049BB8C: 0xEBFE50D6,  # call shared profile/item update helper
    0x0049CE84: 0xEB000C1F,  # process deferred purchase transaction
}


def extract_locale(archive: zipfile.ZipFile, lang: str) -> dict[str, str]:
    path = "PvZ2_METADATA/LOCALES/" + lang + "/PROPERTIES/LAWNSTRINGS.TXT"
    text = archive.read(path).decode("utf-16")
    result: dict[str, str] = {}
    for match in re.finditer(r"(?m)^\\[([^]\\r\\n]+)\\]\\s*\\r?\\n([^\\r\\n]*)", text):
        result[match.group(1)] = match.group(2).strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path, help="Project PvZ2_METADATA(1).zip")
    parser.add_argument("--apk", required=True, type=Path, help="Reference Android 1.5.252752 APK")
    parser.add_argument("--catalog", type=Path, help="Optional local part_01.inc from v168")
    args = parser.parse_args()

    with zipfile.ZipFile(args.metadata) as z:
        for lang, expected in LOCALES.items():
            messages = extract_locale(z, lang)
            for key, needle in expected.items():
                actual = messages.get(key)
                if actual is None or needle not in actual:
                    raise ValueError(f"{lang}: {key} missing or changed: {actual!r}")
            print(f"PASS original {lang}: shared nonconsumable plant/upgrade CLAIM is documented")

    with zipfile.ZipFile(args.apk) as z:
        elf = z.read("lib/armeabi-v7a/libPVZ2.so")
    if not elf.startswith(b"\\x7fELF") or elf[4] != 1 or elf[5] != 1:
        raise ValueError("Expected little-endian 32-bit reference ARM ELF")
    for address, word in ARM_WORDS.items():
        actual = struct.unpack_from("<I", elf, address)[0]
        if actual != word:
            raise ValueError(
                f"Wrong ELF or changed native anchor 0x{address:x}: "
                f"expected 0x{word:08x}, got 0x{actual:08x}")
    print("PASS six reference ELF ARM anchors: per-item state 6 -> CURRENT local profile")
    for token in (b"global_save_data\\0", b"local_profiles\\0",
                  b"RetrieveGlobalPurchase\\0"):
        if token not in elf:
            raise ValueError(f"Original ELF lacks {token!r}")
    print("PASS original ELF has global/local saves and RetrieveGlobalPurchase state")

    if args.catalog:
        source = args.catalog.read_text(encoding="utf-8")
        entries = re.findall(
            r'\\{"(com\\.popcap\\.pvz2\\.android\\.[^"]+\\.nonconsume)",'
            r'.*?OfflineStoreEntitlementKind::(Plant|GameFeature),',
            source)
        if len(entries) != 10 or len(set(k for k, _ in entries)) != 10:
            raise ValueError(f"Expected 10 unique offline SKUs; got {entries!r}")
        plants = sum(kind == "Plant" for _, kind in entries)
        features = sum(kind == "GameFeature" for _, kind in entries)
        if (plants, features) != (6, 4):
            raise ValueError(f"Unexpected offline SKU kinds: {plants}/{features}")
        print("PASS custom host catalog: exactly 6 plant + 4 game-feature offline SKUs")

    print("FACT: cross-profile free CLAIM is intentional in original PvZ2.")
    print("UNKNOWN: native exact BUY-versus-CLAIM permission predicate and its storage.")
    print("REQUIREMENT: change the policy ONLY for ten custom coin-backed SKUs.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
