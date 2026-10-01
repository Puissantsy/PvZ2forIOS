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
# Exactly the ten custom offline coin entries, also present in the original
# MAGENTO.RTON with identical canonical SKU names. A legacy genuine receipt
# may therefore collide with a synthetic v2 coin receipt: preserve provenance.
OFFLINE_SKUS = tuple(
    "com.popcap.pvz2.android." + name + ".nonconsume"
    for name in (
        "plant.snowpea", "plant.squash", "plant.imitater",
        "plant.jalapeno", "plant.torchwood", "plant.powerlily",
        "gameupgrade.sunshovel3", "gameupgrade.pfslot2",
        "gameupgrade.startingsun2", "gameupgrade.seedslot2",
    )
)
# ARM opcode anchors validated against EXACT Android 1.5.252752 libPVZ2.so.
# An offset mismatch means a different ELF or another build: STOP analysis.
ARM_WORDS = {
    0x0049BA50: 0xE3500006,  # broker state == 6
    0x0049AFB8: 0xE2890020,  # broker + 0x20 per-item field
    0x0049AFC8: 0xE3A01006,  # set broker state 6
    0x0049BB54: 0xEBFF8F55,  # call GetCurrentProfile
    0x0049BB8C: 0xEBFE50D6,  # call shared profile/item update helper
    0x0049CE84: 0xEB000C1F,  # process deferred purchase transaction
    # Listener 0x49ccf0: reconstruct the 40-byte native pending transaction.
    # The event contributes six RtString* fields through driver dispatch.
    # This proves tx+0x18 is token and tx+0x0c is canonical product SKU.
    0x0049CD94: 0xE5AB100C,  # initialize tx+0x0c (SKU)
    0x0049CD98: 0xE5A01010,  # initialize tx+0x10 (receipt)
    0x0049CD9C: 0xE5A41014,  # initialize tx+0x14 (order)
    0x0049CDA0: 0xE5A71018,  # initialize tx+0x18 (token)
    0x0049CDA4: 0xE5A6101C,  # initialize tx+0x1c (JSON)
    0x0049CDA8: 0xE5AA1020,  # initialize tx+0x20 (signature)
    0x0049CDB8: 0xE5C51008,  # initialize tx+0x08 (processing flag)
    0x0049CDD4: 0xE1A00007,  # destination tx+0x18 for first event string
    0x0049CDD8: 0xE1A01009,  # source eventString[0] (token)
    0x0049CDE0: 0xE2891008,  # source eventString[2] (SKU)
    0x0049CDE8: 0xEB1B5F7E,  # assign SKU into tx+0x0c
}


def extract_locale(archive: zipfile.ZipFile, lang: str) -> dict[str, str]:
    path = "PvZ2_METADATA/LOCALES/" + lang + "/PROPERTIES/LAWNSTRINGS.TXT"
    text = archive.read(path).decode("utf-16")
    result: dict[str, str] = {}
    for match in re.finditer(r"(?m)^\[([^]\r\n]+)\]\s*\r?\n([^\r\n]*)", text):
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
        original_catalog = z.read("PvZ2_METADATA/PACKAGES/MAGENTO.RTON")
        for sku in OFFLINE_SKUS:
            if sku.encode("ascii") not in original_catalog:
                raise ValueError(f"Custom SKU not in original MAGENTO.RTON: {sku}")
        print("PASS original MAGENTO.RTON contains all ten SAME canonical SKU IDs")

    with zipfile.ZipFile(args.apk) as z:
        elf = z.read("lib/armeabi-v7a/libPVZ2.so")
    if not elf.startswith(b"\x7fELF") or elf[4] != 1 or elf[5] != 1:
        raise ValueError("Expected little-endian 32-bit reference ARM ELF")
    for address, word in ARM_WORDS.items():
        actual = struct.unpack_from("<I", elf, address)[0]
        if actual != word:
            raise ValueError(
                f"Wrong ELF or changed native anchor 0x{address:x}: "
                f"expected 0x{word:08x}, got 0x{actual:08x}")
    print(f"PASS {len(ARM_WORDS)} reference ELF ARM anchors: state 6 and precise pending native receipt fields")
    for token in (b"global_save_data\0", b"local_profiles\0",
                  b"RetrieveGlobalPurchase\0"):
        if token not in elf:
            raise ValueError(f"Original ELF lacks {token!r}")
    print("PASS original ELF has global/local saves and RetrieveGlobalPurchase state")

    if args.catalog:
        source = args.catalog.read_text(encoding="utf-8")
        entries = re.findall(
            r'\{"(com\.popcap\.pvz2\.android\.[^"]+\.nonconsume)",'
            r'.*?OfflineStoreEntitlementKind::(Plant|GameFeature),',
            source)
        if len(entries) != 10 or set(sku for sku, _ in entries) != set(OFFLINE_SKUS):
            raise ValueError(
                "Host offline SKUs no longer match the ten verified ORIGINAL "
                f"Magento entries: {entries!r}")
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
