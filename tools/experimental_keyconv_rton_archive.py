#!/usr/bin/env python3
"""Create a disposable PvZ2forIOS KEYCONV save experiment, never overwrite.

EXPERIMENTAL: Do NOT import on your main profile. The nonempty real saved-key
record schema has not been verified by a physical iPad save differential.
Requires an explicit output path and opt-in flag; no source ZIP is edited.
"""
import argparse
import hashlib
import json
import plistlib
import sys
import zipfile
from pathlib import Path

from inspect_pvz2_rton_save import RtonError, RtonReader, inspect_archive
from experimental_keyconv_rton_memory import in_memory_egypt_surplus_candidate

MAX_TOTAL_UNCOMPRESSED = 128 * 1024 * 1024


def build_disposable_copy(original, output, profile_slot):
    original, output = Path(original), Path(output)
    if (type(profile_slot) is not int or profile_slot < 0 or
            not original.is_file() or
            original.resolve() == output.resolve() or
            output.exists()):
        raise RtonError("Invalid input, profile slot or existing output")

    inspection = inspect_archive(original)
    if inspection["manifest"]["status"] != "VERIFIED":
        raise RtonError("Refuse experiment without verified save manifest")
    if inspection["snapshot2_comparison"] != "IDENTICAL":
        raise RtonError("Refuse experiment with non-identical profile mirror")

    with zipfile.ZipFile(original) as archive:
        infos = archive.infolist()
        if len(infos) > 20000:
            raise RtonError("Excessive ZIP entry count")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise RtonError("Duplicate ZIP member")
        total = sum(info.file_size for info in infos)
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise RtonError("ZIP exceeds 128 MiB uncompressed limit")
        matches = [name for name in names
                   if name.endswith("/UserData/No_Backup/pp.dat")]
        if len(matches) != 1:
            raise RtonError("Expected exactly one canonical PlayerInfo path")
        pp = matches[0]
        root = pp[:-len("UserData/No_Backup/pp.dat")]
        mirror = root + "UserData/No_Backup/snapshot2.dat"
        manifest_name = root + "snapshot-info.plist"
        local_name = root + "UserData/No_Backup/local_profiles"
        if (mirror not in names or manifest_name not in names or
                local_name not in names):
            raise RtonError("Missing native profile mirror, registry or manifest")
        original_pp = archive.read(pp)
        # Real physical saves: PlayerInfo.objdata.i matches
        # PlayerInfoLocalSaveData.objdata.ProfileIndex at the same slot.
        # Refuse any ambiguous cross-profile mapping before touching bytes.
        player_doc = RtonReader(original_pp).decode()
        local_doc = RtonReader(archive.read(local_name)).decode()
        players = player_doc.get("objects")
        locals_ = local_doc.get("objects")
        if (not isinstance(players, list) or
                not isinstance(locals_, list) or
                profile_slot >= len(players) or
                profile_slot >= len(locals_) or
                not isinstance(players[profile_slot], dict) or
                not isinstance(locals_[profile_slot], dict) or
                players[profile_slot].get("objclass") != "PlayerInfo" or
                locals_[profile_slot].get("objclass") != "PlayerInfoLocalSaveData"):
            raise RtonError("No unambiguous matching native profile slot")
        player_data = players[profile_slot].get("objdata")
        local_data = locals_[profile_slot].get("objdata")
        if not isinstance(player_data, dict) or not isinstance(local_data, dict):
            raise RtonError("Invalid native profile id records")
        original_id = player_data.get("i")
        local_id = local_data.get("ProfileIndex")
        if (type(original_id) is not int or original_id <= 0 or
                type(local_id) is not int or local_id != original_id):
            raise RtonError("PlayerInfo ID mismatch with local_profiles")
        changed_pp, preview = in_memory_egypt_surplus_candidate(
            original_pp, profile_slot)
        if not preview.get("changed"):
            raise RtonError("No eligible saved Egypt keys; nothing to export")

        meta = plistlib.loads(archive.read(manifest_name))
        inventory = meta.get("files")
        if not isinstance(inventory, list):
            raise RtonError("Invalid backup manifest")
        patched = {"UserData/No_Backup/pp.dat",
                   "UserData/No_Backup/snapshot2.dat"}
        found = set()
        for entry in inventory:
            if isinstance(entry, dict) and entry.get("path") in patched:
                if entry["path"] in found:
                    raise RtonError("Duplicate profile manifest entry")
                found.add(entry["path"])
                entry["size"] = len(changed_pp)
                entry["sha256"] = hashlib.sha256(changed_pp).hexdigest()
        if found != patched:
            raise RtonError("Original manifest omits protected profile pair")

        updates = {
            pp: changed_pp,
            mirror: changed_pp,
            manifest_name: plistlib.dumps(meta, fmt=plistlib.FMT_XML),
        }
        copied_original_bytes = {
            info.filename: archive.read(info)
            for info in infos if not info.is_dir()
        }
        created = False
        try:
            # 'x' never overwrites a preexisting destination. Original
            # snapshot is opened read-only and never opened for writing.
            with zipfile.ZipFile(output, "x") as target:
                created = True
                for info in infos:
                    if info.is_dir():
                        target.writestr(info, b"")
                    else:
                        target.writestr(
                            info,
                            updates.get(info.filename,
                                        copied_original_bytes[info.filename]))
            verified = inspect_archive(output)
            if (verified["manifest"]["status"] != "VERIFIED" or
                    verified["snapshot2_comparison"] != "IDENTICAL" or
                    profile_slot >= len(verified["players"]) or
                    verified["players"][profile_slot]["coins"] !=
                    preview["coins_after"]):
                raise RtonError("Post-write snapshot validation failed")
            with zipfile.ZipFile(output) as target:
                for name, data in copied_original_bytes.items():
                    if name in updates:
                        continue
                    if target.read(name) != data:
                        raise RtonError("Unrelated backup bytes changed")
            return {
                "status": "EXPERIMENTAL_DISPOSABLE_COPY_CREATED",
                "never_import_on_main_profile": True,
                "original_unchanged": True,
                "manifest": verified["manifest"],
                "snapshot2": verified["snapshot2_comparison"],
                "profile_slot": profile_slot,
                "keys_recycled": preview["key_count"],
                "coins_before": preview["coins_before"],
                "coins_after": preview["coins_after"],
            }
        except Exception:
            if created:
                output.unlink(missing_ok=True)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot_zip", help="Original local backup ZIP")
    parser.add_argument("--profile-slot", type=int, required=True,
                        help="Zero-based PlayerInfo slot from read-only inspector")
    parser.add_argument("--output", required=True,
                        help="New disposable ZIP path; must NOT already exist")
    parser.add_argument("--ack-disposable-only", action="store_true",
                        help="Required acknowledgement of research-only export")
    args = parser.parse_args()
    if not args.ack_disposable_only:
        parser.exit(2, "Refused: --ack-disposable-only is required\n")
    try:
        result = build_disposable_copy(
            args.snapshot_zip, args.output, args.profile_slot)
    except (OSError, RtonError, zipfile.BadZipFile, ValueError) as exc:
        parser.exit(2, f"Experimental export refused: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
