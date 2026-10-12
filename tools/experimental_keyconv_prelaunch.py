#!/usr/bin/env python3
"""Research-only, stopped-guest prelaunch Egyptian surplus-key transaction.

OFF-DEVICE PROTOTYPE, NOT WIRED INTO iOS. Complete v165 restoration first;
the caller must keep guest/V128 threads stopped until this returns. Journal
conflicts must block startup, never trigger blind repair or another credit.
"""
import hashlib
import json
import os
import stat
from pathlib import Path

from inspect_pvz2_rton_save import RtonReader, RtonError
from experimental_keyconv_rton_memory import in_memory_egypt_surplus_candidate

FILES = ("pp.dat", "snapshot2.dat")
JOURNAL = ".pvz2-keyconv-prelaunch-journal"
DONE = JOURNAL + ".done"
MAX_IMAGE = 64 * 1024 * 1024
MAX_REGISTRY = 4 * 1024 * 1024


class PrelaunchConflict(RtonError):
    """Fail closed: do not launch the game with an unresolved transaction."""


class SimulatedInterruption(RuntimeError):
    """Only used by synthetic crash-injection tests."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def syncdir(path):
    # fsync directories is mandatory; unsupported filesystems fail closed.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_regular(path, limit):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
        raise PrelaunchConflict("Unsafe, linked or oversized file")
    data = path.read_bytes()
    if len(data) != st.st_size or len(data) > limit:
        raise PrelaunchConflict("File changed during read")
    return data


def exclusive(path, data):
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def image_names():
    return {f"{kind}-{name}" for kind in ("old", "new") for name in FILES}


def validate_directory(path, permitted):
    if path.is_symlink() or not path.is_dir():
        raise PrelaunchConflict("Unsafe journal directory")
    names = {x.name for x in path.iterdir()}
    if not names.issubset(permitted):
        raise PrelaunchConflict("Unknown journal entry: refuse cleanup")
    for item in path.iterdir():
        st = item.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise PrelaunchConflict("Unsafe journal entry type")
    return names


def clear_done(root):
    done = root / DONE
    if done.exists() or done.is_symlink():
        validate_directory(done, image_names() | {
            "manifest", "manifest.tmp", "committed", "committed.tmp",
            "swap-pp.dat", "swap-snapshot2.dat"
        })
        for item in done.iterdir():
            item.unlink()
        syncdir(done)
        done.rmdir()
        syncdir(root)


def finish(root, journal):
    # A durable atomic rename to .done makes partial cleanup replayable.
    done = root / DONE
    if done.exists() or done.is_symlink():
        raise PrelaunchConflict("Conflicting disposal marker")
    os.replace(journal, done)
    syncdir(root)
    clear_done(root)


def validate_manifest(journal):
    raw = read_regular(journal / "manifest", 4096)
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise PrelaunchConflict("Unreadable journal manifest") from exc
    if (not isinstance(doc, dict) or
            set(doc) != {"version", "profile_id", "files"} or
            doc["version"] != 1 or
            type(doc["profile_id"]) is not int or doc["profile_id"] <= 0 or
            not isinstance(doc["files"], dict) or
            set(doc["files"]) != set(FILES)):
        raise PrelaunchConflict("Unexpected journal manifest")
    images = {}
    for name in FILES:
        entry = doc["files"][name]
        if (not isinstance(entry, dict) or
                set(entry) != {"old", "new"} or
                any(not isinstance(v, str) or len(v) != 64 or
                    any(c not in "0123456789abcdef" for c in v)
                    for v in entry.values())):
            raise PrelaunchConflict("Invalid journal hashes")
        for kind in ("old", "new"):
            data = read_regular(journal / f"{kind}-{name}", MAX_IMAGE)
            if digest(data) != entry[kind]:
                raise PrelaunchConflict("Corrupt journal image")
            images[(kind, name)] = data
    return images


def install_image(journal, destination, data):
    temporary = journal / f"swap-{destination.name}"
    if temporary.exists() or temporary.is_symlink():
        if temporary.is_symlink() or not temporary.is_file():
            raise PrelaunchConflict("Unsafe interrupted swap")
        temporary.unlink()
        syncdir(journal)
    exclusive(temporary, data)
    syncdir(journal)
    os.replace(temporary, destination)
    syncdir(destination.parent)


def recover(live_root):
    """Mandatory BEFORE reading profiles or letting the guest run."""
    root = Path(live_root)
    if (root.is_symlink() or not root.is_dir() or
            (root / "UserData").is_symlink()):
        raise PrelaunchConflict("Invalid live root")
    journal, done = root / JOURNAL, root / DONE
    if (journal.exists() or journal.is_symlink()) and (
            done.exists() or done.is_symlink()):
        raise PrelaunchConflict("Overlapping transaction journals")
    if done.exists() or done.is_symlink():
        clear_done(root)
    if not journal.exists() and not journal.is_symlink():
        return "NO_JOURNAL"
    present = validate_directory(journal, image_names() | {
        "manifest", "manifest.tmp", "committed", "committed.tmp",
        "swap-pp.dat", "swap-snapshot2.dat"
    })
    if "manifest" not in present:
        # No target files may have changed before durable manifest publish.
        if ("committed" in present or "committed.tmp" in present or
                any(n.startswith("swap-") for n in present)):
            raise PrelaunchConflict("Inconsistent unpublished transaction")
        finish(root, journal)
        return "DISCARDED_UNPUBLISHED"
    images = validate_manifest(journal)
    working = root / "UserData" / "No_Backup"
    if (working.is_symlink() or (root / "UserData").is_symlink() or
            not working.is_dir()):
        raise PrelaunchConflict("Unsafe live PlayerInfo directory")
    for name in FILES:
        state = read_regular(working / name, MAX_IMAGE)
        if state not in (images[("old", name)], images[("new", name)]):
            raise PrelaunchConflict(
                "Live save diverged from journal; manual recovery required")
    if "committed" in present:
        if read_regular(journal / "committed", 64) != b"COMMITTED\n":
            raise PrelaunchConflict("Invalid commit marker")
        if any(read_regular(working / name, MAX_IMAGE) !=
               images[("new", name)] for name in FILES):
            raise PrelaunchConflict("Committed images differ")
        finish(root, journal)
        return "CONFIRMED_COMMIT"
    # Uncommitted: roll BOTH RTON images back; interruption can resume.
    for name in FILES:
        destination = working / name
        if read_regular(destination, MAX_IMAGE) != images[("old", name)]:
            install_image(journal, destination, images[("old", name)])
    finish(root, journal)
    return "ROLLED_BACK"


def prepare(live_root, profile_slot):
    root = Path(live_root)
    working = root / "UserData" / "No_Backup"
    if (root.is_symlink() or (root / "UserData").is_symlink() or
            working.is_symlink() or not working.is_dir() or
            type(profile_slot) is not int or profile_slot < 0):
        raise PrelaunchConflict("Unsafe game save path or profile slot")
    old = {name: read_regular(working / name, MAX_IMAGE) for name in FILES}
    registry = RtonReader(
        read_regular(working / "local_profiles", MAX_REGISTRY)).decode()
    registered = registry.get("objects")
    parsed = {name: RtonReader(old[name]).decode() for name in FILES}
    if not isinstance(registered, list) or profile_slot >= len(registered):
        raise PrelaunchConflict("Profile missing from local registry")
    local = registered[profile_slot]
    if not isinstance(local, dict) or local.get(
            "objclass") != "PlayerInfoLocalSaveData":
        raise PrelaunchConflict("Wrong local profile object class")
    local_data = local.get("objdata")
    if not isinstance(local_data, dict):
        raise PrelaunchConflict("Invalid local profile record")
    native_id = local_data.get("ProfileIndex")
    if type(native_id) is not int or native_id <= 0:
        raise PrelaunchConflict("Invalid native profile identity")
    states = []
    for name in FILES:
        players = parsed[name].get("objects")
        if not isinstance(players, list) or profile_slot >= len(players):
            raise PrelaunchConflict("Selected player missing")
        player = players[profile_slot]
        if not isinstance(player, dict) or player.get("objclass") != "PlayerInfo":
            raise PrelaunchConflict("Wrong PlayerInfo object class")
        state = player.get("objdata")
        if not isinstance(state, dict) or state.get("i") != native_id:
            raise PrelaunchConflict("Native profile identity mismatch")
        states.append(state)
    if states[0].get("wsk") != states[1].get("wsk"):
        raise PrelaunchConflict("Original and fallback key stocks diverge")
    changed, previews = {}, {}
    for name in FILES:
        changed[name], previews[name] = (
            in_memory_egypt_surplus_candidate(old[name], profile_slot))
    flags = [previews[name].get("changed") is True for name in FILES]
    if not any(flags):
        return old, {}, native_id, {"status": "NO_ELIGIBLE_STOCK"}
    if not all(flags) or (
            previews[FILES[0]]["key_count"] !=
            previews[FILES[1]]["key_count"]):
        raise PrelaunchConflict("Inconsistent fallback eligibility")
    first = previews[FILES[0]]
    return old, changed, native_id, {
        "status": "READY", "keys": first["key_count"],
        "primary_coins_before": first["coins_before"],
        "primary_coins_after": first["coins_after"]
    }


def settle_disposable_root(live_root, profile_slot, *,
                           guest_stopped=False, crash_at=None):
    """Opt-in only on a COPIED research sandbox; never called by current IPA.

    No guest/V128 thread may be active. Caller must handle any conflict by
    blocking startup; simulated crash injection is strictly test-only.
    """
    if guest_stopped is not True:
        raise PrelaunchConflict("Requires an explicitly stopped guest")
    root = Path(live_root)
    prior = recover(root)
    old, new, native_id, plan = prepare(root, profile_slot)
    if not new:
        return {"status": "NOOP", "prior_recovery": prior}
    journal = root / JOURNAL
    journal.mkdir(mode=0o700)
    syncdir(root)
    for name in FILES:
        exclusive(journal / f"old-{name}", old[name])
        exclusive(journal / f"new-{name}", new[name])
    syncdir(journal)
    manifest = {
        "version": 1, "profile_id": native_id,
        "files": {n: {"old": digest(old[n]), "new": digest(new[n])}
                  for n in FILES}
    }
    exclusive(journal / "manifest.tmp",
              (json.dumps(manifest, sort_keys=True) + "\n").encode())
    syncdir(journal)
    os.replace(journal / "manifest.tmp", journal / "manifest")
    syncdir(journal)
    if crash_at == "after_prepare":
        raise SimulatedInterruption("after_prepare")
    working = root / "UserData" / "No_Backup"
    for i, name in enumerate(FILES):
        if read_regular(working / name, MAX_IMAGE) != old[name]:
            raise PrelaunchConflict("Save changed during prelaunch settlement")
        install_image(journal, working / name, new[name])
        if crash_at == f"after_replace_{i}":
            raise SimulatedInterruption(f"after_replace_{i}")
    # Recheck BOTH installed target images before publishing commit.
    if any(read_regular(working / name, MAX_IMAGE) != new[name]
           for name in FILES):
        raise PrelaunchConflict("Post-install image verification failed")
    exclusive(journal / "committed.tmp", b"COMMITTED\n")
    syncdir(journal)
    if crash_at == "before_commit_marker":
        raise SimulatedInterruption("before_commit_marker")
    os.replace(journal / "committed.tmp", journal / "committed")
    syncdir(journal)
    if crash_at == "after_commit":
        raise SimulatedInterruption("after_commit")
    finish(root, journal)
    return {
        "status": "COMMITTED", "key_count": plan["keys"],
        "coins_before": plan["primary_coins_before"],
        "coins_after": plan["primary_coins_after"], "profile_slot": profile_slot
    }
