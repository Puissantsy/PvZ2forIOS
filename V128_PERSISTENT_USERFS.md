# v128 — Persistent UserFS

## Root cause

The v51 Android private filesystem bridge was process-local only. PvZ2 wrote
profile/config/progression data beneath its normal Android private paths, but
the bridge stored those files only in memory. Relaunching the app erased the
whole user-data surface.

## Mapping

- /data/data/com.ea.game.pvz2_row/files -> $HOME/Library/Application Support/PvZ2forIOS/UserData
- /data/data/com.ea.game.pvz2_row/cache -> $HOME/Library/Caches/PvZ2forIOS

Guest-visible paths are unchanged.

## Behavior

The existing v51 vectors remain the guest-facing cache. An existing file is
loaded lazily on first open. Writes/truncates mark the path dirty. fflush,
fsync, fclose and close atomically persist dirty bytes through a temporary file,
host fsync and rename. mkdir/unlink are mirrored to the sandbox.

The v127 audio worker-drain fix is inherited unchanged.

## iPad validation

Make visible progress, wait for the game to save, fully close the app, relaunch
the same installation and verify that the profile/progression is restored.
The terminal summary reports loads, flushes, bytes, mkdirs, unlinks, failures
and dirtyRemaining.
