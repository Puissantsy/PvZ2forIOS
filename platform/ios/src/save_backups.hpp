#pragma once
#import <Foundation/Foundation.h>

// All methods must run with the guest stopped. Paths and files never leave the
// user device unless the user copies a snapshot out through Files.
FOUNDATION_EXPORT NSURL * _Nullable PVZSaveCreateSnapshot(NSString *reason, NSError **error);
FOUNDATION_EXPORT NSArray<NSURL *> *PVZSavePendingRestores(void);
FOUNDATION_EXPORT BOOL PVZSaveRestoreSnapshot(NSURL *snapshot, NSError **error);
// v166-compatible read-only presence check reused by KEYOBS prelaunch snapshots.
FOUNDATION_EXPORT BOOL PVZSaveHasLocalSave(void);