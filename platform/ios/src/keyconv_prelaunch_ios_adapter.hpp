#pragma once
// KEYCONV experimental iOS adapter. Compiled only for isolated KEYOBS app.
// No automatic conversion without a verified prelaunch snapshot and explicit
// user confirmation of a specific native profile slot. Never production PvZ2.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
// The same research identity gate is shared by the disposable lab.
FOUNDATION_EXPORT BOOL PVZKeyconvResearchIdentityIsAllowed(void);
typedef NS_ENUM(NSInteger, PVZKeyconvRecoveryResult) {
    PVZKeyconvRecoveryFailed = -1,
    PVZKeyconvRecoveryNoJournal = 0,
    PVZKeyconvRecoveryUnpublishedDiscarded = 1,
    PVZKeyconvRecoveryRolledBack = 2,
    PVZKeyconvRecoveryCommitted = 3,
    PVZKeyconvRecoveryCleanedDone = 4
};
// This must run before offering a v165 restore. Guest/JNI/V128 must be idle.
// Missing live root on a new installation is a normal NoJournal condition.
FOUNDATION_EXPORT PVZKeyconvRecoveryResult
PVZKeyconvRecoverBeforeRestore(NSError * _Nullable * _Nullable error);
// Read-only; nil means corrupted or ambiguous native profile state.
// Empty array means no eligible conversion; array contains zero-based slots.
FOUNDATION_EXPORT NSArray<NSNumber *> * _Nullable
PVZKeyconvEligibleSlots(NSError * _Nullable * _Nullable error);
// Requires explicit user confirmation of the selected zero-based slot.
// Caller MUST already have an integrity-verified, separate prelaunch backup.
FOUNDATION_EXPORT BOOL PVZKeyconvSettleSelectedSlot(
    NSUInteger slot, NSUInteger * _Nullable recycledKeys,
    NSError * _Nullable * _Nullable error);
// Optional explicit research-file gate for unattended batch conversion.
// Invalid token produces NO + error. Missing token => NO, no error.
FOUNDATION_EXPORT BOOL
PVZKeyconvAutoResearchRequested(NSError * _Nullable * _Nullable error);
// Research-only: all eligible Egypt-only profiles, in order, through
// the existing independently crash-safe per-profile SHA256 journal.
// Caller MUST confirm guest stopped, verified backup and clean recovery.
FOUNDATION_EXPORT BOOL PVZKeyconvSettleAllEligible(
    BOOL guestStopped, BOOL verifiedBackup, BOOL recoveredClean,
    NSUInteger * _Nullable totalProfiles,
    NSUInteger * _Nullable totalKeys,
    NSError * _Nullable * _Nullable error);
NS_ASSUME_NONNULL_END
