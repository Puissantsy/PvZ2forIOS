#pragma once
// KEYCONV opt-in Probe iOS adapter. Inactive unless the explicit Probe request is present.
// No automatic conversion without a verified prelaunch snapshot, JIT ready,
// and the exact Probe-only request token. Historical transaction stays unchanged.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
// Build identity gate for the PvZ2forIOS Probe only.
FOUNDATION_EXPORT BOOL PVZKeyconvProbeIdentityIsAllowed(void);
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
// Optional exact Probe-only request file gate for automatic Egypt conversion.
// Invalid token produces NO + error. Missing token => NO, no error.
FOUNDATION_EXPORT BOOL
PVZKeyconvAutoResearchRequested(NSError * _Nullable * _Nullable error);
// Opt-in Probe: all eligible Egypt-only profiles, in order, through
// the existing independently crash-safe per-profile SHA256 journal.
// Caller MUST confirm guest stopped, verified backup and clean recovery.
FOUNDATION_EXPORT BOOL PVZKeyconvSettleAllEligible(
    BOOL guestStopped, BOOL verifiedBackup, BOOL recoveredClean,
    NSUInteger * _Nullable totalProfiles,
    NSUInteger * _Nullable totalKeys,
    NSError * _Nullable * _Nullable error);
NS_ASSUME_NONNULL_END
