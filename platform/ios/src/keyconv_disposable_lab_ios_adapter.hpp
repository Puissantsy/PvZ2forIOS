#pragma once
// Research-only fake-RTON lab. Never mutate live pp.dat or snapshot2.dat.
// This is only a bridge: no automatic crash, no user interface yet.
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
// Only an explicit Files-visible request enables the optional crash-lab UI.
FOUNDATION_EXPORT BOOL
PVZKeyconvLabHasExplicitRequest(NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nonnull
PVZKeyconvLabConfirmationPhrase(void);
FOUNDATION_EXPORT NSString * _Nullable
PVZKeyconvLabRecoverOnLaunch(NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nullable
PVZKeyconvLabReadAudit(NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT BOOL
PVZKeyconvLabPrepare(BOOL guestStopped,NSError * _Nullable * _Nullable error);
// Future UI must require two separate confirmations. Exact phrase mandatory.
// A successful injected fault terminates the TEST process by SIGKILL.
FOUNDATION_EXPORT BOOL PVZKeyconvLabKillOnlySynthetic(
    NSString *phase, NSString *typedConfirmation, BOOL guestStopped,
    NSError * _Nullable * _Nullable error);
NS_ASSUME_NONNULL_END
