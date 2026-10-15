#import "keyconv_prelaunch_ios_adapter.hpp"
#include "world_key_prelaunch_native.hpp"
#include "world_key_auto_settlement.hpp"
#include <cerrno>
#include <mutex>
#include <sys/stat.h>
#include <string>

namespace {
namespace native = pvz2_key_study::prelaunch_native;
namespace rton = pvz2_key_study::rton_native;
std::mutex gKeyconvMutex;
NSString * const kDomain = @"PvZ2forIOS.Keyconv.Prelaunch";
// Never expose private PlayerInfo names, native profile IDs, raw RTON,
// original save byte content or real absolute device paths in alerts/logs.
NSError *ErrorMessage(NSString *message) {
    return [NSError errorWithDomain:kDomain code:1 userInfo:@{
        NSLocalizedDescriptionKey:(message != nil ? message : @"Transaction KEYCONV non vérifiée")
    }];
}
#if !defined(PVZ2_KEYCONV_PROBE_BUILD) || PVZ2_KEYCONV_PROBE_BUILD != 1
#error "KEYCONV Probe adapter must only be compiled into explicit opt-in Probe builds"
#endif
bool ProbeBundle() {
    NSBundle *bundle=[NSBundle mainBundle];
    NSString *runtimeID=bundle.bundleIdentifier;
    id marker=[bundle objectForInfoDictionaryKey:@"PVZ2KeyconvProbeBuild"];
    id original=[bundle objectForInfoDictionaryKey:@"PVZ2KeyconvOriginalIdentifier"];
    // A sideload signer may rewrite the actual CFBundleIdentifier.
    // Only this specifically compiled Probe with an independent signed
    // metadata marker may run the adapter; KEYOBS or EA bundles are denied.
    const bool marked=[marker isKindOfClass:[NSNumber class]] &&
                      [marker boolValue] &&
                      [original isKindOfClass:[NSString class]] &&
                      [original isEqualToString:@"com.puissantsy.pvz2forios"];
    const BOOL denied=runtimeID==nil || runtimeID.length==0 ||
        [runtimeID containsString:@".keyobs"] ||
        [runtimeID hasPrefix:@"com.ea.game.pvz2_row"];
    if (!marked || denied) {
        NSLog(@"[KEYCONV PROBE] BUNDLE_IDENTITY_REFUSED marker=%@",marked?@"YES":@"NO");
        return false;
    }
    return true;
}
std::filesystem::path LiveRoot() {
    NSURL *support = [[NSFileManager defaultManager]
        URLsForDirectory:NSApplicationSupportDirectory
              inDomains:NSUserDomainMask].firstObject;
    if (support == nil || support.path == nil)
        throw native::Conflict("Cannot resolve isolated support container");
    return std::filesystem::path(support.fileSystemRepresentation)/"PvZ2forIOS";
}
bool ExistsWithoutFollowing(const std::filesystem::path& path) {
    struct stat st{};
    if (::lstat(path.c_str(), &st) == 0) return true;
    if (errno == ENOENT) return false;
    throw native::Conflict("Unable to inspect isolated live-root");
}
PVZKeyconvRecoveryResult MapRecovery(native::Recovery r) {
    switch (r) {
        case native::Recovery::NoJournal:
            return PVZKeyconvRecoveryNoJournal;
        case native::Recovery::DiscardedUnpublished:
            return PVZKeyconvRecoveryUnpublishedDiscarded;
        case native::Recovery::RolledBack:
            return PVZKeyconvRecoveryRolledBack;
        case native::Recovery::Committed:
            return PVZKeyconvRecoveryCommitted;
        case native::Recovery::CleanedDone:
            return PVZKeyconvRecoveryCleanedDone;
    }
    return PVZKeyconvRecoveryFailed;
}
} // namespace

BOOL PVZKeyconvProbeIdentityIsAllowed(void) {
    return ProbeBundle() ? YES:NO;
}

PVZKeyconvRecoveryResult PVZKeyconvRecoverBeforeRestore(NSError **error) {
    std::lock_guard<std::mutex> lock(gKeyconvMutex);
    if (!ProbeBundle()) {
        if (error) *error=ErrorMessage(@"KEYCONV réservé au Probe opt-in.");
        return PVZKeyconvRecoveryFailed;
    }
    try {
        auto root=LiveRoot();
        if (!ExistsWithoutFollowing(root))
            return PVZKeyconvRecoveryNoJournal;
        return MapRecovery(native::Recover(root,true));
    } catch (const std::exception&) {
        if (error) *error=ErrorMessage(
            @"Un journal KEYCONV est incompatible ou endommagé. Démarrage bloqué afin de protéger la sauvegarde.");
        return PVZKeyconvRecoveryFailed;
    }
}
NSArray<NSNumber *> * PVZKeyconvEligibleSlots(NSError **error) {
    std::lock_guard<std::mutex> lock(gKeyconvMutex);
    if (!ProbeBundle()) {
        if (error) *error=ErrorMessage(@"KEYCONV réservé au Probe opt-in.");
        return nil;
    }
    try {
        auto root=LiveRoot();
        if (!ExistsWithoutFollowing(root)) return @[];
        // A UI eligibility query MUST NOT open a file while a recovery
        // journal remains; recovery gate already ran in v130ContinueLaunch.
        if (ExistsWithoutFollowing(root/native::Journal) ||
            ExistsWithoutFollowing(root/native::Done))
            throw native::Conflict("Unresolved KEYCONV transaction");
        const auto working=native::Working(root);
        native::ValidateRoot(root);
        // Absent save in a newly initialized app: no conversion needed.
        if (!ExistsWithoutFollowing(working/"local_profiles") ||
            !ExistsWithoutFollowing(working/"pp.dat") ||
            !ExistsWithoutFollowing(working/"snapshot2.dat"))
            return @[];
        auto registry=native::ReadRegular(working/"local_profiles",native::MaxRegistry);
        auto primary=native::ReadRegular(working/"pp.dat",native::MaxImage);
        auto fallback=native::ReadRegular(working/"snapshot2.dat",native::MaxImage);
        auto parsed=rton::Reader(registry,0).Parse();
        const auto& objs=parsed.Field("objects");
        if (objs.kind!=rton::Value::Kind::Array || objs.items.size()>16)
            throw native::Conflict("Ambiguous local profile registry");
        NSMutableArray<NSNumber *> *candidates=[NSMutableArray array];
        for (std::size_t slot=0;slot<objs.items.size();++slot) {
            auto plan=rton::PlanNativePair(primary,fallback,registry,slot);
            if (plan.changed) [candidates addObject:@(slot)];
        }
        return candidates;
    } catch (const std::exception&) {
        // Discovery is read-only. Failure must never turn into a guessed
        // profile or a silent modification. Existing game can still launch.
        if (error) *error=ErrorMessage(
            @"Profils ou sauvegardes KEYCONV non compatibles : conversion désactivée.");
        return nil;
    }
}
BOOL PVZKeyconvSettleSelectedSlot(NSUInteger slot, NSUInteger *recycledKeys,
                                  NSError **error) {
    std::lock_guard<std::mutex> lock(gKeyconvMutex);
    if (!ProbeBundle() || slot>=16) {
        if (error) *error=ErrorMessage(@"Identité ou emplacement de profil KEYCONV invalide.");
        return NO;
    }
    try {
        auto root=LiveRoot();
        // Caller guarantees a prior separate verified backup and a stopped
        // guest. No background task, JNI handler or V128 thread may run.
        auto result=native::Settle(root,static_cast<std::size_t>(slot),
                                  true,true);
        if (result.prior!=native::Recovery::NoJournal)
            throw native::Conflict("Unexpected concurrent recovery");
        if (recycledKeys)
            *recycledKeys=result.changed ?
                static_cast<NSUInteger>(result.keys):0u;
        return YES;
    } catch (const std::exception&) {
        if (error) *error=ErrorMessage(
            @"La conversion a été interrompue ou refusée. Ne relance pas le jeu tant que la récupération du journal n'est pas terminée.");
        return NO;
    }
}

BOOL PVZKeyconvAutoResearchRequested(NSError **error) {
    std::lock_guard<std::mutex> lock(gKeyconvMutex);
    if(!ProbeBundle()) {
        if(error)*error=ErrorMessage(@"Mode automatique réservé au Probe explicitement activé.");
        return NO;
    }
    try {
        NSURL *documents=[[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory
            inDomains:NSUserDomainMask].firstObject;
        if(documents==nil || documents.path==nil)
            throw native::Conflict("Missing isolated Documents");
        const auto folder=std::filesystem::path(documents.fileSystemRepresentation);
        native::SafeDirectory(folder);
        const auto request=folder/"PvZ2ProbeKeyconvRequest.txt";
        if(!ExistsWithoutFollowing(request))return NO;
        const auto contents=native::ReadRegular(request,128);
        if(contents!="ENABLE_EGYPT_AUTOMATIC_KEYCONV_PROBE_V1\n")
            throw native::Conflict("Invalid auto request");
        return YES;
    }catch(const std::exception&) {
        if(error)*error=ErrorMessage(
            @"Fichier d'activation KEYCONV automatique invalide ; aucune conversion.");
        return NO;
    }
}

BOOL PVZKeyconvSettleAllEligible(BOOL guestStopped, BOOL verifiedBackup,
                                 BOOL recoveredClean,
                                 NSUInteger *totalProfiles,NSUInteger *totalKeys,
                                 NSError **error) {
    std::lock_guard<std::mutex> lock(gKeyconvMutex);
    if(!ProbeBundle() || !guestStopped || !verifiedBackup ||
       !recoveredClean) {
        if(error)*error=ErrorMessage(
            @"Conversion automatique refusée : moteur actif, sauvegarde non vérifiée ou reprise en attente.");
        return NO;
    }
    try {
        const auto root=LiveRoot();
        const auto outcome=pvz2_key_study::auto_keyconv::SettleEligible(
            root,true,true,true,true);
        if(outcome.deferred)
            throw native::Conflict("Unexpected deferred automatic transaction");
        if(totalProfiles)*totalProfiles=static_cast<NSUInteger>(outcome.profiles);
        if(totalKeys)*totalKeys=static_cast<NSUInteger>(outcome.keys);
        return YES;
    }catch(const pvz2_key_study::auto_keyconv::ReadOnlyPreviewError& preview) {
        // Safe and unambiguous: no Settle() or journal operation ran.
        // The user may choose a one-shot "Launch WITHOUT conversion".
        // Never log player IDs, raw RTON or file paths.
        if(error)*error=[NSError errorWithDomain:kDomain code:2 userInfo:@{
            NSLocalizedDescriptionKey:
                @"KEYCONV : conversion non applicable à cette sauvegarde. "
                 @"Les fichiers sont inchangés et le jeu peut démarrer sans conversion.",
            @"KEYCONVReadOnlyPreviewReason":
                [NSString stringWithUTF8String:preview.code.c_str()]
        }];
        return NO;
    }catch(const std::exception&) {
        // Failing an actual transaction or a filesystem precondition remains
        // fatal until a fresh startup successfully recovers the journal.
        if(error)*error=ErrorMessage(
            @"Conversion KEYCONV automatique interrompue ; démarrage bloqué afin de préserver le journal et les sauvegardes.");
        return NO;
    }
}
