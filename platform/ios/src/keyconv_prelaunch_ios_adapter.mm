#import "keyconv_prelaunch_ios_adapter.hpp"
#include "world_key_prelaunch_native.hpp"
#include "world_key_auto_settlement.hpp"
#include "keyconv_research_identity_policy.hpp"
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
#if !defined(PVZ2_KEYCONV_RESEARCH_BUILD) || PVZ2_KEYCONV_RESEARCH_BUILD != 1
#error "KEYCONV adapter must only be compiled into the isolated research IPA"
#endif
bool ResearchBundle() {
    NSBundle *bundle=[NSBundle mainBundle];
    NSString *runtimeID=bundle.bundleIdentifier;
    id marker=[bundle objectForInfoDictionaryKey:@"PVZ2KeyconvResearchBuild"];
    id original=[bundle objectForInfoDictionaryKey:@"PVZ2KeyconvOriginalIdentifier"];
    // The build-specific marker stays in Info.plist when AltStore/iLoader
    // re-signs an IPA with a changed CFBundleIdentifier.
    const bool marked=[marker isKindOfClass:[NSNumber class]] &&
                      [marker boolValue] &&
                      [original isKindOfClass:[NSString class]] &&
                      [original isEqualToString:
                          @"com.puissantsy.pvz2forios.keyobs"];
    const auto checked=pvz2_key_study::keyconv_identity::Evaluate(
        runtimeID != nil ? std::string_view(runtimeID.UTF8String) :
                           std::string_view{},
        marked);
    if (checked!=pvz2_key_study::keyconv_identity::Result::Allowed) {
        NSLog(@"[KEYCONV PRELAUNCH] RESEARCH_IDENTITY_REFUSED cause=%ld marker=%@",
              static_cast<long>(checked), marked ? @"YES":@"NO");
        return false;
    }
    if (![runtimeID isEqualToString:
          @"com.puissantsy.pvz2forios.keyobs"]) {
        NSLog(@"[KEYCONV PRELAUNCH] RESIGNED_BUNDLE_ID_ACCEPTED research_marker=YES");
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

BOOL PVZKeyconvResearchIdentityIsAllowed(void) {
    return ResearchBundle() ? YES:NO;
}

PVZKeyconvRecoveryResult PVZKeyconvRecoverBeforeRestore(NSError **error) {
    std::lock_guard<std::mutex> lock(gKeyconvMutex);
    if (!ResearchBundle()) {
        if (error) *error=ErrorMessage(@"KEYCONV réservé à l'application de recherche.");
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
    if (!ResearchBundle()) {
        if (error) *error=ErrorMessage(@"KEYCONV réservé à l'application de recherche.");
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
    if (!ResearchBundle() || slot>=16) {
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
    if(!ResearchBundle()) {
        if(error)*error=ErrorMessage(@"Mode automatique réservé à KEYOBS.");
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
        const auto request=folder/"PvZ2AutoKeyconvRequest.txt";
        if(!ExistsWithoutFollowing(request))return NO;
        const auto contents=native::ReadRegular(request,128);
        if(contents!="ENABLE_EGYPT_AUTOMATIC_KEYCONV_RESEARCH_V1\n")
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
    if(!ResearchBundle() || !guestStopped || !verifiedBackup ||
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
    }catch(const std::exception&) {
        if(error)*error=ErrorMessage(
            @"Conversion KEYCONV automatique interrompue ; démarrage bloqué afin de préserver le journal et les sauvegardes.");
        return NO;
    }
}
