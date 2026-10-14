#import "keyconv_disposable_lab_ios_adapter.hpp"
#import "keyconv_prelaunch_ios_adapter.hpp"
#include "keyconv_disposable_crash_lab.hpp"
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>

#if !defined(PVZ2_KEYCONV_RESEARCH_BUILD) || PVZ2_KEYCONV_RESEARCH_BUILD != 1
#error "Synthetic crash lab must be built only in research KEYOBS"
#endif

namespace {
namespace lab=pvz2_key_study::disposable_lab;
namespace tx=pvz2_key_study::prelaunch_native;
std::mutex gDisposableLabMutex;
NSError *Failure(NSString *message) {
    return [NSError errorWithDomain:@"PvZ2forIOS.KEYCONV.DISPOSABLE.LAB"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey:message}];
}
std::filesystem::path SupportPath() {
    NSURL *u=[[NSFileManager defaultManager]
        URLsForDirectory:NSApplicationSupportDirectory
              inDomains:NSUserDomainMask].firstObject;
    if (u==nil || u.path==nil)throw tx::Conflict("No lab support directory");
    return std::filesystem::path(u.fileSystemRepresentation);
}
bool Allowed(bool guestStopped) {
    return guestStopped && PVZKeyconvResearchIdentityIsAllowed();
}
tx::CrashAt Phase(NSString *label) {
    if([label isEqualToString:@"primary-installed"])
        return tx::CrashAt::PrimaryInstalled;
    if([label isEqualToString:@"fallback-installed"])
        return tx::CrashAt::FallbackInstalled;
    if([label isEqualToString:@"marker-prepared"])
        return tx::CrashAt::MarkerPrepared;
    if([label isEqualToString:@"marker-published"])
        return tx::CrashAt::MarkerPublished;
    throw tx::Conflict("Unknown or absent synthetic crash checkpoint");
}
NSString *Outcome(const lab::Report& r) {
    if(!r.exists)return nil;
    NSString *state=r.old_pair?@"OLD_OLD":@"NEW_NEW";
    return [NSString stringWithFormat:
        @"[KEYCONV LAB] recovered=%ld verified_pair=%@ audit=LAB_ONLY",
        (long)r.recovery,state];
}
} // namespace

NSString *PVZKeyconvLabConfirmationPhrase(void) {
    return @"JE CONFIRME LE CRASH FACTICE";
}
BOOL PVZKeyconvLabHasExplicitRequest(NSError **error) {
    std::lock_guard<std::mutex> lock(gDisposableLabMutex);
    if (!PVZKeyconvResearchIdentityIsAllowed()) {
        if(error)*error=Failure(@"Demande de laboratoire réservée à KEYOBS.");
        return NO;
    }
    try {
        NSURL *documents=[[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory
                  inDomains:NSUserDomainMask].firstObject;
        if(documents==nil||documents.path==nil)
            throw tx::Conflict("Documents directory absent");
        const auto root=std::filesystem::path(documents.fileSystemRepresentation);
        tx::SafeDirectory(root);
        const auto request=root/"PvZ2CrashLabRequest.txt";
        if(!tx::Present(request))return NO;
        const auto text=tx::ReadRegular(request,128);
        if(text!="ENABLE_PVZ2_KEYCONV_DISPOSABLE_LAB_V1\n")
            throw tx::Conflict("Malformed synthetic crash-lab request");
        return YES;
    }catch(const std::exception&) {
        if(error)*error=Failure(
            @"Demande du laboratoire invalide (fichier attendu dans Documents).");
        return NO;
    }
}

NSString *PVZKeyconvLabRecoverOnLaunch(NSError **error) {
    std::lock_guard<std::mutex> lock(gDisposableLabMutex);
    if(!Allowed(true)) {
        if(error)*error=Failure(@"Laboratoire réservé à KEYOBS.");
        return nil;
    }
    try {
        const auto report=lab::RecoverAndVerify(SupportPath());
        return Outcome(report);
    }catch(const std::exception&) {
        if(error)*error=Failure(
            @"Laboratoire synthétique incohérent. Aucune sauvegarde du jeu modifiée ; test interrompu.");
        return nil;
    }
}
NSString *PVZKeyconvLabReadAudit(NSError **error) {
    std::lock_guard<std::mutex> lock(gDisposableLabMutex);
    if(!Allowed(true)) {
        if(error)*error=Failure(@"Laboratoire réservé à KEYOBS.");
        return nil;
    }
    try {
        const auto text=lab::AuditText(SupportPath());
        return [[NSString alloc] initWithBytes:text.data()
                                       length:text.size()
                                     encoding:NSUTF8StringEncoding];
    }catch(const std::exception&) {
        if(error)*error=Failure(@"Journal du laboratoire indisponible.");
        return nil;
    }
}
BOOL PVZKeyconvLabPrepare(BOOL guestStopped,NSError **error) {
    std::lock_guard<std::mutex> lock(gDisposableLabMutex);
    if(!Allowed(guestStopped)) {
        if(error)*error=Failure(@"La préparation nécessite KEYOBS et le moteur arrêté.");
        return NO;
    }
    try {
        (void)lab::PrepareOrRearm(SupportPath());
        return YES;
    }catch(const std::exception&) {
        if(error)*error=Failure(
            @"Préparation refusée : laboratoire non récupéré, incomplet ou déjà converti. Aucun fichier n’a été supprimé.");
        return NO;
    }
}
BOOL PVZKeyconvLabKillOnlySynthetic(NSString *phase,
                                   NSString *typedConfirmation,
                                   BOOL guestStopped,
                                   NSError **error) {
    std::lock_guard<std::mutex> lock(gDisposableLabMutex);
    // This function MUST NOT be called by viewDidLoad/v130ContinueLaunch.
    // A future, separate UI first requires an explicit user-selected phase,
    // then a second, typed confirmation inside a destructive warning alert.
    const bool consent=[typedConfirmation
        isEqualToString:@"JE CONFIRME LE CRASH FACTICE"];
    if(!Allowed(guestStopped)||!consent) {
        if(error)*error=Failure(
            @"Crash refusé : confirmation explicite ou isolation absente.");
        return NO;
    }
    try {
        lab::SettleArmedForCrash(SupportPath(),Phase(phase));
        if(error)*error=Failure(@"Checkpoint de crash factice non atteint.");
        return NO;
    }catch(const tx::Interrupted&) {
        // All synthetic images/journal checkpoint bytes have been fsynced.
        // SIGKILL mimics process termination, not a device power cut.
        ::kill(::getpid(),SIGKILL);
        ::_exit(211);
    }catch(const std::exception&) {
        if(error)*error=Failure(
            @"Crash factice refusé : laboratoire non prêt ou non vérifié.");
        return NO;
    }
}
