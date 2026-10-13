#pragma once
// Research-only KEYCONV crash laboratory: synthetic RTON images, never user data.
// Future iOS entry point MUST require separate explicit double confirmation.
// This header does not kill a process itself and is not hooked to app launch.
#include "world_key_prelaunch_native.hpp"
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace pvz2_key_study::disposable_lab {
namespace tx=pvz2_key_study::prelaunch_native;
namespace fs=std::filesystem;
namespace rn=pvz2_key_study::rton_native;
constexpr const char* Directory=".pvz2-keyconv-disposable-lab";
constexpr const char* Marker="LAB_SYNTHETIC_RTON_V1_ONLY\n";
constexpr std::size_t MaxAudit=32768;
constexpr std::size_t Slot=0;
using Fields=std::vector<std::pair<std::string,std::string>>;
struct Report {
    bool exists=false;
    bool old_pair=false;
    bool new_pair=false;
    tx::Recovery recovery=tx::Recovery::NoJournal;
};
inline std::string Var(std::uint64_t n) {
    std::string s;
    do {
        auto byte=static_cast<unsigned char>(n&127u);
        n>>=7u;
        if(n!=0) byte|=128u;
        s.push_back(static_cast<char>(byte));
    }while(n!=0);
    return s;
}
inline std::string Txt(const std::string& t,bool cached=false) {
    return std::string(1,static_cast<char>(cached?0x90:0x81))+
        Var(t.size())+t;
}
inline std::string Num(std::uint64_t n) {
    return std::string(1,char(0x24))+Var(n);
}
inline std::string Obj(const Fields& f) {
    std::string out(1,char(0x85));
    for(const auto& [key,value]:f)out+=Txt(key,true)+value;
    return out+char(0xff);
}
inline std::string Arr(const std::vector<std::string>& f) {
    std::string out{char(0x86),char(0xfd)};
    out+=Var(f.size());
    for(const auto& value:f)out+=value;
    return out+char(0xfe);
}
inline std::string Doc(const Fields& f) {
    std::string out("RTON\x01\x00\x00\x00",8);
    for(const auto& [key,value]:f)out+=Txt(key,true)+value;
    out+=char(0xff);
    return out+"DONE";
}
inline std::string Player(std::uint64_t coins) {
    std::vector<std::string> world_events;
    for(const unsigned event:{13u,23u,33u,39u,41u}) {
        world_events.push_back(Obj({
            {"W",Num(2)},{"E",Num(event)},{"S",Num(3)}
        }));
    }
    return Doc({
        {"version",Num(1)},
        {"objects",Arr({Obj({
            {"objclass",Txt("PlayerInfo")},
            {"objdata",Obj({
                {"i",Num(731)},{"c",Num(coins)},
                {"wsk",Arr({Obj({{"wn",Txt("egypt")},{"kc",Num(1)}})})},
                {"wm",Arr(world_events)},
                {"n",Txt("SYNTHETIC-KEYCONV-TEST-NOT-A-PLAYER")}
            })}
        })})}
    });
}
inline std::string Registry() {
    return Doc({
        {"version",Num(1)},
        {"objects",Arr({Obj({
            {"objclass",Txt("PlayerInfoLocalSaveData")},
            {"objdata",Obj({{"ProfileIndex",Num(731)}})}
        })})}
    });
}
inline std::array<std::string,2> Originals() {
    // Intentionally divergent wallets prove that the fallback remains intact.
    return {Player(9010),Player(7750)};
}
inline fs::path Root(const fs::path& support) {
    // Caller MUST provide NSApplicationSupportDirectory, NEVER V128 live root.
    tx::SafeDirectory(support);
    const auto normalized=support.lexically_normal();
    for(const auto& component:normalized) {
        tx::Require(component!="PvZ2forIOS" &&
                    component!="UserData" &&
                    component!="No_Backup",
                    "Crash lab must never be nested inside guest UserData");
    }
    tx::Require(normalized.is_absolute(),
                "Crash lab support directory must be absolute");
    return normalized/Directory;
}
inline bool Exists(const fs::path& support) {
    return tx::Present(Root(support));
}
inline void Audit(const fs::path& root,std::string_view event) {
    tx::Require(event.size()>0 && event.size()<96 &&
                event.find('\n')==std::string_view::npos,
                "Invalid bounded laboratory event");
    const auto audit=root/"lab-audit.log";
    const int fd=::open(audit.c_str(),O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW);
    tx::Require(fd>=0,"Missing, linked or unsafe laboratory audit");
    struct stat st{};
    if(::fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) ||
       st.st_nlink!=1 || st.st_size<0 ||
       static_cast<std::uint64_t>(st.st_size)>MaxAudit-event.size()-1) {
        ::close(fd);throw tx::Conflict("Laboratory audit size/type changed");
    }
    std::string message(event);
    message.push_back('\n');
    std::size_t offset=0;
    while(offset<message.size()) {
        const ssize_t n=::write(fd,message.data()+offset,message.size()-offset);
        if(n<0 && errno==EINTR)continue;
        if(n<=0) {::close(fd);throw tx::Conflict("Laboratory audit write failed");}
        offset+=static_cast<std::size_t>(n);
    }
    const bool sync=::fsync(fd)==0;
    const bool closed=::close(fd)==0;
    tx::Require(sync&&closed,"Laboratory audit fsync failed");
}
inline std::string AuditText(const fs::path& support) {
    const auto root=Root(support);
    tx::Require(tx::ReadRegular(root/"lab.marker",128)==Marker,
                "Missing synthetic RTON laboratory marker");
    return tx::ReadRegular(root/"lab-audit.log",MaxAudit);
}
inline void Validate(const fs::path& support) {
    const auto root=Root(support);
    tx::ValidateRoot(root);
    tx::Require(tx::ReadRegular(root/"lab.marker",128)==Marker,
                "Crash lab lacks exact synthetic-only marker");
    const auto registry=tx::ReadRegular(tx::Working(root)/"local_profiles",
                                         tx::MaxRegistry);
    tx::Require(registry==Registry(),
                "Crash lab native profile registry changed");
    (void)tx::ReadRegular(root/"lab-audit.log",MaxAudit);
}
inline void Prepare(const fs::path& support) {
    const auto root=Root(support);
    tx::Require(!tx::Present(root),
                "Disposable lab already exists; explicit reset required");
    tx::Require(::mkdir(root.c_str(),0700)==0,
                "Unable to create exclusive disposable lab");
    tx::SyncDirectory(support);
    tx::Require(::mkdir((root/"UserData").c_str(),0700)==0,
                "Unable to stage synthetic UserData");
    tx::Require(::mkdir(tx::Working(root).c_str(),0700)==0,
                "Unable to stage synthetic No_Backup");
    const auto originals=Originals();
    tx::ExclusiveWrite(root/"lab.marker",Marker);
    tx::ExclusiveWrite(root/"lab-audit.log","PREPARED_ONLY_SYNTHETIC\n");
    tx::ExclusiveWrite(tx::Working(root)/"pp.dat",originals[0]);
    tx::ExclusiveWrite(tx::Working(root)/"snapshot2.dat",originals[1]);
    tx::ExclusiveWrite(tx::Working(root)/"local_profiles",Registry());
    tx::SyncDirectory(tx::Working(root));
    tx::SyncDirectory(root/"UserData");
    tx::SyncDirectory(root);
    tx::SyncDirectory(support);
    Validate(support);
}
inline rn::NativePairPlan Planned(const fs::path& support) {
    Validate(support);
    const auto originals=Originals();
    const auto plan=rn::PlanNativePair(originals[0],originals[1],Registry(),Slot);
    tx::Require(plan.changed && plan.saved_keys==1 &&
                plan.primary!=originals[0] &&
                plan.fallback!=originals[1],
                "Synthetic KEYCONV plan is ineligible");
    return plan;
}
inline std::array<std::string,2> LiveImages(const fs::path& support) {
    Validate(support);
    const auto live=tx::Working(Root(support));
    return {tx::ReadRegular(live/"pp.dat",tx::MaxImage),
            tx::ReadRegular(live/"snapshot2.dat",tx::MaxImage)};
}
inline Report RecoverAndVerify(const fs::path& support) {
    Report result;
    if(!Exists(support))return result;
    Validate(support);
    result.exists=true;
    const auto lab=Root(support);
    result.recovery=tx::Recover(lab,true);
    const auto pair=LiveImages(support);
    const auto expected=Planned(support);
    const auto original=Originals();
    result.old_pair=pair==original;
    result.new_pair=pair==std::array<std::string,2>{expected.primary,
                                                      expected.fallback};
    tx::Require(result.old_pair||result.new_pair,
                "Disposable lab torn save after recovery");
    tx::Require(!tx::Present(lab/tx::Journal) &&
                !tx::Present(lab/tx::Done),
                "Disposable lab recovery left unfinished journal");
    // No player names, user amounts, private paths or timestamps emitted.
    switch(result.recovery) {
        case tx::Recovery::NoJournal: Audit(lab,"RECOVERY_NO_JOURNAL");break;
        case tx::Recovery::DiscardedUnpublished:
            Audit(lab,"RECOVERY_UNPUBLISHED_DISCARDED");break;
        case tx::Recovery::RolledBack:Audit(lab,"RECOVERY_ROLLED_BACK");break;
        case tx::Recovery::Committed:Audit(lab,"RECOVERY_COMMITTED");break;
        case tx::Recovery::CleanedDone:Audit(lab,"RECOVERY_CLEANED_DONE");break;
    }
    Audit(lab,result.old_pair?"VERIFIED_OLD_OLD":"VERIFIED_NEW_NEW");
    return result;
}
inline void SettleArmedForCrash(const fs::path& support,tx::CrashAt fault) {
    // Called ONLY after two separate user confirmations in the future iPad UI.
    // Never accept unbounded phase integers or an unknown/None checkpoint.
    switch(fault) {
        case tx::CrashAt::PrimaryInstalled:
        case tx::CrashAt::FallbackInstalled:
        case tx::CrashAt::MarkerPrepared:
        case tx::CrashAt::MarkerPublished:break;
        default:throw tx::Conflict("Unsupported on-device crash phase");
    }
    const auto lab=Root(support);
    Validate(support);
    const auto originals=Originals();
    tx::Require(LiveImages(support)==originals,
                "Disposable lab must begin with unchanged synthetic inputs");
    tx::Require(!tx::Present(lab/tx::Journal) &&
                !tx::Present(lab/tx::Done),
                "Unresolved lab transaction before crash");
    Audit(lab,"USER_CONFIRMED_SYNTHETIC_CRASH");
    switch(fault) {
        case tx::CrashAt::PrimaryInstalled:Audit(lab,"ARM_PRIMARY_RENAMED");break;
        case tx::CrashAt::FallbackInstalled:Audit(lab,"ARM_FALLBACK_RENAMED");break;
        case tx::CrashAt::MarkerPrepared:Audit(lab,"ARM_COMMIT_TEMP");break;
        case tx::CrashAt::MarkerPublished:Audit(lab,"ARM_COMMIT_PUBLISHED");break;
        default:break;
    }
    (void)tx::Settle(lab,Slot,true,true,fault);
    throw tx::Conflict("Requested synthetic crash checkpoint was missed");
}
} // namespace pvz2_key_study::disposable_lab
