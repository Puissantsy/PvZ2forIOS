#pragma once
// KEYCONV research-only C++20 stopped-guest two-RTON transaction.
// NOT linked into iOS. All real app use requires an explicit opt-in + JIT gate.
// The on-disk journal is OUTSIDE UserData; recovery is mandatory before
// offering a new restore or allowing the original guest/V128 to start.
#include "world_key_rton_native_pair.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif

namespace pvz2_key_study::prelaunch_native {
namespace fs=std::filesystem;
using rton_native::PlanNativePair;
using rton_native::Reader;
using rton_native::Error;
constexpr std::size_t MaxImage=64u*1024u*1024u;
constexpr std::size_t MaxRegistry=4u*1024u*1024u;
constexpr const char* Journal=".pvz2-keyconv-native-journal";
constexpr const char* Done=".pvz2-keyconv-native-journal.done";
constexpr std::array<std::string_view,2> Files={"pp.dat","snapshot2.dat"};

struct Conflict:std::runtime_error { using std::runtime_error::runtime_error; };
struct Interrupted:std::runtime_error { using std::runtime_error::runtime_error; };
enum class CrashAt { None, DirectoryCreated, ImagesStaged, ManifestPublished,
    PrimaryInstalled, FallbackInstalled, MarkerPrepared, MarkerPublished,
    DonePublished };
enum class Recovery { NoJournal, DiscardedUnpublished, RolledBack,
    Committed, CleanedDone };
struct Settlement {
    bool changed=false;
    std::int64_t profile_id=0;
    std::int64_t keys=0;
    Recovery prior=Recovery::NoJournal;
};

inline void Require(bool ok,const char* why) {
    if(!ok) throw Conflict(why);
}
inline void Crash(CrashAt actual,CrashAt expected) {
    if(actual==expected) throw Interrupted("Simulated prelaunch interruption");
}
inline void SafeDirectory(const fs::path& path) {
    std::error_code ec;
    const auto st=fs::symlink_status(path,ec);
    Require(!ec && fs::is_directory(st) && !fs::is_symlink(st),
            "Unsafe or absent parent directory");
}
inline void SyncDirectory(const fs::path& path) {
    const int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    Require(fd>=0,"Cannot open directory for durable sync");
    struct stat st{};
    const bool ok=::fstat(fd,&st)==0 && S_ISDIR(st.st_mode) &&
                  ::fsync(fd)==0;
    const bool close_ok=::close(fd)==0;
    Require(ok && close_ok,"Directory fsync failed");
}
inline std::string ReadRegular(const fs::path& path,std::size_t max_size) {
    const int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    Require(fd>=0,"Missing or unsafe regular file");
    struct stat st{};
    if(::fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_nlink!=1 ||
       st.st_size<0 || static_cast<std::uint64_t>(st.st_size)>max_size) {
        ::close(fd);
        throw Conflict("Linked, non-regular or oversized file");
    }
    std::string result;
    result.reserve(static_cast<std::size_t>(st.st_size));
    std::array<char,16384> block{};
    for(;;) {
        const ssize_t n=::read(fd,block.data(),block.size());
        if(n<0 && errno==EINTR) continue;
        if(n<0) {::close(fd);throw Conflict("Failed file read");}
        if(n==0) break;
        if(static_cast<std::size_t>(n)>max_size-result.size()) {
            ::close(fd);throw Conflict("File grew over limit");
        }
        result.append(block.data(),static_cast<std::size_t>(n));
    }
    const bool close_ok=::close(fd)==0;
    Require(close_ok && result.size()==static_cast<std::size_t>(st.st_size),
            "Unstable file size during read");
    return result;
}
inline void ExclusiveWrite(const fs::path& path,const std::string& data) {
    const int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    Require(fd>=0,"Exclusive checkpoint create failed");
    std::size_t offset=0;
    while(offset<data.size()) {
        const ssize_t n=::write(fd,data.data()+offset,data.size()-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) {::close(fd);throw Conflict("Write checkpoint failed");}
        offset+=static_cast<std::size_t>(n);
    }
    const bool ok=::fsync(fd)==0;
    const bool closed=::close(fd)==0;
    Require(ok && closed,"Checkpoint fsync failed");
}
inline std::string SHA(const std::string& content) {
    unsigned char hash[32]{};
#ifdef __APPLE__
    Require(content.size()<=std::numeric_limits<CC_LONG>::max(),
            "CommonCrypto input too large");
    CC_SHA256(content.data(),static_cast<CC_LONG>(content.size()),hash);
#else
    Require(SHA256(reinterpret_cast<const unsigned char*>(content.data()),
                   content.size(),hash)!=nullptr,"OpenSSL SHA-256 failed");
#endif
    static constexpr char H[]="0123456789abcdef";
    std::string out; out.reserve(64);
    for(unsigned char c:hash) {out.push_back(H[c>>4]);out.push_back(H[c&15]);}
    return out;
}
inline bool IsHexDigest(const std::string& value) {
    if(value.size()!=64) return false;
    return std::all_of(value.begin(),value.end(),[](char c) {
        return (c>='0'&&c<='9') || (c>='a'&&c<='f');
    });
}
inline void RemoveRegular(const fs::path& path) {
    const auto file=ReadRegular(path,MaxImage);
    (void)file;
    Require(::unlink(path.c_str())==0,"Failed to remove journal file");
}
inline std::vector<std::string> Entries(const fs::path& dir) {
    SafeDirectory(dir);
    std::vector<std::string> result;
    std::error_code ec;
    for(fs::directory_iterator i(dir,ec),end; !ec && i!=end; i.increment(ec)) {
        const auto name=i->path().filename().string();
        const bool known=name=="manifest" || name=="manifest.tmp" ||
            name=="committed" || name=="committed.tmp" ||
            name=="old-pp.dat" || name=="old-snapshot2.dat" ||
            name=="new-pp.dat" || name=="new-snapshot2.dat" ||
            name=="swap-pp.dat" || name=="swap-snapshot2.dat";
        Require(known,"Unknown entry in transaction journal");
        const auto st=fs::symlink_status(i->path(),ec);
        Require(!ec && fs::is_regular_file(st) && !fs::is_symlink(st),
                "Unsafe journal entry");
        result.push_back(name);
    }
    Require(!ec,"Cannot inspect transaction journal");
    return result;
}
inline bool Has(const std::vector<std::string>& list,std::string_view name) {
    return std::find(list.begin(),list.end(),name)!=list.end();
}
inline void CleanupDirectory(const fs::path& root,const fs::path& dir) {
    const auto entries=Entries(dir);
    for(const auto& name:entries) RemoveRegular(dir/name);
    SyncDirectory(dir);
    Require(::rmdir(dir.c_str())==0,"Cannot remove transaction journal");
    SyncDirectory(root);
}
inline void Finish(const fs::path& root) {
    const auto j=root/Journal,d=root/Done;
    Require(!fs::exists(d) && !fs::is_symlink(d),
            "A previous finalization is incomplete");
    Require(::rename(j.c_str(),d.c_str())==0,
            "Cannot publish finalized transaction");
    SyncDirectory(root);
    CleanupDirectory(root,d);
}
inline void AtomicInstall(const fs::path& journal,const fs::path& destination,
                          const std::string& image) {
    const auto temp=journal/("swap-"+destination.filename().string());
    if(fs::exists(temp) || fs::is_symlink(temp)) {
        RemoveRegular(temp); SyncDirectory(journal);
    }
    ExclusiveWrite(temp,image);
    SyncDirectory(journal);
    Require(::rename(temp.c_str(),destination.c_str())==0,
            "Atomic image replacement failed");
    SyncDirectory(destination.parent_path());
}
struct Record {
    std::size_t old_size=0,new_size=0;
    std::string old_hash,new_hash;
};
struct Manifest {
    std::size_t slot=0;
    std::int64_t native_id=0;
    std::string registry_sha;
    std::array<Record,2> files{};
};
inline std::string FormatManifest(const Manifest& m) {
    std::ostringstream ss;
    ss<<"PVZ2KEYCONV_NATIVE1 "<<m.slot<<" "<<m.native_id<<" "
      <<m.registry_sha<<"\n";
    for(std::size_t i=0;i<Files.size();++i) {
        const auto& r=m.files[i];
        ss<<Files[i]<<" "<<r.old_size<<" "<<r.old_hash<<" "
          <<r.new_size<<" "<<r.new_hash<<"\n";
    }
    return ss.str();
}
inline Manifest ParseManifest(const std::string& data) {
    Require(data.size()<4096,"Oversized transaction manifest");
    std::istringstream in(data);
    std::string magic;
    Manifest m;
    Require(static_cast<bool>(in>>magic>>m.slot>>m.native_id>>m.registry_sha) &&
            magic=="PVZ2KEYCONV_NATIVE1" &&
            m.slot<128 && m.native_id>0 && IsHexDigest(m.registry_sha),
            "Invalid journal manifest header");
    for(std::size_t i=0;i<Files.size();++i) {
        std::string filename;
        auto& r=m.files[i];
        Require(static_cast<bool>(in>>filename>>r.old_size>>r.old_hash>>
                                  r.new_size>>r.new_hash) &&
                filename==Files[i] && r.old_size<=MaxImage &&
                r.new_size<=MaxImage && IsHexDigest(r.old_hash) &&
                IsHexDigest(r.new_hash),
                "Invalid manifest file record");
    }
    std::string trailing;
    Require(!(in>>trailing),"Unexpected manifest trailing contents");
    return m;
}
inline void ValidateRoot(const fs::path& root) {
    SafeDirectory(root);
    SafeDirectory(root/"UserData");
    SafeDirectory(root/"UserData"/"No_Backup");
}
inline fs::path Working(const fs::path& root) {
    return root/"UserData"/"No_Backup";
}
inline std::int64_t RegistryId(const std::string& registry,std::size_t slot) {
    try {
        const auto record=Reader(registry,slot).Parse().Field("objects").At(slot);
        Require(record.Field("objclass").StrValue()=="PlayerInfoLocalSaveData",
                "Wrong local profile type");
        const auto id=record.Field("objdata").Field("ProfileIndex").IntValue();
        Require(id>0,"Invalid local native profile");
        return id;
    } catch(const Error&) { throw Conflict("Cannot verify native profile registry"); }
}
inline std::array<std::string,4> ValidateImages(const fs::path& journal,
                                                const Manifest& m) {
    std::array<std::string,4> images;
    for(std::size_t i=0;i<Files.size();++i) {
        const auto& name=Files[i];
        const auto& record=m.files[i];
        const auto old=ReadRegular(journal/("old-"+std::string(name)),MaxImage);
        const auto next=ReadRegular(journal/("new-"+std::string(name)),MaxImage);
        Require(old.size()==record.old_size && SHA(old)==record.old_hash &&
                next.size()==record.new_size && SHA(next)==record.new_hash,
                "Transaction image hash or size changed");
        images[i*2]=old;
        images[i*2+1]=next;
    }
    return images;
}
inline Recovery Recover(const fs::path& root,bool guest_stopped) {
    Require(guest_stopped,"Recovery requires stopped guest and V128");
    // A fresh app has no UserData yet: the recovery gate must be safe even
    // BEFORE v165 offers its first restore or before the first game launch.
    SafeDirectory(root);
    const auto journal=root/Journal,done=root/Done;
    const bool active=fs::exists(journal) || fs::is_symlink(journal);
    const bool completed=fs::exists(done) || fs::is_symlink(done);
    Require(!(active&&completed),"Conflicting active/finalized journals");
    if(completed) {
        CleanupDirectory(root,done);
        return Recovery::CleanedDone;
    }
    if(!active) return Recovery::NoJournal;
    ValidateRoot(root);
    const auto entries=Entries(journal);
    if(!Has(entries,"manifest")) {
        Require(!Has(entries,"committed") && !Has(entries,"committed.tmp") &&
                !Has(entries,"swap-pp.dat") &&
                !Has(entries,"swap-snapshot2.dat"),
                "Unpublished journal contains write or marker");
        Finish(root);
        return Recovery::DiscardedUnpublished;
    }
    const auto m=ParseManifest(ReadRegular(journal/"manifest",4096));
    const auto images=ValidateImages(journal,m);
    const auto working=Working(root);
    const auto registry=ReadRegular(working/"local_profiles",MaxRegistry);
    Require(SHA(registry)==m.registry_sha &&
            RegistryId(registry,m.slot)==m.native_id,
            "Native profile registry changed during interrupted transaction");
    std::array<std::string,2> live{};
    for(std::size_t i=0;i<2;++i) {
        live[i]=ReadRegular(working/std::string(Files[i]),MaxImage);
        Require(live[i]==images[i*2] || live[i]==images[i*2+1],
                "Live save differs from both transaction images");
    }
    const bool committed=Has(entries,"committed");
    if(committed) {
        Require(ReadRegular(journal/"committed",64)=="COMMITTED\n",
                "Corrupt durable commit marker");
        for(std::size_t i=0;i<2;++i)
            Require(live[i]==images[i*2+1],
                    "Committed transaction has an incomplete image");
        Finish(root);
        return Recovery::Committed;
    }
    for(std::size_t i=0;i<2;++i) {
        if(live[i]!=images[i*2])
            AtomicInstall(journal,working/std::string(Files[i]),images[i*2]);
    }
    Finish(root);
    return Recovery::RolledBack;
}
inline Settlement Settle(const fs::path& root,std::size_t slot,
                         bool guest_stopped,bool explicit_opt_in,
                         CrashAt fault=CrashAt::None) {
    Require(guest_stopped,"Settlement requires stopped guest and V128");
    // Always resolve any previous journal before accepting NEW restorations.
    const auto prior=Recover(root,guest_stopped);
    if(!explicit_opt_in) return Settlement{false,0,0,prior};
    const auto working=Working(root);
    const auto original_reg=ReadRegular(working/"local_profiles",MaxRegistry);
    std::array<std::string,2> original{},target{};
    for(std::size_t i=0;i<2;++i)
        original[i]=ReadRegular(working/std::string(Files[i]),MaxImage);
    rton_native::NativePairPlan plan;
    try { plan=PlanNativePair(original[0],original[1],original_reg,slot); }
    catch(const Error&) { throw Conflict("Native RTON eligibility/identity conflict"); }
    if(!plan.changed) return Settlement{false,plan.native_id,0,prior};
    const auto journal=root/Journal;
    Require(::mkdir(journal.c_str(),0700)==0,
            "Cannot create exclusive native transaction journal");
    SyncDirectory(root);
    Crash(fault,CrashAt::DirectoryCreated);
    const auto mreg=SHA(original_reg);
    Manifest m;
    m.slot=slot; m.native_id=plan.native_id; m.registry_sha=mreg;
    target={plan.primary,plan.fallback};
    for(std::size_t i=0;i<2;++i) {
        const auto name=std::string(Files[i]);
        m.files[i]={original[i].size(),target[i].size(),
                    SHA(original[i]),SHA(target[i])};
        ExclusiveWrite(journal/("old-"+name),original[i]);
        ExclusiveWrite(journal/("new-"+name),target[i]);
    }
    SyncDirectory(journal);
    Crash(fault,CrashAt::ImagesStaged);
    Require(ReadRegular(working/"local_profiles",MaxRegistry)==original_reg,
            "Native profile registry changed while staging");
    ExclusiveWrite(journal/"manifest.tmp",FormatManifest(m));
    SyncDirectory(journal);
    Require(::rename((journal/"manifest.tmp").c_str(),
                     (journal/"manifest").c_str())==0,
            "Cannot atomically publish manifest");
    SyncDirectory(journal);
    Crash(fault,CrashAt::ManifestPublished);
    for(std::size_t i=0;i<2;++i) {
        Require(ReadRegular(working/std::string(Files[i]),MaxImage)==original[i],
                "Live image changed while guest was expected to be stopped");
        AtomicInstall(journal,working/std::string(Files[i]),target[i]);
        Crash(fault,i==0?CrashAt::PrimaryInstalled:CrashAt::FallbackInstalled);
    }
    Require(ReadRegular(working/"local_profiles",MaxRegistry)==original_reg,
            "Native registry changed before durable commit");
    for(std::size_t i=0;i<2;++i)
        Require(ReadRegular(working/std::string(Files[i]),MaxImage)==target[i],
                "Installed RTON image differs from planned target");
    ExclusiveWrite(journal/"committed.tmp","COMMITTED\n");
    SyncDirectory(journal);
    Crash(fault,CrashAt::MarkerPrepared);
    Require(::rename((journal/"committed.tmp").c_str(),
                     (journal/"committed").c_str())==0,
            "Cannot publish durable commit marker");
    SyncDirectory(journal);
    Crash(fault,CrashAt::MarkerPublished);
    Require(::rename(journal.c_str(),(root/Done).c_str())==0,
            "Cannot finalize committed transaction");
    SyncDirectory(root);
    Crash(fault,CrashAt::DonePublished);
    CleanupDirectory(root,root/Done);
    return Settlement{true,plan.native_id,plan.saved_keys,prior};
}
} // namespace pvz2_key_study::prelaunch_native
