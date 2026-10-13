// Independent synthetic process-level SIGKILL crash/restart test for the
// KEYCONV research-only two-RTON journal. No iPad save or live app touched.
// The test launches NEW executable processes for settlement and recovery;
// injected failures end with SIGKILL, bypassing destructors and exception
// unwinding. Does NOT simulate a device power loss / APFS durability failure.
#include "world_key_prelaunch_native.hpp"
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace fs=std::filesystem;
namespace txn=pvz2_key_study::prelaunch_native;
namespace native=pvz2_key_study::rton_native;
using Fields=std::vector<std::pair<std::string,std::string>>;
static int verified=0;
void Check(bool ok,const char* cause) {
    ++verified;
    if(!ok) throw std::runtime_error(cause);
}
std::string Var(std::uint64_t n) {
    std::string s;
    do {auto b=static_cast<unsigned char>(n&127u);
        n>>=7u; if(n!=0) b|=128u; s.push_back(static_cast<char>(b));
    } while(n);
    return s;
}
std::string Txt(const std::string& s,bool cache=false) {
    return std::string(1,static_cast<char>(cache?0x90:0x81))+
        Var(s.size())+s;
}
std::string Num(std::uint64_t n) {return std::string(1,char(0x24))+Var(n);}
std::string Obj(const Fields& fields) {
    std::string s(1,char(0x85));
    for(const auto& [k,v]:fields) s+=Txt(k,true)+v;
    return s+char(0xff);
}
std::string Arr(const std::vector<std::string>& items) {
    std::string s{char(0x86),char(0xfd)};
    s+=Var(items.size());
    for(const auto& v:items) s+=v;
    return s+char(0xfe);
}
std::string Doc(const Fields& fields) {
    std::string s("RTON\x01\x00\x00\x00",8);
    for(const auto& [k,v]:fields) s+=Txt(k,true)+v;
    s+=char(0xff);
    return s+"DONE";
}
std::string Player(std::uint64_t wallet,std::uint64_t keys=1) {
    std::vector<std::string> events;
    for(const unsigned event:{13u,23u,33u,39u,41u})
        events.push_back(Obj({{"W",Num(2)},{"E",Num(event)},{"S",Num(3)}}));
    const auto info=Obj({{"c",Num(wallet)},{"i",Num(731)},
        {"wsk",Arr({Obj({{"wn",Txt("egypt")},{"kc",Num(keys)}})})},
        {"wm",Arr(events)},{"n",Txt("FAKE-FIXTURE")}});
    return Doc({{"version",Num(1)},{"objects",Arr({
        Obj({{"objclass",Txt("PlayerInfo")},{"objdata",info}})
    })}});
}
std::string Registry() {
    return Doc({{"version",Num(1)},{"objects",Arr({
        Obj({{"objclass",Txt("PlayerInfoLocalSaveData")},
             {"objdata",Obj({{"ProfileIndex",Num(731)}})}})
    })}});
}
void Write(const fs::path& path,const std::string& bytes) {
    std::ofstream file(path,std::ios::binary|std::ios::trunc);
    if(!file || !file.write(bytes.data(),
                           static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("Could not write synthetic disposable RTON");
}
std::string Read(const fs::path& path) {
    return txn::ReadRegular(path,txn::MaxImage);
}
struct Sandbox {
    fs::path root;
    Sandbox() {
        auto prefix=(fs::temp_directory_path()/"pvz2-sigkill-test-XXXXXX").string();
        std::vector<char> characters(prefix.begin(),prefix.end());
        characters.push_back('\0');
        char* name=::mkdtemp(characters.data());
        if(!name) throw std::runtime_error("mkdtemp failed");
        root=fs::path(name);
        fs::create_directories(txn::Working(root));
        Write(txn::Working(root)/"pp.dat",Player(9010));
        Write(txn::Working(root)/"snapshot2.dat",Player(7750));
        Write(txn::Working(root)/"local_profiles",Registry());
    }
    ~Sandbox() {std::error_code ec;fs::remove_all(root,ec);}
};
int RunWorker(int argc,char** argv) {
    if(argc!=5) throw std::runtime_error("Worker arguments invalid");
    const std::string mode=argv[1];
    const fs::path root=argv[2];
    const int phase=std::stoi(argv[3]);
    const int expected=std::stoi(argv[4]);
    if(mode=="abort-settle") {
        try {txn::Settle(root,0,true,true,static_cast<txn::CrashAt>(phase));}
        catch(const txn::Interrupted&) {
            ::kill(::getpid(),SIGKILL);
            ::_exit(121);
        }
        return 122; // An injected fault was unexpectedly missed.
    }
    if(mode=="abort-rollback") {
        try {txn::Recover(root,true,txn::CrashAt::RollbackPrimaryInstalled);}
        catch(const txn::Interrupted&) {
            ::kill(::getpid(),SIGKILL);
            ::_exit(123);
        }
        return 124;
    }
    if(mode=="recover") {
        const auto outcome=txn::Recover(root,true);
        return static_cast<int>(outcome)==expected ? 0:125;
    }
    if(mode=="settle") {
        const auto result=txn::Settle(root,0,true,true);
        return result.changed==static_cast<bool>(expected) ? 0:126;
    }
    throw std::runtime_error("Unrecognized worker mode");
}
int Child(const char* executable,const char* mode,const fs::path& root,
          int phase=0,int expected=0) {
    const pid_t child=::fork();
    if(child<0) throw std::runtime_error("fork failed");
    if(child==0) {
        const auto phase_arg=std::to_string(phase);
        const auto expected_arg=std::to_string(expected);
        ::execl(executable,executable,mode,root.c_str(),
                phase_arg.c_str(),expected_arg.c_str(),
                static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int status=0;
    while(::waitpid(child,&status,0)<0) {
        if(errno!=EINTR) throw std::runtime_error("waitpid failed");
    }
    return status;
}
void WaitForKill(const char* executable,const char* mode,const fs::path& root,
                 txn::CrashAt phase=txn::CrashAt::None) {
    const int status=Child(executable,mode,root,static_cast<int>(phase));
    Check(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL,
          "Worker did not really terminate via SIGKILL");
}
void WaitForSuccess(const char* exe,const char* mode,const fs::path& root,
                    int expected=0) {
    const int status=Child(exe,mode,root,0,expected);
    Check(WIFEXITED(status) && WEXITSTATUS(status)==0,
          "Independent cold-restart process failed");
}
void CheckImages(const fs::path& root,const std::array<std::string,2>& images) {
    const auto working=txn::Working(root);
    Check(Read(working/"pp.dat")==images[0],
          "Primary RTON unexpectedly changed across kill/recover");
    Check(Read(working/"snapshot2.dat")==images[1],
          "Fallback RTON unexpectedly changed across kill/recover");
}
void JournalAbsent(const fs::path& root) {
    Check(!txn::Present(root/txn::Journal) &&
          !txn::Present(root/txn::Done),
          "Transaction journal leaked into following guest start");
}
void RunAll(const char* executable) {
    const std::array phases={
        txn::CrashAt::DirectoryCreated,
        txn::CrashAt::OldPrimaryStaged,
        txn::CrashAt::NewPrimaryStaged,
        txn::CrashAt::OldFallbackStaged,
        txn::CrashAt::NewFallbackStaged,
        txn::CrashAt::ImagesStaged,
        txn::CrashAt::ManifestTempWritten,
        txn::CrashAt::ManifestPublished,
        txn::CrashAt::PrimarySwapStaged,
        txn::CrashAt::PrimaryInstalled,
        txn::CrashAt::FallbackSwapStaged,
        txn::CrashAt::FallbackInstalled,
        txn::CrashAt::MarkerPrepared,
        txn::CrashAt::MarkerPublished,
        txn::CrashAt::DonePublished
    };
    for(const auto phase:phases) {
        Sandbox s;
        const auto working=txn::Working(s.root);
        const std::array old={Read(working/"pp.dat"),
                              Read(working/"snapshot2.dat")};
        const auto planned=native::PlanNativePair(
            old[0],old[1],Read(working/"local_profiles"),0);
        Check(planned.changed && planned.saved_keys==1,
              "Invalid original synthetic world key");
        const std::array new_images={planned.primary,planned.fallback};
        WaitForKill(executable,"abort-settle",s.root,phase);
        const bool commit=phase==txn::CrashAt::MarkerPublished ||
                          phase==txn::CrashAt::DonePublished;
        const bool no_manifest=phase==txn::CrashAt::DirectoryCreated ||
                               phase==txn::CrashAt::OldPrimaryStaged ||
                               phase==txn::CrashAt::NewPrimaryStaged ||
                               phase==txn::CrashAt::OldFallbackStaged ||
                               phase==txn::CrashAt::NewFallbackStaged ||
                               phase==txn::CrashAt::ImagesStaged ||
                               phase==txn::CrashAt::ManifestTempWritten;
        const auto expected=phase==txn::CrashAt::DonePublished ?
            txn::Recovery::CleanedDone :
            commit? txn::Recovery::Committed :
            no_manifest? txn::Recovery::DiscardedUnpublished:
                         txn::Recovery::RolledBack;
        WaitForSuccess(executable,"recover",s.root,static_cast<int>(expected));
        CheckImages(s.root,commit?new_images:old);
        JournalAbsent(s.root);
        // The follow-up conversion is a NEW process, not a retry following
        // a fault in the same app lifetime.
        WaitForSuccess(executable,"settle",s.root,commit?0:1);
        CheckImages(s.root,new_images);
        WaitForSuccess(executable,"settle",s.root,0);
        CheckImages(s.root,new_images);
        JournalAbsent(s.root);
    }
    // Interrupted ROLLBACK itself: first settlement crashes after BOTH live
    // files became new (but before commit), next process dies after restoring
    // only primary; the third fresh process must finish both rollbacks.
    {
        Sandbox s;
        const auto working=txn::Working(s.root);
        const std::array old={Read(working/"pp.dat"),
                              Read(working/"snapshot2.dat")};
        const auto planned=native::PlanNativePair(
            old[0],old[1],Read(working/"local_profiles"),0);
        const std::array target={planned.primary,planned.fallback};
        WaitForKill(executable,"abort-settle",s.root,
                    txn::CrashAt::FallbackInstalled);
        CheckImages(s.root,target);
        WaitForKill(executable,"abort-rollback",s.root);
        CheckImages(s.root,{old[0],target[1]}); // actual intermediate state
        WaitForSuccess(executable,"recover",s.root,
                       static_cast<int>(txn::Recovery::RolledBack));
        CheckImages(s.root,old);
        JournalAbsent(s.root);
        WaitForSuccess(executable,"settle",s.root,1);
        CheckImages(s.root,target);
        WaitForSuccess(executable,"settle",s.root,0);
    }
    std::cout<<"PASS: "<<verified
             <<" synthetic cross-process assertions; "<<phases.size()
             <<" independent SIGKILL settlement points + interrupted rollback,"
             <<" full restart, exact two-image recovery, no double credit\n";
}
int main(int argc,char** argv) {
    try {
        if(argc==1) {RunAll(argv[0]);return 0;}
        return RunWorker(argc,argv);
    } catch(const std::exception& e) {
        std::cerr<<"KEYCONV synthetic process kill failure: "<<e.what()<<"\n";
        return 2;
    }
}
