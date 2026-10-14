// Synthetic KEYCONV device crash laboratory, tested under real SIGKILL.
// This fixture uses a separate temporary ApplicationSupport-like directory.
// A sentinel "production" file is never read, renamed, opened or rewritten.
#include "keyconv_disposable_crash_lab.hpp"
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
#include <vector>
namespace fs=std::filesystem;
namespace lab=pvz2_key_study::disposable_lab;
namespace tx=pvz2_key_study::prelaunch_native;
static int checks=0;
void Check(bool condition,const char* msg) {
    ++checks;
    if(!condition)throw std::runtime_error(msg);
}
struct Temp {
    fs::path support;
    fs::path live_canary;
    Temp() {
        auto pattern=(fs::temp_directory_path()/"pvz2-disposable-lab-XXXXXX").string();
        std::vector<char> name(pattern.begin(),pattern.end());
        name.push_back('\0');
        const char* folder=::mkdtemp(name.data());
        if(!folder)throw std::runtime_error("mkdtemp failure");
        support=folder;
        const auto working=support/"PvZ2forIOS"/"UserData"/"No_Backup";
        fs::create_directories(working);
        live_canary=working/"pp.dat";
        std::ofstream out(live_canary,std::ios::binary);
        out<<"DO_NOT_TOUCH_REAL_USERDATA_CANARY";
    }
    ~Temp() {
        std::error_code ec;
        fs::remove_all(support,ec); // test-owned /tmp ONLY
    }
    void Canary()const {
        std::ifstream file(live_canary,std::ios::binary);
        const std::string content(std::istreambuf_iterator<char>(file),{});
        Check(content=="DO_NOT_TOUCH_REAL_USERDATA_CANARY",
              "Real game-side canary was modified");
    }
};
int Child(const char* executable,const char* mode,const fs::path& root,
          int phase=0) {
    const auto phaseString=std::to_string(phase);
    const pid_t child=::fork();
    if(child<0)throw std::runtime_error("fork failure");
    if(child==0) {
        ::execl(executable,executable,mode,root.c_str(),
                phaseString.c_str(),static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int status=0;
    while(::waitpid(child,&status,0)<0) {
        if(errno!=EINTR)throw std::runtime_error("waitpid failure");
    }
    return status;
}
int Worker(int argc,char** argv) {
    if(argc!=4)throw std::runtime_error("worker parameters invalid");
    const std::string action=argv[1];
    const fs::path support=argv[2];
    const auto phase=static_cast<tx::CrashAt>(std::stoi(argv[3]));
    if(action=="interrupt") {
        try {lab::SettleArmedForCrash(support,phase);}
        catch(const tx::Interrupted&) {
            ::kill(::getpid(),SIGKILL);
            ::_exit(201);
        }
        return 202;
    }
    if(action=="recover") {
        const auto result=lab::RecoverAndVerify(support);
        return result.exists&&(result.old_pair||result.new_pair)?0:203;
    }
    return 204;
}
void ExpectKilled(const char* executable,const fs::path& support,
                  tx::CrashAt phase) {
    const int status=Child(executable,"interrupt",support,
                           static_cast<int>(phase));
    Check(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL,
          "Lab child did not actually die with SIGKILL");
}
void RecoverClean(const char* executable,const fs::path& support) {
    const int status=Child(executable,"recover",support);
    Check(WIFEXITED(status)&&WEXITSTATUS(status)==0,
          "Lab was not recovered by a different clean process");
}
void TestBasicGuards() {
    Temp t;
    auto missing=lab::RecoverAndVerify(t.support);
    Check(!missing.exists,"Synthetic lab unexpectedly exists");
    t.Canary();
    // Even fake test support cannot ever be nested under the game's root.
    bool denied=false;
    try {lab::Prepare(t.support/"PvZ2forIOS");}
    catch(const tx::Conflict&) {denied=true;}
    Check(denied,"Crash lab permitted placement inside real root");
    lab::Prepare(t.support);
    const auto initial=lab::LiveImages(t.support);
    Check(initial==lab::Originals(),"Prepared synthetic images differ");
    const auto m=lab::Root(t.support);
    Check(m.filename()==lab::Directory &&
          m.parent_path()==t.support &&
          m!=t.support/"PvZ2forIOS","Lab escaped sibling-root boundary");
    Check(lab::AuditText(t.support)=="PREPARED_ONLY_SYNTHETIC\n",
          "Lab initial audit not durable");
    denied=false;
    try {lab::Prepare(t.support);}catch(const tx::Conflict&){denied=true;}
    Check(denied,"Existing lab was overwritten");
    denied=false;
    try {lab::SettleArmedForCrash(t.support,tx::CrashAt::None);}
    catch(const tx::Conflict&){denied=true;}
    Check(denied,"Crash lab can be called without an explicit phase");
    const auto result=lab::RecoverAndVerify(t.support);
    Check(result.exists && result.old_pair && !result.new_pair &&
          result.recovery==tx::Recovery::NoJournal,
          "Fresh synthetic lab was not recognized as old state");
    t.Canary();
}
void TestKillAndRecover(const char* executable) {
    constexpr std::array phases={
        tx::CrashAt::PrimaryInstalled,
        tx::CrashAt::FallbackInstalled,
        tx::CrashAt::MarkerPrepared,
        tx::CrashAt::MarkerPublished
    };
    for(const auto phase:phases) {
        Temp t;
        lab::Prepare(t.support);
        ExpectKilled(executable,t.support,phase);
        t.Canary();
        const bool committed=phase==tx::CrashAt::MarkerPublished;
        RecoverClean(executable,t.support);
        const auto pair=lab::LiveImages(t.support);
        const auto plan=lab::Planned(t.support);
        const auto originals=lab::Originals();
        Check(pair==(committed ?
            std::array<std::string,2>{plan.primary,plan.fallback}:originals),
            "Lab recovery left a torn pair");
        Check(!tx::Present(lab::Root(t.support)/tx::Journal) &&
              !tx::Present(lab::Root(t.support)/tx::Done),
              "Lab recovery did not clean journal");
        const auto text=lab::AuditText(t.support);
        Check(text.find("PREPARED_ONLY_SYNTHETIC\n")==0 &&
              text.find("USER_CONFIRMED_SYNTHETIC_CRASH")!=std::string::npos &&
              text.find(committed?"RECOVERY_COMMITTED":"RECOVERY_ROLLED_BACK")
                  !=std::string::npos &&
              text.find(committed?"VERIFIED_NEW_NEW":"VERIFIED_OLD_OLD")
                  !=std::string::npos,
              "Crash lab audit failed to survive SIGKILL");
        // Reboot again: no auto re-credit, no silent synthetic re-settlement.
        RecoverClean(executable,t.support);
        Check(lab::LiveImages(t.support)==pair,
              "Second lab recovery awarded keys again");
        if(committed) {
            bool refused=false;
            try {lab::SettleArmedForCrash(t.support,
                                          tx::CrashAt::PrimaryInstalled);}
            catch(const tx::Conflict&){refused=true;}
            Check(refused,"Already-converted lab allowed another crash");
        }
        // After an UNCOMMITTED rollback, the old synthetic key is still
        // eligible. Do not arm a new fault from the parent test process.
        t.Canary();
    }
}
void TestSequentialRearm(const char* executable) {
    Temp t;
    const auto original=lab::Originals();
    Check(!lab::PrepareOrRearm(t.support),"Initial lab did not create fixture");
    bool rejected=false;
    try {lab::PrepareOrRearm(t.support);}
    catch(const tx::Conflict&) {rejected=true;}
    Check(rejected,"Prepared lab re-armed without recovery evidence");
    const std::array stages={
        tx::CrashAt::PrimaryInstalled,
        tx::CrashAt::FallbackInstalled,
        tx::CrashAt::MarkerPrepared,
        tx::CrashAt::MarkerPublished
    };
    for(std::size_t i=0;i<stages.size();++i) {
        if(i!=0) {
            const auto before=lab::AuditText(t.support);
            Check(lab::PrepareOrRearm(t.support),
                  "Verified OLD_OLD could not rearm");
            const auto after=lab::AuditText(t.support);
            Check(after.starts_with(before) &&
                  after.ends_with("REARMED_VERIFIED_OLD_OLD\n"),
                  "Rearming destroyed older crash evidence");
            Check(lab::LiveImages(t.support)==original,
                  "Rearming rewrote synthetic RTON bytes");
        }
        t.Canary();
        ExpectKilled(executable,t.support,stages[i]);
        RecoverClean(executable,t.support);
        const auto pair=lab::LiveImages(t.support);
        const auto plan=lab::Planned(t.support);
        const bool committed=(i+1==stages.size());
        Check(pair==(committed?
            std::array<std::string,2>{plan.primary,plan.fallback}:
            original),"Sequential cold recovery left wrong RTON pair");
        t.Canary();
    }
    const auto audit=lab::AuditText(t.support);
    Check(audit.find("ARM_PRIMARY_RENAMED")!=std::string::npos &&
          audit.find("ARM_FALLBACK_RENAMED")!=std::string::npos &&
          audit.find("ARM_COMMIT_TEMP")!=std::string::npos &&
          audit.find("ARM_COMMIT_PUBLISHED")!=std::string::npos &&
          audit.find("RECOVERY_COMMITTED")!=std::string::npos &&
          audit.ends_with("VERIFIED_NEW_NEW\n"),
          "Sequential lab history lost fault or commit recovery");
    rejected=false;
    try {lab::PrepareOrRearm(t.support);}
    catch(const tx::Conflict&) {rejected=true;}
    Check(rejected,"Committed NEW_NEW lab was incorrectly re-armed");
    t.Canary();
}

void TestTampering() {
    Temp t;
    lab::Prepare(t.support);
    const auto root=lab::Root(t.support);
    // Marker removal or symlink-swapping must fail closed.
    fs::remove(root/"lab.marker");
    fs::create_symlink(t.live_canary,root/"lab.marker");
    bool refused=false;
    try {lab::RecoverAndVerify(t.support);}
    catch(const tx::Conflict&){refused=true;}
    Check(refused,"Symlinked lab marker was accepted");
    t.Canary();
}
int main(int argc,char** argv) {
    try {
        if(argc>1)return Worker(argc,argv);
        TestBasicGuards();
        TestKillAndRecover(argv[0]);
        TestSequentialRearm(argv[0]);
        TestTampering();
        std::cout<<"PASS: "<<checks
                 <<" research-only isolated synthetic crash-lab assertions"
                 <<"; real SIGKILL, durable audit, rollback/commit,"
                 <<" production canary untouched\n";
        return 0;
    }catch(const std::exception& e) {
        std::cerr<<"Disposable KEYCONV crash-lab error: "<<e.what()<<"\n";
        return 1;
    }
}
