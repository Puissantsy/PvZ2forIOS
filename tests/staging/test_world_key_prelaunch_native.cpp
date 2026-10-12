// Synthetic-only native prelaunch transaction crash and recovery tests.
// This fixture never reads or publishes private iPad saves.
#include "world_key_prelaunch_native.hpp"
#include <array>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
using namespace pvz2_key_study::prelaunch_native;
namespace rton_native=pvz2_key_study::rton_native;
using Fields=std::vector<std::pair<std::string,std::string>>;
static int checks=0;
void Check(bool value,const char* msg) {++checks; if(!value) throw std::runtime_error(msg);}
std::string Var(std::uint64_t n) {
    std::string s;
    do {auto b=static_cast<unsigned char>(n&127);n>>=7;if(n)b|=128;
        s.push_back(static_cast<char>(b));}while(n);
    return s;
}
std::string Txt(std::string s,bool cache=false) {
    return std::string(1,static_cast<char>(cache?0x90:0x81))+
           Var(s.size())+s;
}
std::string Num(std::uint64_t n) {return std::string(1,char(0x24))+Var(n);}
std::string Obj(const Fields& fields) {
    std::string s(1,char(0x85));
    for(const auto& [k,v]:fields)s+=Txt(k,true)+v;
    return s+char(0xff);
}
std::string Arr(const std::vector<std::string>& fields) {
    std::string s{char(0x86),char(0xfd)};
    s+=Var(fields.size());
    for(const auto& v:fields)s+=v;
    return s+char(0xfe);
}
std::string Doc(const Fields& fields) {
    std::string s("RTON\x01\x00\x00\x00",8);
    for(const auto& [k,v]:fields)s+=Txt(k,true)+v;
    s+=char(0xff);
    return s+"DONE";
}
std::string Player(std::uint64_t coins,std::uint64_t keys=1,bool open=true,
                   std::uint64_t profile=731) {
    std::vector<std::string> events;
    for(const auto e:{13,23,33,39,41})
        events.push_back(Obj({{"W",Num(2)},{"E",Num(e)},
                              {"S",Num(open||e!=41?3:2)}}));
    return Doc({{"version",Num(1)},
                {"objects",Arr({Obj({{"objclass",Txt("PlayerInfo")},
                   {"objdata",Obj({
                       {"c",Num(coins)},{"i",Num(profile)},
                       {"wsk",Arr({Obj({{"wn",Txt("egypt")},{"kc",Num(keys)}})})},
                       {"wm",Arr(events)},{"n",Txt("FAKE-TEST-PLAYER")}})}})})}});
}
std::string Local(std::uint64_t profile=731) {
    return Doc({{"version",Num(1)},
                {"objects",Arr({Obj({{"objclass",Txt("PlayerInfoLocalSaveData")},
                    {"objdata",Obj({{"ProfileIndex",Num(profile)}})}})})}});
}
void File(const fs::path& path,const std::string& data) {
    std::ofstream out(path,std::ios::binary|std::ios::trunc);
    if(!out)throw std::runtime_error("Cannot write test fixture");
    out.write(data.data(),static_cast<std::streamsize>(data.size()));
    if(!out.good())throw std::runtime_error("Fixture write failure");
}
struct Sandbox {
    fs::path root;
    Sandbox() {
        auto prefix=(fs::temp_directory_path()/"keyconv-native-test-XXXXXX").string();
        std::vector<char> name(prefix.begin(),prefix.end());
        name.push_back('\0');
        char* temp=::mkdtemp(name.data());
        if(!temp)throw std::runtime_error("mkdtemp failure");
        root=temp;
        fs::create_directories(Working(root));
        File(Working(root)/"pp.dat",Player(7800));
        File(Working(root)/"snapshot2.dat",Player(7801));
        File(Working(root)/"local_profiles",Local());
    }
    ~Sandbox() {std::error_code ec;fs::remove_all(root,ec);}
    std::string Read(std::string filename) const {
        return ReadRegular(Working(root)/filename,MaxImage);
    }
};
void ExpectConflict(const std::function<void()>& fn) {
    bool refused=false;
    try {fn();}catch(const Conflict&) {refused=true;}
    Check(refused,"Unsafe native transaction failed to refuse");
}
void TestSha() {
    Check(SHA("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256 known-answer vector");
    Check(SHA("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "SHA-256 empty vector");
}
void TestNormalAndNoRepeat() {
    Sandbox s;
    const auto before=s.Read("snapshot2.dat");
    const auto run=Settle(s.root,0,true,true);
    Check(run.changed && run.keys==1 && run.profile_id==731,
          "Failed synthetic native settlement");
    Check(run.prior==Recovery::NoJournal,"Unexpected prior journal");
    const auto primary=rton_native::Reader(s.Read("pp.dat"),0).Parse();
    const auto fallback=rton_native::Reader(s.Read("snapshot2.dat"),0).Parse();
    const auto& p=rton_native::Player(primary,0);
    const auto& q=rton_native::Player(fallback,0);
    Check(p.Field("c").IntValue()==8800 && q.Field("c").IntValue()==8801,
          "Wallet state or historical fallback divergence changed");
    Check(p.Field("wsk").At(0).Field("kc").IntValue()==0 &&
          q.Field("wsk").At(0).Field("kc").IntValue()==0,
          "Egypt key counter not consumed");
    Check(before!=s.Read("snapshot2.dat"),"Fallback was not transformed");
    Check(Recover(s.root,true)==Recovery::NoJournal,"Journal not cleaned");
    const auto once=s.Read("pp.dat"),other=s.Read("snapshot2.dat");
    const auto again=Settle(s.root,0,true,true);
    Check(!again.changed && once==s.Read("pp.dat") &&
          other==s.Read("snapshot2.dat"),"Double credit on restart");
}
void TestRecoveryFaults() {
    const std::array uncommitted={CrashAt::DirectoryCreated,
        CrashAt::ImagesStaged,CrashAt::ManifestPublished,
        CrashAt::PrimaryInstalled,CrashAt::FallbackInstalled,
        CrashAt::MarkerPrepared};
    for(const auto phase:uncommitted) {
        Sandbox s;
        const auto original=s.Read("pp.dat"),fallback=s.Read("snapshot2.dat");
        bool injected=false;
        try {Settle(s.root,0,true,true,phase);}
        catch(const Interrupted&) {injected=true;}
        Check(injected,"Expected injected interruption");
        const auto status=Recover(s.root,true);
        const auto expected=phase==CrashAt::DirectoryCreated ||
            phase==CrashAt::ImagesStaged ?
            Recovery::DiscardedUnpublished:Recovery::RolledBack;
        Check(status==expected,"Wrong rollback classification");
        Check(s.Read("pp.dat")==original && s.Read("snapshot2.dat")==fallback,
              "Partial native conversion survived rollback");
        Check(Recover(s.root,true)==Recovery::NoJournal,
              "Rollback left active journal");
        const auto newrun=Settle(s.root,0,true,true);
        Check(newrun.changed,"Retry after complete rollback must work");
    }
    for(const auto phase:{CrashAt::MarkerPublished,CrashAt::DonePublished}) {
        Sandbox s;
        bool injected=false;
        try {Settle(s.root,0,true,true,phase);}
        catch(const Interrupted&) {injected=true;}
        Check(injected,"Expected post-commit interruption");
        const auto status=Recover(s.root,true);
        Check(status==(phase==CrashAt::MarkerPublished ?
            Recovery::Committed:Recovery::CleanedDone),
            "Committed journal was rolled back");
        const auto primary=rton_native::Reader(s.Read("pp.dat"),0).Parse();
        Check(rton_native::Player(primary,0).Field("c").IntValue()==8800,
              "Post-commit balance lost");
        Check(!Settle(s.root,0,true,true).changed,
              "Committed conversion double credited after crash");
    }
}
void TestFreshAppRecovery() {
    auto prefix=(fs::temp_directory_path()/"keyconv-native-empty-XXXXXX").string();
    std::vector<char> buffer(prefix.begin(),prefix.end()); buffer.push_back('\0');
    char* tmp=::mkdtemp(buffer.data());
    Check(tmp!=nullptr,"Fresh sandbox creation failed");
    const fs::path empty(tmp);
    Check(Recover(empty,true)==Recovery::NoJournal,
          "Fresh install without UserData was blocked");
    Check(!Settle(empty,0,true,false).changed,
          "Disabled research conversion cannot require a save yet");
    std::error_code ec; fs::remove_all(empty,ec);
}
void TestSafetyBarriers() {
    {
        Sandbox s;
        ExpectConflict([&]{Settle(s.root,0,false,true);});
        Check(s.Read("pp.dat")==Player(7800),"Live-guest attempt mutated save");
        const auto x=Settle(s.root,0,true,false);
        Check(!x.changed && s.Read("pp.dat")==Player(7800),
              "Opt-in gate mutated player");
    }
    {
        Sandbox s;
        File(Working(s.root)/"local_profiles",Local(732));
        ExpectConflict([&]{Settle(s.root,0,true,true);});
        Check(!fs::exists(s.root/Journal),"Invalid profile started journal");
    }
    {
        Sandbox s;
        File(Working(s.root)/"snapshot2.dat",Player(7801,2));
        ExpectConflict([&]{Settle(s.root,0,true,true);});
        Check(!fs::exists(s.root/Journal),"Diverged key count started journal");
    }
    {
        Sandbox s;
        File(Working(s.root)/"pp.dat",Player(7800,6,false));
        File(Working(s.root)/"snapshot2.dat",Player(7801,6,false));
        Check(!Settle(s.root,0,true,true).changed &&
              !fs::exists(s.root/Journal),"Closed last door converted keys");
    }
    {
        Sandbox s;
        File(Working(s.root)/"pp.dat",Player(2147483647));
        ExpectConflict([&]{Settle(s.root,0,true,true);});
    }
    {
        Sandbox s;
        try {Settle(s.root,0,true,true,CrashAt::PrimaryInstalled);}
        catch(const Interrupted&) {}
        File(Working(s.root)/"local_profiles",Local(732));
        ExpectConflict([&]{Recover(s.root,true);});
        Check(fs::exists(s.root/Journal),"Mismatch journal was removed");
    }
    {
        Sandbox s;
        try {Settle(s.root,0,true,true,CrashAt::PrimaryInstalled);}
        catch(const Interrupted&) {}
        File(Working(s.root)/"snapshot2.dat","UNEXPECTED CONCURRENT WRITE");
        ExpectConflict([&]{Recover(s.root,true);});
    }
    {
        Sandbox s;
        try {Settle(s.root,0,true,true,CrashAt::PrimaryInstalled);}
        catch(const Interrupted&) {}
        File(s.root/Journal/"new-pp.dat","CORRUPTED IMAGE");
        ExpectConflict([&]{Recover(s.root,true);});
    }
    {
        Sandbox s;
        fs::create_directories(s.root/Journal);
        File(s.root/Journal/"unknown","unsafe");
        ExpectConflict([&]{Recover(s.root,true);});
    }
    {
        Sandbox s;
        fs::create_directories(s.root/Journal);
        fs::create_symlink(Working(s.root)/"pp.dat",s.root/Journal/"old-pp.dat");
        ExpectConflict([&]{Recover(s.root,true);});
    }
    {
        Sandbox s;
        const auto live=Working(s.root)/"pp.dat";
        fs::remove(live);
        fs::create_symlink(Working(s.root)/"snapshot2.dat",live);
        ExpectConflict([&]{Settle(s.root,0,true,true);});
    }
    {
        Sandbox s;
        try {Settle(s.root,0,true,true,CrashAt::PrimaryInstalled);}
        catch(const Interrupted&) {}
        const auto x=Settle(s.root,0,true,false);
        Check(x.prior==Recovery::RolledBack && !x.changed,
              "Disabled migration skipped mandatory recovery");
        Check(s.Read("pp.dat")==Player(7800),"Read-only recovery failed");
    }
}
int main() {
    try {
        TestSha();
        TestFreshAppRecovery();
        TestNormalAndNoRepeat();
        TestRecoveryFaults();
        TestSafetyBarriers();
        std::cout<<"PASS: "<<checks<<" native prelaunch SHA-256 transaction/recovery assertions\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"FAIL: native transaction test: "<<e.what()<<"\n";
        return 1;
    }
}
