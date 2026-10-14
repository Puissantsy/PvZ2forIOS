// All input RTONs in this test are fabricated: no private game/profile data.
#include "world_key_auto_settlement.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
namespace fs=std::filesystem;
namespace ak=pvz2_key_study::auto_keyconv;
namespace tx=pvz2_key_study::prelaunch_native;
using Fields=std::vector<std::pair<std::string,std::string>>;
static int assertions=0;
void Check(bool ok,const char* note){++assertions;if(!ok)throw std::runtime_error(note);}
std::string Var(std::uint64_t n) {
    std::string s;
    do {unsigned char b=static_cast<unsigned char>(n&127);
        n>>=7;if(n)b|=128;s.push_back(static_cast<char>(b));}while(n);
    return s;
}
std::string Str(const std::string& t,bool cached=false) {
    return std::string(1,char(cached?0x90:0x81))+Var(t.size())+t;
}
std::string Num(std::uint64_t n){return std::string(1,char(0x24))+Var(n);}
std::string Obj(const Fields& f){
    std::string s(1,char(0x85));
    for(const auto& [k,v]:f)s+=Str(k,true)+v;
    return s+char(0xff);
}
std::string Array(const std::vector<std::string>& items){
    std::string s{char(0x86),char(0xfd)};
    s+=Var(items.size());
    for(const auto& x:items)s+=x;
    return s+char(0xfe);
}
std::string Doc(const Fields& f){
    std::string s("RTON\x01\x00\x00\x00",8);
    for(const auto& [k,v]:f)s+=Str(k,true)+v;
    return s+char(0xff)+"DONE";
}
std::string Save(const std::array<std::uint64_t,2>& coins,
                 bool secondOpen=true) {
    std::vector<std::string> people;
    for(std::size_t i=0;i<2;++i) {
        std::vector<std::string> gates;
        for(auto id:{13u,23u,33u,39u,41u})
            gates.push_back(Obj({{"W",Num(2)},{"E",Num(id)},
                {"S",Num(i==0||secondOpen||id!=41u?3:2)}}));
        auto keys=Array({Obj({{"wn",Str("egypt")},{"kc",Num(i==0?3:2)}}),
                         Obj({{"wn",Str("pirate")},{"kc",Num(9)}})});
        people.push_back(Obj({{"objclass",Str("PlayerInfo")},
            {"objdata",Obj({{"i",Num(900+i)},{"c",Num(coins[i])},
                {"wm",Array(gates)},{"wsk",keys},
                {"sentinel",Str("FAKE-ONLY")}})}}));
    }
    return Doc({{"objects",Array(people)}});
}
std::string Registry() {
    return Doc({{"objects",Array({
        Obj({{"objclass",Str("PlayerInfoLocalSaveData")},
            {"objdata",Obj({{"ProfileIndex",Num(900)}})}}),
        Obj({{"objclass",Str("PlayerInfoLocalSaveData")},
            {"objdata",Obj({{"ProfileIndex",Num(901)}})}})
    })}});
}
void Write(const fs::path& p,const std::string& s) {
    std::ofstream file(p,std::ios::binary);
    if(!file || !file.write(s.data(),static_cast<std::streamsize>(s.size())))
        throw std::runtime_error("Cannot create synthetic test image");
}
struct Scratch {
    fs::path root;
    explicit Scratch(bool secondOpen=true) {
        auto pattern=(fs::temp_directory_path()/"pvz2-auto-txn-XXXXXX").string();
        std::vector<char> path(pattern.begin(),pattern.end());
        path.push_back('\0');
        const char* dir=::mkdtemp(path.data());
        if(!dir)throw std::runtime_error("mkdtemp failure");
        root=dir;
        fs::create_directories(tx::Working(root));
        Write(tx::Working(root)/"pp.dat",Save({9010,510},secondOpen));
        Write(tx::Working(root)/"snapshot2.dat",Save({7750,490},secondOpen));
        Write(tx::Working(root)/"local_profiles",Registry());
    }
    ~Scratch(){std::error_code ec;fs::remove_all(root,ec);}
    std::string Read(const char* n)const{
        return tx::ReadRegular(tx::Working(root)/n,tx::MaxImage);
    }
};
void Verify(const Scratch& s,std::array<std::int64_t,2> primary,
            std::array<std::int64_t,2> fallback,
            std::array<std::int64_t,2> keyCount) {
    const auto first=pvz2_key_study::rton_native::Reader(s.Read("pp.dat"),0).Parse();
    const auto second=pvz2_key_study::rton_native::Reader(s.Read("snapshot2.dat"),0).Parse();
    for(std::size_t slot=0;slot<2;++slot) {
        const auto& a=pvz2_key_study::rton_native::Player(first,slot);
        const auto& b=pvz2_key_study::rton_native::Player(second,slot);
        Check(a.Field("c").IntValue()==primary[slot],"wrong primary wallet");
        Check(b.Field("c").IntValue()==fallback[slot],"fallback wallet overwritten");
        Check(a.Field("wsk").At(0).Field("kc").IntValue()==keyCount[slot],
              "Primary Egypt key mismatch");
        Check(b.Field("wsk").At(0).Field("kc").IntValue()==keyCount[slot],
              "Fallback Egypt key mismatch");
        Check(a.Field("wsk").At(1).Field("kc").IntValue()==9,
              "Pirate keys were touched without validation");
        Check(a.Field("sentinel").StrValue()=="FAKE-ONLY","Other RTON fields changed");
    }
}
int main(){
 try {
    {
        Scratch s;
        const auto origA=s.Read("pp.dat"),origB=s.Read("snapshot2.dat");
        bool refusedRunningGuest=false;
        try {
            (void)ak::SettleEligible(s.root,false,true,true,true);
        } catch(const tx::Conflict&) {refusedRunningGuest=true;}
        Check(refusedRunningGuest,"Running guest must be rejected");
        for(unsigned gate=0;gate<3;++gate) {
            const auto r=ak::SettleEligible(s.root,true,
                gate!=0,gate!=1,gate!=2);
            Check(r.deferred && r.profiles==0 && r.keys==0,
                  "Unsafe preflight executed a settlement");
            Check(s.Read("pp.dat")==origA && s.Read("snapshot2.dat")==origB,
                  "Unsafe preflight modified the saves");
        }
        const auto settled=ak::SettleEligible(s.root,true,true,true,true);
        Check(settled.profiles==2 && settled.keys==5&&!settled.deferred,
              "Both fake profiles were not settled exactly once");
        Verify(s,{12010,2510},{10750,2490},{0,0});
        const auto again=ak::SettleEligible(s.root,true,true,true,true);
        Check(!again.deferred && again.profiles==0 && again.keys==0,
              "Cold restart produced duplicate credit");
    }
    {
        Scratch s(false);
        const auto r=ak::SettleEligible(s.root,true,true,true,true);
        Check(r.profiles==1 && r.keys==3,"Closed second profile key gate converted");
        Verify(s,{12010,510},{10750,490},{0,2});
    }
    {
        Scratch s;
        bool interrupted=false;
        try{
            (void)ak::SettleEligible(s.root,true,true,true,true,
                                    tx::CrashAt::PrimaryInstalled,1);
        }catch(const tx::Interrupted&){interrupted=true;}
        Check(interrupted,"Second-slot crash checkpoint not reached");
        const auto recovered=tx::Recover(s.root,true);
        Check(recovered==tx::Recovery::RolledBack,
              "Interrupted second slot did not roll back");
        // First slot committed before second slot crashed. Recovery must
        // never undo that independent, already-committed first slot.
        Verify(s,{12010,510},{10750,490},{0,2});
        const auto skip=ak::SettleEligible(s.root,true,true,false,true);
        Check(skip.deferred && skip.profiles==0,
              "Crash recovery was re-applied automatically in same launch");
        Verify(s,{12010,510},{10750,490},{0,2});
        const auto subsequent=ak::SettleEligible(s.root,true,true,true,true);
        Check(subsequent.profiles==1 && subsequent.keys==2,
              "Next clean launch did not settle untouched second slot");
        Verify(s,{12010,2510},{10750,2490},{0,0});
        const auto zero=ak::SettleEligible(s.root,true,true,true,true);
        Check(zero.profiles==0,"Second subsequent launch double-credited");
    }
    std::cout<<"PASS: "<<assertions
             <<" auto KEYCONV SHA-256 journal assertions; profiles 2,"
             <<" closed gates, original other world keys, restart idempotence,"
             <<" kill during second slot, deferred after rollback\n";
 }catch(const std::exception& e) {
    std::cerr<<"FAIL KEYCONV automatic journal: "<<e.what()<<"\n";
    return 1;
 }
}
