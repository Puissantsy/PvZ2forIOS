// Synthetic-only fail-closed multi-profile KEYCONV automatic candidate tests.
#include "world_key_auto_batch.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
using namespace pvz2_key_study::auto_keyconv;
using Fields=std::vector<std::pair<std::string,std::string>>;
static int checks=0;
void Check(bool yes,const char* msg) {
    ++checks;if(!yes)throw std::runtime_error(msg);
}
std::string Var(std::uint64_t n) {
    std::string s;
    do {auto v=static_cast<std::uint8_t>(n&127u);
        n>>=7u;if(n)v|=128u;s.push_back(static_cast<char>(v));}while(n);
    return s;
}
std::string Txt(const std::string& s,bool cache=false) {
    return std::string(1,static_cast<char>(cache?0x90:0x81))+
        Var(s.size())+s;
}
std::string Num(std::uint64_t n) {return std::string(1,char(0x24))+Var(n);}
std::string Obj(const Fields& fields) {
    std::string out(1,char(0x85));
    for(const auto& [k,v]:fields)out+=Txt(k,true)+v;
    return out+char(0xff);
}
std::string Arr(const std::vector<std::string>& items) {
    std::string out{char(0x86),char(0xfd)};
    out+=Var(items.size());
    for(const auto& item:items)out+=item;
    return out+char(0xfe);
}
std::string Doc(const Fields& fields) {
    std::string out("RTON\x01\x00\x00\x00",8);
    for(const auto& [k,v]:fields)out+=Txt(k,true)+v;
    out+=char(0xff);
    return out+"DONE";
}
std::string SavedProfile(std::uint64_t id,std::uint64_t coins,
                         std::uint64_t egyptKeys,bool allGatesOpen,
                         bool addOtherWorld=false) {
    std::vector<std::string> events;
    for(const auto gate:{13u,23u,33u,39u,41u})
        events.push_back(Obj({{"W",Num(2)},{"E",Num(gate)},
            {"S",Num(allGatesOpen||gate!=41u?3u:2u)}}));
    std::vector<std::string> keys;
    keys.push_back(Obj({{"wn",Txt("egypt")},{"kc",Num(egyptKeys)}}));
    if(addOtherWorld)
        keys.push_back(Obj({{"wn",Txt("pirate")},{"kc",Num(8)}}));
    return Obj({{"objclass",Txt("PlayerInfo")},
        {"objdata",Obj({{"i",Num(id)},{"c",Num(coins)},
            {"wsk",Arr(keys)},{"wm",Arr(events)},
            {"unknownValue",Txt("RETAIN-ALL-OTHER-DATA")}})}});
}
struct Sample {
    std::string primary,fallback,registry;
};
Sample Make(const std::vector<std::string>& pp,
            const std::vector<std::string>& snapshot,
            const std::vector<std::uint64_t>& ids) {
    std::vector<std::string> records;
    for(auto id:ids)records.push_back(Obj({{
        "objclass",Txt("PlayerInfoLocalSaveData")},
        {"objdata",Obj({{"ProfileIndex",Num(id)}})}}));
    return {Doc({{"objects",Arr(pp)}}),
            Doc({{"objects",Arr(snapshot)}}),
            Doc({{"objects",Arr(records)}})};
}
Sample Standard(bool secondEligible=true,std::uint64_t first=3) {
    return Make({
        SavedProfile(101,9010,first,true,true),
        SavedProfile(102,500,5,secondEligible),
        SavedProfile(103,6000,0,true)
    },{
        SavedProfile(101,7750,first,true,true),
        SavedProfile(102,490,5,secondEligible),
        SavedProfile(103,5900,0,true)
    },{101,102,103});
}
void Reject(const std::function<void()>& op,const char* label) {
    bool blocked=false;
    try{op();}catch(const native::Error&){blocked=true;}
    Check(blocked,label);
}
void VerifySlot(const std::string& image,std::size_t slot,
                std::int64_t coins,std::int64_t egypt,
                std::int64_t pirate=-1) {
    const auto t=native::Reader(image,slot).Parse();
    const auto& info=native::Player(t,slot);
    Check(info.Field("c").IntValue()==coins,"Wallet wrong");
    Check(info.Field("wsk").At(0).Field("kc").IntValue()==egypt,
          "Key debit wrong");
    Check(info.Field("unknownValue").StrValue()=="RETAIN-ALL-OTHER-DATA",
          "Unrelated RTON token changed");
    if(pirate>=0)
        Check(info.Field("wsk").At(1).Field("kc").IntValue()==pirate,
              "Other world key stock was altered");
}
int main() {
 try {
    {
        const auto s=Standard(false);
        const auto batch=Preview(s.primary,s.fallback,s.registry);
        Check(batch.profiles.size()==1 && batch.profiles[0].slot==0,
              "Only completed world profile should convert");
        Check(batch.total_keys==3,"3 keys must mean exactly 3000 coins");
        VerifySlot(batch.primary,0,12010,0,8);
        VerifySlot(batch.fallback,0,10750,0,8);
        VerifySlot(batch.primary,1,500,5);
        Check(Preview(batch.primary,batch.fallback,s.registry).profiles.empty(),
              "Fresh startup would credit same 3-key profile twice");
    }
    {
        const auto s=Standard();
        const auto batch=Preview(s.primary,s.fallback,s.registry);
        Check(batch.profiles.size()==2 && batch.total_keys==8,
              "Two eligible profiles / eight keys not detected");
        Check(batch.profiles[0].slot==0 && batch.profiles[1].slot==1,
              "Selected profiles were reordered");
        VerifySlot(batch.primary,0,12010,0,8);
        VerifySlot(batch.fallback,0,10750,0,8);
        VerifySlot(batch.primary,1,5500,0);
        VerifySlot(batch.fallback,1,5490,0);
        VerifySlot(batch.primary,2,6000,0);
        const auto repeat=Preview(batch.primary,batch.fallback,s.registry);
        Check(repeat.profiles.empty() && repeat.total_keys==0 &&
              repeat.primary==batch.primary &&
              repeat.fallback==batch.fallback,"Batch is not idempotent");
    }
    {
        const auto s=Make({SavedProfile(101,1000,99,true)},
            {SavedProfile(101,2000,99,true)},{101});
        const auto b=Preview(s.primary,s.fallback,s.registry);
        Check(b.total_keys==99,"Maximum stored stock 99 not covered");
        VerifySlot(b.primary,0,100000,0);
        VerifySlot(b.fallback,0,101000,0);
    }
    {
        const auto s=Make({SavedProfile(101,5000,0,true)},
            {SavedProfile(101,6000,0,true)},{101});
        const auto b=Preview(s.primary,s.fallback,s.registry);
        Check(b.profiles.empty() && b.primary==s.primary &&
              b.fallback==s.fallback,"Zero-stock no-op mutated a save");
    }
    {
        const auto s=Standard();
        Reject([&]{
            auto broken=s;broken.registry=Make({},{},{101,101,103}).registry;
            (void)Preview(broken.primary,broken.fallback,broken.registry);
        },"Native profile registry mismatch accepted");
        Reject([&]{
            auto broken=s;broken.fallback=Make({
                SavedProfile(101,7000,2,true,true),
                SavedProfile(102,490,5,true),
                SavedProfile(103,5900,0,true)}, {},{}).primary;
            (void)Preview(broken.primary,broken.fallback,broken.registry);
        },"Primary/fallback divergent stock accepted");
        Reject([&]{
            auto broken=s;broken.primary=Make({
                SavedProfile(101,2147483647,3,true,true),
                SavedProfile(102,500,5,true),
                SavedProfile(103,6000,0,true)}, {},{}).primary;
            (void)Preview(broken.primary,broken.fallback,broken.registry);
        },"Overflow wallet silently credited");
        Reject([&]{
            auto broken=s;broken.fallback=Make({
                SavedProfile(101,7750,3,true,true),
                SavedProfile(102,490,5,false),
                SavedProfile(103,5900,0,true)}, {},{}).primary;
            (void)Preview(broken.primary,broken.fallback,broken.registry);
        },"Different primary/fallback gate states accepted");
    }
    {
        std::vector<std::string> records;
        std::vector<std::uint64_t> ids;
        for(std::uint64_t i=0;i<17;++i) {
            ids.push_back(101+i);
            records.push_back(SavedProfile(101+i,10,1,true));
        }
        const auto tooMany=Make(records,records,ids);
        Reject([&]{(void)Preview(tooMany.primary,tooMany.fallback,tooMany.registry);},
              "More than 16 profiles accepted");
    }
    std::cout<<"PASS "<<checks
             <<" auto KEYCONV synthetic assertions: 1-99 keys, 3 profiles,"
             <<" independent wallet, closed gate, no double credit,"
             <<" wrong registry, divergent stock, overflow, 17-slot refusal\n";
 }catch(const std::exception& e) {
    std::cerr<<"FAIL auto KEYCONV policy: "<<e.what()<<"\n";
    return 1;
 }
}
