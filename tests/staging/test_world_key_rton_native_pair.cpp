// Synthetic C++20 native pairing tests, no real saves or player names.
#include "world_key_rton_native_pair.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
using namespace pvz2_key_study::rton_native;
using Fields=std::vector<std::pair<std::string,std::string>>;

std::string Var(std::uint64_t n) {
    std::string s;
    do { auto b=static_cast<std::uint8_t>(n&127); n>>=7;
         if(n) b|=128; s.push_back(static_cast<char>(b));
    } while(n);
    return s;
}
std::string Txt(const std::string& s,bool cache=false) {
    return std::string(1,static_cast<char>(cache?0x90:0x81))+
           Var(s.size())+s;
}
std::string Num(std::uint64_t n) { return std::string(1,char(0x24))+Var(n); }
std::string Obj(const Fields& fields) {
    std::string s(1,char(0x85));
    for(const auto& [name,value]:fields) s+=Txt(name,true)+value;
    s.push_back(char(0xff));
    return s;
}
std::string Arr(const std::vector<std::string>& items) {
    std::string s; s.push_back(char(0x86)); s.push_back(char(0xfd));
    s+=Var(items.size());
    for(const auto& v:items) s+=v;
    s.push_back(char(0xfe)); return s;
}
std::string Doc(const Fields& fields) {
    std::string s("RTON\x01\x00\x00\x00",8);
    for(const auto& [name,value]:fields) s+=Txt(name,true)+value;
    s.push_back(char(0xff));
    return s+"DONE";
}
std::string PlayerSave(std::uint64_t wallet,std::uint64_t keys,
                       bool opened=true,std::uint64_t id=73,
                       bool include_egypt=true) {
    const std::array<unsigned,5> gates{13,23,33,39,41};
    std::vector<std::string> events;
    for(const auto e:gates)
        events.push_back(Obj({{"W",Num(2)},{"E",Num(e)},
                               {"S",Num(opened || e!=41?3:2)}}));
    std::vector<std::string> stock;
    if(include_egypt) stock.push_back(Obj({{"wn",Txt("egypt")},{"kc",Num(keys)}}));
    const auto info=Obj({
        {"c",Num(wallet)}, {"i",Num(id)},
        {"wm",Arr(events)}, {"wsk",Arr(stock)},
        {"n",Txt("SYNTHETIC-NONPERSONAL")}});
    return Doc({{"version",Num(1)},
                {"objects",Arr({Obj({{"objclass",Txt("PlayerInfo")},
                                      {"objdata",info}})})}});
}
std::string Registry(std::uint64_t id=73) {
    return Doc({{"version",Num(1)},
                {"objects",Arr({Obj({{"objclass",Txt("PlayerInfoLocalSaveData")},
                                      {"objdata",Obj({{"ProfileIndex",Num(id)}})}})})}});
}
void Require(bool ok,const char* note) {
    if(!ok) throw std::runtime_error(note);
}
void Reject(const std::function<void()>& run) {
    try { run(); }
    catch(const Error&) { return; }
    throw std::runtime_error("Missing native fail-closed rejection");
}
int main() {
    try {
        const auto reg=Registry();
        const auto original=PlayerSave(7800,1);
        const auto backup=PlayerSave(7801,1);
        const auto planned=PlanNativePair(original,backup,reg,0);
        Require(planned.changed,"no conversion");
        Require(planned.native_id==73 && planned.saved_keys==1,"wrong identity/amount");
        const auto a=Player(Reader(planned.primary,0).Parse(),0);
        const auto b=Player(Reader(planned.fallback,0).Parse(),0);
        Require(a.Field("c").IntValue()==8800,"wrong primary wallet");
        Require(b.Field("c").IntValue()==8801,"fallback wallet was overwritten");
        Require(a.Field("wsk").At(0).Field("kc").IntValue()==0,"primary key");
        Require(b.Field("wsk").At(0).Field("kc").IntValue()==0,"fallback key");
        const auto again=PlanNativePair(planned.primary,planned.fallback,reg,0);
        Require(!again.changed && again.primary==planned.primary &&
                again.fallback==planned.fallback,"double credit");
        const auto unopened=PlayerSave(7800,6,false);
        const auto unopened_fallback=PlayerSave(7801,6,false);
        const auto no=PlanNativePair(unopened,unopened_fallback,reg,0);
        Require(!no.changed && no.primary==unopened &&
                no.fallback==unopened_fallback,"closed gate changed");
        Reject([&]{ PlanNativePair(original,PlayerSave(7801,2),reg,0); });
        Reject([&]{ PlanNativePair(original,backup,Registry(74),0); });
        Reject([&]{ PlanNativePair(original,PlayerSave(7801,1,false),reg,0); });
        Reject([&]{ PlanNativePair(original,backup,reg,1); });
        Reject([&]{ PlanNativePair(original,backup,"NOT_RTON",0); });
        Reject([&]{ PlanNativePair(PlayerSave(2147483647,1),
                                 PlayerSave(2147483646,1),reg,0); });
        Reject([&]{ PlanNativePair(PlayerSave(7800,1,true,73),
                                 PlayerSave(7801,1,true,74),reg,0); });
        std::cout<<"PASS native C++20 paired RTON identity, fallback divergence, "
                    "all-open gates, idempotence and fail-closed cases\n";
    } catch(const std::exception& e) {
        std::cerr<<"FAIL paired RTON synthetic tests: "<<e.what()<<"\n";
        return 1;
    }
}
