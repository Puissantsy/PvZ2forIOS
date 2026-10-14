#pragma once
// Research only: pure C++20 two-image prelaunch plan, no disk or iOS writes.
// The selected slot MUST be supplied explicitly; never infer active account.
#include "world_key_rton_native.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

namespace pvz2_key_study::rton_native {
struct NativePairPlan {
    bool changed=false;
    std::int64_t native_id=0, saved_keys=0;
    std::int64_t primary_coins_before=0, fallback_coins_before=0;
    std::string primary, fallback;
};
inline const Value& Player(const Value& tree,std::size_t slot) {
    const auto& p=tree.Field("objects").At(slot);
    if(p.Field("objclass").StrValue()!="PlayerInfo") throw Error("Wrong native PlayerInfo class");
    return p.Field("objdata");
}
inline NativePairPlan PlanNativePair(const std::string& primary,
                                     const std::string& fallback,
                                     const std::string& registry,
                                     std::size_t slot) {
    const auto profiles=Reader(registry,slot).Parse().Field("objects");
    const auto& local=profiles.At(slot);
    if(local.Field("objclass").StrValue()!="PlayerInfoLocalSaveData")
        throw Error("Wrong native local_profiles class");
    const auto profile_id=local.Field("objdata").Field("ProfileIndex").IntValue();
    if(profile_id<=0) throw Error("Invalid native ProfileIndex");
    const auto first=Reader(primary,slot).Parse();
    const auto second=Reader(fallback,slot).Parse();
    const auto& a=first.Field("objects");
    const auto& b=second.Field("objects");
    if(a.kind!=Value::Kind::Array || b.kind!=Value::Kind::Array ||
       a.items.size()!=b.items.size())
        throw Error("Primary/fallback slot count mismatch");
    const auto& pa=Player(first,slot);
    const auto& pb=Player(second,slot);
    if(pa.Field("i").IntValue()!=profile_id ||
       pb.Field("i").IntValue()!=profile_id)
        throw Error("Native PlayerInfo and registry identity mismatch");
    if(!(pa.Field("wsk")==pb.Field("wsk")))
        throw Error("Primary/fallback native key stocks diverge");
    const auto change_a=ConvertEgypt(primary,slot);
    const auto change_b=ConvertEgypt(fallback,slot);
    if(change_a.changed!=change_b.changed ||
       change_a.native_id!=profile_id || change_b.native_id!=profile_id ||
       (change_a.changed && change_a.keys!=change_b.keys))
        throw Error("Primary/fallback gate eligibility mismatch");
    return NativePairPlan{
        change_a.changed,profile_id,change_a.keys,
        change_a.before,change_b.before,
        change_a.data,change_b.data};
}
} // namespace pvz2_key_study::rton_native
