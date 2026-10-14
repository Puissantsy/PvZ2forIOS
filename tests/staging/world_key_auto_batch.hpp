#pragma once
// KEYCONV prelaunch batch preview; PURE READ/MEMORY, no mutations on disk.
// Egypt is the ONLY enabled saved-key stock world in the validated iPad build.
// Pirate/Cowboy metadata may be evaluated separately in research, but must
// never be silently enabled here without on-device gate and RTON evidence.
#include "world_key_rton_native_pair.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pvz2_key_study::auto_keyconv {
namespace native=pvz2_key_study::rton_native;
struct Profile {
    std::size_t slot=0;
    std::int64_t native_id=0;
    std::int64_t keys=0;
    std::int64_t primary_before=0;
    std::int64_t fallback_before=0;
};
struct Batch {
    std::vector<Profile> profiles;
    std::int64_t total_keys=0;
    std::string primary, fallback;
};

// Strict all-or-nothing READ-ONLY preview: if ANY slot is malformed, unknown,
// mismatched or unsafe, no candidate set is returned. The caller must NOT
// partly settle from this function's output if it reports an error.
// All writes must later go through the already tested per-slot journal in a
// stopped-guest + separate verified backup context.
inline Batch Preview(const std::string& primary,const std::string& fallback,
                     const std::string& local_profiles) {
    const auto parsed=native::Reader(local_profiles,0).Parse();
    const auto& locals=parsed.Field("objects");
    if(locals.kind!=native::Value::Kind::Array || locals.items.size()>16)
        throw native::Error("KEYCONV auto: invalid local profile count");
    const auto pa=native::Reader(primary,0).Parse().Field("objects");
    const auto pb=native::Reader(fallback,0).Parse().Field("objects");
    if(pa.kind!=native::Value::Kind::Array ||
       pb.kind!=native::Value::Kind::Array ||
       pa.items.size()!=pb.items.size() ||
       pa.items.size()<locals.items.size())
        throw native::Error("KEYCONV auto: inconsistent profile images");
    Batch batch;
    batch.primary=primary;
    batch.fallback=fallback;
    std::set<std::int64_t> unique_ids;
    for(std::size_t slot=0;slot<locals.items.size();++slot) {
        const auto plan=native::PlanNativePair(batch.primary,
                                               batch.fallback,
                                               local_profiles,slot);
        if(plan.native_id<=0 || !unique_ids.insert(plan.native_id).second)
            throw native::Error("KEYCONV auto: duplicate native profile identity");
        if(!plan.changed) continue;
        if(plan.saved_keys<=0 || plan.saved_keys>99 ||
           batch.total_keys>std::numeric_limits<std::int64_t>::max()-plan.saved_keys)
            throw native::Error("KEYCONV auto: invalid total key delta");
        batch.profiles.push_back(Profile{slot,plan.native_id,
            plan.saved_keys,plan.primary_coins_before,
            plan.fallback_coins_before});
        batch.total_keys+=plan.saved_keys;
        // Only staged in memory for a full batch PREVIEW. This does not
        // publish any file, journal, coin credit or profile side effect.
        batch.primary=std::move(plan.primary);
        batch.fallback=std::move(plan.fallback);
    }
    return batch;
}
} // namespace pvz2_key_study::auto_keyconv
