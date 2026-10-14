#pragma once
// Opt-in KEYCONV stopped-guest batch settlement; reuses proven single-slot
// durable SHA-256 journal for each profile, never edits pp.dat directly.
// This header makes NO runtime calls unless invoked by a trusted host gate.
#include "world_key_auto_batch.hpp"
#include "world_key_prelaunch_native.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
namespace pvz2_key_study::auto_keyconv {
namespace tx=pvz2_key_study::prelaunch_native;
namespace fs=std::filesystem;
struct Settlement {
    std::size_t profiles=0;
    std::int64_t keys=0;
    bool deferred=false;
};
inline Settlement SettleEligible(const fs::path& root,
                                  bool guest_stopped,
                                  bool verified_external_backup,
                                  bool prelaunch_recovery_was_clean,
                                  bool explicitly_authorized_for_research,
                                  tx::CrashAt test_fault=tx::CrashAt::None,
                                  std::size_t test_fault_slot=
                                      std::numeric_limits<std::size_t>::max()) {
    tx::Require(guest_stopped,"Guest must be stopped before automatic settlement");
    if(!verified_external_backup || !prelaunch_recovery_was_clean ||
       !explicitly_authorized_for_research)
        return {0,0,true};
    tx::ValidateRoot(root);
    tx::Require(!tx::Present(root/tx::Journal) &&
                !tx::Present(root/tx::Done),
                "A pending recovery cannot start another conversion");
    const auto working=tx::Working(root);
    const auto registry=tx::ReadRegular(working/"local_profiles",tx::MaxRegistry);
    const auto primary=tx::ReadRegular(working/"pp.dat",tx::MaxImage);
    const auto fallback=tx::ReadRegular(working/"snapshot2.dat",tx::MaxImage);
    const auto planned=Preview(primary,fallback,registry);
    Settlement result;
    // Explicitly limited to Egypt: multi-world conversion awaits real-device
    // Pirate/Cowboy gate validations. 1..99 historic saved keys per profile.
    for(const auto& profile:planned.profiles) {
        const auto fault=profile.slot==test_fault_slot?
            test_fault:tx::CrashAt::None;
        const auto changed=tx::Settle(root,profile.slot,true,true,fault);
        tx::Require(changed.prior==tx::Recovery::NoJournal &&
                    changed.changed &&
                    changed.profile_id==profile.native_id &&
                    changed.keys==profile.keys,
                    "Unexpected profile conversion/recovery result");
        ++result.profiles;
        result.keys+=changed.keys;
    }
    // All candidates were planned from the initial image. Any difference
    // can signal a concurrent V128 write, duplicate credit or wrong profile.
    tx::Require(tx::ReadRegular(working/"local_profiles",tx::MaxRegistry)==registry &&
                tx::ReadRegular(working/"pp.dat",tx::MaxImage)==planned.primary &&
                tx::ReadRegular(working/"snapshot2.dat",tx::MaxImage)==planned.fallback,
                "Batch settlement differs from exact full-image preview");
    tx::Require(result.profiles==planned.profiles.size() &&
                result.keys==planned.total_keys,
                "Batch credit/identity totals differ from full preview");
    return result;
}
} // namespace pvz2_key_study::auto_keyconv
