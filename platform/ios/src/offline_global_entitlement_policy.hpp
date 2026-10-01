#pragma once
// Independent, read-only PLANNING for the verified PvZ2 v1.5.252752
// original-global vs NEW synthetic PvZCoin ownership conflict.
//
// No guest pointer dereference, no disk mutation, no JNI call. In particular,
// a pre-existing authentic original global ID must NEVER be deleted solely
// because it is one of our ten canonical offline store identifiers.
//
// Inputs for each catalog category (plants: six local bits, upgrades: four):
//   baseline: verified original GLOBAL rights captured BEFORE new synthetic
//             purchases can publish original global ownership;
//   observed: current original-global catalog bits;
//   injected: ONLY rights from a successfully validated NEW v2 synthetic
//             payment known to have passed native global-publication path.
// The original serialized arrays contain IDs, not receipt provenance:
// without a trusted baseline + receipt evidence, deletion MUST defer.
#include <cstdint>

namespace pvz2offline {

enum class GlobalIsolationDecision : std::uint8_t {
    PreserveUnverifiedBaseline,
    PreserveMissingOriginalRights,
    PreserveUnattributedChanges,
    NoSyntheticChange,
    SyntheticChangeCanBeRemoved
};

struct GlobalIsolationPlan {
    GlobalIsolationDecision decision =
        GlobalIsolationDecision::PreserveUnverifiedBaseline;
    std::uint32_t original_baseline = 0;
    std::uint32_t observed_global = 0;
    std::uint32_t eligible_synthetic_delta = 0;
    std::uint32_t preserve_global = 0;
};

constexpr GlobalIsolationPlan PlanGlobalIsolation(
    bool baseline_verified,
    std::uint32_t original_baseline,
    std::uint32_t observed_global,
    std::uint32_t verified_v2_published,
    std::uint32_t catalog_mask) {

    GlobalIsolationPlan plan;
    plan.original_baseline = original_baseline & catalog_mask;
    plan.observed_global = observed_global & catalog_mask;
    plan.preserve_global = observed_global;
    if (!baseline_verified) {
        plan.decision = GlobalIsolationDecision::PreserveUnverifiedBaseline;
        return plan;
    }

    if ((plan.original_baseline & ~plan.observed_global) != 0u) {
        // Some ORIGINAL purchased right disappeared unexpectedly:
        // do not compound damage with any synthetic cleanup.
        plan.decision = GlobalIsolationDecision::PreserveMissingOriginalRights;
        return plan;
    }
    const std::uint32_t added = plan.observed_global & ~plan.original_baseline;
    if ((added & ~verified_v2_published) != 0u) {
        // Unattributed changes may be real purchased/restored rights.
        plan.decision = GlobalIsolationDecision::PreserveUnattributedChanges;
        return plan;
    }
    if (added == 0u) {
        plan.decision = GlobalIsolationDecision::NoSyntheticChange;
        return plan;
    }
    plan.decision = GlobalIsolationDecision::SyntheticChangeCanBeRemoved;
    plan.eligible_synthetic_delta = added;
    plan.preserve_global = observed_global & ~added;
    return plan;
}

// The original 2013 game ALLOWS free cross-profile CLAIM on authentic
// purchases. The existing v166 mask-only overlay strips B's raw plant even
// when its original-global legacy receipt is genuine. A future adapter
// should project genuine verified global rights onto all profiles WITHOUT
// falsely writing an additional paid custom host-sidecar purchase.
constexpr std::uint32_t EffectivePlayableCatalogMask(
    std::uint32_t current_profile_paid,
    std::uint32_t verified_legacy_global,
    std::uint32_t catalog_mask) {
    return (current_profile_paid | verified_legacy_global) & catalog_mask;
}
}  // namespace pvz2offline
