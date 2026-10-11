#pragma once
// Pure, read-only proposal for reconciling keys already stored in the profile.
// NO native calls, save edits, state writes, or implicit transaction commits.
#include "world_key_conversion_policy.hpp"
#include <cstdint>
#include <span>

namespace pvz2_key_study {
enum class StockReason {
    Ready, NoSurplus, InvalidStock, WorldNotEligible, WalletOverflow
};
struct StockPlan {
    StockReason reason;
    std::uint32_t world_id;
    std::uint32_t keys_to_remove;
    std::uint32_t coins_before;
    std::uint32_t coins_after;
    constexpr bool ready() const { return reason == StockReason::Ready; }
};

// Inventory observations are *not* sufficient permission to apply a plan.
// Native stock-vector layout, notifications, all-gates-open eligibility,
// and a crash-safe save transaction still require actual iPad validation.
// Do not call either SpendWorldKeys or SetCoins from inside an SVC callback.
inline StockPlan PlanExistingWorldKeys(
    std::uint32_t world_id,
    std::uint32_t stock,
    std::uint32_t coins_before,
    std::span<const WorldEvent> observed_events,
    bool future_enabled=false) {
    const StockPlan no_change{StockReason::NoSurplus,world_id,0u,
                              coins_before,coins_before};
    if (stock==0u) return no_change;
    // Exact native AddWorldKeys caps saved count at 99.
    if (stock>99u)
        return {StockReason::InvalidStock,world_id,0u,
                coins_before,coins_before};
    const auto gate_decision=Evaluate(
        world_id,1u,observed_events,future_enabled);
    if (!gate_decision.convert())
        return {StockReason::WorldNotEligible,world_id,0u,
                coins_before,coins_before};
    const std::uint32_t coin_delta=stock*1000u;
    const auto credit=PlanCoinCredit(coins_before,coin_delta);
    if (!credit.apply)
        return {StockReason::WalletOverflow,world_id,0u,
                coins_before,coins_before};
    return {StockReason::Ready,world_id,stock,coins_before,credit.after};
}
} // namespace pvz2_key_study
