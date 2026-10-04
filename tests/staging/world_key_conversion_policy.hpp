#pragma once
// Standalone, non-mutating policy for researched 2013 world-key conversion.
// No original game bytes, guest runtime hooks, or save rewrites.
#include <array>
#include <cstdint>
#include <span>

namespace pvz2_key_study {
enum class Reason { Convert, UnknownWorld, InactiveWorld, InvalidQuantity,
                    IncompleteState, DuplicateEvent, GateNotOpen };
struct WorldEvent { std::uint32_t world_id, event_id, state; };
struct Decision {
    Reason reason;
    std::uint32_t coins;
    constexpr bool convert() const { return reason == Reason::Convert; }
};
struct WorldDefinition {
    std::uint32_t id;
    std::span<const std::uint32_t> gates;
    bool requires_activation;
};
inline constexpr std::array<std::uint32_t, 5> egypt{13,23,33,39,41};
inline constexpr std::array<std::uint32_t, 4> pirate{15,23,28,32};
inline constexpr std::array<std::uint32_t, 4> cowboy{14,22,28,36};
inline constexpr std::array<std::uint32_t, 4> future{13,14,15,16};
inline constexpr std::array<WorldDefinition, 4> worlds{{
    {2,egypt,false}, {3,pirate,false}, {4,cowboy,false}, {5,future,true}
}};
struct CoinCreditPlan {
    bool apply;
    std::uint32_t after;
};
inline constexpr std::uint32_t kMaxSignedCoins = 0x7fffffffu;
inline CoinCreditPlan PlanCoinCredit(std::uint32_t before,
                                     std::uint32_t delta) {
    const std::uint64_t after =
        static_cast<std::uint64_t>(before) + delta;
    if (delta == 0u || after > kMaxSignedCoins)
        return {false, before};
    return {true, static_cast<std::uint32_t>(after)};
}
inline Decision Evaluate(std::uint32_t world_id,
                         std::uint32_t key_count,
                         std::span<const WorldEvent> saved_events,
                         bool future_enabled=false) {
    const WorldDefinition* definition = nullptr;
    for (const auto& world : worlds)
        if (world.id == world_id) { definition = &world; break; }
    if (!definition) return {Reason::UnknownWorld,0};
    if (definition->requires_activation && !future_enabled)
        return {Reason::InactiveWorld,0};
    if (key_count == 0 || key_count > 3)
        return {Reason::InvalidQuantity,0};
    // Whitelist has only worlds with a nonempty verified gate set.
    if (definition->gates.empty()) return {Reason::IncompleteState,0};
    for (std::uint32_t gate : definition->gates) {
        unsigned matches = 0;
        std::uint32_t state = 0;
        for (const auto& event : saved_events) {
            if (event.world_id == world_id && event.event_id == gate) {
                ++matches; state = event.state;
            }
        }
        if (!matches) return {Reason::IncompleteState,0};
        if (matches != 1) return {Reason::DuplicateEvent,0};
        // Exact key-gate opening calls monotonically set native state=3.
        if (state < 3) return {Reason::GateNotOpen,0};
    }
    return {Reason::Convert, 1000 * key_count};
}
} // namespace pvz2_key_study
