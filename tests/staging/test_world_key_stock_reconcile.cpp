#include "world_key_stock_reconcile.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
using namespace pvz2_key_study;
static std::vector<WorldEvent> Gates(unsigned id,unsigned state=3) {
    std::vector<WorldEvent> out;
    for (const auto& w: worlds) if(w.id==id)
        for (auto gate:w.gates) out.push_back({id,gate,state});
    return out;
}
int main() {
    unsigned checks=0;
    for(auto world:{2u,3u,4u}) {
        auto events=Gates(world);
        auto one=PlanExistingWorldKeys(world,1,7800,events);
        assert(one.ready() && one.keys_to_remove==1 &&
               one.coins_before==7800 && one.coins_after==8800); ++checks;
        auto six=PlanExistingWorldKeys(world,6,7800,events);
        assert(six.ready() && six.keys_to_remove==6 &&
               six.coins_after==13800); ++checks;
        auto maximum=PlanExistingWorldKeys(world,99,7800,events);
        assert(maximum.ready() && maximum.coins_after==106800); ++checks;
        auto consumed=PlanExistingWorldKeys(world,0,maximum.coins_after,events);
        assert(consumed.reason==StockReason::NoSurplus &&
               !consumed.ready() && consumed.keys_to_remove==0); ++checks;
        auto invalid=PlanExistingWorldKeys(world,100,7800,events);
        assert(invalid.reason==StockReason::InvalidStock &&
               invalid.coins_after==7800); ++checks;
        auto near_limit=PlanExistingWorldKeys(
             world,2,kMaxSignedCoins-1999u,events);
        assert(near_limit.reason==StockReason::WalletOverflow &&
               near_limit.keys_to_remove==0); ++checks;
        events[0].state=2;
        auto blocked=PlanExistingWorldKeys(world,6,7800,events);
        assert(blocked.reason==StockReason::WorldNotEligible &&
               blocked.coins_after==7800); ++checks;
    }
    {
        auto event=Gates(5);
        assert(PlanExistingWorldKeys(5,4,7800,event).reason==
               StockReason::WorldNotEligible); ++checks;
        assert(PlanExistingWorldKeys(5,4,7800,event,true).ready()); ++checks;
    }
    {
        auto event=Gates(2);
        assert(PlanExistingWorldKeys(8,4,7800,event).reason==
               StockReason::WorldNotEligible); ++checks;
        event.pop_back();
        assert(PlanExistingWorldKeys(2,4,7800,event).reason==
               StockReason::WorldNotEligible); ++checks;
        event=Gates(2);
        event.push_back(event[0]);
        assert(PlanExistingWorldKeys(2,4,7800,event).reason==
               StockReason::WorldNotEligible); ++checks;
    }
    // User's preserved backup: 6 Egypt keys, one 5-key door not yet open.
    // The native door spends 5 -> 1; only after its native state becomes 3
    // is the remaining key eligible for the 1,000-coin reconciliation.
    {
        auto pre=Gates(2u);
        pre.back().state=2u;
        const auto before=PlanExistingWorldKeys(2u,6u,7800u,pre);
        assert(before.reason==StockReason::WorldNotEligible &&
               before.keys_to_remove==0u && before.coins_after==7800u);
        ++checks;
        pre.back().state=3u;
        const auto after=PlanExistingWorldKeys(2u,1u,7800u,pre);
        assert(after.ready() && after.keys_to_remove==1u &&
               after.coins_before==7800u && after.coins_after==8800u);
        ++checks;
        assert(InspectSettlement(after,0u,8800u)==
               SettlementObservation::FullyApplied);
        ++checks;
    }
    // After a restart, compare persisted native stock+wallet with the plan.
    // Any partial state must stop; it must never trigger a blind retry.
    {
        const auto p=PlanExistingWorldKeys(2u,6u,10000u,Gates(2u));
        assert(p.ready() && p.coins_after==16000u); ++checks;
        assert(InspectSettlement(p,6u,10000u)==
               SettlementObservation::NotYetApplied); ++checks;
        assert(InspectSettlement(p,0u,16000u)==
               SettlementObservation::FullyApplied); ++checks;
        assert(InspectSettlement(p,0u,10000u)==
               SettlementObservation::PartialKeyDebit); ++checks;
        assert(InspectSettlement(p,6u,16000u)==
               SettlementObservation::PartialCoinCredit); ++checks;
        assert(InspectSettlement(p,3u,13000u)==
               SettlementObservation::UnexpectedState); ++checks;
        assert(InspectSettlement(p,6u,14000u)==
               SettlementObservation::UnexpectedState); ++checks;
        const auto zero=PlanExistingWorldKeys(2u,0u,10000u,Gates(2u));
        assert(InspectSettlement(zero,0u,10000u)==
               SettlementObservation::InvalidPlan); ++checks;
    }
    std::cout << "PASS: " << checks <<
        " pure existing-key reconciliation policy checks (zero writes)\n";
}
