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
    std::cout << "PASS: " << checks <<
        " pure existing-key reconciliation policy checks (zero writes)\n";
}
