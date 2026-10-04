#include "world_key_conversion_policy.hpp"
#include <cassert>
#include <iostream>
#include <vector>
using namespace pvz2_key_study;
static std::vector<WorldEvent> AllOpen(unsigned id) {
    std::vector<WorldEvent> events;
    for (const auto& world : worlds) if (world.id == id)
        for (unsigned gate : world.gates)
            events.push_back({id,gate,3});
    return events;
}
int main() {
    unsigned checks = 0;
    for (unsigned world : {2u,3u,4u}) {
        for (unsigned qty : {1u,2u,3u}) {
            const auto result = Evaluate(world,qty,AllOpen(world));
            assert(result.convert() && result.coins == qty*1000);
            ++checks;
        }
    }
    {
        const auto events=AllOpen(5);
        assert(Evaluate(5,1,events).reason==Reason::InactiveWorld); ++checks;
        assert(Evaluate(5,2,events,true).coins==2000); ++checks;
    }
    {
        auto events=AllOpen(2);
        assert(Evaluate(77,1,events).reason==Reason::UnknownWorld); ++checks;
        assert(Evaluate(2,0,events).reason==Reason::InvalidQuantity); ++checks;
        assert(Evaluate(2,4,events).reason==Reason::InvalidQuantity); ++checks;
        events[0].state=1;
        assert(Evaluate(2,1,events).reason==Reason::GateNotOpen); ++checks;
        events[0].state=2;
        assert(Evaluate(2,1,events).reason==Reason::GateNotOpen); ++checks;
        events[0].state=4;
        assert(Evaluate(2,3,events).coins==3000); ++checks;
        events.pop_back();
        assert(Evaluate(2,1,events).reason==Reason::IncompleteState); ++checks;
        events=AllOpen(2); events.push_back(events[0]);
        assert(Evaluate(2,1,events).reason==Reason::DuplicateEvent); ++checks;
        events=AllOpen(2); events.push_back({3,15,1});
        assert(Evaluate(2,1,events).coins==1000); ++checks;
        events=AllOpen(2); events.push_back({2,4000,1});
        assert(Evaluate(2,1,events).coins==1000); ++checks;
    }
    {
        auto p=PlanCoinCredit(680,1000);
        assert(p.apply && p.after==1680); ++checks;
        p=PlanCoinCredit(680,3000);
        assert(p.apply && p.after==3680); ++checks;
        p=PlanCoinCredit(kMaxSignedCoins-999,1000);
        assert(!p.apply && p.after==kMaxSignedCoins-999); ++checks;
        p=PlanCoinCredit(kMaxSignedCoins,1000);
        assert(!p.apply && p.after==kMaxSignedCoins); ++checks;
        p=PlanCoinCredit(10,0);
        assert(!p.apply && p.after==10); ++checks;
    }
    std::cout<<"PASS: "<<checks<<" decision checks\n";
}
