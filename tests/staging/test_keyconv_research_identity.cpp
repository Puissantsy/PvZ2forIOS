#include "keyconv_research_identity_policy.hpp"
#include <cassert>
#include <iostream>
using pvz2_key_study::keyconv_identity::Evaluate;
using pvz2_key_study::keyconv_identity::Result;
int main() {
    // Canonical unsigned build and two real-world signing transformations.
    assert(Evaluate("com.puissantsy.pvz2forios.keyobs",true)==Result::Allowed);
    assert(Evaluate("com.puissantsy.pvz2forios.keyobs.ABCDEFG123",true)==Result::Allowed);
    assert(Evaluate("com.sideload.randomized.71923",true)==Result::Allowed);
    // Reject normal game, copied adapter, missing proof and empty ID.
    assert(Evaluate("com.puissantsy.pvz2forios",true)==Result::ProductionIdentifier);
    assert(Evaluate("com.puissantsy.pvz2forios.production",true)==Result::ProductionIdentifier);
    assert(Evaluate("com.ea.game.pvz2_row",true)==Result::ProductionIdentifier);
    assert(Evaluate("com.ea.game.pvz2_row.abc",true)==Result::ProductionIdentifier);
    assert(Evaluate("com.puissantsy.pvz2forios.keyobs",false)==Result::MissingResearchMarker);
    assert(Evaluate("com.sideload.randomized.71923",false)==Result::MissingResearchMarker);
    assert(Evaluate("",true)==Result::MissingRuntimeBundle);
    std::cout<<"PASS: canonical/re-signed KEYOBS accepted only with research marker; production blocked\n";
}
