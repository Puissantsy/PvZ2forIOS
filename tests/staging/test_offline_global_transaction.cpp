#include "offline_global_transaction.hpp"
#include <cassert>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
using namespace pvz2offline;

static std::optional<GlobalJournalSku> Lookup(std::string_view sku) {
    if (sku == "com.popcap.pvz2.android.plant.snowpea.nonconsume")
        return GlobalJournalSku{true, 21u, 1u};
    if (sku == "com.popcap.pvz2.android.gameupgrade.seedslot2.nonconsume")
        return GlobalJournalSku{false, 12u, 8u};
    return std::nullopt;
}
static GlobalJournal SnowPea() {
    GlobalJournal j;
    j.token = MakeReceiptTokenV2(
        7u, 23u, "com.popcap.pvz2.android.plant.snowpea.nonconsume");
    j.owner = 7u;
    j.sku = *Lookup("com.popcap.pvz2.android.plant.snowpea.nonconsume");
    j.before_plants = {99u, 43u};
    j.before_features = {12u, 61u};
    return j;
}
int main() {
    auto j = SnowPea();
    const auto encoded = EncodeGlobalJournal(j, Lookup);
    assert(encoded);
    const auto decoded = DecodeGlobalJournal(*encoded, Lookup);
    assert(decoded && decoded->owner == 7u &&
           decoded->before_plants == j.before_plants);
    assert(PlanExactGlobalTransaction(j,{99u,43u,21u},{12u,61u},true) ==
           GlobalJournalDecision::AwaitingConfirmation);
    j.native_confirmed = true;
    j.local_committed = true;
    assert(PlanExactGlobalTransaction(j,{99u,43u,21u},{12u,61u},true) ==
           GlobalJournalDecision::ExactSyntheticOnlyDelta);
    assert(PlanExactGlobalTransaction(j,{99u,43u,21u},{12u,61u},false) ==
           GlobalJournalDecision::RecoveryMustPreserve);
    assert(PlanExactGlobalTransaction(j,{99u,43u,21u},{12u,62u},true) ==
           GlobalJournalDecision::ConcurrentOrUnexpectedChange);
    assert(PlanExactGlobalTransaction(j,{99u,43u,21u,21u},{12u,61u},true) ==
           GlobalJournalDecision::ConcurrentOrUnexpectedChange);
    assert(PlanExactGlobalTransaction(j,{99u,21u,43u,55u},{12u,61u},true) ==
           GlobalJournalDecision::ConcurrentOrUnexpectedChange);
    assert(PlanExactGlobalTransaction(j,{99u,43u},{12u,61u},true) ==
           GlobalJournalDecision::NoNewGlobalRight);
    j.before_plants.push_back(21u);
    assert(PlanExactGlobalTransaction(j,{99u,43u,21u},{12u,61u},true) ==
           GlobalJournalDecision::OriginalRightPreexisting);
    assert(!DecodeGlobalJournal(*encoded + "x", Lookup));
    auto corrupted = *encoded;
    corrupted[5] = 'X';
    assert(!DecodeGlobalJournal(corrupted, Lookup));
    auto invalid = SnowPea();
    invalid.owner = 8u;
    assert(!EncodeGlobalJournal(invalid, Lookup));
    invalid = SnowPea();
    invalid.sku.target_bit = 2u;
    assert(!EncodeGlobalJournal(invalid, Lookup));
    invalid = SnowPea();
    invalid.cleanup_intent = true;
    assert(!EncodeGlobalJournal(invalid, Lookup));
    invalid = SnowPea();
    invalid.native_confirmed = true;
    invalid.local_committed = true;
    invalid.cleanup_intent = true;
    assert(DecodeGlobalJournal(
        *EncodeGlobalJournal(invalid, Lookup), Lookup)->cleanup_intent);

    auto upgrade = SnowPea();
    upgrade.token = MakeReceiptTokenV2(
        7u, 24u, "com.popcap.pvz2.android.gameupgrade.seedslot2.nonconsume");
    upgrade.sku = *Lookup(
        "com.popcap.pvz2.android.gameupgrade.seedslot2.nonconsume");
    upgrade.before_features = {19u, 71u};
    upgrade.native_confirmed = true;
    upgrade.local_committed = true;
    assert(PlanExactGlobalTransaction(
        upgrade,{99u,43u},{19u,12u,71u},true) ==
        GlobalJournalDecision::ExactSyntheticOnlyDelta);
    assert(DecodeGlobalJournal(
        *EncodeGlobalJournal(upgrade, Lookup), Lookup).has_value());
    std::cout << "PASS: journal codec and fail-closed exact-vector plant + upgrade policies\n";
}
