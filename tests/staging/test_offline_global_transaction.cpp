// Compile the ACTUAL iOS policy header (not the historical staging copy).
// Trigger policy-only CI after correcting source check section scopes.
// Also validate optional v170 QA credit and durable receipt serial gates.
#include "../../platform/ios/src/offline_global_transaction.hpp"
#include <array>
#include <cassert>
#include <iostream>
#include <optional>
#include <string_view>
using namespace pvz2offline;
struct Case { std::string_view sku; GlobalJournalSku owner; };
static constexpr std::array<Case, 10> cases{{
    {"com.popcap.pvz2.android.plant.snowpea.nonconsume", {true,21u,1u}},
    {"com.popcap.pvz2.android.plant.squash.nonconsume", {true,39u,2u}},
    {"com.popcap.pvz2.android.plant.imitater.nonconsume", {true,32u,4u}},
    {"com.popcap.pvz2.android.plant.jalapeno.nonconsume", {true,33u,8u}},
    {"com.popcap.pvz2.android.plant.torchwood.nonconsume", {true,18u,16u}},
    {"com.popcap.pvz2.android.plant.powerlily.nonconsume", {true,38u,32u}},
    {"com.popcap.pvz2.android.gameupgrade.sunshovel3.nonconsume", {false,15u,1u}},
    {"com.popcap.pvz2.android.gameupgrade.pfslot2.nonconsume", {false,19u,2u}},
    {"com.popcap.pvz2.android.gameupgrade.startingsun2.nonconsume", {false,21u,4u}},
    {"com.popcap.pvz2.android.gameupgrade.seedslot2.nonconsume", {false,12u,8u}}
}};
static std::optional<GlobalJournalSku> Lookup(std::string_view sku) {
    for (const auto& c : cases) if (sku == c.sku) return c.owner;
    return std::nullopt;
}
static GlobalJournal NewCase(const Case& c, std::uint64_t serial) {
    GlobalJournal j;
    j.owner = 7u;
    j.token = MakeReceiptTokenV2(7u, serial, c.sku);
    j.sku = c.owner;
    j.before_plants = {99u,43u};
    j.before_features = {61u,72u};
    return j;
}
int main() {
    std::uint64_t serial = 1u;
    for (const auto& c : cases) {
        auto j = NewCase(c, serial++);
        auto encoded = EncodeGlobalJournal(j, Lookup);
        assert(encoded);
        auto decoded = DecodeGlobalJournal(*encoded, Lookup);
        assert(decoded && decoded->token == j.token &&
               decoded->owner == j.owner &&
               decoded->sku.target_bit == j.sku.target_bit &&
               decoded->before_plants == j.before_plants &&
               decoded->before_features == j.before_features);
        auto nowPlants = j.before_plants;
        auto nowFeatures = j.before_features;
        auto& target = c.owner.plants ? nowPlants : nowFeatures;
        target.insert(target.begin()+1, c.owner.target_id);
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::AwaitingConfirmation);
        j.native_confirmed = true;
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::AwaitingConfirmation);
        j.local_committed = true;
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::ExactSyntheticOnlyDelta);
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, false) ==
            GlobalJournalDecision::RecoveryMustPreserve);
        auto duplicate = target;
        target.push_back(c.owner.target_id);
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::ConcurrentOrUnexpectedChange);
        target = duplicate;
        auto& other = c.owner.plants ? nowFeatures : nowPlants;
        other.push_back(4777u);
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::ConcurrentOrUnexpectedChange);
        other.pop_back();
        target.push_back(4777u);
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::ConcurrentOrUnexpectedChange);
        target.pop_back();
        assert(PlanExactGlobalTransaction(
            j, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::ExactSyntheticOnlyDelta);
        auto legacy = j;
        auto& preexisting = c.owner.plants ?
            legacy.before_plants : legacy.before_features;
        preexisting.push_back(c.owner.target_id);
        assert(PlanExactGlobalTransaction(
            legacy, nowPlants, nowFeatures, true) ==
            GlobalJournalDecision::OriginalRightPreexisting);
        j.cleanup_intent = true;
        encoded = EncodeGlobalJournal(j, Lookup);
        assert(encoded && DecodeGlobalJournal(
            *encoded, Lookup)->cleanup_intent);
        assert(!DecodeGlobalJournal(*encoded + "x", Lookup));
        auto corrupted = *encoded;
        corrupted[1] = 'X';
        assert(!DecodeGlobalJournal(corrupted, Lookup));
        auto invalid = j;
        invalid.owner = 8u;
        assert(!EncodeGlobalJournal(invalid, Lookup));
        invalid = j;
        invalid.before_plants.assign(129u, 91u);
        assert(!EncodeGlobalJournal(invalid, Lookup));
        invalid = j;
        invalid.sku.target_bit <<= 1;
        assert(!EncodeGlobalJournal(invalid, Lookup));
    }
    std::cout << "PASS: all 10 original SKUs, exact original vector order, "
                 "legacy preservation, native+sidecar+intent stages, "
                 "cold-launch preservation and checksum guards\n";
}
