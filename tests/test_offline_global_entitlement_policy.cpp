// Standalone C++20 tests; no iOS toolchain, no real user save writes.
// clang++ -std=c++20 -Wall -Wextra -Werror -pedantic \
//     -Iplatform/ios/src tests/test_offline_global_entitlement_policy.cpp \
//     -o /tmp/test_global_policy && /tmp/test_global_policy
#include "offline_global_entitlement_policy.hpp"
#include <cassert>
#include <iostream>
using namespace pvz2offline;
constexpr std::uint32_t kPlants = 0x3fu;
constexpr std::uint32_t kFeatures = 0x0fu;

constexpr auto cleanSyntheticA = PlanGlobalIsolation(
    true, 0, 1, 1, kPlants);
static_assert(cleanSyntheticA.decision ==
              GlobalIsolationDecision::SyntheticChangeCanBeRemoved);
static_assert(cleanSyntheticA.eligible_synthetic_delta == 1u);
static_assert(cleanSyntheticA.preserve_global == 0u);

constexpr auto preserveLegacySnowPea = PlanGlobalIsolation(
    true, 1, 1, 1, kPlants);
static_assert(preserveLegacySnowPea.decision ==
              GlobalIsolationDecision::NoSyntheticChange);
static_assert(preserveLegacySnowPea.preserve_global == 1u);

constexpr auto mixedLegacyAndSynthetic = PlanGlobalIsolation(
    true, 1, 3, 2, kPlants);
static_assert(mixedLegacyAndSynthetic.decision ==
              GlobalIsolationDecision::SyntheticChangeCanBeRemoved);
static_assert(mixedLegacyAndSynthetic.eligible_synthetic_delta == 2u);
static_assert(mixedLegacyAndSynthetic.preserve_global == 1u);

constexpr auto noBaseline = PlanGlobalIsolation(false, 0, 1, 1, kPlants);
static_assert(noBaseline.decision ==
              GlobalIsolationDecision::PreserveUnverifiedBaseline);
static_assert(noBaseline.preserve_global == 1u);

constexpr auto unattributedOriginal = PlanGlobalIsolation(
    true, 0, 2, 1, kPlants);
static_assert(unattributedOriginal.decision ==
              GlobalIsolationDecision::PreserveUnattributedChanges);
static_assert(unattributedOriginal.preserve_global == 2u);

constexpr auto mixedUnattributed = PlanGlobalIsolation(
    true, 0, 3, 1, kPlants);
static_assert(mixedUnattributed.decision ==
              GlobalIsolationDecision::PreserveUnattributedChanges);
static_assert(mixedUnattributed.preserve_global == 3u);

constexpr auto legacyMissing = PlanGlobalIsolation(
    true, 1, 0, 1, kPlants);
static_assert(legacyMissing.decision ==
              GlobalIsolationDecision::PreserveMissingOriginalRights);
static_assert(legacyMissing.preserve_global == 0u);

constexpr auto featureOnly = PlanGlobalIsolation(
    true, 0, 4, 4, kFeatures);
static_assert(featureOnly.decision ==
              GlobalIsolationDecision::SyntheticChangeCanBeRemoved);
static_assert(featureOnly.preserve_global == 0u);

constexpr auto unrelatedNonCatalogBits = PlanGlobalIsolation(
    true, 1, 0x81, 0, kPlants);
static_assert(unrelatedNonCatalogBits.decision ==
              GlobalIsolationDecision::NoSyntheticChange);
static_assert(unrelatedNonCatalogBits.preserve_global == 0x81u);

static_assert(EffectivePlayableCatalogMask(1, 0, kPlants) == 1u);
static_assert(EffectivePlayableCatalogMask(0, 1, kPlants) == 1u);
static_assert(EffectivePlayableCatalogMask(0, 0, kPlants) == 0u);
static_assert(EffectivePlayableCatalogMask(0, 0x80, kPlants) == 0u);

int main() {
    assert(cleanSyntheticA.eligible_synthetic_delta == 1u);
    assert(mixedLegacyAndSynthetic.preserve_global == 1u);
    std::cout << "PASS 9 global policy + 4 gameplay projection cases\n";
}
