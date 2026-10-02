// Host-only no-guest-memory test. Verified using the EXACT committed header
// (same Git blob SHA as independently compiled local C++20 source).
// clang++ -std=c++20 -Wall -Wextra -Werror -pedantic
//   -Iplatform/ios/src tests/test_offline_global_compaction.cpp -o /tmp/global-compact-test
// /tmp/global-compact-test
#include "offline_global_compaction.hpp"
#include <cassert>
#include <iostream>
#include <vector>
using namespace pvz2offline;
int main() {
    auto all=PreviewGlobalCatalogRemoval({99u,21u,39u,88u},true,1u);
    assert(all.safe() && all.removed_catalog_mask==1u);
    assert((all.kept==std::vector<std::uint32_t>{99u,39u,88u}));
    auto both=PreviewGlobalCatalogRemoval({21u,39u,32u},true,3u);
    assert(both.safe() && (both.kept==std::vector<std::uint32_t>{32u}));
    auto upgrades=PreviewGlobalCatalogRemoval({15u,19u,500u},false,2u);
    assert(upgrades.safe() && (upgrades.kept==std::vector<std::uint32_t>{15u,500u}));
    auto empty=PreviewGlobalCatalogRemoval({7u},true,0u);
    assert(empty.safe() && empty.kept==std::vector<std::uint32_t>{7u});
    auto badmask=PreviewGlobalCatalogRemoval({21u},true,1u<<6u);
    assert(badmask.failure==GlobalCompactFailure::UnsupportedMask && badmask.kept.empty());
    auto missing=PreviewGlobalCatalogRemoval({39u},true,1u);
    assert(missing.failure==GlobalCompactFailure::MissingTarget && missing.kept.empty());
    auto duplicate=PreviewGlobalCatalogRemoval({21u,21u},true,1u);
    assert(duplicate.failure==GlobalCompactFailure::DuplicateTarget && duplicate.kept.empty());
    std::vector<std::uint32_t> oversize(129u,42u);
    auto oversized=PreviewGlobalCatalogRemoval(oversize,true,1u);
    assert(oversized.failure==GlobalCompactFailure::OversizedVector && oversized.kept.empty());
    auto original=std::vector<std::uint32_t>{99u,21u,39u,88u};
    (void) PreviewGlobalCatalogRemoval(original,true,1u);
    assert((original==std::vector<std::uint32_t>{99u,21u,39u,88u}));
    std::cout << "PASS 9/9 isolated global-vector compaction policy cases\n";
}
