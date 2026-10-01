// Pure-host v168 purchase admission test; no iPad/Xcode required.
// clang++ -std=c++20 -Wall -Wextra -Werror -pedantic \
//   -Iplatform/ios/src tests/test_offline_purchase_policy.cpp -o /tmp/qa-gate
// /tmp/qa-gate
#include "offline_purchase_policy.hpp"
#include <iostream>
using namespace pvz2offline;
static_assert(OfflineNewBuyGate(LocalOwnerStatus::Unowned)
              == OfflineBuyGate::AllowPaidPurchase);
static_assert(OfflineNewBuyGate(LocalOwnerStatus::NotOfflineSku)
              == OfflineBuyGate::RejectUnsupportedSku);
static_assert(OfflineNewBuyGate(LocalOwnerStatus::NoProfile)
              == OfflineBuyGate::RejectMissingProfile);
static_assert(OfflineNewBuyGate(LocalOwnerStatus::SidecarNotReady)
              == OfflineBuyGate::RejectSidecarNotReady);
static_assert(OfflineNewBuyGate(LocalOwnerStatus::Owned)
              == OfflineBuyGate::RejectAlreadyOwned);
int main() {
    std::cout << "PASS 5/5: unowned paid purchase allowed; duplicate, unknown "
                 "SKU, missing profile, uninitialized sidecar rejected\n";
}
