// Host-only C++20 test for the reference ARM purchase-transaction layout
// and NON-ENFORCING per-profile provenance classification.
// clang++ -std=c++20 -Wall -Wextra -Werror -pedantic -Iplatform/ios/src \
// tests/test_offline_native_purchase_probe.cpp -o /tmp/native-probe-test
// /tmp/native-probe-test
#include "offline_native_purchase_probe.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <string_view>
using namespace pvz2offline;

int main() {
    static_assert(NativeTransactionOffsets::kSku == 12u);
    static_assert(NativeTransactionOffsets::kReceipt == 16u);
    static_assert(NativeTransactionOffsets::kOrderId == 20u);
    static_assert(NativeTransactionOffsets::kToken == 24u);
    static_assert(NativeTransactionOffsets::kOriginalJson == 28u);
    static_assert(NativeTransactionOffsets::kSignature == 32u);
    static_assert(NativeTransactionOffsets::kSize == 40u);

    const std::string known_sku =
        "com.popcap.pvz2.android.plant.snowpea.nonconsume";
    const auto known = [&](std::string_view sku) { return sku == known_sku; };
    ParsedReceiptV2 decoded;
    decoded.initiating_profile_id = 777u;
    decoded.serial = 25u;
    decoded.sku = "retain on rejection";

    assert(InspectPendingNativeReceipt("REAL-OLD-APP-STORE-RECEIPT", 20u,
                                        known, &decoded)
           == NativeV2Observation::OriginalOrUnknownReceipt);
    // Previous synthetic receipts lack v2 provenance, same SKU must NOT
    // cause them to be classified as a new owner-bound transaction.
    assert(InspectPendingNativeReceipt(
              "pvz2-offline:12:" + known_sku, 20u, known, &decoded)
           == NativeV2Observation::OriginalOrUnknownReceipt);
    assert(decoded.sku == "retain on rejection");

    assert(InspectPendingNativeReceipt(
              "pvz2-offline:v2:-1:22:" + known_sku, 20u, known, &decoded)
           == NativeV2Observation::MalformedCustomToken);
    assert(decoded.initiating_profile_id == 777u);

    const std::string token = MakeReceiptTokenV2(10u, 42u, known_sku);
    assert(InspectPendingNativeReceipt(token, 10u, known, &decoded)
           == NativeV2Observation::CustomOwnerIsSelected);
    assert(decoded.initiating_profile_id == 10u && decoded.serial == 42u);
    assert(decoded.sku == known_sku);
    assert(InspectPendingNativeReceipt(token, 11u, known)
           == NativeV2Observation::CustomOwnerIsOtherProfile);

    std::cout << "PASS five receipt-provenance cases and "
                 "native transaction offsets 12/16/20/24/28/32\n";
}
