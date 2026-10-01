// Host-only contract test: never requires Xcode or the guest runtime.
// clang++ -std=c++20 -Wall -Wextra -Werror -pedantic
//   -Iplatform/ios/src tests/test_offline_receipt_v2.cpp -o /tmp/receipt-v2-test
// /tmp/receipt-v2-test
#include "offline_receipt_v2.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

int main() {
    const std::string sku =
        "com.popcap.pvz2.android.plant.snowpea.nonconsume";
    const auto known = [&](std::string_view x) { return x == sku; };
    const std::string valid =
        pvz2offline::MakeReceiptTokenV2(1790838014u, 123u, sku);
    assert(valid == "pvz2-offline:v2:1790838014:123:" + sku);
    pvz2offline::ParsedReceiptV2 receipt;
    assert(pvz2offline::ParseReceiptTokenV2(valid, known, receipt));
    assert(receipt.initiating_profile_id == 1790838014u);
    assert(receipt.serial == 123u && receipt.sku == sku);

    const std::vector<std::string> reject = {
        "pvz2-offline:123:" + sku, // legacy receipt: must be untouched
        "pvz2-offline:v2:1790838014:123:other", // unrelated SKU
        "pvz2-offline:v2:01790838014:123:" + sku, // noncanonical
        "pvz2-offline:v2:1790838014:000123:" + sku,
        "pvz2-offline:v2:1790838014:0:" + sku,
        "pvz2-offline:v2:4294967295:123:" + sku, // invalid profile
        "pvz2-offline:v2:4294967296:123:" + sku, // owner overflow
        "pvz2-offline:v2:1:18446744073709551616:" + sku,
        "pvz2-offline:v2:-1:123:" + sku,
        "pvz2-offline:v2:1:123:" + sku + ":suffix",
        "pvz2-offline:v3:1:1:" + sku, // future version: fail closed
        "pvz2-offline:v2:1:1:",
        std::string(257u, 'X')
    };
    for (const auto& candidate : reject) {
        const auto previous = receipt;
        assert(!pvz2offline::ParseReceiptTokenV2(candidate, known, receipt));
        assert(receipt.initiating_profile_id == previous.initiating_profile_id);
        assert(receipt.serial == previous.serial && receipt.sku == previous.sku);
    }
    assert(pvz2offline::MakeReceiptTokenV2(0xffffffffu, 1u, sku).empty());
    assert(pvz2offline::MakeReceiptTokenV2(1u, 0u, sku).empty());
    const auto largest = pvz2offline::MakeReceiptTokenV2(
        4294967294u, 18446744073709551615ull, sku);
    assert(pvz2offline::ParseReceiptTokenV2(largest, known, receipt));
    assert(receipt.initiating_profile_id == 4294967294u);
    assert(receipt.serial == 18446744073709551615ull);
    std::cout << "PASS: two valid boundary cases and " << reject.size()
              << " invalid/legacy cases, no partial output changes\n";
}
