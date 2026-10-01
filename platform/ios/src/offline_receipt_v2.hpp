#pragma once
// The original 2013 game intentionally shares authentic IAPs across local
// accounts. Only identify the synthetic replacement coin-backed receipts here.
// This parsing helper DOES NOT grant or revoke any original receipt.
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace pvz2offline {
struct ParsedReceiptV2 {
    std::uint32_t initiating_profile_id = 0xffffffffu;
    std::uint64_t serial = 0u;
    std::string sku;
};

inline std::string MakeReceiptTokenV2(std::uint32_t profile_id,
                                     std::uint64_t serial,
                                     std::string_view sku) {
    if (profile_id == 0xffffffffu || serial == 0u || sku.empty()) return {};
    return "pvz2-offline:v2:" + std::to_string(profile_id) + ":" +
           std::to_string(serial) + ":" + std::string(sku);
}

// Reject aliases, digit overflows, unsupported SKUs, and partial matches.
// No mutation of 'out' occurs unless the ENTIRE token is accepted.
// KnownSkuPredicate must accept std::string_view and return bool.
template <class KnownSkuPredicate>
bool ParseReceiptTokenV2(std::string_view token,
                         KnownSkuPredicate known_sku,
                         ParsedReceiptV2& out) {
    constexpr std::string_view kPrefix = "pvz2-offline:v2:";
    if (token.size() < kPrefix.size() + 5u || token.size() > 256u ||
        token.substr(0, kPrefix.size()) != kPrefix) return false;
    token.remove_prefix(kPrefix.size());

    auto decimal = [](std::string_view& remaining,
                      std::uint64_t max,
                      std::uint64_t& parsed) -> bool {
        const std::size_t separator = remaining.find(':');
        if (separator == std::string_view::npos || separator == 0u ||
            separator > 20u) return false;
        std::uint64_t value = 0u;
        for (std::size_t i = 0; i < separator; ++i) {
            const char c = remaining[i];
            if (c < '0' || c > '9') return false;
            // Reject noncanonical numbers: a second spelling could bypass
            // transaction-id comparisons or owner-to-profile keying.
            if (i == 0u && separator > 1u && c == '0') return false;
            const unsigned digit = static_cast<unsigned>(c - '0');
            if (value > (max - digit) / 10u) return false;
            value = value * 10u + digit;
        }
        remaining.remove_prefix(separator + 1u);
        parsed = value;
        return true;
    };

    std::uint64_t owner = 0u;
    std::uint64_t serial = 0u;
    if (!decimal(token, 0xffffffffull, owner) ||
        owner == 0xffffffffull ||
        !decimal(token, std::numeric_limits<std::uint64_t>::max(), serial) ||
        serial == 0u || token.empty() || !known_sku(token)) return false;

    out.initiating_profile_id = static_cast<std::uint32_t>(owner);
    out.serial = serial;
    out.sku = std::string(token);
    return true;
}
}  // namespace pvz2offline
