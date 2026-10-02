#pragma once
// HOST-side v2-only provenance and exact whole-vector guard. A persisted
// journal NEVER independently authorizes automatic destructive crash replay.
// Pure C++20: no guest read/write, original receipt changes or save edits.
#include "offline_global_compaction.hpp"
#include "offline_receipt_v2.hpp"
#include <array>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pvz2offline {

struct GlobalJournalSku {
    bool plants = true;
    std::uint32_t target_id = 0u;
    std::uint32_t target_bit = 0u;
};
struct GlobalJournal {
    std::string token;
    std::uint32_t owner = 0xffffffffu;
    GlobalJournalSku sku;
    std::vector<std::uint32_t> before_plants;
    std::vector<std::uint32_t> before_features;
    bool native_confirmed = false;
    bool local_committed = false;
    bool cleanup_intent = false;
};
enum class GlobalJournalDecision : std::uint8_t {
    InvalidJournal, AwaitingConfirmation, RecoveryMustPreserve,
    OriginalRightPreexisting, NoNewGlobalRight,
    ConcurrentOrUnexpectedChange, ExactSyntheticOnlyDelta
};

inline bool ValidGlobalJournalShape(const GlobalJournal& j) {
    if (j.owner == 0xffffffffu || j.token.empty() || j.token.size() > 256u ||
        j.before_plants.size() > 128u || j.before_features.size() > 128u ||
        j.sku.target_id == 0u || j.sku.target_bit == 0u ||
        (j.sku.target_bit & (j.sku.target_bit - 1u)) != 0u ||
        (j.sku.target_bit & ~(j.sku.plants ? 0x3fu : 0x0fu)) != 0u ||
        (j.cleanup_intent && !(j.native_confirmed && j.local_committed))) {
        return false;
    }
    constexpr std::array<std::uint32_t, 6> plants =
        {21u, 39u, 32u, 33u, 18u, 38u};
    constexpr std::array<std::uint32_t, 4> upgrades =
        {15u, 19u, 21u, 12u};
    for (unsigned bit = 0u; bit < (j.sku.plants ? 6u : 4u); ++bit) {
        if (j.sku.target_bit == (1u << bit)) {
            return j.sku.target_id ==
                (j.sku.plants ? plants[bit] : upgrades[bit]);
        }
    }
    return false;
}

// Caller must independently verify SAME LIVE process + exact native v2
// delivery + successful per-profile sidecar commit. Full original vector
// equality (order and unknown IDs included) excludes other mutations.
inline GlobalJournalDecision PlanExactGlobalTransaction(
    const GlobalJournal& j,
    const std::vector<std::uint32_t>& now_plants,
    const std::vector<std::uint32_t>& now_features,
    bool same_live_transaction) {
    if (!ValidGlobalJournalShape(j) ||
        now_plants.size() > 128u || now_features.size() > 128u) {
        return GlobalJournalDecision::InvalidJournal;
    }
    if (!same_live_transaction) {
        return GlobalJournalDecision::RecoveryMustPreserve;
    }
    if (!j.native_confirmed || !j.local_committed) {
        return GlobalJournalDecision::AwaitingConfirmation;
    }
    const auto& baseline = j.sku.plants ? j.before_plants : j.before_features;
    const auto& now = j.sku.plants ? now_plants : now_features;
    const auto& baseline_other =
        j.sku.plants ? j.before_features : j.before_plants;
    const auto& now_other = j.sku.plants ? now_features : now_plants;
    for (auto id : baseline) {
        if (id == j.sku.target_id) {
            return GlobalJournalDecision::OriginalRightPreexisting;
        }
    }
    if (now == baseline && now_other == baseline_other) {
        return GlobalJournalDecision::NoNewGlobalRight;
    }
    if (now_other != baseline_other) {
        return GlobalJournalDecision::ConcurrentOrUnexpectedChange;
    }
    const auto preview =
        PreviewGlobalCatalogRemoval(now, j.sku.plants, j.sku.target_bit);
    if (!preview.safe() || preview.removed_catalog_mask != j.sku.target_bit ||
        preview.kept != baseline) {
        return GlobalJournalDecision::ConcurrentOrUnexpectedChange;
    }
    return GlobalJournalDecision::ExactSyntheticOnlyDelta;
}

// FNV-1a detects accidental corruption, NOT adversarial modifications.
inline std::uint64_t GlobalJournalChecksum(std::string_view body) {
    std::uint64_t hash = 14695981039346656037ull;
    for (unsigned char c : body) {
        hash = (hash ^ c) * 1099511628211ull;
    }
    return hash;
}
inline std::string GlobalJournalHex16(std::uint64_t n) {
    constexpr char kHex[] = "0123456789abcdef";
    std::string s(16, '0');
    for (unsigned i = 0u; i < 16u; ++i) {
        s[15u - i] = kHex[n & 15u];
        n >>= 4u;
    }
    return s;
}
inline std::string GlobalJournalIds(const std::vector<std::uint32_t>& ids) {
    if (ids.empty()) return "-";
    std::string s;
    for (auto id : ids) {
        if (!s.empty()) s.push_back(',');
        s += std::to_string(id);
    }
    return s;
}

template <class SkuLookup>
std::optional<std::string> EncodeGlobalJournal(const GlobalJournal& j,
                                                SkuLookup lookup) {
    if (!ValidGlobalJournalShape(j)) return std::nullopt;
    ParsedReceiptV2 receipt;
    if (!ParseReceiptTokenV2(j.token,
            [&](std::string_view sku) { return lookup(sku).has_value(); },
            receipt) || receipt.initiating_profile_id != j.owner) {
        return std::nullopt;
    }
    const auto expected = lookup(receipt.sku);
    if (!expected || expected->plants != j.sku.plants ||
        expected->target_id != j.sku.target_id ||
        expected->target_bit != j.sku.target_bit) return std::nullopt;
    const unsigned flags = (j.native_confirmed ? 1u : 0u) |
                           (j.local_committed ? 2u : 0u) |
                           (j.cleanup_intent ? 4u : 0u);
    std::string body = "v1|" + j.token + "|" +
        (j.sku.plants ? "p" : "u") + "|" +
        std::to_string(j.sku.target_id) + "|" +
        std::to_string(j.sku.target_bit) + "|" +
        GlobalJournalIds(j.before_plants) + "|" +
        GlobalJournalIds(j.before_features) + "|" +
        std::to_string(flags);
    return body + "|" + GlobalJournalHex16(GlobalJournalChecksum(body));
}
inline bool GlobalJournalParseUint(std::string_view s,
                                   std::uint32_t& out) {
    if (s.empty() || (s.size() > 1u && s.front() == '0')) return false;
    const auto parsed = std::from_chars(s.data(), s.data() + s.size(), out);
    return parsed.ec == std::errc{} &&
           parsed.ptr == s.data() + s.size();
}
inline bool GlobalJournalParseIds(std::string_view s,
                                 std::vector<std::uint32_t>& out) {
    if (s == "-") return true;
    if (s.empty() || s.size() > 1407u) return false;
    while (!s.empty()) {
        const auto sep = s.find(',');
        std::uint32_t id = 0u;
        if (!GlobalJournalParseUint(s.substr(0u, sep), id) ||
            out.size() == 128u) return false;
        out.push_back(id);
        if (sep == std::string_view::npos) break;
        s.remove_prefix(sep + 1u);
        if (s.empty()) return false;
    }
    return true;
}

template <class SkuLookup>
std::optional<GlobalJournal> DecodeGlobalJournal(std::string_view saved,
                                                  SkuLookup lookup) {
    if (saved.empty() || saved.size() > 3200u) return std::nullopt;
    const std::string serialized{saved};
    std::array<std::string_view, 9> columns{};
    for (unsigned i = 0u; i < columns.size(); ++i) {
        const auto sep = saved.find('|');
        if (i + 1u < columns.size()) {
            if (sep == std::string_view::npos) return std::nullopt;
            columns[i] = saved.substr(0u, sep);
            saved.remove_prefix(sep + 1u);
        } else {
            if (sep != std::string_view::npos) return std::nullopt;
            columns[i] = saved;
        }
    }
    if (columns[0] != "v1" || columns[8].size() != 16u ||
        (columns[2] != "p" && columns[2] != "u")) return std::nullopt;
    GlobalJournal out;
    ParsedReceiptV2 receipt;
    if (!ParseReceiptTokenV2(columns[1],
            [&](std::string_view sku) { return lookup(sku).has_value(); },
            receipt)) return std::nullopt;
    out.token = std::string(columns[1]);
    out.owner = receipt.initiating_profile_id;
    out.sku.plants = columns[2] == "p";
    std::uint32_t flags = 0u;
    if (!GlobalJournalParseUint(columns[3], out.sku.target_id) ||
        !GlobalJournalParseUint(columns[4], out.sku.target_bit) ||
        !GlobalJournalParseIds(columns[5], out.before_plants) ||
        !GlobalJournalParseIds(columns[6], out.before_features) ||
        !GlobalJournalParseUint(columns[7], flags) || flags > 7u) {
        return std::nullopt;
    }
    out.native_confirmed = (flags & 1u) != 0u;
    out.local_committed = (flags & 2u) != 0u;
    out.cleanup_intent = (flags & 4u) != 0u;
    // Canonical roundtrip validates all numbers, SKU mapping, size and hash.
    const auto canonical = EncodeGlobalJournal(out, lookup);
    if (!canonical || *canonical != serialized) return std::nullopt;
    return out;
}
} // namespace pvz2offline
