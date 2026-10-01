#pragma once
// Android PvZ2 1.5.252752 ARM32 reference ELF: independently verified
// listener 0x49ccf0 writes its 40-byte broker PurchaseTransaction as below.
// These are v1.5.252752 GUEST OFFSETS, never host sizeof/offsetof values.
// Intentionally observation only: B's free original CLAIM may not emit this
// callback, and a valid token alone does not authorize an entitlement.
#include "offline_receipt_v2.hpp"
#include <cstdint>
#include <string_view>

namespace pvz2offline {

struct NativeTransactionOffsets {
    static constexpr std::uint32_t kSku = 0x0cu;
    static constexpr std::uint32_t kReceipt = 0x10u;
    static constexpr std::uint32_t kOrderId = 0x14u;
    static constexpr std::uint32_t kToken = 0x18u;
    static constexpr std::uint32_t kOriginalJson = 0x1cu;
    static constexpr std::uint32_t kSignature = 0x20u;
    static constexpr std::uint32_t kState = 0x04u;
    static constexpr std::uint32_t kProcessingFlag = 0x08u;
    static constexpr std::uint32_t kSize = 40u;
};

enum class NativeV2Observation {
    OriginalOrUnknownReceipt,  // do not change original restore behavior
    MalformedCustomToken,      // synthetic namespace, but not a valid v2 token
    CustomOwnerIsSelected,     // still NOT proof of paid/committed ownership
    CustomSelectedProfileUnavailable,  // don't misclassify absent UI account
    CustomOwnerIsOtherProfile
};

// Provenance classification only. A subsequent enforcement adapter must
// additionally prove transaction context, serial idempotency, sidecar state,
// and actual native mutation semantics. It must NEVER reject a genuine old
// receipt solely because its SKU matches our ten canonical SKU identifiers.
template <class KnownSkuPredicate>
NativeV2Observation InspectPendingNativeReceipt(
    std::string_view token,
    std::uint32_t selected_profile_id,
    KnownSkuPredicate known_sku,
    ParsedReceiptV2* decoded = nullptr) {

    constexpr std::string_view kMarker = "pvz2-offline:v2:";
    if (token.substr(0, kMarker.size()) != kMarker) {
        return NativeV2Observation::OriginalOrUnknownReceipt;
    }

    ParsedReceiptV2 result;
    if (!ParseReceiptTokenV2(token, known_sku, result)) {
        return NativeV2Observation::MalformedCustomToken;
    }
    if (decoded != nullptr) *decoded = result;
    if (selected_profile_id == 0xffffffffu) {
        return NativeV2Observation::CustomSelectedProfileUnavailable;
    }
    return result.initiating_profile_id == selected_profile_id
        ? NativeV2Observation::CustomOwnerIsSelected
        : NativeV2Observation::CustomOwnerIsOtherProfile;
}
} // namespace pvz2offline
