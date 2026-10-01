#pragma once
// Pure host-side gate for a NEW profile-local PvZCoin purchase attempt.
// Authentic ORIGINAL global receipts never enter this gate: use provenance
// of the transaction, not its canonical SKU alone, to distinguish them.
namespace pvz2offline {
enum class LocalOwnerStatus {
    NotOfflineSku,
    NoProfile,
    SidecarNotReady,
    Owned,
    Unowned
};

enum class OfflineBuyGate {
    AllowPaidPurchase,
    RejectUnsupportedSku,
    RejectMissingProfile,
    RejectSidecarNotReady,
    RejectAlreadyOwned
};

constexpr OfflineBuyGate OfflineNewBuyGate(LocalOwnerStatus s) {
    switch (s) {
        case LocalOwnerStatus::Unowned:
            return OfflineBuyGate::AllowPaidPurchase;
        case LocalOwnerStatus::NotOfflineSku:
            return OfflineBuyGate::RejectUnsupportedSku;
        case LocalOwnerStatus::NoProfile:
            return OfflineBuyGate::RejectMissingProfile;
        case LocalOwnerStatus::SidecarNotReady:
            return OfflineBuyGate::RejectSidecarNotReady;
        case LocalOwnerStatus::Owned:
            return OfflineBuyGate::RejectAlreadyOwned;
    }
    return OfflineBuyGate::RejectSidecarNotReady;
}
} // namespace pvz2offline
