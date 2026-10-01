#pragma once
// Pure preview of a constrained in-memory original GlobalSaveData vector
// cleanup. NEVER operate on arbitrary guest memory: caller must prove
// (1) original instance/vector bounds, (2) trusted global legacy baseline,
// (3) published delta exactly attributable to a successfully committed v2
// synthetic transaction. Preserve all unknown/noncatalog DWORD identifiers.
// This helper does NOT write guest memory, invoke the native saver or alter
// old original authentic purchase receipts.
#include <array>
#include <cstdint>
#include <vector>

namespace pvz2offline {

enum class GlobalCompactFailure : std::uint8_t {
    None,
    UnsupportedMask,
    MissingTarget,
    DuplicateTarget,
    OversizedVector,
};

struct GlobalCompactPreview {
    GlobalCompactFailure failure = GlobalCompactFailure::None;
    std::vector<std::uint32_t> kept;
    std::uint32_t removed_catalog_mask = 0u;
    [[nodiscard]] bool safe() const { return failure == GlobalCompactFailure::None; }
};

inline GlobalCompactPreview PreviewGlobalCatalogRemoval(
    const std::vector<std::uint32_t>& original,
    bool plants,
    std::uint32_t allowed_remove_mask) {

    constexpr std::array<std::uint32_t, 6> kPlants =
        {21u, 39u, 32u, 33u, 18u, 38u};
    constexpr std::array<std::uint32_t, 4> kFeatures =
        {15u, 19u, 21u, 12u};
    const unsigned nbits = plants ? 6u : 4u;
    const unsigned valid_mask = (1u << nbits) - 1u;
    GlobalCompactPreview preview;
    if ((allowed_remove_mask & ~valid_mask) != 0u) {
        preview.failure = GlobalCompactFailure::UnsupportedMask;
        return preview;
    }
    // The actual 2013 global vector is tiny. Refuse corrupted/unknown-size
    // vectors instead of allocating an unbounded host staging buffer.
    if (original.size() > 128u) {
        preview.failure = GlobalCompactFailure::OversizedVector;
        return preview;
    }
    preview.kept.reserve(original.size());
    for (auto id : original) {
        int bit = -1;
        for (unsigned index = 0u; index < nbits; ++index) {
            if (id == (plants ? kPlants[index] : kFeatures[index])) {
                bit = static_cast<int>(index);
                break;
            }
        }
        if (bit >= 0 && (allowed_remove_mask & (1u << bit)) != 0u) {
            if ((preview.removed_catalog_mask & (1u << bit)) != 0u) {
                // Do not silently normalize/corrupt unexpected duplicated
                // native ownership entries; discard the whole preview.
                preview.failure = GlobalCompactFailure::DuplicateTarget;
                preview.kept.clear();
                preview.removed_catalog_mask = 0u;
                return preview;
            }
            preview.removed_catalog_mask |= 1u << bit;
        } else {
            preview.kept.push_back(id);
        }
    }
    if (preview.removed_catalog_mask != allowed_remove_mask) {
        preview.failure = GlobalCompactFailure::MissingTarget;
        preview.kept.clear();
        preview.removed_catalog_mask = 0u;
    }
    return preview;
}
} // namespace pvz2offline
