#pragma once
// Pure decoding of original PvZ2 1.5.252752 native WorldSpecificKeys
// vector entries (8 bytes each: char* worldName, u32 count).
// No guest memory dereference, native call, or save mutation here.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace pvz2_key_study {
inline constexpr std::size_t kWorldKeyStockStride = 8u;
inline constexpr std::size_t kMaxWorldKeyStockSlots = 16u;
struct WorldKeyStockEntry {
    std::string world;
    std::uint32_t count;
};
inline bool ValidStockWorld(const std::string& world) {
    return world=="egypt" || world=="pirate" || world=="cowboy" ||
           world=="future" || world=="dark";
}
template<class ResolveNativeString>
std::optional<std::vector<WorldKeyStockEntry>>
DecodeNativeWorldKeyStock(
    std::span<const std::byte> snapshot,
    ResolveNativeString resolve_native_string) {
    if (snapshot.size()%kWorldKeyStockStride != 0u ||
        snapshot.size()/kWorldKeyStockStride > kMaxWorldKeyStockSlots)
        return std::nullopt;
    std::vector<WorldKeyStockEntry> result;
    result.reserve(snapshot.size()/kWorldKeyStockStride);
    for (std::size_t i=0; i<snapshot.size(); i+=kWorldKeyStockStride) {
        const auto u32=[&](std::size_t at) -> std::uint32_t {
            return std::uint32_t(std::to_integer<std::uint8_t>(snapshot[at])) |
                (std::uint32_t(std::to_integer<std::uint8_t>(snapshot[at+1]))<<8u) |
                (std::uint32_t(std::to_integer<std::uint8_t>(snapshot[at+2]))<<16u) |
                (std::uint32_t(std::to_integer<std::uint8_t>(snapshot[at+3]))<<24u);
        };
        const auto chars=u32(i);
        const auto count=u32(i+4u);
        if (chars<12u || count>99u) return std::nullopt;
        auto world=resolve_native_string(chars);
        if (!world || !ValidStockWorld(*world)) return std::nullopt;
        for (const auto& prior:result)
            if (prior.world==*world) return std::nullopt;
        result.push_back({std::move(*world),count});
    }
    return result;
}
} // namespace pvz2_key_study
