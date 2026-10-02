#pragma once
// Decode only the observed fixed-width native event-record prefix from a
// trusted, bounded snapshot of the original guest event vector. NO guest writes.
#include "world_key_conversion_policy.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pvz2_key_study {
inline constexpr std::size_t kNativeEventStride=24;
inline constexpr std::size_t kMaxNativeEvents=1024;
// Layout witness: original ELF 0x42d2b4 (stride 3*8), 0x42d378
// (byte at +0), 0x42d380 (halfword at +2), 0x42d388 (state at +4).
// Validate on real iPad BEFORE treating this read-only snapshot as truth.
inline std::optional<std::vector<WorldEvent>>
DecodeNativeEventSnapshot(std::span<const std::byte> bytes) {
    if (bytes.empty() || bytes.size()%kNativeEventStride!=0 ||
        bytes.size()/kNativeEventStride>kMaxNativeEvents) return std::nullopt;
    std::vector<WorldEvent> result;
    result.reserve(bytes.size()/kNativeEventStride);
    for (std::size_t pos=0;pos<bytes.size();pos+=kNativeEventStride) {
        const auto u8=[&](std::size_t offset) -> std::uint32_t {
            return std::to_integer<std::uint8_t>(bytes[pos+offset]);
        };
        WorldEvent event{u8(0),u8(2)|(u8(3)<<8),
            u8(4)|(u8(5)<<8)|(u8(6)<<16)|(u8(7)<<24)};
        result.push_back(event);
    }
    return result;
}
} // namespace pvz2_key_study
