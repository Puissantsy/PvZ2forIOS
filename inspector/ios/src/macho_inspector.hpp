#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct PvZ2IpaInspectorResult {
    bool ok = false;
    std::size_t ipa_size = 0;
    std::size_t macho_size = 0;
    std::string executable_path;
    std::string summary;
    std::string report;
    std::string message;
};

PvZ2IpaInspectorResult InspectPvZ2IpaReference(
    const std::uint8_t* ipa_data,
    std::size_t ipa_size);
