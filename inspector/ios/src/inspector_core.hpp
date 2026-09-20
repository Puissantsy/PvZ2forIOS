#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct PvZ2InspectorResult {
    bool ok = false;
    std::size_t apk_size = 0;
    std::size_t elf_size = 0;
    std::uint32_t image_size = 0;
    std::uint32_t load_segments = 0;
    std::uint32_t sections = 0;
    std::uint32_t dynamic_symbols = 0;
    std::uint32_t undefined_symbols = 0;
    std::uint32_t exidx_function_starts = 0;
    std::uint32_t relocations = 0;
    std::uint32_t log_hex_occurrences = 0;
    std::uint32_t log_unique_addresses = 0;
    std::size_t source_log_bytes = 0;
    std::size_t generic_log_bytes = 0;
    bool log_address_analysis_sampled = false;

    std::string summary;
    std::string report;
    std::string summary_json;
    std::string addresses_csv;
    std::string annotated_log;
    std::string startup_diagnosis;
    std::string matrix_diagnosis;
    std::string v57_plan;
    std::string v61_crash_diagnosis;
    std::string next_probe_plan;
    std::string critical_log_excerpt;
    std::string message;
};

PvZ2InspectorResult InspectPvZ2ApkAndLog(
    const std::uint8_t* apk_data,
    std::size_t apk_size,
    const std::string& log_text);
