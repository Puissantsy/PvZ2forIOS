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
    std::string v68_resource_stall_diagnosis;
    std::string v69_plan;
    std::string v68_critical_excerpt;
    std::string v74_display_diagnosis;
    std::string v75_display_plan;
    std::string v74_display_critical_excerpt;

    // v2.3: remaining oversized UI / virtual-layout forensics.
    std::string v78_ui_scale_diagnosis;
    std::string ui_scale_static_markers;
    std::string v79_ui_scale_plan;
    std::string v78_ui_scale_critical_excerpt;

    std::string message;
};

PvZ2InspectorResult InspectPvZ2ApkAndLog(
    const std::uint8_t* apk_data,
    std::size_t apk_size,
    const std::string& log_text);
