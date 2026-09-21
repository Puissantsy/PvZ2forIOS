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
    std::string shared_strings_csv;
    std::size_t shared_string_count = 0;
    std::string objc_classes_csv;
    std::string objc_methods_csv;
    std::string objc_ivars_csv;
    std::string ios_import_calls_csv;
    std::string pthread_reference;
    std::size_t objc_class_count = 0;
    std::size_t objc_method_count = 0;
    std::size_t objc_ivar_count = 0;
    std::string message;
};

PvZ2IpaInspectorResult InspectPvZ2IpaReference(
    const std::uint8_t* ipa_data,
    std::size_t ipa_size,
    const std::uint8_t* apk_data,
    std::size_t apk_size);
