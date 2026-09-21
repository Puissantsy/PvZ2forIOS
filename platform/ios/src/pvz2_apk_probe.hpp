#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

struct PvZ2ApkProbeResult {
    bool ok = false;
    bool exact_15252752_profile = false;

    std::size_t apk_size = 0;
    std::size_t elf_compressed_size = 0;
    std::size_t elf_size = 0;

    std::uint32_t guest_base = 0x10000000u;
    std::uint32_t image_size = 0;
    std::uint32_t jni_onload_value = 0;
    std::uint32_t jni_onload_guest = 0;

    std::uint32_t load_segments = 0;
    std::uint32_t dynsym_count = 0;
    std::uint32_t undefined_symbol_count = 0;
    std::uint32_t needed_library_count = 0;
    std::uint32_t init_array_count = 0;

    std::uint32_t relative_relocations = 0;
    std::uint32_t relative_applied = 0;
    std::uint32_t glob_dat_relocations = 0;
    std::uint32_t jump_slot_relocations = 0;
    std::uint32_t unsupported_relocations = 0;

    std::string soname;
    std::string needed_libraries;
    std::string message;
};

PvZ2ApkProbeResult InspectAndMapPvZ2Apk(const std::uint8_t* apk_data, std::size_t apk_size);


using PvZ2ProbeProgress = std::function<void(const std::string&)>;

enum class PvZ2DiagnosticMode : std::uint32_t {
    PassiveRegistry = 0u,
    GateAScout = 1u,
    FullMatrix = 2u,

    // v57 modes. FullMatrix remains the exact v56 control path.
    CtypeCompatNativePath = 3u,
    CtypeCompatDeepScout = 4u,

    // v62: same ctype/native path, with an explicit A/B around the
    // resource-stream TaskResource pump. A preserves v61 scheduling while
    // collecting provenance; B adds coherent ownership for manager+0x68.
    V62TaskProvenanceControlA = 5u,
    V62PumpMutexCoherentB = 6u,

    // v63: single forward-progress mode. It keeps the validated ctype/native
    // path but makes deferred-worker scheduling aware of every guest pthread
    // mutex critical section instead of one resource-pump mutex.
    V63CriticalSectionScheduler = 7u,
};

struct PvZ2JniProbeResult {
    bool ok = false;
    bool reached_jni_onload = false;
    bool returned_from_jni_onload = false;
    bool reached_game_app_initialize = false;
    bool returned_game_app_initialize = false;
    bool reached_first_draw_frame = false;
    bool returned_first_draw_frame = false;
    bool host_gles_active = false;
    std::uint32_t draw_frames_completed = 0;
    std::uint32_t best_frame_number = 0;
    std::uint64_t best_frame_nonblack = 0;
    std::uint32_t last_nonblack_frame_number = 0;
    std::uint64_t last_nonblack_pixels = 0;
    bool adaptive_frame_stop = false;

    // v53: passive exact startup state-machine tracing. Unlike the aborted
    // pre-first-draw experiment, these fields are observational only.
    std::uint32_t game_state_manager = 0;
    std::int32_t game_state_current = -999;
    std::int32_t game_state_pending = -999;
    std::uint64_t game_state_request_calls = 0;
    std::uint64_t game_state_apply_calls = 0;

    // v54: passive StartupLogo.Update gate/depth summary. Detailed per-hit
    // values remain in the exported V54 STARTUPLOGO log lines.
    std::string startup_logo_summary;

    // v55: passive Gate-A resource-group vector / lookup / progress summary.
    std::string startup_resource_group_summary;

    // v56: multi-mode ResourceManager registry pipeline / scout summary.
    std::string diagnostic_matrix_summary;
    PvZ2DiagnosticMode diagnostic_mode =
        PvZ2DiagnosticMode::PassiveRegistry;
    bool gate_a_scout_activated = false;

    // v57: Bionic ctype compatibility + deep Scout summary.
    std::string ctype_deep_scout_summary;
    bool ctype_self_check_passed = false;
    bool gate_c_scout_activated = false;

    std::uint32_t return_value = 0;
    std::uint32_t game_app_initialize_address = 0;
    std::uint32_t game_app_initialize_return = 0;
    std::uint32_t unsupported_jni_slot = 0xffffffffu;
    std::uint32_t final_pc = 0;
    std::uint32_t halt_reason = 0;

    std::uint32_t imports_patched = 0;
    std::uint32_t supported_import_calls = 0;

    bool rsb_manifest_resolved = false;
    std::uint32_t rsb_resolved_files = 0;
    std::uint32_t resource_registry_lookup_calls = 0;
    std::uint32_t resource_registry_direct_hits = 0;
    std::uint32_t resource_registry_path_fallback_hits = 0;
    std::uint32_t resource_registry_misses = 0;
    std::uint32_t resource_path_index_entries = 0;
    std::uint64_t malloc_calls = 0;
    std::uint64_t free_calls = 0;
    std::uint64_t realloc_calls = 0;
    std::uint32_t heap_high_water = 0;
    std::uint32_t heap_live_bytes = 0;
    std::uint32_t heap_live_allocations = 0;

    std::uint32_t init_array_slots = 0;
    std::uint32_t constructors_total = 0;
    std::uint32_t constructors_completed = 0;
    std::uint32_t constructor_failure_index = 0xffffffffu;
    std::uint32_t constructor_failure_address = 0;
    std::uint32_t cxa_atexit_calls = 0;
    std::uint32_t lifecycle_calls_completed = 0;

    std::uint32_t sweep_issue_count = 0;
    std::uint32_t sweep_recovery_count = 0;
    bool sweep_speculative = false;

    std::uint32_t find_class_calls = 0;
    std::uint32_t register_natives_calls = 0;
    std::uint32_t registered_native_methods = 0;

    std::string first_unsupported_import;
    std::string game_app_initialize_signature;
    std::string lifecycle_failure_name;
    // v52 keeps the old field as the image selected for UI display, but also
    // exposes the diagnostic captures independently so a splash frame can no
    // longer masquerade as the final framebuffer.
    std::string host_frame_png_path;
    std::string best_frame_png_path;
    std::string last_nonblack_frame_png_path;
    std::string final_frame_png_path;
    std::string diagnostic_summary;
    std::string sweep_summary;
    std::string trace;
    std::string message;
};

PvZ2JniProbeResult RunPvZ2JniOnLoadProbe(
    const std::uint8_t* apk_data,
    std::size_t apk_size);


PvZ2JniProbeResult RunPvZ2FullLoadProbe(
    const std::uint8_t* apk_data,
    std::size_t apk_size,
    const std::uint8_t* obb_data,
    std::size_t obb_size,
    PvZ2ProbeProgress progress = {},
    PvZ2DiagnosticMode diagnostic_mode =
        PvZ2DiagnosticMode::PassiveRegistry);
