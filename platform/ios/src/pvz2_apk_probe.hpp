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

// v72 live-display callback. rgba points to a top-left-oriented, opaque RGBA8
// copy of the host default framebuffer and is valid only for the callback.
using PvZ2LiveFrameCallback =
    std::function<void(
        std::uint32_t frame,
        std::uint32_t width,
        std::uint32_t height,
        const std::uint8_t* rgba,
        std::size_t rgba_size)>;

// UIKit owns input collection on the main thread while the guest runs on the
// probe worker queue. These functions are intentionally narrow so the C++
// runtime does not depend on UIKit types.
void PvZ2ResetInteractiveInput();
void PvZ2QueueTouchEvent(
    std::uint32_t pointer_id,
    std::int32_t x,
    std::int32_t y,
    std::int32_t previous_x,
    std::int32_t previous_y,
    std::uint32_t phase,
    double timestamp_ms);

// v73: exact Android UITextInputEvent path. action=0 mirrors commitText,
// action=3 mirrors deleteSurroundingText. The bytes are UTF-8 and copied
// synchronously into the host event queue.
// v110: exact Android UIPinchEvent type=3 bridge.
void PvZ2QueuePinchEvent(
    std::int32_t x,
    std::int32_t y,
    float scale_dist_sq,
    float scale_delta);

void PvZ2QueueTextInputEvent(
    std::uint32_t action,
    const std::uint8_t* utf8,
    std::size_t utf8_size);

// Implemented by the UIKit host in main.mm. The guest thread uses these only
// for Android Device_ShowKeyboard/HideKeyboard/IsKeyboardShowing.
void PvZ2HostSetKeyboardVisible(bool visible);
bool PvZ2HostKeyboardVisible();
bool PvZ2HostKeyboardFirstResponder();

// v90: lightweight notification after direct GPU presentation. No framebuffer
// pixels cross this boundary.
void PvZ2HostNotifyDirectFrame(
    std::uint32_t frame,
    std::uint32_t width,
    std::uint32_t height);

void PvZ2RequestInteractiveStop();

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

    // v64: preserves v63 ownership tracking, but once a worker quantum expires
    // inside a guest critical section it stops at the first subsequent
    // held-mutex transition to zero instead of sampling only at whole quanta.
    V64ReleaseBoundaryScheduler = 8u,

    // v65: preserves v64 and adds scheduler-visible pthread condition-variable
    // semantics for deferred workers: cond_wait atomically releases its mutex,
    // sleeps the worker, and resumes only after signal/broadcast/timeout plus
    // successful mutex reacquisition.
    V65ConditionVariableScheduler = 9u,

    // v66: preserves v65 and models the other blocking primitives reached by
    // permanent Wwise workers. Empty sem_wait/sem_timedwait sleep until post
    // (or timeout), while usleep/nanosleep suspend the worker until a host
    // steady-clock deadline instead of becoming hot CPU loops.
    V66BlockingWaitScheduler = 10u,

    // v67: preserves v66 and traces the resource-stream completion-token
    // family. Counter increment/decrement stores are observed with caller and
    // allocation provenance; no readiness result or counter is forced.
    V67CompletionTokenProvenance = 11u,

    // v68: preserves the validated v66 scheduler, but uses the v67 result to
    // correct the watchdog semantics. The shared token vfnC reports
    // counter > 0 (busy), so counter==0 is an idle/available state rather than
    // intrinsic evidence of a stalled TaskResource. The v67 store traps are
    // intentionally not inherited so the hot worker path runs at normal speed.
    V68CompletionTokenSemantics = 12u,

    // v69: Inspector v2.1 + Android/iOS static correlation isolate the remaining
    // post-LogoScreen loop to the TaskResource lifecycle. Observe the whole
    // active -> started -> completed -> finalized chain in one bounded probe.
    V69TaskResourceLifecycle = 13u,

    // v70: v69 proves TaskResource itself drains correctly. The remaining
    // recycled Task-A jobs are the ResStreams inflate path. Keep host z_stream
    // objects at a stable address for their entire initialized lifetime instead
    // of copying them after inflateInit_/deflateInit_.
    V70ZlibStreamOwnership = 14u,

    // v71: the Android PTX RGB plane is ETC1 (GL_ETC1_RGB8_OES). iOS GLES2
    // rejects that Android-only compressed upload, so decode ETC1 to host RGB8
    // while preserving PvZ2's separate alpha texture and shader path.
    V71Etc1TextureBridge = 15u,

    // v72: first-frame + 600-frame stability are proven. Keep v71 rendering
    // and bridge real UIKit touches into AndroidUIEventManager::ProcessEvents
    // while streaming the live host framebuffer back to UIKit.
    V72LiveTouchBridge = 16u,

    // v73: v72 proves touch delivery end-to-end. Bridge the Android keyboard
    // surface to a host UITextField, serialize UITextInputEvent type 6 exactly
    // as classes.dex does, and make the live presentation edge-to-edge.
    V73KeyboardFullscreenBridge = 17u,

    // v74: the v73 iPad run proves keyboard text is lossless (10/10) but also
    // exposes three host-presentation issues: the final FBO is still 1180x820
    // despite a 2360x1640 Retina screen, a transient startup Show/Hide pair can
    // flash UIKit's keyboard, and text can be presented one sampling interval
    // after the guest consumes it. Keep guest behavior intact while fixing the
    // host surface/presentation bridge.
    V74RetinaInputPolish = 18u,

    // v75: v74 proves the host Retina surface is correct, while Inspector v2.2
    // shows the guest still selects RESFILE_PACKAGES_UI_ANDROID. The historical
    // iOS 1.5 binary selects UI_IPAD. Keep every v74 scheduler/render/input
    // behavior and change only this one package-selection literal for a clean
    // causal A/B test of the oversized/cropped UI.
    V75IpadUiPackage = 19u,

    // v76: preserve v75, but replace the synthetic Android GL-view-scale
    // contract with the behavior statically confirmed in the historical
    // iOS 1.5 binary. EAGLView responds to contentScaleFactor, Get returns
    // that property, Set writes it, and the renderer then sizes its backing
    // store from the drawable. The host FBO is resized in-place to keep the
    // same framebuffer identity while matching the guest-requested scale.
    V76IosScaleContract = 20u,

    // v77: v76 proved that exposing the iOS scale setter to the Android guest
    // activates Android-specific scaling math (2.000666 on the iPad 10th gen)
    // and produces a 2361x1641 host surface. Return to the stable v75 scale
    // contract and instead emulate the historical iPad 1.5 geometry exactly:
    // 1024x768 points / 2048x1536 Retina pixels, presented aspect-fit by UIKit.
    V77LegacyIpadGeometry = 21u,

    // v80: preserve the validated v77 historical iPad geometry and all
    // v71-v79 bridges/probes, but instrument the common GLES transform chain.
    // screenMatrix uploads plus sampled position bounds show where the same
    // oversize/crop seen on EA, the PvZ2 title/loading screen and Profile is
    // introduced. Keyboard tracing separately distinguishes guest requests
    // from the real UIKit first-responder state. Observation only.
    V80GlobalTransformProbe = 22u,

    // v81: preserve the complete v80 transform/profile/keyboard probe and add
    // a causal input-space A/B. V80 remains the pixel-coordinate control.
    // V81 maps the same presented touches into the historical iPad logical
    // 1024x768 space while logging both pixel and point candidates. The v39
    // Native_onSurfaceChanged height,width ABI fix is intentionally untouched.
    V81HitTestLogicalPoints = 23u,

    // v82: keep the v81 logical-touch experiment and add an observation-only
    // Profile widget/action radar. Candidate button objects are named by the
    // constructor IDs seen statically (5/6/7) until runtime proves semantics.
    // No rendering, widget, touch or GameState value is forced.
    V82ProfileLayoutRadar = 24u,

    // v83: reuse the v82 Profile radar but return touch delivery to the v80
    // 2048x1536 pixel control. Trace the verified Profile button dispatcher
    // switch so a hidden button can be identified by its real runtime ID.
    V83ProfileButtonDispatch = 25u,

    // v84: isolate the global render-contract fault in one IPA.
    V84FinalBlitTrace = 26u,

    // AndroidSurfaceView.GetScreenSizeInPoints uses the actual view dimensions
    // (the APK overrides DisplayMetrics density with 1.0 in this method).
    V84PointsEqualPixels = 27u,

    // Original APK AndroidSurfaceView contract: CanSet=true, scale field starts
    // at 0.5, Get/Set are simple field access and Set never resizes the FBO.
    V84AndroidGraphicsContract = 28u,

    // v85: performance baseline. Preserve the validated functional ladder
    // (VFS/OBB, scheduler, zlib, ETC1, GLES, iPad UI, touch, keyboard,
    // USERFS and the v84 Points=Pixels fix) while disabling the historical
    // transform/profile/startup hot-path diagnostics. Only lightweight
    // wall-clock performance/input timing remains enabled.
    V85PerformanceBaseline = 29u,

    // v86: keep the v85 measurements/functional bridges, but raise only the
    // full-load guest heap to 128 MiB after the real iPad reached 67,104,288
    // bytes high-water in a 64 MiB arena immediately before the post-PLAYER
    // __aeabi_memset OOB stop. Also hard-disable residual hot scheduler logs.
    V86HeapPerformanceFix = 30u,

    // v87: replace the v63/v64 "run mutex owners until release" workaround
    // with cooperative preemption plus real blocking mutex waiters. This mode
    // deliberately keeps the v86 heap/render/input/resource baseline intact.
    V87PreemptiveMutexScheduler = 31u,

    // v88: keep v87's real blocking mutex semantics, but replace one-quantum
    // over-preemption during concrete startup waits with a bounded adaptive
    // critical-section burst. Also retain lightweight wall-clock startup phase
    // markers so the next iPad log identifies where startup time is spent.
    V88AdaptiveMutexStartup = 32u,

    // v89 remains selectable as the heavy provenance control.
    V89PerformanceProfiler = 33u,

    // v90 keeps the v88 scheduler/128 MiB heap/functional bridges, presents
    // every completed guest frame directly on-GPU, and adds low-overhead
    // deterministic performance probes without inheriting v89's BLX/HOTPC
    // hot-path instrumentation.
    V90DirectPresentationProfiler = 34u,

    // v91: preserve v90 direct-GPU/runtime behavior, replace only the
    // pathological linear guest-heap first-fit scan with an address-indexed
    // equivalent first-fit, and emulate ELF GNU_RELRO protection for resolved
    // import/GOT state with bounded corruption provenance.
    V91IndexedAllocatorRelro = 35u,

    // v92: inherit the complete validated v91 runtime, but remove the legacy
    // 600-frame probe ceiling so the game can remain interactively alive until
    // the user requests Hard Stop or a real guest/runtime failure occurs.
    V92LongRunInteractive = 36u,

    // v93: inherit the complete v92 long-run runtime and add non-invasive
    // provenance around the exact free/delete return path implicated by the
    // recurrent 0x1086fcea Thumb-state crash. No guest recovery is applied.
    V93ReturnProvenance = 37u,

    // v94: v93 proved FreeHeap and the inner delete frame are clean. Track
    // the immediately outer frame (0x10868978), whose saved LR is expected
    // to be 0x1086f1fc but is observed as 0x1086f203 at the fatal POP.
    // Observation only: no stack repair or guest-code patch is applied.
    V94CallerReturnWatch = 38u,

    // v95: restore capability-driven runtime inheritance and replace v94's
    // inferred memory-callback watch with exact PUSH/POP provenance traps.
    V95PreciseCallerReturnWatch = 39u,

    // v96: preserve the v95 provenance watcher and give lifecycle tid=0
    // real cooperative sem/cond/sleep blocking semantics.
    V96MainThreadBlocking = 40u,

    // v97: treat a handed-off/granted V87 mutex wait as runnable ownership,
    // not as a live edge in the wait-for graph.
    V97GrantedMutexWaitGraph = 41u,

    // v98: preserve the final composited framebuffer RGB verbatim during
    // host presentation instead of unpremultiplying it by framebuffer alpha.
    V98PresentationRgbFidelity = 42u,

    // v99: keep the complete playable v98 runtime and replace the deliberate
    // OpenSL ES failure shim with the narrow object/interface surface used by
    // Wwise CAkSinkOpenSL. Mixed PCM is bridged to AVAudioEngine and completed
    // buffer callbacks are delivered only at scheduler-safe guest boundaries.
    V99AudioOpenSLBridge = 43u,

    // v100: v99 proved the complete host audio path through PCM enqueue, but
    // the first OpenSL callback was accidentally entered through the JNI ABI
    // helper (r0=JNIEnv*, shifting BufferQueue/context by one register). Keep
    // the same scheduler-safe delivery point and use the raw ARM C callback ABI.
    V100OpenSLCallbackABI = 44u,

    // v101: pin AVAudioSourceNode itself to Wwise's PCM sample clock instead of
    // relying on graph negotiation, and expose requested/session/source/mixer
    // rates so any remaining pitch/time mismatch is directly observable.
    V101AudioClockContract = 45u,

    // v102: decouple OpenSL buffer-complete delivery from rendered-frame
    // boundaries. CoreAudio remains the real-time clock and only publishes
    // atomic completion counters; the guest callback is injected from safe
    // Dynarmic scheduler checkpoints using a dedicated guest stack/thread id.
    V102AudioRealtimePump = 46u,

    // v103: preserve v102's CoreAudio-driven completion pump, but permit
    // asynchronous guest callback injection only while Native_onDrawFrame is
    // active. Startup/surface lifecycles retain the validated v101 scheduling.
    V103AudioDrawFramePump = 47u,

    // v104: after each CoreAudio/OpenSL completion, schedule the actual Wwise
    // CAkAudioThread worker before allowing another completion callback. This
    // restores the producer/consumer handshake instead of only pumping the sink.
    V104AudioWorkerHandshake = 48u,

    // v105: observational Wwise resampler probe. Preserve the complete v104
    // audio/runtime behavior while tracing source/target sample rates, base
    // ratio, pitch fixed-point steps and source/sound IDs at low-frequency
    // CAkResampler lifecycle points (Init, SetPitch and SwitchTo).
    V105WwiseResamplerProbe = 49u,

    // v106: restore the Android OpenSL output-rate contract (24/32/48 kHz)
    // instead of falsely advertising only 48 kHz, and prioritize/trace the
    // real CAkBankMgr worker during synchronous UnloadBank semaphore waits.
    V106AudioRateBankWait = 50u,

    // v107: repair lost cooperative semaphore wakeups by reconciling the
    // authoritative wait map with its FIFO index, enforce one live blocking
    // primitive per executing worker, and trace the exact BankMgr wake pair.
    V107SemaphoreWakeRepair = 51u,

    // v108: trace the real asynchronous SoundBank teardown chain and keep
    // CAkAudioThread progressing if a synchronous UnloadBank wait drains the
    // synthetic OpenSL ring before CAkUsageSlot can release its final refs.
    V108BankCompletionLiveness = 52u,

    // v109: production-like performance pass. Keep every functional v108
    // audio/bank fix, but remove the now-proven v105 resampler SVC observer
    // from the hot Wwise path and suppress per-frame lifecycle trace spam.
    V109LeanAudioPerformance = 53u,

    // v110 preserves v109 runtime; only input/profiling/UI package selection
    // change between the two A/B arms.
    V110AudioPinchUiAndroid = 54u,
    V110AudioPinchUiIpad = 55u,

    // v111: observational-only sampled-PC profiler for CAkAudioThread. The
    // validated v110 runtime, pinch bridge, Android UI control and scheduler
    // semantics remain unchanged.
    V111AudioSamplingProfiler = 56u,

    // v112: natural import-boundary profiler. No periodic guest halt is
    // injected; timing is collected only around import SVCs already executed
    // by CAkAudioThread and around the existing jit.Run worker spans.
    V112AudioBoundaryProfiler = 57u,

    // v113: first performance optimization after v112 isolated the cost in
    // guest Wwise execution. Enable Dynarmic's direct page-table path only
    // for the stable guest heap after startup/at the first real frame.
    V113DynarmicHeapPageTable = 58u,

    // v114: observational main-thread profiler layered on top of the validated
    // v113 heap page-table optimization. It uses only natural import/SVC and
    // existing jit.Run boundaries while Native_onDrawFrame is executing.
    V114MainBoundaryProfiler = 59u,

    // v115: keep v114 telemetry and the v113 heap direct mapping, then map
    // the first 255/256 pages of the 1 MiB main guest stack directly through
    // Dynarmic. The final 4 KiB page stays callback-backed so the validated
    // v94/v95 LR-slot provenance/watch path remains observable.
    V115DynarmicMainStackPageTable = 60u,

    // v116: keep the validated v115 heap/main-stack mappings and additionally
    // direct-map only complete pages of libPVZ2.so's non-writable RX PT_LOAD.
    // The partial tail page plus the complete writable PT_LOAD/GOT/RELRO stay
    // callback-backed.
    V116DynarmicReadOnlyImagePageTable = 61u,
};

enum class PvZ2ProbeCapability : std::uint64_t {
    None = 0u,
    LivePresentation = 1ull << 0,
    CpuLiveFrame = 1ull << 1,
    TransformProbe = 1ull << 2,
    HitTestTrace = 1ull << 3,
    LogicalTouch = 1ull << 4,
    ProfileProbe = 1ull << 5,
    PerformanceBaseline = 1ull << 6,
    Heap128 = 1ull << 7,
    PreemptiveMutex = 1ull << 8,
    AdaptiveMutex = 1ull << 9,
    HeavyPerformanceProfiler = 1ull << 10,
    HostCostProfiler = 1ull << 11,
    DirectPresentation = 1ull << 12,
    IndexedAllocatorRelro = 1ull << 13,
    LongRunInteractive = 1ull << 14,
    ReturnProvenance = 1ull << 15,
    CallerReturnWatch = 1ull << 16,
    AllocatorProfiling = 1ull << 17,
    PreciseCallerReturnWatch = 1ull << 18,
    MainThreadBlocking = 1ull << 19,
    GrantedMutexWaitGraph = 1ull << 20,
    PresentationRgbFidelity = 1ull << 21,
    AudioOpenSLBridge = 1ull << 22,
    RawGuestCallbackABI = 1ull << 23,
    AudioClockContract = 1ull << 24,
    AudioRealtimePump = 1ull << 25,
    AudioDrawFramePump = 1ull << 26,
    AudioWorkerHandshake = 1ull << 27,
    WwiseResamplerProbe = 1ull << 28,
    AudioRateBankWait = 1ull << 29,
    SemaphoreWakeRepair = 1ull << 30,
    BankCompletionLiveness = 1ull << 31,
    LeanAudioPerformance = 1ull << 32,
};

struct PvZ2DiagnosticModeDescriptor {
    PvZ2DiagnosticMode mode;
    const char* internal_name;
    const char* ui_name;
    std::uint64_t capabilities;
    bool selectable;
};

const PvZ2DiagnosticModeDescriptor*
PvZ2DescribeDiagnosticMode(PvZ2DiagnosticMode mode);

bool PvZ2DiagnosticModeHasCapability(
    PvZ2DiagnosticMode mode,
    PvZ2ProbeCapability capability);

std::size_t PvZ2SelectableDiagnosticModeCount();

const PvZ2DiagnosticModeDescriptor*
PvZ2SelectableDiagnosticModeAt(std::size_t index);

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
    bool hard_stop_requested = false;

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
        PvZ2DiagnosticMode::PassiveRegistry,
    PvZ2LiveFrameCallback live_frame = {});
