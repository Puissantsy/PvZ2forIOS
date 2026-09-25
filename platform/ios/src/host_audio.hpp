#pragma once

#include <cstddef>
#include <cstdint>

// v99 host audio backend. The guest/Wwise side remains PCM16 interleaved.
// AVAudioEngine consumes a bounded lock-free frame ring on its real-time
// render thread. No guest/Dynarmic callback is ever invoked from that thread.
bool PvZ2HostAudioConfigure(
    std::uint32_t sample_rate,
    std::uint32_t channels);
void PvZ2HostAudioShutdown();
void PvZ2HostAudioSetPlaying(bool playing);
bool PvZ2HostAudioEnqueuePCM16(
    const void* data,
    std::size_t bytes);
void PvZ2HostAudioClear();

std::uint32_t PvZ2HostAudioQueuedBufferCount();
std::uint32_t PvZ2HostAudioTakeConsumedBufferCount();
std::uint64_t PvZ2HostAudioConsumedBufferTotal();
std::uint32_t PvZ2HostAudioRingCapacityFrames();
std::uint32_t PvZ2HostAudioRequestedSampleRate();
std::uint32_t PvZ2HostAudioSessionSampleRate();
std::uint32_t PvZ2HostAudioSourceSampleRate();
std::uint32_t PvZ2HostAudioMixerSampleRate();

// v102 real-time clock telemetry. These counters are produced only by the
// AVAudioSourceNode render thread and are safe to sample from the guest
// scheduler. They let us distinguish a host clock problem from guest/Wwise
// starvation without ever entering Dynarmic from CoreAudio.
std::uint64_t PvZ2HostAudioRenderCallbackCount();
std::uint64_t PvZ2HostAudioRenderRequestedFrames();
std::uint64_t PvZ2HostAudioRenderedPCMFrames();
std::uint64_t PvZ2HostAudioUnderrunFrames();
std::uint64_t PvZ2HostAudioUnderrunEvents();

// v121 host-only diagnostic snapshot. These counters never affect queue,
// callback or scheduler behavior. The CoreAudio render path updates atomics;
// the guest scheduler only stores the current frame tag once per frame.
struct PvZ2HostAudioDiagnostics {
    std::uint64_t render_callbacks = 0u;
    std::uint64_t requested_frames = 0u;
    std::uint64_t rendered_frames = 0u;
    std::uint64_t underrun_events = 0u;
    std::uint64_t underrun_frames = 0u;
    std::uint64_t empty_underruns = 0u;
    std::uint64_t partial_underruns = 0u;
    std::uint64_t first_underrun_guest_frame = 0u;
    std::uint64_t last_underrun_guest_frame = 0u;
    std::uint64_t low_water_events = 0u;
    std::uint64_t min_available_frames = 0u;
    std::uint64_t max_available_frames = 0u;
    std::uint64_t min_queued_blocks = 0u;
    std::uint64_t max_queued_blocks = 0u;
    std::uint64_t max_completed_blocks_per_render = 0u;
    std::uint64_t read_wraps = 0u;
    std::uint64_t enqueue_wraps = 0u;
    std::uint64_t read_cas_conflicts = 0u;
    std::uint64_t enqueue_calls = 0u;
    std::uint64_t enqueue_frames = 0u;
    std::uint64_t enqueue_reject_ring_full = 0u;
    std::uint64_t enqueue_reject_block_full = 0u;
    std::uint64_t boundary_checks = 0u;
    std::uint64_t boundary_jump_gt_4096 = 0u;
    std::uint64_t boundary_jump_gt_8192 = 0u;
    std::uint64_t boundary_jump_gt_16384 = 0u;
    std::uint64_t max_boundary_jump = 0u;
    std::uint64_t max_boundary_jump_guest_frame = 0u;
    std::uint64_t repeated_sparse_blocks = 0u;
    std::uint64_t max_sparse_repeat_run = 0u;
    std::uint64_t first_sparse_repeat_guest_frame = 0u;
    std::uint64_t last_sparse_repeat_guest_frame = 0u;
    std::uint64_t non_silent_repeated_sparse_blocks = 0u;
    std::uint64_t max_non_silent_repeat_run = 0u;
    std::uint64_t first_non_silent_repeat_guest_frame = 0u;
    std::uint64_t last_non_silent_repeat_guest_frame = 0u;
    std::uint64_t animation_window_non_silent_repeats = 0u;
    std::uint64_t animation_window_first_repeat_frame = 0u;
    std::uint64_t animation_window_last_repeat_frame = 0u;
    std::uint64_t late_window_non_silent_repeats = 0u;
    std::uint64_t late_window_first_repeat_frame = 0u;
    std::uint64_t late_window_last_repeat_frame = 0u;
    std::uint64_t animation_window_jump_gt_8192 = 0u;
    std::uint64_t late_window_jump_gt_8192 = 0u;
};

void PvZ2HostAudioResetDiagnostics();
void PvZ2HostAudioSetDiagnosticGuestFrame(std::uint32_t frame);
PvZ2HostAudioDiagnostics PvZ2HostAudioDiagnosticSnapshot();

const char* PvZ2HostAudioLastError();
