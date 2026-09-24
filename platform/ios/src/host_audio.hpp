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

const char* PvZ2HostAudioLastError();
