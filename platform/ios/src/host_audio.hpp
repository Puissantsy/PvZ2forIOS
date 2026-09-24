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
const char* PvZ2HostAudioLastError();
