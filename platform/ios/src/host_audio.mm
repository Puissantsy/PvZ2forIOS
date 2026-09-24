#include "host_audio.hpp"

#import <AVFoundation/AVFoundation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

namespace {

constexpr std::uint32_t kMaxChannels = 2u;
constexpr std::uint32_t kRingFrames = 131072u;
constexpr std::uint32_t kBlockSlots = 512u;

std::array<std::int16_t,
           static_cast<std::size_t>(kRingFrames) *
               kMaxChannels>
    gPcmRing{};
std::array<std::atomic<std::uint64_t>, kBlockSlots>
    gBlockEndFrames{};

std::atomic<std::uint64_t> gWriteFrame{0u};
std::atomic<std::uint64_t> gReadFrame{0u};
std::atomic<std::uint64_t> gBlockHead{0u};
std::atomic<std::uint64_t> gBlockTail{0u};
std::atomic<std::uint32_t> gConsumedPending{0u};
std::atomic<std::uint64_t> gConsumedTotal{0u};
std::atomic<bool> gPlaying{false};
std::atomic<bool> gConfigured{false};
std::atomic<std::uint32_t> gChannels{0u};
std::atomic<std::uint32_t> gSampleRate{0u};
std::atomic<std::uint32_t> gSessionSampleRate{0u};
std::atomic<std::uint32_t> gSourceSampleRate{0u};
std::atomic<std::uint32_t> gMixerSampleRate{0u};

// v102: measure the real AVAudioSourceNode consumption clock. The render
// callback only touches atomics here; no logging, allocation, mutex or guest
// execution is allowed on the CoreAudio real-time thread.
std::atomic<std::uint64_t> gRenderCallbackCount{0u};
std::atomic<std::uint64_t> gRenderRequestedFrames{0u};
std::atomic<std::uint64_t> gRenderedPCMFrames{0u};
std::atomic<std::uint64_t> gUnderrunFrames{0u};
std::atomic<std::uint64_t> gUnderrunEvents{0u};

std::mutex gControlMutex;
std::string gLastError;
AVAudioEngine* gEngine = nil;
AVAudioSourceNode* gSource = nil;

void SetErrorLocked(
    const std::string& value) {
    gLastError = value;
}

std::string DescribeNSError(
    NSString* prefix,
    NSError* error) {
    NSString* message =
        error != nil
            ? error.localizedDescription
            : @"unknown error";
    NSString* full =
        [NSString
            stringWithFormat:
                @"%@: %@",
                prefix,
                message];
    const char* utf8 =
        full.UTF8String;
    return utf8 != nullptr
        ? std::string{utf8}
        : std::string{"AVAudioEngine error"};
}

void ResetQueueState() {
    gPlaying.store(
        false,
        std::memory_order_release);
    gWriteFrame.store(
        0u,
        std::memory_order_release);
    gReadFrame.store(
        0u,
        std::memory_order_release);
    gBlockHead.store(
        0u,
        std::memory_order_release);
    gBlockTail.store(
        0u,
        std::memory_order_release);
    gConsumedPending.store(
        0u,
        std::memory_order_release);
    gConsumedTotal.store(
        0u,
        std::memory_order_release);
    gRenderCallbackCount.store(
        0u,
        std::memory_order_release);
    gRenderRequestedFrames.store(
        0u,
        std::memory_order_release);
    gRenderedPCMFrames.store(
        0u,
        std::memory_order_release);
    gUnderrunFrames.store(
        0u,
        std::memory_order_release);
    gUnderrunEvents.store(
        0u,
        std::memory_order_release);
}

void StopLocked() {
    gPlaying.store(
        false,
        std::memory_order_release);
    gConfigured.store(
        false,
        std::memory_order_release);

    if (gEngine != nil) {
        [gEngine stop];
        if (gSource != nil) {
            [gEngine
                disconnectNodeOutput:
                    gSource];
            [gEngine
                detachNode:
                    gSource];
        }
    }

    gSource = nil;
    gEngine = nil;

    NSError* ignored = nil;
    [[AVAudioSession sharedInstance]
        setActive:NO
        withOptions:
            AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation
        error:&ignored];

    gChannels.store(
        0u,
        std::memory_order_release);
    gSampleRate.store(
        0u,
        std::memory_order_release);
    gSessionSampleRate.store(
        0u,
        std::memory_order_release);
    gSourceSampleRate.store(
        0u,
        std::memory_order_release);
    gMixerSampleRate.store(
        0u,
        std::memory_order_release);
    ResetQueueState();
}

OSStatus RenderAudio(
    std::uint32_t channels,
    BOOL* isSilence,
    AVAudioFrameCount frameCount,
    AudioBufferList* outputData) {

    if (outputData == nullptr) {
        return noErr;
    }

    for (UInt32 b = 0u;
         b < outputData->mNumberBuffers;
         ++b) {
        AudioBuffer& buffer =
            outputData->mBuffers[b];
        if (buffer.mData != nullptr &&
            buffer.mDataByteSize != 0u) {
            std::memset(
                buffer.mData,
                0,
                buffer.mDataByteSize);
        }
    }

    if (!gConfigured.load(
            std::memory_order_acquire) ||
        !gPlaying.load(
            std::memory_order_acquire) ||
        channels == 0u ||
        channels > kMaxChannels) {
        if (isSilence != nullptr) {
            *isSilence = YES;
        }
        return noErr;
    }

    gRenderCallbackCount.fetch_add(
        1u,
        std::memory_order_relaxed);
    gRenderRequestedFrames.fetch_add(
        static_cast<std::uint64_t>(frameCount),
        std::memory_order_relaxed);

    const std::uint64_t read =
        gReadFrame.load(
            std::memory_order_relaxed);
    const std::uint64_t write =
        gWriteFrame.load(
            std::memory_order_acquire);
    const std::uint64_t available =
        write >= read
            ? write - read
            : 0u;
    const std::uint32_t to_read =
        static_cast<std::uint32_t>(
            std::min<std::uint64_t>(
                available,
                frameCount));

    gRenderedPCMFrames.fetch_add(
        static_cast<std::uint64_t>(to_read),
        std::memory_order_relaxed);

    if (to_read < frameCount) {
        gUnderrunFrames.fetch_add(
            static_cast<std::uint64_t>(
                frameCount - to_read),
            std::memory_order_relaxed);
        gUnderrunEvents.fetch_add(
            1u,
            std::memory_order_relaxed);
    }

    if (to_read == 0u) {
        if (isSilence != nullptr) {
            *isSilence = YES;
        }
        return noErr;
    }

    const bool planar =
        outputData->mNumberBuffers >=
            channels;

    for (std::uint32_t frame = 0u;
         frame < to_read;
         ++frame) {
        const std::uint64_t absolute =
            read + frame;
        const std::size_t ring_base =
            static_cast<std::size_t>(
                absolute % kRingFrames) *
            kMaxChannels;

        for (std::uint32_t channel = 0u;
             channel < channels;
             ++channel) {
            const float sample =
                static_cast<float>(
                    gPcmRing[
                        ring_base +
                        channel]) /
                32768.0f;

            if (planar) {
                AudioBuffer& dst_buffer =
                    outputData
                        ->mBuffers[channel];
                if (dst_buffer.mData ==
                    nullptr) {
                    continue;
                }
                const std::size_t capacity =
                    dst_buffer
                        .mDataByteSize /
                    sizeof(float);
                if (frame < capacity) {
                    static_cast<float*>(
                        dst_buffer.mData)[
                            frame] =
                        sample;
                }
            } else if (
                outputData
                    ->mNumberBuffers != 0u) {
                AudioBuffer& dst_buffer =
                    outputData
                        ->mBuffers[0];
                if (dst_buffer.mData ==
                    nullptr) {
                    continue;
                }
                const std::size_t capacity =
                    dst_buffer
                        .mDataByteSize /
                    sizeof(float);
                const std::size_t index =
                    static_cast<std::size_t>(
                        frame) *
                        channels +
                    channel;
                if (index < capacity) {
                    static_cast<float*>(
                        dst_buffer.mData)[
                            index] =
                        sample;
                }
            }
        }
    }

    const std::uint64_t new_read =
        read + to_read;

    // Clear() is guest/control-thread driven while this render callback is
    // real-time. Never let an in-flight callback overwrite the newer read/tail
    // positions established by Clear(). A failed CAS means the queue epoch
    // changed underneath this render; its already-rendered samples are harmless
    // but it must not report stale completions.
    std::uint64_t expected_read =
        read;
    if (!gReadFrame.compare_exchange_strong(
            expected_read,
            new_read,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        if (isSilence != nullptr) {
            *isSilence = NO;
        }
        return noErr;
    }

    const std::uint64_t tail =
        gBlockTail.load(
            std::memory_order_acquire);
    const std::uint64_t head =
        gBlockHead.load(
            std::memory_order_acquire);
    std::uint64_t new_tail =
        tail;
    std::uint32_t completed = 0u;

    while (new_tail < head &&
           gBlockEndFrames[
               static_cast<std::size_t>(
                   new_tail % kBlockSlots)]
               .load(
                   std::memory_order_acquire) <=
               new_read) {
        ++new_tail;
        ++completed;
    }

    if (completed != 0u) {
        std::uint64_t expected_tail =
            tail;
        if (gBlockTail.compare_exchange_strong(
                expected_tail,
                new_tail,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            gConsumedPending.fetch_add(
                completed,
                std::memory_order_acq_rel);
            gConsumedTotal.fetch_add(
                completed,
                std::memory_order_acq_rel);
        }
    }

    if (isSilence != nullptr) {
        *isSilence = NO;
    }
    return noErr;
}

} // namespace

bool PvZ2HostAudioConfigure(
    std::uint32_t sample_rate,
    std::uint32_t channels) {

    std::lock_guard<std::mutex> lock(
        gControlMutex);

    StopLocked();
    SetErrorLocked({});

    if (sample_rate == 0u ||
        channels == 0u ||
        channels > kMaxChannels) {
        SetErrorLocked(
            "invalid PCM format");
        return false;
    }

    AVAudioSession* session =
        [AVAudioSession sharedInstance];
    NSError* error = nil;

    if (![session
            setCategory:
                AVAudioSessionCategoryPlayback
            mode:
                AVAudioSessionModeDefault
            options:0
            error:&error]) {
        SetErrorLocked(
            DescribeNSError(
                @"AVAudioSession setCategory",
                error));
        return false;
    }

    error = nil;
    [session
        setPreferredSampleRate:
            static_cast<double>(
                sample_rate)
        error:&error];

    error = nil;
    [session
        setPreferredIOBufferDuration:
            1024.0 /
            static_cast<double>(
                sample_rate)
        error:&error];

    error = nil;
    if (![session
            setActive:YES
            error:&error]) {
        SetErrorLocked(
            DescribeNSError(
                @"AVAudioSession setActive",
                error));
        return false;
    }

    const std::uint32_t render_channels =
        channels;

    AVAudioFormat* format =
        [[AVAudioFormat alloc]
            initWithCommonFormat:
                AVAudioPCMFormatFloat32
            sampleRate:
                static_cast<double>(
                    sample_rate)
            channels:
                static_cast<AVAudioChannelCount>(
                    channels)
            interleaved:NO];

    if (format == nil) {
        SetErrorLocked(
            "unable to create AVAudioFormat");
        StopLocked();
        return false;
    }

    AVAudioSourceNodeRenderBlock render_block =
        ^OSStatus(
            BOOL* isSilence,
            const AudioTimeStamp*,
            AVAudioFrameCount frameCount,
            AudioBufferList* outputData) {
            return RenderAudio(
                render_channels,
                isSilence,
                frameCount,
                outputData);
        };

    gEngine =
        [[AVAudioEngine alloc] init];
    gSource =
        [[AVAudioSourceNode alloc]
            initWithFormat:
                format
            renderBlock:
                render_block];

    if (gEngine == nil ||
        gSource == nil) {
        SetErrorLocked(
            "unable to create AVAudioEngine/AVAudioSourceNode");
        StopLocked();
        return false;
    }

    [gEngine
        attachNode:
            gSource];
    [gEngine
        connect:
            gSource
        to:
            gEngine.mainMixerNode
        format:
            format];
    [gEngine prepare];

    error = nil;
    if (![gEngine
            startAndReturnError:
                &error]) {
        SetErrorLocked(
            DescribeNSError(
                @"AVAudioEngine start",
                error));
        StopLocked();
        return false;
    }

    const double session_rate =
        session.sampleRate;
    const double source_rate =
        [gSource
            outputFormatForBus:0]
            .sampleRate;
    const double mixer_rate =
        [gEngine.mainMixerNode
            outputFormatForBus:0]
            .sampleRate;

    auto rounded_rate =
        [](double value) -> std::uint32_t {
            return value > 0.0
                ? static_cast<std::uint32_t>(
                      value + 0.5)
                : 0u;
        };

    ResetQueueState();
    gChannels.store(
        channels,
        std::memory_order_release);
    gSampleRate.store(
        sample_rate,
        std::memory_order_release);
    gSessionSampleRate.store(
        rounded_rate(session_rate),
        std::memory_order_release);
    gSourceSampleRate.store(
        rounded_rate(source_rate),
        std::memory_order_release);
    gMixerSampleRate.store(
        rounded_rate(mixer_rate),
        std::memory_order_release);
    gConfigured.store(
        true,
        std::memory_order_release);
    return true;
}

void PvZ2HostAudioShutdown() {
    std::lock_guard<std::mutex> lock(
        gControlMutex);
    StopLocked();
}

void PvZ2HostAudioSetPlaying(
    bool playing) {
    gPlaying.store(
        playing &&
            gConfigured.load(
                std::memory_order_acquire),
        std::memory_order_release);
}

bool PvZ2HostAudioEnqueuePCM16(
    const void* data,
    std::size_t bytes) {

    if (data == nullptr ||
        bytes == 0u ||
        !gConfigured.load(
            std::memory_order_acquire)) {
        return false;
    }

    const std::uint32_t channels =
        gChannels.load(
            std::memory_order_acquire);
    if (channels == 0u ||
        channels > kMaxChannels) {
        return false;
    }

    const std::size_t frame_bytes =
        static_cast<std::size_t>(
            channels) *
        sizeof(std::int16_t);

    if (frame_bytes == 0u ||
        (bytes % frame_bytes) != 0u) {
        return false;
    }

    const std::uint64_t frames =
        bytes /
        frame_bytes;

    if (frames == 0u ||
        frames > kRingFrames) {
        return false;
    }

    const std::uint64_t write =
        gWriteFrame.load(
            std::memory_order_relaxed);
    const std::uint64_t read =
        gReadFrame.load(
            std::memory_order_acquire);

    if (write < read ||
        frames >
            static_cast<std::uint64_t>(
                kRingFrames) -
                (write - read)) {
        return false;
    }

    const std::uint64_t head =
        gBlockHead.load(
            std::memory_order_relaxed);
    const std::uint64_t tail =
        gBlockTail.load(
            std::memory_order_acquire);

    if (head < tail ||
        head - tail >=
            kBlockSlots) {
        return false;
    }

    const auto* src =
        static_cast<const std::uint8_t*>(
            data);

    for (std::uint64_t frame = 0u;
         frame < frames;
         ++frame) {
        const std::size_t ring_base =
            static_cast<std::size_t>(
                (write + frame) %
                kRingFrames) *
            kMaxChannels;

        for (std::uint32_t channel = 0u;
             channel < channels;
             ++channel) {
            std::int16_t sample = 0;
            std::memcpy(
                &sample,
                src +
                    (static_cast<std::size_t>(
                         frame) *
                         channels +
                     channel) *
                        sizeof(
                            std::int16_t),
                sizeof(sample));
            gPcmRing[
                ring_base +
                channel] =
                sample;
        }

        for (std::uint32_t channel =
                 channels;
             channel < kMaxChannels;
             ++channel) {
            gPcmRing[
                ring_base +
                channel] =
                0;
        }
    }

    gBlockEndFrames[
        static_cast<std::size_t>(
            head %
            kBlockSlots)]
        .store(
            write + frames,
            std::memory_order_release);

    gBlockHead.store(
        head + 1u,
        std::memory_order_release);
    gWriteFrame.store(
        write + frames,
        std::memory_order_release);
    return true;
}

void PvZ2HostAudioClear() {
    const std::uint64_t write =
        gWriteFrame.load(
            std::memory_order_acquire);
    const std::uint64_t head =
        gBlockHead.load(
            std::memory_order_acquire);

    gReadFrame.store(
        write,
        std::memory_order_release);
    gBlockTail.store(
        head,
        std::memory_order_release);
    gConsumedPending.store(
        0u,
        std::memory_order_release);
}

std::uint32_t
PvZ2HostAudioQueuedBufferCount() {
    const std::uint64_t head =
        gBlockHead.load(
            std::memory_order_acquire);
    const std::uint64_t tail =
        gBlockTail.load(
            std::memory_order_acquire);
    const std::uint64_t queued =
        head >= tail
            ? head - tail
            : 0u;

    return static_cast<std::uint32_t>(
        std::min<std::uint64_t>(
            queued,
            0xffffffffull));
}

std::uint32_t
PvZ2HostAudioTakeConsumedBufferCount() {
    return
        gConsumedPending.exchange(
            0u,
            std::memory_order_acq_rel);
}

std::uint64_t
PvZ2HostAudioConsumedBufferTotal() {
    return
        gConsumedTotal.load(
            std::memory_order_acquire);
}

std::uint32_t
PvZ2HostAudioRingCapacityFrames() {
    return kRingFrames;
}

std::uint32_t
PvZ2HostAudioRequestedSampleRate() {
    return gSampleRate.load(
        std::memory_order_acquire);
}

std::uint32_t
PvZ2HostAudioSessionSampleRate() {
    return gSessionSampleRate.load(
        std::memory_order_acquire);
}

std::uint32_t
PvZ2HostAudioSourceSampleRate() {
    return gSourceSampleRate.load(
        std::memory_order_acquire);
}

std::uint32_t
PvZ2HostAudioMixerSampleRate() {
    return gMixerSampleRate.load(
        std::memory_order_acquire);
}

std::uint64_t
PvZ2HostAudioRenderCallbackCount() {
    return gRenderCallbackCount.load(
        std::memory_order_acquire);
}

std::uint64_t
PvZ2HostAudioRenderRequestedFrames() {
    return gRenderRequestedFrames.load(
        std::memory_order_acquire);
}

std::uint64_t
PvZ2HostAudioRenderedPCMFrames() {
    return gRenderedPCMFrames.load(
        std::memory_order_acquire);
}

std::uint64_t
PvZ2HostAudioUnderrunFrames() {
    return gUnderrunFrames.load(
        std::memory_order_acquire);
}

std::uint64_t
PvZ2HostAudioUnderrunEvents() {
    return gUnderrunEvents.load(
        std::memory_order_acquire);
}

const char* PvZ2HostAudioLastError() {
    thread_local std::string copy;
    {
        std::lock_guard<std::mutex> lock(
            gControlMutex);
        copy = gLastError;
    }
    return copy.c_str();
}
