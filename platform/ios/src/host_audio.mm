#include "host_audio.hpp"

#import <AVFoundation/AVFoundation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <limits>
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

// v121 diagnostic-only atomics. They are deliberately independent from the
// functional v102 counters above so frame-1 reset cannot change audio state.
std::atomic<std::uint64_t> gDiagGuestFrame{0u};
std::atomic<std::uint64_t> gDiagRenderCallbacks{0u};
std::atomic<std::uint64_t> gDiagRequestedFrames{0u};
std::atomic<std::uint64_t> gDiagRenderedFrames{0u};
std::atomic<std::uint64_t> gDiagUnderrunEvents{0u};
std::atomic<std::uint64_t> gDiagUnderrunFrames{0u};
std::atomic<std::uint64_t> gDiagEmptyUnderruns{0u};
std::atomic<std::uint64_t> gDiagPartialUnderruns{0u};
std::atomic<std::uint64_t> gDiagFirstUnderrunGuestFrame{0u};
std::atomic<std::uint64_t> gDiagLastUnderrunGuestFrame{0u};
std::atomic<std::uint64_t> gDiagLowWaterEvents{0u};
std::atomic<std::uint64_t> gDiagMinAvailableFrames{
    std::numeric_limits<std::uint64_t>::max()};
std::atomic<std::uint64_t> gDiagMaxAvailableFrames{0u};
std::atomic<std::uint64_t> gDiagMinQueuedBlocks{
    std::numeric_limits<std::uint64_t>::max()};
std::atomic<std::uint64_t> gDiagMaxQueuedBlocks{0u};
std::atomic<std::uint64_t> gDiagMaxCompletedBlocksPerRender{0u};
std::atomic<std::uint64_t> gDiagReadWraps{0u};
std::atomic<std::uint64_t> gDiagEnqueueWraps{0u};
std::atomic<std::uint64_t> gDiagReadCasConflicts{0u};
std::atomic<std::uint64_t> gDiagEnqueueCalls{0u};
std::atomic<std::uint64_t> gDiagEnqueueFrames{0u};
std::atomic<std::uint64_t> gDiagEnqueueRejectRingFull{0u};
std::atomic<std::uint64_t> gDiagEnqueueRejectBlockFull{0u};

std::atomic<std::uint64_t> gDiagBoundaryChecks{0u};
std::atomic<std::uint64_t> gDiagBoundaryJumpGt4096{0u};
std::atomic<std::uint64_t> gDiagBoundaryJumpGt8192{0u};
std::atomic<std::uint64_t> gDiagBoundaryJumpGt16384{0u};
std::atomic<std::uint64_t> gDiagMaxBoundaryJump{0u};
std::atomic<std::uint64_t> gDiagMaxBoundaryJumpGuestFrame{0u};
std::atomic<std::uint64_t> gDiagRepeatedSparseBlocks{0u};
std::atomic<std::uint64_t> gDiagMaxSparseRepeatRun{0u};
std::atomic<std::uint64_t> gDiagFirstSparseRepeatGuestFrame{0u};
std::atomic<std::uint64_t> gDiagLastSparseRepeatGuestFrame{0u};
std::atomic<std::uint64_t> gDiagNonSilentRepeatedSparseBlocks{0u};
std::atomic<std::uint64_t> gDiagMaxNonSilentRepeatRun{0u};
std::atomic<std::uint64_t> gDiagFirstNonSilentRepeatGuestFrame{0u};
std::atomic<std::uint64_t> gDiagLastNonSilentRepeatGuestFrame{0u};
std::atomic<std::uint64_t> gDiagAnimationWindowNonSilentRepeats{0u};
std::atomic<std::uint64_t> gDiagAnimationWindowFirstRepeatFrame{0u};
std::atomic<std::uint64_t> gDiagAnimationWindowLastRepeatFrame{0u};
std::atomic<std::uint64_t> gDiagLateWindowNonSilentRepeats{0u};
std::atomic<std::uint64_t> gDiagLateWindowFirstRepeatFrame{0u};
std::atomic<std::uint64_t> gDiagLateWindowLastRepeatFrame{0u};
std::atomic<std::uint64_t> gDiagAnimationWindowJumpGt8192{0u};
std::atomic<std::uint64_t> gDiagLateWindowJumpGt8192{0u};

// Producer-side continuity state. EnqueuePCM16 is invoked serially by the
// cooperative guest thread, so these do not participate in the realtime
// CoreAudio callback.
bool gDiagHavePreviousBlock = false;
std::array<std::int16_t, kMaxChannels> gDiagPreviousLastSample{};
std::uint64_t gDiagPreviousSparseSignature = 0u;
std::uint64_t gDiagSparseRepeatRun = 0u;
std::uint64_t gDiagNonSilentSparseRepeatRun = 0u;

void DiagnosticAtomicMin(
    std::atomic<std::uint64_t>& target,
    std::uint64_t value) {
    std::uint64_t current =
        target.load(std::memory_order_relaxed);
    while (value < current &&
           !target.compare_exchange_weak(
               current,
               value,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

void DiagnosticAtomicMax(
    std::atomic<std::uint64_t>& target,
    std::uint64_t value) {
    std::uint64_t current =
        target.load(std::memory_order_relaxed);
    while (value > current &&
           !target.compare_exchange_weak(
               current,
               value,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

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

    gDiagRenderCallbacks.fetch_add(
        1u,
        std::memory_order_relaxed);
    gDiagRequestedFrames.fetch_add(
        static_cast<std::uint64_t>(frameCount),
        std::memory_order_relaxed);
    gDiagRenderedFrames.fetch_add(
        static_cast<std::uint64_t>(to_read),
        std::memory_order_relaxed);
    DiagnosticAtomicMin(
        gDiagMinAvailableFrames,
        available);
    DiagnosticAtomicMax(
        gDiagMaxAvailableFrames,
        available);
    if (available <=
        static_cast<std::uint64_t>(frameCount)) {
        gDiagLowWaterEvents.fetch_add(
            1u,
            std::memory_order_relaxed);
    }

    const std::uint64_t diag_head =
        gBlockHead.load(std::memory_order_acquire);
    const std::uint64_t diag_tail =
        gBlockTail.load(std::memory_order_acquire);
    const std::uint64_t diag_queued =
        diag_head >= diag_tail
            ? diag_head - diag_tail
            : 0u;
    DiagnosticAtomicMin(
        gDiagMinQueuedBlocks,
        diag_queued);
    DiagnosticAtomicMax(
        gDiagMaxQueuedBlocks,
        diag_queued);

    gRenderedPCMFrames.fetch_add(
        static_cast<std::uint64_t>(to_read),
        std::memory_order_relaxed);

    if (to_read < frameCount) {
        const std::uint64_t missing =
            static_cast<std::uint64_t>(
                frameCount - to_read);
        gUnderrunFrames.fetch_add(
            missing,
            std::memory_order_relaxed);
        gUnderrunEvents.fetch_add(
            1u,
            std::memory_order_relaxed);
        gDiagUnderrunFrames.fetch_add(
            missing,
            std::memory_order_relaxed);
        gDiagUnderrunEvents.fetch_add(
            1u,
            std::memory_order_relaxed);
        if (to_read == 0u) {
            gDiagEmptyUnderruns.fetch_add(
                1u,
                std::memory_order_relaxed);
        } else {
            gDiagPartialUnderruns.fetch_add(
                1u,
                std::memory_order_relaxed);
        }

        const std::uint64_t guest_frame =
            gDiagGuestFrame.load(
                std::memory_order_relaxed);
        std::uint64_t expected_first = 0u;
        gDiagFirstUnderrunGuestFrame
            .compare_exchange_strong(
                expected_first,
                guest_frame,
                std::memory_order_relaxed,
                std::memory_order_relaxed);
        gDiagLastUnderrunGuestFrame.store(
            guest_frame,
            std::memory_order_relaxed);
    }

    if (to_read != 0u &&
        (read % kRingFrames) +
                static_cast<std::uint64_t>(to_read) >
            kRingFrames) {
        gDiagReadWraps.fetch_add(
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
        gDiagReadCasConflicts.fetch_add(
            1u,
            std::memory_order_relaxed);
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
        DiagnosticAtomicMax(
            gDiagMaxCompletedBlocksPerRender,
            completed);
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

    gDiagEnqueueCalls.fetch_add(
        1u,
        std::memory_order_relaxed);

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
        gDiagEnqueueRejectRingFull.fetch_add(
            1u,
            std::memory_order_relaxed);
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
        gDiagEnqueueRejectBlockFull.fetch_add(
            1u,
            std::memory_order_relaxed);
        return false;
    }

    gDiagEnqueueFrames.fetch_add(
        frames,
        std::memory_order_relaxed);
    if ((write % kRingFrames) + frames >
        kRingFrames) {
        gDiagEnqueueWraps.fetch_add(
            1u,
            std::memory_order_relaxed);
    }

    const auto* src =
        static_cast<const std::uint8_t*>(
            data);

    std::array<std::int16_t, kMaxChannels> first_sample{};
    std::array<std::int16_t, kMaxChannels> last_sample{};
    for (std::uint32_t channel = 0u;
         channel < channels;
         ++channel) {
        std::memcpy(
            &first_sample[channel],
            src + channel * sizeof(std::int16_t),
            sizeof(std::int16_t));
        const std::size_t last_index =
            (static_cast<std::size_t>(frames - 1u) *
                 channels +
             channel) *
            sizeof(std::int16_t);
        std::memcpy(
            &last_sample[channel],
            src + last_index,
            sizeof(std::int16_t));
    }

    const std::uint64_t guest_frame =
        gDiagGuestFrame.load(
            std::memory_order_relaxed);

    if (gDiagHavePreviousBlock) {
        std::uint64_t jump = 0u;
        for (std::uint32_t channel = 0u;
             channel < channels;
             ++channel) {
            const std::int64_t delta =
                static_cast<std::int64_t>(
                    first_sample[channel]) -
                static_cast<std::int64_t>(
                    gDiagPreviousLastSample[channel]);
            const std::uint64_t abs_delta =
                static_cast<std::uint64_t>(
                    delta < 0 ? -delta : delta);
            jump = std::max(jump, abs_delta);
        }

        gDiagBoundaryChecks.fetch_add(
            1u,
            std::memory_order_relaxed);
        if (jump > 4096u) {
            gDiagBoundaryJumpGt4096.fetch_add(
                1u,
                std::memory_order_relaxed);
        }
        if (jump > 8192u) {
            gDiagBoundaryJumpGt8192.fetch_add(
                1u,
                std::memory_order_relaxed);
            if (guest_frame >= 800u &&
                guest_frame <= 2500u) {
                gDiagAnimationWindowJumpGt8192.fetch_add(
                    1u,
                    std::memory_order_relaxed);
            }
            if (guest_frame >= 10000u &&
                guest_frame <= 12500u) {
                gDiagLateWindowJumpGt8192.fetch_add(
                    1u,
                    std::memory_order_relaxed);
            }
        }
        if (jump > 16384u) {
            gDiagBoundaryJumpGt16384.fetch_add(
                1u,
                std::memory_order_relaxed);
        }

        std::uint64_t old_max =
            gDiagMaxBoundaryJump.load(
                std::memory_order_relaxed);
        while (jump > old_max) {
            if (gDiagMaxBoundaryJump
                    .compare_exchange_weak(
                        old_max,
                        jump,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed)) {
                gDiagMaxBoundaryJumpGuestFrame.store(
                    guest_frame,
                    std::memory_order_relaxed);
                break;
            }
        }
    }

    // 16-point sparse FNV-1a signature: 16 frames x <=2 channels.
    std::uint64_t sparse_signature =
        1469598103934665603ull;
    std::uint64_t sparse_peak = 0u;
    constexpr std::uint64_t kSparsePoints = 16u;
    for (std::uint64_t point = 0u;
         point < kSparsePoints;
         ++point) {
        const std::uint64_t frame_index =
            frames > 1u
                ? (point * (frames - 1u)) /
                      (kSparsePoints - 1u)
                : 0u;
        for (std::uint32_t channel = 0u;
             channel < channels;
             ++channel) {
            std::int16_t sample = 0;
            const std::size_t byte_index =
                (static_cast<std::size_t>(frame_index) *
                     channels +
                 channel) *
                sizeof(std::int16_t);
            std::memcpy(
                &sample,
                src + byte_index,
                sizeof(sample));
            const std::int64_t signed_sample =
                static_cast<std::int64_t>(sample);
            const std::uint64_t abs_sample =
                static_cast<std::uint64_t>(
                    signed_sample < 0
                        ? -signed_sample
                        : signed_sample);
            sparse_peak =
                std::max(sparse_peak, abs_sample);
            const std::uint16_t raw =
                static_cast<std::uint16_t>(sample);
            sparse_signature ^=
                static_cast<std::uint8_t>(raw & 0xffu);
            sparse_signature *= 1099511628211ull;
            sparse_signature ^=
                static_cast<std::uint8_t>(raw >> 8u);
            sparse_signature *= 1099511628211ull;
        }
    }

    if (gDiagHavePreviousBlock &&
        sparse_signature ==
            gDiagPreviousSparseSignature) {
        ++gDiagSparseRepeatRun;
        gDiagRepeatedSparseBlocks.fetch_add(
            1u,
            std::memory_order_relaxed);
        DiagnosticAtomicMax(
            gDiagMaxSparseRepeatRun,
            gDiagSparseRepeatRun);
        std::uint64_t expected_first = 0u;
        gDiagFirstSparseRepeatGuestFrame
            .compare_exchange_strong(
                expected_first,
                guest_frame,
                std::memory_order_relaxed,
                std::memory_order_relaxed);
        gDiagLastSparseRepeatGuestFrame.store(
            guest_frame,
            std::memory_order_relaxed);

        if (sparse_peak >= 256u) {
            ++gDiagNonSilentSparseRepeatRun;
            gDiagNonSilentRepeatedSparseBlocks.fetch_add(
                1u,
                std::memory_order_relaxed);
            DiagnosticAtomicMax(
                gDiagMaxNonSilentRepeatRun,
                gDiagNonSilentSparseRepeatRun);
            std::uint64_t expected_non_silent_first = 0u;
            gDiagFirstNonSilentRepeatGuestFrame
                .compare_exchange_strong(
                    expected_non_silent_first,
                    guest_frame,
                    std::memory_order_relaxed,
                    std::memory_order_relaxed);
            gDiagLastNonSilentRepeatGuestFrame.store(
                guest_frame,
                std::memory_order_relaxed);

            if (guest_frame >= 800u &&
                guest_frame <= 2500u) {
                gDiagAnimationWindowNonSilentRepeats.fetch_add(
                    1u,
                    std::memory_order_relaxed);
                std::uint64_t expected_window_first = 0u;
                gDiagAnimationWindowFirstRepeatFrame
                    .compare_exchange_strong(
                        expected_window_first,
                        guest_frame,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed);
                gDiagAnimationWindowLastRepeatFrame.store(
                    guest_frame,
                    std::memory_order_relaxed);
            }

            if (guest_frame >= 10000u &&
                guest_frame <= 12500u) {
                gDiagLateWindowNonSilentRepeats.fetch_add(
                    1u,
                    std::memory_order_relaxed);
                std::uint64_t expected_window_first = 0u;
                gDiagLateWindowFirstRepeatFrame
                    .compare_exchange_strong(
                        expected_window_first,
                        guest_frame,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed);
                gDiagLateWindowLastRepeatFrame.store(
                    guest_frame,
                    std::memory_order_relaxed);
            }
        } else {
            gDiagNonSilentSparseRepeatRun = 0u;
        }
    } else {
        gDiagSparseRepeatRun = 1u;
        gDiagNonSilentSparseRepeatRun = 0u;
    }

    gDiagPreviousLastSample = last_sample;
    gDiagPreviousSparseSignature =
        sparse_signature;
    gDiagHavePreviousBlock = true;

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

void PvZ2HostAudioResetDiagnostics() {
    gDiagRenderCallbacks.store(0u, std::memory_order_relaxed);
    gDiagRequestedFrames.store(0u, std::memory_order_relaxed);
    gDiagRenderedFrames.store(0u, std::memory_order_relaxed);
    gDiagUnderrunEvents.store(0u, std::memory_order_relaxed);
    gDiagUnderrunFrames.store(0u, std::memory_order_relaxed);
    gDiagEmptyUnderruns.store(0u, std::memory_order_relaxed);
    gDiagPartialUnderruns.store(0u, std::memory_order_relaxed);
    gDiagFirstUnderrunGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagLastUnderrunGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagLowWaterEvents.store(0u, std::memory_order_relaxed);
    gDiagMinAvailableFrames.store(
        std::numeric_limits<std::uint64_t>::max(),
        std::memory_order_relaxed);
    gDiagMaxAvailableFrames.store(0u, std::memory_order_relaxed);
    gDiagMinQueuedBlocks.store(
        std::numeric_limits<std::uint64_t>::max(),
        std::memory_order_relaxed);
    gDiagMaxQueuedBlocks.store(0u, std::memory_order_relaxed);
    gDiagMaxCompletedBlocksPerRender.store(0u, std::memory_order_relaxed);
    gDiagReadWraps.store(0u, std::memory_order_relaxed);
    gDiagEnqueueWraps.store(0u, std::memory_order_relaxed);
    gDiagReadCasConflicts.store(0u, std::memory_order_relaxed);
    gDiagEnqueueCalls.store(0u, std::memory_order_relaxed);
    gDiagEnqueueFrames.store(0u, std::memory_order_relaxed);
    gDiagEnqueueRejectRingFull.store(0u, std::memory_order_relaxed);
    gDiagEnqueueRejectBlockFull.store(0u, std::memory_order_relaxed);
    gDiagBoundaryChecks.store(0u, std::memory_order_relaxed);
    gDiagBoundaryJumpGt4096.store(0u, std::memory_order_relaxed);
    gDiagBoundaryJumpGt8192.store(0u, std::memory_order_relaxed);
    gDiagBoundaryJumpGt16384.store(0u, std::memory_order_relaxed);
    gDiagMaxBoundaryJump.store(0u, std::memory_order_relaxed);
    gDiagMaxBoundaryJumpGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagRepeatedSparseBlocks.store(0u, std::memory_order_relaxed);
    gDiagMaxSparseRepeatRun.store(0u, std::memory_order_relaxed);
    gDiagFirstSparseRepeatGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagLastSparseRepeatGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagNonSilentRepeatedSparseBlocks.store(0u, std::memory_order_relaxed);
    gDiagMaxNonSilentRepeatRun.store(0u, std::memory_order_relaxed);
    gDiagFirstNonSilentRepeatGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagLastNonSilentRepeatGuestFrame.store(0u, std::memory_order_relaxed);
    gDiagAnimationWindowNonSilentRepeats.store(0u, std::memory_order_relaxed);
    gDiagAnimationWindowFirstRepeatFrame.store(0u, std::memory_order_relaxed);
    gDiagAnimationWindowLastRepeatFrame.store(0u, std::memory_order_relaxed);
    gDiagLateWindowNonSilentRepeats.store(0u, std::memory_order_relaxed);
    gDiagLateWindowFirstRepeatFrame.store(0u, std::memory_order_relaxed);
    gDiagLateWindowLastRepeatFrame.store(0u, std::memory_order_relaxed);
    gDiagAnimationWindowJumpGt8192.store(0u, std::memory_order_relaxed);
    gDiagLateWindowJumpGt8192.store(0u, std::memory_order_relaxed);
    gDiagHavePreviousBlock = false;
    gDiagPreviousLastSample.fill(0);
    gDiagPreviousSparseSignature = 0u;
    gDiagSparseRepeatRun = 0u;
    gDiagNonSilentSparseRepeatRun = 0u;
}

void PvZ2HostAudioSetDiagnosticGuestFrame(
    std::uint32_t frame) {
    gDiagGuestFrame.store(
        frame,
        std::memory_order_relaxed);
}

PvZ2HostAudioDiagnostics
PvZ2HostAudioDiagnosticSnapshot() {
    PvZ2HostAudioDiagnostics out;
    out.render_callbacks = gDiagRenderCallbacks.load(std::memory_order_relaxed);
    out.requested_frames = gDiagRequestedFrames.load(std::memory_order_relaxed);
    out.rendered_frames = gDiagRenderedFrames.load(std::memory_order_relaxed);
    out.underrun_events = gDiagUnderrunEvents.load(std::memory_order_relaxed);
    out.underrun_frames = gDiagUnderrunFrames.load(std::memory_order_relaxed);
    out.empty_underruns = gDiagEmptyUnderruns.load(std::memory_order_relaxed);
    out.partial_underruns = gDiagPartialUnderruns.load(std::memory_order_relaxed);
    out.first_underrun_guest_frame =
        gDiagFirstUnderrunGuestFrame.load(std::memory_order_relaxed);
    out.last_underrun_guest_frame =
        gDiagLastUnderrunGuestFrame.load(std::memory_order_relaxed);
    out.low_water_events = gDiagLowWaterEvents.load(std::memory_order_relaxed);
    out.min_available_frames =
        gDiagMinAvailableFrames.load(std::memory_order_relaxed);
    if (out.min_available_frames ==
        std::numeric_limits<std::uint64_t>::max()) {
        out.min_available_frames = 0u;
    }
    out.max_available_frames =
        gDiagMaxAvailableFrames.load(std::memory_order_relaxed);
    out.min_queued_blocks =
        gDiagMinQueuedBlocks.load(std::memory_order_relaxed);
    if (out.min_queued_blocks ==
        std::numeric_limits<std::uint64_t>::max()) {
        out.min_queued_blocks = 0u;
    }
    out.max_queued_blocks =
        gDiagMaxQueuedBlocks.load(std::memory_order_relaxed);
    out.max_completed_blocks_per_render =
        gDiagMaxCompletedBlocksPerRender.load(std::memory_order_relaxed);
    out.read_wraps = gDiagReadWraps.load(std::memory_order_relaxed);
    out.enqueue_wraps = gDiagEnqueueWraps.load(std::memory_order_relaxed);
    out.read_cas_conflicts =
        gDiagReadCasConflicts.load(std::memory_order_relaxed);
    out.enqueue_calls = gDiagEnqueueCalls.load(std::memory_order_relaxed);
    out.enqueue_frames = gDiagEnqueueFrames.load(std::memory_order_relaxed);
    out.enqueue_reject_ring_full =
        gDiagEnqueueRejectRingFull.load(std::memory_order_relaxed);
    out.enqueue_reject_block_full =
        gDiagEnqueueRejectBlockFull.load(std::memory_order_relaxed);
    out.boundary_checks =
        gDiagBoundaryChecks.load(std::memory_order_relaxed);
    out.boundary_jump_gt_4096 =
        gDiagBoundaryJumpGt4096.load(std::memory_order_relaxed);
    out.boundary_jump_gt_8192 =
        gDiagBoundaryJumpGt8192.load(std::memory_order_relaxed);
    out.boundary_jump_gt_16384 =
        gDiagBoundaryJumpGt16384.load(std::memory_order_relaxed);
    out.max_boundary_jump =
        gDiagMaxBoundaryJump.load(std::memory_order_relaxed);
    out.max_boundary_jump_guest_frame =
        gDiagMaxBoundaryJumpGuestFrame.load(std::memory_order_relaxed);
    out.repeated_sparse_blocks =
        gDiagRepeatedSparseBlocks.load(std::memory_order_relaxed);
    out.max_sparse_repeat_run =
        gDiagMaxSparseRepeatRun.load(std::memory_order_relaxed);
    out.first_sparse_repeat_guest_frame =
        gDiagFirstSparseRepeatGuestFrame.load(std::memory_order_relaxed);
    out.last_sparse_repeat_guest_frame =
        gDiagLastSparseRepeatGuestFrame.load(std::memory_order_relaxed);
    out.non_silent_repeated_sparse_blocks =
        gDiagNonSilentRepeatedSparseBlocks.load(std::memory_order_relaxed);
    out.max_non_silent_repeat_run =
        gDiagMaxNonSilentRepeatRun.load(std::memory_order_relaxed);
    out.first_non_silent_repeat_guest_frame =
        gDiagFirstNonSilentRepeatGuestFrame.load(std::memory_order_relaxed);
    out.last_non_silent_repeat_guest_frame =
        gDiagLastNonSilentRepeatGuestFrame.load(std::memory_order_relaxed);
    out.animation_window_non_silent_repeats =
        gDiagAnimationWindowNonSilentRepeats.load(std::memory_order_relaxed);
    out.animation_window_first_repeat_frame =
        gDiagAnimationWindowFirstRepeatFrame.load(std::memory_order_relaxed);
    out.animation_window_last_repeat_frame =
        gDiagAnimationWindowLastRepeatFrame.load(std::memory_order_relaxed);
    out.late_window_non_silent_repeats =
        gDiagLateWindowNonSilentRepeats.load(std::memory_order_relaxed);
    out.late_window_first_repeat_frame =
        gDiagLateWindowFirstRepeatFrame.load(std::memory_order_relaxed);
    out.late_window_last_repeat_frame =
        gDiagLateWindowLastRepeatFrame.load(std::memory_order_relaxed);
    out.animation_window_jump_gt_8192 =
        gDiagAnimationWindowJumpGt8192.load(std::memory_order_relaxed);
    out.late_window_jump_gt_8192 =
        gDiagLateWindowJumpGt8192.load(std::memory_order_relaxed);
    return out;
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
