#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

bool PvZ2HostGLESBegin(std::uint32_t width, std::uint32_t height);
std::uint32_t PvZ2HostGLESDefaultFramebuffer(void);
const char* PvZ2HostGLESCapturePNG(void);
const char* PvZ2HostGLESFrameStats(void);
const char* PvZ2HostGLESFramebufferStats(
    std::uint32_t framebuffer,
    std::uint32_t width,
    std::uint32_t height);
std::uint64_t PvZ2HostGLESLastNonBlackPixels(void);

// v72: copies the default host framebuffer into a top-left-oriented,
// straight/opaque RGBA8 buffer. The returned pointer remains valid until the
// next live-copy call or PvZ2HostGLESEnd.
const std::uint8_t* PvZ2HostGLESCopyDisplayRGBA(
    std::uint32_t* width,
    std::uint32_t* height,
    std::size_t* size);

const char* PvZ2HostGLESCapturePNGNamed(const char* file_name);
void PvZ2HostGLESEnd(void);

#ifdef __cplusplus
}
#endif
