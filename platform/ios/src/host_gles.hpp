#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

bool PvZ2HostGLESBegin(std::uint32_t width, std::uint32_t height);

// v76: resize the existing offscreen default framebuffer in-place. The FBO,
// texture and renderbuffer object IDs are preserved so guest<->host GLES
// mappings remain valid across a GL-view scale-factor change.
bool PvZ2HostGLESResize(std::uint32_t width, std::uint32_t height);

// v90: present the validated offscreen guest framebuffer directly through a
// CAEAGLLayer-backed renderbuffer. The layer is opaque here so this header
// stays independent from Objective-C/UIKit types.
void PvZ2HostGLESSetPresentationLayer(void* ca_eagl_layer);
void PvZ2HostGLESClearPresentationLayer(void);
bool PvZ2HostGLESPresent(
    std::uint32_t* drawable_width,
    std::uint32_t* drawable_height);

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
