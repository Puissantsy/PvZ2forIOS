#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

bool PvZ2HostGLESBegin(std::uint32_t width, std::uint32_t height);
std::uint32_t PvZ2HostGLESDefaultFramebuffer(void);
const char* PvZ2HostGLESCapturePNG(void);
const char* PvZ2HostGLESFrameStats(void);
std::uint64_t PvZ2HostGLESLastNonBlackPixels(void);
const char* PvZ2HostGLESCapturePNGNamed(const char* file_name);
void PvZ2HostGLESEnd(void);

#ifdef __cplusplus
}
#endif
