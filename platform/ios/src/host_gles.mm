#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <OpenGLES/EAGL.h>
#import <OpenGLES/ES2/gl.h>
#import <OpenGLES/ES2/glext.h>

#include "host_gles.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>

namespace {

EAGLContext *gContext = nil;
GLuint gFramebuffer = 0;
GLuint gColorTexture = 0;
GLuint gDepthRenderbuffer = 0;
std::uint32_t gWidth = 0;
std::uint32_t gHeight = 0;
NSString *gCapturePath = nil;
std::string gFrameStats;
std::uint64_t gLastNonBlackPixels = 0u;

void DestroySurface() {
    if (gContext != nil) {
        [EAGLContext setCurrentContext:gContext];

        if (gDepthRenderbuffer != 0) {
            glDeleteRenderbuffers(1, &gDepthRenderbuffer);
            gDepthRenderbuffer = 0;
        }

        if (gColorTexture != 0) {
            glDeleteTextures(1, &gColorTexture);
            gColorTexture = 0;
        }

        if (gFramebuffer != 0) {
            glDeleteFramebuffers(1, &gFramebuffer);
            gFramebuffer = 0;
        }

        [EAGLContext setCurrentContext:nil];
        gContext = nil;
    }

    gWidth = 0;
    gHeight = 0;
}

} // namespace

extern "C" bool PvZ2HostGLESBegin(
    std::uint32_t width,
    std::uint32_t height) {

    DestroySurface();

    if (width == 0 || height == 0) {
        return false;
    }

    gContext =
        [[EAGLContext alloc]
            initWithAPI:kEAGLRenderingAPIOpenGLES2];

    if (gContext == nil ||
        ![EAGLContext setCurrentContext:gContext]) {
        DestroySurface();
        return false;
    }

    glGenFramebuffers(1, &gFramebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, gFramebuffer);

    glGenTextures(1, &gColorTexture);
    glBindTexture(GL_TEXTURE_2D, gColorTexture);
    glTexParameteri(
        GL_TEXTURE_2D,
        GL_TEXTURE_MIN_FILTER,
        GL_LINEAR);
    glTexParameteri(
        GL_TEXTURE_2D,
        GL_TEXTURE_MAG_FILTER,
        GL_LINEAR);
    glTexParameteri(
        GL_TEXTURE_2D,
        GL_TEXTURE_WRAP_S,
        GL_CLAMP_TO_EDGE);
    glTexParameteri(
        GL_TEXTURE_2D,
        GL_TEXTURE_WRAP_T,
        GL_CLAMP_TO_EDGE);
    glTexImage2D(
        GL_TEXTURE_2D,
        0,
        GL_RGBA,
        static_cast<GLsizei>(width),
        static_cast<GLsizei>(height),
        0,
        GL_RGBA,
        GL_UNSIGNED_BYTE,
        nullptr);

    glFramebufferTexture2D(
        GL_FRAMEBUFFER,
        GL_COLOR_ATTACHMENT0,
        GL_TEXTURE_2D,
        gColorTexture,
        0);

    glGenRenderbuffers(1, &gDepthRenderbuffer);
    glBindRenderbuffer(
        GL_RENDERBUFFER,
        gDepthRenderbuffer);
    glRenderbufferStorage(
        GL_RENDERBUFFER,
        GL_DEPTH_COMPONENT16,
        static_cast<GLsizei>(width),
        static_cast<GLsizei>(height));
    glFramebufferRenderbuffer(
        GL_FRAMEBUFFER,
        GL_DEPTH_ATTACHMENT,
        GL_RENDERBUFFER,
        gDepthRenderbuffer);

    const GLenum status =
        glCheckFramebufferStatus(GL_FRAMEBUFFER);

    if (status != GL_FRAMEBUFFER_COMPLETE) {
        DestroySurface();
        return false;
    }

    gWidth = width;
    gHeight = height;

    glViewport(
        0,
        0,
        static_cast<GLsizei>(width),
        static_cast<GLsizei>(height));
    glClearColor(0, 0, 0, 1);
    glClear(
        GL_COLOR_BUFFER_BIT |
        GL_DEPTH_BUFFER_BIT);

    return true;
}

extern "C" std::uint32_t
PvZ2HostGLESDefaultFramebuffer(void) {
    return
        static_cast<std::uint32_t>(
            gFramebuffer);
}

extern "C" const char*
PvZ2HostGLESFrameStats(void) {
    if (gContext == nil ||
        gFramebuffer == 0 ||
        gWidth == 0 ||
        gHeight == 0 ||
        ![EAGLContext setCurrentContext:gContext]) {
        gFrameStats = "unavailable";
        return gFrameStats.c_str();
    }

    GLint previous_framebuffer = 0;
    GLint previous_pack_alignment = 4;

    glGetIntegerv(
        GL_FRAMEBUFFER_BINDING,
        &previous_framebuffer);
    glGetIntegerv(
        GL_PACK_ALIGNMENT,
        &previous_pack_alignment);

    glBindFramebuffer(
        GL_FRAMEBUFFER,
        gFramebuffer);

    const std::size_t pixel_count =
        static_cast<std::size_t>(
            gWidth) *
        static_cast<std::size_t>(
            gHeight);
    const std::size_t total_bytes =
        pixel_count * 4u;

    std::vector<std::uint8_t>
        pixels(total_bytes);

    glPixelStorei(
        GL_PACK_ALIGNMENT,
        1);

    glReadPixels(
        0,
        0,
        static_cast<GLsizei>(gWidth),
        static_cast<GLsizei>(gHeight),
        GL_RGBA,
        GL_UNSIGNED_BYTE,
        pixels.data());

    std::uint64_t non_black = 0u;
    std::uint64_t non_transparent = 0u;
    std::uint64_t sum_r = 0u;
    std::uint64_t sum_g = 0u;
    std::uint64_t sum_b = 0u;
    std::uint64_t fnv =
        1469598103934665603ull;

    for (std::size_t i = 0u;
         i < pixel_count;
         ++i) {

        const std::uint8_t r =
            pixels[i * 4u + 0u];
        const std::uint8_t g =
            pixels[i * 4u + 1u];
        const std::uint8_t b =
            pixels[i * 4u + 2u];
        const std::uint8_t a =
            pixels[i * 4u + 3u];

        if (r > 4u ||
            g > 4u ||
            b > 4u) {
            ++non_black;
        }

        if (a != 0u) {
            ++non_transparent;
        }

        sum_r += r;
        sum_g += g;
        sum_b += b;

        fnv ^= r;
        fnv *= 1099511628211ull;
        fnv ^= g;
        fnv *= 1099511628211ull;
        fnv ^= b;
        fnv *= 1099511628211ull;
        fnv ^= a;
        fnv *= 1099511628211ull;
    }

    const std::size_t center =
        ((static_cast<std::size_t>(
              gHeight) /
          2u) *
             static_cast<std::size_t>(
                 gWidth) +
         (static_cast<std::size_t>(
              gWidth) /
          2u)) *
        4u;

    std::ostringstream out;
    out
        << "size="
        << gWidth
        << "x"
        << gHeight
        << " pixels="
        << pixel_count
        << " nonBlack="
        << non_black
        << " nonTransparent="
        << non_transparent
        << " avgRGB=("
        << (pixel_count
                ? sum_r / pixel_count
                : 0u)
        << ","
        << (pixel_count
                ? sum_g / pixel_count
                : 0u)
        << ","
        << (pixel_count
                ? sum_b / pixel_count
                : 0u)
        << ") centerRGBA=("
        << static_cast<unsigned>(
               pixels[center + 0u])
        << ","
        << static_cast<unsigned>(
               pixels[center + 1u])
        << ","
        << static_cast<unsigned>(
               pixels[center + 2u])
        << ","
        << static_cast<unsigned>(
               pixels[center + 3u])
        << ") fnv64=0x"
        << std::hex
        << fnv;

    gFrameStats =
        out.str();
    gLastNonBlackPixels =
        non_black;

    glPixelStorei(
        GL_PACK_ALIGNMENT,
        previous_pack_alignment);
    glBindFramebuffer(
        GL_FRAMEBUFFER,
        static_cast<GLuint>(
            previous_framebuffer));

    return
        gFrameStats.c_str();
}

extern "C" std::uint64_t
PvZ2HostGLESLastNonBlackPixels(void) {
    return gLastNonBlackPixels;
}

extern "C" const char*
PvZ2HostGLESCapturePNGNamed(
    const char* file_name) {
    if (gContext == nil ||
        gFramebuffer == 0 ||
        gWidth == 0 ||
        gHeight == 0 ||
        ![EAGLContext setCurrentContext:gContext]) {
        return "";
    }

    GLint previous_framebuffer = 0;
    GLint previous_pack_alignment = 4;

    glGetIntegerv(
        GL_FRAMEBUFFER_BINDING,
        &previous_framebuffer);
    glGetIntegerv(
        GL_PACK_ALIGNMENT,
        &previous_pack_alignment);

    glBindFramebuffer(
        GL_FRAMEBUFFER,
        gFramebuffer);

    const std::size_t row_bytes =
        static_cast<std::size_t>(
            gWidth) *
        4u;
    const std::size_t total_bytes =
        row_bytes *
        static_cast<std::size_t>(
            gHeight);

    std::vector<std::uint8_t>
        pixels(total_bytes);

    glPixelStorei(
        GL_PACK_ALIGNMENT,
        1);

    glReadPixels(
        0,
        0,
        static_cast<GLsizei>(gWidth),
        static_cast<GLsizei>(gHeight),
        GL_RGBA,
        GL_UNSIGNED_BYTE,
        pixels.data());

    glPixelStorei(
        GL_PACK_ALIGNMENT,
        previous_pack_alignment);
    glBindFramebuffer(
        GL_FRAMEBUFFER,
        static_cast<GLuint>(
            previous_framebuffer));

    std::vector<std::uint8_t>
        flipped(total_bytes);

    for (std::uint32_t y = 0;
         y < gHeight;
         ++y) {
        std::memcpy(
            flipped.data() +
                static_cast<std::size_t>(y) *
                    row_bytes,
            pixels.data() +
                static_cast<std::size_t>(
                    gHeight - 1u - y) *
                    row_bytes,
            row_bytes);
    }

    // v40: the offscreen framebuffer is already the final composited RGB
    // result we want to inspect. Its alpha channel is still meaningful to
    // PvZ2 during its splash/fade path, but feeding those bytes to UIKit as
    // premultiplied alpha makes the diagnostic image get darkened again
    // against the black UIImageView background.
    //
    // Normalize the diagnostic capture only:
    //   1. undo premultiplication for partially transparent pixels;
    //   2. force the exported image opaque so UIKit cannot composite it a
    //      second time.
    //
    // This does NOT modify the GLES framebuffer or any pixels seen by PvZ2.
    for (std::size_t i = 0u;
         i < total_bytes;
         i += 4u) {

        const std::uint32_t alpha =
            flipped[i + 3u];

        if (alpha == 0u) {
            flipped[i + 0u] = 0u;
            flipped[i + 1u] = 0u;
            flipped[i + 2u] = 0u;
        } else if (alpha < 255u) {
            for (std::size_t channel = 0u;
                 channel < 3u;
                 ++channel) {

                const std::uint32_t value =
                    flipped[i + channel];

                const std::uint32_t straight =
                    (value * 255u +
                     alpha / 2u) /
                    alpha;

                flipped[i + channel] =
                    static_cast<std::uint8_t>(
                        std::min<std::uint32_t>(
                            255u,
                            straight));
            }
        }

        flipped[i + 3u] = 255u;
    }

    CGColorSpaceRef color_space =
        CGColorSpaceCreateDeviceRGB();

    NSData *data =
        [NSData
            dataWithBytes:
                flipped.data()
            length:
                flipped.size()];

    CGDataProviderRef provider =
        CGDataProviderCreateWithCFData(
            (__bridge CFDataRef)data);

    CGImageRef image_ref =
        CGImageCreate(
            gWidth,
            gHeight,
            8,
            32,
            row_bytes,
            color_space,
            kCGBitmapByteOrder32Big |
                kCGImageAlphaLast,
            provider,
            nullptr,
            false,
            kCGRenderingIntentDefault);

    UIImage *image =
        image_ref != nullptr
            ? [UIImage imageWithCGImage:image_ref]
            : nil;

    if (image_ref != nullptr) {
        CGImageRelease(image_ref);
    }
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(color_space);

    NSData *png =
        image != nil
            ? UIImagePNGRepresentation(image)
            : nil;

    if (png == nil) {
        return "";
    }

    NSArray<NSURL *> *urls =
        [[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory
                   inDomains:NSUserDomainMask];

    NSURL *documents =
        urls.firstObject;

    NSString *safe_name =
        file_name != nullptr &&
        *file_name != '\0'
            ? [NSString
                stringWithUTF8String:
                    file_name]
            : @"pvz2-v43-frame.png";

    if (safe_name.length == 0 ||
        [safe_name containsString:@"/"] ||
        [safe_name containsString:@"\\"]) {
        safe_name =
            @"pvz2-v43-frame.png";
    }

    NSURL *target =
        [documents
            URLByAppendingPathComponent:
                safe_name];

    if (![png
            writeToURL:target
               options:NSDataWritingAtomic
                 error:nil]) {
        return "";
    }

    gCapturePath =
        target.path;

    return
        gCapturePath.UTF8String ?: "";
}

extern "C" const char*
PvZ2HostGLESCapturePNG(void) {
    return
        PvZ2HostGLESCapturePNGNamed(
            "pvz2-v43-final-frame.png");
}

extern "C" void PvZ2HostGLESEnd(void) {
    DestroySurface();
}
