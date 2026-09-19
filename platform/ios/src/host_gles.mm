#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <OpenGLES/EAGL.h>
#import <OpenGLES/ES2/gl.h>
#import <OpenGLES/ES2/glext.h>

#include "host_gles.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

EAGLContext *gContext = nil;
GLuint gFramebuffer = 0;
GLuint gColorTexture = 0;
GLuint gDepthRenderbuffer = 0;
std::uint32_t gWidth = 0;
std::uint32_t gHeight = 0;
NSString *gCapturePath = nil;

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
PvZ2HostGLESCapturePNG(void) {
    if (gContext == nil ||
        gFramebuffer == 0 ||
        gWidth == 0 ||
        gHeight == 0 ||
        ![EAGLContext setCurrentContext:gContext]) {
        return "";
    }

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
                kCGImageAlphaPremultipliedLast,
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

    NSURL *target =
        [documents
            URLByAppendingPathComponent:
                @"pvz2-v31-first-frame.png"];

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

extern "C" void PvZ2HostGLESEnd(void) {
    DestroySurface();
}
