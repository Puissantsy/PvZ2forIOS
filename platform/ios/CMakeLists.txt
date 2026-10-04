cmake_minimum_required(VERSION 3.22)

project(PvZ2forIOS LANGUAGES C CXX OBJC OBJCXX)

if(NOT IOS)
    message(FATAL_ERROR "This target is intended for iOS/iPadOS. Configure with -DCMAKE_SYSTEM_NAME=iOS.")
endif()

# Build source for Dynarmic:
# - CI may pass PVZ2_PREBUILT_DYNARMIC_ROOT pointing at LiveExec32's published
#   iOS arm64 include/ + lib/libdynarmic.a bundle. This avoids depending on a
#   currently unreliable external Git clone during GitHub Actions.
# - Local/development builds retain the original exact-source FetchContent path.
set(PVZ2_PREBUILT_DYNARMIC_ROOT "" CACHE PATH
    "Optional directory containing include/dynarmic and lib/libdynarmic.a")

if(PVZ2_PREBUILT_DYNARMIC_ROOT)
    set(_pvz2_dynarmic_lib
        "${PVZ2_PREBUILT_DYNARMIC_ROOT}/lib/libdynarmic.a")
    set(_pvz2_dynarmic_include
        "${PVZ2_PREBUILT_DYNARMIC_ROOT}/include")

    if(NOT EXISTS "${_pvz2_dynarmic_lib}")
        message(FATAL_ERROR
            "PVZ2 prebuilt Dynarmic library missing: ${_pvz2_dynarmic_lib}")
    endif()
    if(NOT EXISTS
       "${_pvz2_dynarmic_include}/dynarmic/interface/A32/a32.h")
        message(FATAL_ERROR
            "PVZ2 prebuilt Dynarmic headers missing/incompatible under: ${_pvz2_dynarmic_include}")
    endif()

    add_library(dynarmic STATIC IMPORTED GLOBAL)
    set_target_properties(dynarmic PROPERTIES
        IMPORTED_LOCATION "${_pvz2_dynarmic_lib}"
        INTERFACE_INCLUDE_DIRECTORIES "${_pvz2_dynarmic_include}"
    )
    message(STATUS
        "PvZ2: using externally staged prebuilt iOS Dynarmic bundle: ${PVZ2_PREBUILT_DYNARMIC_ROOT}")
else()
    include(FetchContent)

    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_TESTS_USE_UNICORN OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
    set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)
    set(DYNARMIC_USE_LLVM OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_USE_PRECOMPILED_HEADERS OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)

    # Historical exact-source fallback retained for local environments that can
    # still fetch the pinned fork. The project patch is applied only here;
    # LiveExec32's published prebuilt archive already contains its iOS JIT path.
    FetchContent_Declare(
        dynarmic
        GIT_REPOSITORY https://github.com/LiveContainer/dynarmic.git
        GIT_TAG c97c525ec1432b1e5404ebf091027738005ec168
        GIT_SHALLOW TRUE
        PATCH_COMMAND git apply
            "${CMAKE_CURRENT_SOURCE_DIR}/patches/dynarmic-ios-nontxm.patch"
    )
    FetchContent_MakeAvailable(dynarmic)
endif()

set(PVZ2_UI_RESOURCES
    resources/pvz17_fastforward_normal.png
    resources/pvz17_fastforward_selected.png
)

set_source_files_properties(
    ${PVZ2_UI_RESOURCES}
    PROPERTIES MACOSX_PACKAGE_LOCATION Resources
)

add_executable(PvZ2forIOS MACOSX_BUNDLE
    src/main.mm
    src/save_backups.mm
    src/dynarmic_smoke.cpp
    src/pvz2_apk_probe.cpp
    src/host_gles.mm
    src/host_audio.mm
    ${PVZ2_UI_RESOURCES}
)

set_target_properties(PvZ2forIOS PROPERTIES
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.puissantsy.pvz2forios.keyobs"
    XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
    XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "17.4"
    XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
    XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
    XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
    XCODE_ATTRIBUTE_CLANG_ENABLE_OBJC_ARC "YES"
)

target_compile_features(PvZ2forIOS PRIVATE cxx_std_20)

find_library(UIKIT_FRAMEWORK UIKit REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
find_library(COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
find_library(SECURITY_FRAMEWORK Security REQUIRED)
find_library(QUARTZCORE_FRAMEWORK QuartzCore REQUIRED)
find_library(IOKIT_FRAMEWORK IOKit REQUIRED)
find_library(UNIFORMTYPEIDENTIFIERS_FRAMEWORK UniformTypeIdentifiers REQUIRED)
find_library(OPENGLES_FRAMEWORK OpenGLES REQUIRED)
find_library(AVFOUNDATION_FRAMEWORK AVFoundation REQUIRED)
find_library(ZLIB_LIBRARY z REQUIRED)

target_link_libraries(PvZ2forIOS PRIVATE
    dynarmic
    ${UIKIT_FRAMEWORK}
    ${FOUNDATION_FRAMEWORK}
    ${COREFOUNDATION_FRAMEWORK}
    ${COREGRAPHICS_FRAMEWORK}
    ${SECURITY_FRAMEWORK}
    ${QUARTZCORE_FRAMEWORK}
    ${IOKIT_FRAMEWORK}
    ${UNIFORMTYPEIDENTIFIERS_FRAMEWORK}
    ${OPENGLES_FRAMEWORK}
    ${AVFOUNDATION_FRAMEWORK}
    ${ZLIB_LIBRARY}
)
