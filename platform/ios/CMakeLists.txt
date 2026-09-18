cmake_minimum_required(VERSION 3.22)

project(PvZ2forIOS LANGUAGES C CXX OBJC OBJCXX)

if(NOT IOS)
    message(FATAL_ERROR "This target is intended for iOS/iPadOS. Configure with -DCMAKE_SYSTEM_NAME=iOS.")
endif()

include(FetchContent)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_TESTS_USE_UNICORN OFF CACHE BOOL "" FORCE)
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)
set(DYNARMIC_USE_LLVM OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_PRECOMPILED_HEADERS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)

# LiveContainer's Dynarmic fork already contains the Apple/iOS 26 dual-mapped
# executable-memory path used by LiveExec32. Pin the exact revision that was
# validated while bringing up this project.
FetchContent_Declare(
    dynarmic
    GIT_REPOSITORY https://github.com/LiveContainer/dynarmic.git
    GIT_TAG c97c525ec1432b1e5404ebf091027738005ec168
    GIT_SHALLOW TRUE
    PATCH_COMMAND git apply "${CMAKE_CURRENT_SOURCE_DIR}/patches/dynarmic-ios-nontxm.patch"
)
FetchContent_MakeAvailable(dynarmic)

add_executable(PvZ2forIOS MACOSX_BUNDLE
    src/main.mm
    src/dynarmic_smoke.cpp
)

set_target_properties(PvZ2forIOS PROPERTIES
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.puissantsy.pvz2forios"
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
find_library(SECURITY_FRAMEWORK Security REQUIRED)
find_library(QUARTZCORE_FRAMEWORK QuartzCore REQUIRED)
find_library(IOKIT_FRAMEWORK IOKit REQUIRED)

target_link_libraries(PvZ2forIOS PRIVATE
    dynarmic
    ${UIKIT_FRAMEWORK}
    ${FOUNDATION_FRAMEWORK}
    ${COREFOUNDATION_FRAMEWORK}
    ${SECURITY_FRAMEWORK}
    ${QUARTZCORE_FRAMEWORK}
    ${IOKIT_FRAMEWORK}
)
