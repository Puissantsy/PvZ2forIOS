cmake_minimum_required(VERSION 3.22)

project(PvZ2Inspector LANGUAGES C CXX OBJC OBJCXX)

if(NOT IOS)
    message(FATAL_ERROR "PvZ2Inspector is intended for iOS/iPadOS. Configure with -DCMAKE_SYSTEM_NAME=iOS.")
endif()

add_executable(PvZ2Inspector MACOSX_BUNDLE
    src/main.mm
    src/inspector_core.cpp
    src/v68_analyzer.cpp
    src/macho_inspector.cpp
)

set_target_properties(PvZ2Inspector PROPERTIES
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.puissantsy.pvz2inspector"
    XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
    XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "17.4"
    XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
    XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
    XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
    XCODE_ATTRIBUTE_CLANG_ENABLE_OBJC_ARC "YES"
)

target_compile_features(PvZ2Inspector PRIVATE cxx_std_20)

find_library(UIKIT_FRAMEWORK UIKit REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
find_library(UNIFORMTYPEIDENTIFIERS_FRAMEWORK UniformTypeIdentifiers REQUIRED)
find_library(ZLIB_LIBRARY z REQUIRED)

target_link_libraries(PvZ2Inspector PRIVATE
    ${UIKIT_FRAMEWORK}
    ${FOUNDATION_FRAMEWORK}
    ${UNIFORMTYPEIDENTIFIERS_FRAMEWORK}
    ${ZLIB_LIBRARY}
)
