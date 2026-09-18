#pragma once

#include <cstdint>
#include <string>

struct DynarmicSmokeResult {
    bool ok = false;
    std::uint32_t r0 = 0;
    std::uint32_t pc = 0;
    std::uint32_t halt_reason = 0;
    bool svc_seen = false;
    bool exception_seen = false;
    std::string message;
};

DynarmicSmokeResult RunDynarmicArm32Smoke();
