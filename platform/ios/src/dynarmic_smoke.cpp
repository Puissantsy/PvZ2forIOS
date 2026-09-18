#include "dynarmic_smoke.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <map>
#include <string>
#include <vector>

#include <dynarmic/interface/A32/a32.h>

namespace {

constexpr std::uint32_t kCodeBase = 0x1000;
constexpr std::uint32_t kStopSVC = 0x42;

// ARM mode, little-endian:
//   mov r0, #40
//   add r0, r0, #2
//   svc #0x42
constexpr std::array<std::uint32_t, 3> kArmProgram = {
    0xE3A00028u,
    0xE2800002u,
    0xEF000042u,
};

class SmokeCallbacks final : public Dynarmic::A32::UserCallbacks {
public:
    Dynarmic::A32::Jit* jit = nullptr;
    bool svc_seen = false;
    bool exception_seen = false;
    std::string failure;
    std::uint64_t ticks_left = 1000;

    std::optional<std::uint32_t> MemoryReadCode(std::uint32_t vaddr) override {
        if (vaddr < kCodeBase) {
            return std::nullopt;
        }
        const std::uint32_t offset = vaddr - kCodeBase;
        if ((offset & 3u) != 0) {
            return std::nullopt;
        }
        const std::size_t index = offset / 4;
        if (index >= kArmProgram.size()) {
            return std::nullopt;
        }
        return kArmProgram[index];
    }

    std::uint8_t MemoryRead8(std::uint32_t vaddr) override {
        const auto word = MemoryRead32(vaddr & ~3u);
        const unsigned shift = static_cast<unsigned>((vaddr & 3u) * 8u);
        return static_cast<std::uint8_t>((word >> shift) & 0xffu);
    }

    std::uint16_t MemoryRead16(std::uint32_t vaddr) override {
        return static_cast<std::uint16_t>(MemoryRead8(vaddr)) |
               static_cast<std::uint16_t>(MemoryRead8(vaddr + 1)) << 8;
    }

    std::uint32_t MemoryRead32(std::uint32_t vaddr) override {
        if (vaddr >= kCodeBase) {
            const std::uint32_t offset = vaddr - kCodeBase;
            if ((offset & 3u) == 0) {
                const std::size_t index = offset / 4;
                if (index < kArmProgram.size()) {
                    return kArmProgram[index];
                }
            }
        }

        const auto it = data_memory.find(vaddr);
        if (it != data_memory.end()) {
            return it->second;
        }
        return 0;
    }

    std::uint64_t MemoryRead64(std::uint32_t vaddr) override {
        return static_cast<std::uint64_t>(MemoryRead32(vaddr)) |
               static_cast<std::uint64_t>(MemoryRead32(vaddr + 4)) << 32;
    }

    void MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) override {
        const std::uint32_t aligned = vaddr & ~3u;
        std::uint32_t word = MemoryRead32(aligned);
        const unsigned shift = static_cast<unsigned>((vaddr & 3u) * 8u);
        word &= ~(0xffu << shift);
        word |= static_cast<std::uint32_t>(value) << shift;
        data_memory[aligned] = word;
    }

    void MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) override {
        MemoryWrite8(vaddr, static_cast<std::uint8_t>(value));
        MemoryWrite8(vaddr + 1, static_cast<std::uint8_t>(value >> 8));
    }

    void MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) override {
        data_memory[vaddr] = value;
    }

    void MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) override {
        MemoryWrite32(vaddr, static_cast<std::uint32_t>(value));
        MemoryWrite32(vaddr + 4, static_cast<std::uint32_t>(value >> 32));
    }

    void InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) override {
        failure = "InterpreterFallback at PC=0x" + Hex(pc) +
                  " count=" + std::to_string(num_instructions);
        if (jit) {
            jit->HaltExecution(Dynarmic::HaltReason::UserDefined2);
        }
    }

    void CallSVC(std::uint32_t swi) override {
        svc_seen = true;
        if (swi != kStopSVC) {
            failure = "Unexpected SVC #" + std::to_string(swi);
        }
        if (jit) {
            jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
        }
    }

    void ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) override {
        exception_seen = true;
        failure = "Dynarmic exception at PC=0x" + Hex(pc) +
                  " type=" + std::to_string(static_cast<unsigned>(exception));
        if (jit) {
            jit->HaltExecution(Dynarmic::HaltReason::UserDefined3);
        }
    }

    void AddTicks(std::uint64_t ticks) override {
        if (ticks >= ticks_left) {
            ticks_left = 0;
            if (jit) {
                jit->HaltExecution(Dynarmic::HaltReason::UserDefined4);
            }
            return;
        }
        ticks_left -= ticks;
    }

    std::uint64_t GetTicksRemaining() override {
        return ticks_left;
    }

private:
    static std::string Hex(std::uint32_t value) {
        constexpr char digits[] = "0123456789abcdef";
        std::string result(8, '0');
        for (int i = 7; i >= 0; --i) {
            result[static_cast<std::size_t>(i)] = digits[value & 0xfu];
            value >>= 4;
        }
        return result;
    }

    std::map<std::uint32_t, std::uint32_t> data_memory;
};

} // namespace

DynarmicSmokeResult RunDynarmicArm32Smoke() {
    DynarmicSmokeResult result;

    try {
        SmokeCallbacks callbacks;

        Dynarmic::A32::UserConfig config;
        config.callbacks = &callbacks;
        config.arch_version = Dynarmic::A32::ArchVersion::v7;
        config.always_little_endian = true;
        config.enable_cycle_counting = true;
        config.code_cache_size = 8 * 1024 * 1024;

        Dynarmic::A32::Jit jit{config};
        callbacks.jit = &jit;

        jit.Regs().fill(0);
        jit.Regs()[15] = kCodeBase;
        jit.SetCpsr(0x10u); // User mode, ARM state, little-endian.

        const Dynarmic::HaltReason halt = jit.Run();

        result.r0 = jit.Regs()[0];
        result.pc = jit.Regs()[15];
        result.halt_reason = static_cast<std::uint32_t>(halt);
        result.svc_seen = callbacks.svc_seen;
        result.exception_seen = callbacks.exception_seen;

        if (!callbacks.failure.empty()) {
            result.message = callbacks.failure;
            return result;
        }

        if (!callbacks.svc_seen) {
            result.message = "Guest did not reach the stop SVC.";
            return result;
        }

        if (result.r0 != 42) {
            result.message = "Guest returned R0=" + std::to_string(result.r0) + " instead of 42.";
            return result;
        }

        result.ok = true;
        result.message = "Dynarmic translated ARM32 code to host ARM64 and R0 returned 42.";
        return result;
    } catch (const std::exception& e) {
        result.message = std::string{"Dynarmic exception: "} + e.what();
        return result;
    } catch (...) {
        result.message = "Dynarmic failed with an unknown native exception.";
        return result;
    }
}
