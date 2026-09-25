            return;
        }

        result.first_unsupported_import = name;

        const std::uint32_t lr =
            jit ? jit->Regs()[14] : 0u;

        const std::string unsupported_import =
            "Unsupported Android import " +
            name +
            " reached at LR=0x" +
            JniProbeHex(lr) +
            " via trampoline 0x" +
            JniProbeHex(
                binding->second.trampoline);

        RecordSweepIssue(
            "unsupported-import",
            name,
            unsupported_import);

        if (ConsumeSweepRecovery(
                "unsupported-import",
                unsupported_import)) {

            regs[0] = 0u;
            regs[1] = 0u;
            ++supported_calls;
            return;
        }

        result.message =
            unsupported_import;

        jit->HaltExecution(
            Dynarmic::HaltReason::UserDefined2);
    }

    void ExceptionRaised(
        std::uint32_t pc,
        Dynarmic::A32::Exception exception) override {

        auto exception_name =
            [&]() -> const char* {
                switch (exception) {
                case Dynarmic::A32::Exception::UndefinedInstruction:
                    return "UndefinedInstruction";
                case Dynarmic::A32::Exception::UnpredictableInstruction:
                    return "UnpredictableInstruction";
                case Dynarmic::A32::Exception::DecodeError:
                    return "DecodeError";
                case Dynarmic::A32::Exception::SendEvent:
                    return "SendEvent";
                case Dynarmic::A32::Exception::SendEventLocal:
                    return "SendEventLocal";
                case Dynarmic::A32::Exception::WaitForInterrupt:
                    return "WaitForInterrupt";
                case Dynarmic::A32::Exception::WaitForEvent:
                    return "WaitForEvent";
                case Dynarmic::A32::Exception::Yield:
                    return "Yield";
                case Dynarmic::A32::Exception::Breakpoint:
                    return "Breakpoint";
                case Dynarmic::A32::Exception::PreloadData:
                    return "PreloadData";
                case Dynarmic::A32::Exception::PreloadDataWithIntentToWrite:
                    return "PreloadDataWithIntentToWrite";
                case Dynarmic::A32::Exception::PreloadInstruction:
                    return "PreloadInstruction";
                case Dynarmic::A32::Exception::NoExecuteFault:
                    return "NoExecuteFault";
                default:
                    return "Unknown";
                }
            };

        const std::uint32_t lr =
            jit ? jit->Regs()[14] : 0u;
        const std::uint32_t sp =
            jit ? jit->Regs()[13] : 0u;
        const std::uint32_t return_pc =
            lr & ~1u;

        if (V93Enabled() &&
            exception ==
                Dynarmic::A32::Exception::UndefinedInstruction &&
            sp >= 4u) {
            v93_last_exception_valid = true;
            v93_last_exception_pc = pc;
            v93_last_exception_sp = sp;
            v93_last_exception_cpsr =
                jit ? jit->Cpsr() : 0u;
            v93_last_exception_sp_minus_4 =
                mem.Read32Guest(
                    sp - 4u);
        }

        std::ostringstream out;
        out
            << "Dynarmic exception "
            << exception_name()
            << " type="
            << static_cast<unsigned>(exception)
            << " PC=0x"
            << JniProbeHex(pc)
            << " LR=0x"
            << JniProbeHex(lr)
            << " returnPC=0x"
            << JniProbeHex(return_pc)
            << " SP=0x"
            << JniProbeHex(sp)
            << " phase="
            << (current_lifecycle_name.empty()
                    ? "n/a"
                    : current_lifecycle_name)
            << " pthread="
            << current_probe_thread_id
            << " nullRecoveries="
            << null_execute_recoveries;

        if (jit) {
            out
                << " CPSR=0x"
                << JniProbeHex(jit->Cpsr());

            for (std::size_t reg = 0;
                 reg < 13;
                 ++reg) {
                out
                    << " r"
                    << reg
                    << "=0x"
                    << JniProbeHex(
                        jit->Regs()[reg]);
            }

            out
                << " stack={";

            for (std::uint32_t off = 0;
                 off < 32u;
                 off += 4u) {
                if (off != 0u) {
                    out << ",";
                }
                out
                    << "0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            sp + off));
            }

            out << "}";

            if (V93Enabled() &&
                v93_last_exception_valid) {
                out
                    << " v93ReturnWordAtSPMinus4=0x"
                    << JniProbeHex(
                        v93_last_exception_sp_minus_4)
                    << " bit0="
                    << (v93_last_exception_sp_minus_4 & 1u);
            }

            if (return_pc >= 8u) {
                out
                    << " codeAroundLR={0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc - 8u))
                    << ",0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc - 4u))
                    << ",0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc))
                    << ",0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc + 4u))
                    << "}";
            }
        }

        out
            << " VFS{reads="
            << obb_read_calls
            << ",nonzero="
            << obb_nonzero_read_calls
            << ",bytes="
            << obb_bytes_returned
            << ",maxEnd=0x"
            << JniProbeHex(
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        obb_max_read_end,
                        0xffffffffull)))
            << ",seeks="
            << obb_seek_calls
            << ",lastReadOff=0x"
            << JniProbeHex(
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        last_obb_read_offset,
                        0xffffffffull)))
            << ",lastReq="
            << last_obb_read_requested
            << ",lastRet="
            << last_obb_read_returned
            << ",lastSeek=0x"
            << JniProbeHex(
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        last_obb_seek_target,
                        0xffffffffull)))
            << "}";

        if (!last_android_log.empty()) {
            out
                << " lastLog=\""
                << last_android_log
                << "\"";
        }

        const char packages_version[] =
            "RESFILE_PACKAGES_VERSION";

        if (obb_data &&
            obb_size >=
                sizeof(packages_version) - 1u) {

            const auto* begin =
                obb_data;
            const auto* end =
                obb_data + obb_size;
            const auto* hit =
                std::search(
                    begin,
                    end,
                    packages_version,
                    packages_version +
                        sizeof(packages_version) - 1u);

            if (hit != end) {
                out
                    << " packagesVersionInOBB=0x"
                    << JniProbeHex(
                        static_cast<std::uint32_t>(
                            hit - begin));
            } else {
                out
                    << " packagesVersionInOBB=NOT_FOUND";
            }
        }

        const std::string diagnostic =
            out.str();

        AppendCritical(
            "V23 EXCEPTION: " +
            diagnostic);

        V46AppendControlFlowMap(
            "exception",
            pc,
            lr,
            sp);

        // A direct branch/call through address 0 is a common artifact of an
        // optional Android callback/resource hook that is absent from the
        // probe environment. For lifecycle/worker execution, recover a small
        // bounded number of such calls exactly like a null callback returning
        // 0. We still log the complete callsite first so the recovery is
        // auditable and can be replaced by a real bridge later.
        const bool recoverable_null_call =
            exception ==
                Dynarmic::A32::Exception::NoExecuteFault &&
            pc == 0u &&
            jit != nullptr &&
            return_mode == ReturnMode::Lifecycle &&
            return_pc != 0u &&
            mem.Ptr(return_pc, 2) != nullptr &&
            sweep_recoveries <
                kSweepRecoveryLimit;

        if (recoverable_null_call) {
            ++null_execute_recoveries;

            RecordSweepIssue(
                "null-call",
                JniProbeHex(return_pc),
                "NoExecuteFault at PC=0 returned to LR=0x" +
                    JniProbeHex(lr) +
                    " phase=" +
                    (current_lifecycle_name.empty()
                        ? std::string{"n/a"}
                        : current_lifecycle_name));

            if (!ConsumeSweepRecovery(
                    "null-call",
                    "resume at LR=0x" +
                        JniProbeHex(lr))) {

                result.message =
                    diagnostic;
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined3);
                return;
            }

            auto& regs =
                jit->Regs();

            regs[0] = 0u;
            regs[15] =
                return_pc;

            std::uint32_t cpsr =
                jit->Cpsr();

            if ((lr & 1u) != 0u) {
                cpsr |= 0x20u;
            } else {
                cpsr &= ~0x20u;
            }

            jit->SetCpsr(cpsr);
            jit->ClearExclusiveState();

            Append(
                "V23 NULL-CALL RECOVERY #" +
                std::to_string(
                    null_execute_recoveries) +
                ": synthesized r0=0 and resumed at LR=0x" +
                JniProbeHex(lr));

            result.message.clear();

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined4);
            return;
        }

        result.message =
            diagnostic;
        if(V89Enabled())V89EmitTerminalSummaries("guest-exception");
        if(V90Enabled())V90EmitTerminalSummaries("guest-exception");
        if(V91Enabled())V91EmitTerminalSummary("guest-exception");

        if (jit) {
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined3);
        }
    }

    void AddTicks(std::uint64_t ticks) override {
        ticks_consumed += ticks;
        // No clock call and no SVC in Wwise. v110 keeps its guest-tick
        // accounting; v111 only arms a sparse private JIT checkpoint.
        V110RecordAudioTicks(ticks);
        const bool v111_audio_sample_due =
            V111AccumulateAudioSampleTicks(ticks);

        if (V102Enabled() &&
            V103AudioRealtimeWindow() &&
            !v102_audio_inline_active &&
            return_mode == ReturnMode::Lifecycle &&
            current_probe_thread_id == 0u &&
            soft_slice_timeout &&
            current_lifecycle_name !=
                "V100_OpenSL_BufferQueueCallback") {

            v102_audio_poll_ticks += ticks;
            constexpr std::uint64_t
                kV102AudioPollGuestTicks = 32768ull;

            if (v102_audio_poll_ticks >=
                kV102AudioPollGuestTicks) {
                v102_audio_poll_ticks = 0u;

                if (V102RefreshAudioServiceRequest(
                        true)) {
                    ++v102_audio_forced_slices;
                    v102_audio_forced_halt_pending = true;
                    if (jit) {
                        jit->HaltExecution(
                            Dynarmic::HaltReason::UserDefined4);
                    }
                    return;
                }
            }
        }

        if((V89Enabled()||V90Enabled())&&gV72StopRequested.load(std::memory_order_acquire)){
            if(!result.hard_stop_requested){
                result.hard_stop_requested=true;
                const auto pc=jit?jit->Regs()[15]:0u,lr=jit?jit->Regs()[14]:0u,cpsr=jit?jit->Cpsr():0u;
                const std::string tag=
                    RuntimeModeTag();
                result.message=tag+" Hard Stop requested by user.";
                AppendCritical(tag+" HARD STOP frame="+std::to_string(current_frame_number)+" tid="+std::to_string(current_probe_thread_id)+" PC="+V46DescribeGuestAddress(pc)+" LR="+V46DescribeGuestAddress(lr)+" CPSR=0x"+JniProbeHex(cpsr));
                if(V89Enabled())V89EmitTerminalSummaries("user-hard-stop");
                if(V90Enabled())V90EmitTerminalSummaries("user-hard-stop");
                if(V91Enabled())V91EmitTerminalSummary("user-hard-stop");
            }
            ticks_left=0u;if(jit)jit->HaltExecution(Dynarmic::HaltReason::UserDefined3);return;
        }

        auto phase_name =
            [&]() -> std::string {
                switch (return_mode) {
                case ReturnMode::Constructor:
                    return
                        "constructor[" +
                        std::to_string(current_constructor_index) +
                        "]";
                case ReturnMode::GameAppInitialize:
                    return "Native_GameAppInitialize";
                case ReturnMode::Lifecycle:
                    return
                        current_lifecycle_name.empty()
                            ? "lifecycle"
                            : current_lifecycle_name;
                case ReturnMode::AudioCallback:
                    return "V102_OpenSL_AsyncCallback";
                case ReturnMode::JniOnLoad:
                default:
                    return "JNI_OnLoad";
                }
            };

        if (ticks_consumed >= next_tick_report) {
            std::ostringstream progress;
            progress
                << phase_name()
                << " long-run progress: ticks="
                << ticks_consumed
                << " PC=0x"
                << JniProbeHex(jit ? jit->Regs()[15] : 0u)
                << " LR=0x"
                << JniProbeHex(jit ? jit->Regs()[14] : 0u)
                << " SP=0x"
                << JniProbeHex(jit ? jit->Regs()[13] : 0u);

            Append(progress.str());

            while (next_tick_report <= ticks_consumed) {
                next_tick_report += 5000000ull;
            }
        }

        if (ticks >= ticks_left) {
            ticks_left = 0;

            if (soft_slice_timeout) {
                if(V89Enabled())V89RecordQuantumSample();
                if (jit) {
                    jit->HaltExecution(
                        Dynarmic::HaltReason::UserDefined4);
                }
                return;
            }

            const std::uint32_t pc =
                jit ? jit->Regs()[15] : 0u;
            const std::uint32_t lr =
                jit ? jit->Regs()[14] : 0u;
            const std::uint32_t sp =
                jit ? jit->Regs()[13] : 0u;

            std::ostringstream timeout;
            timeout
                << phase_name()
                << " exceeded the 50M-tick probe budget"
                << " at PC=0x" << JniProbeHex(pc)
                << " LR=0x" << JniProbeHex(lr)
                << " caller=0x"
                << JniProbeHex(lr >= 4u ? lr - 4u : lr)
                << " SP=0x" << JniProbeHex(sp)
                << " after " << ticks_consumed
                << " ticks";

            if (jit) {
                timeout
                    << "; r0=0x" << JniProbeHex(jit->Regs()[0])
                    << " r1=0x" << JniProbeHex(jit->Regs()[1])
                    << " r2=0x" << JniProbeHex(jit->Regs()[2])
                    << " r3=0x" << JniProbeHex(jit->Regs()[3])
                    << " r4=0x" << JniProbeHex(jit->Regs()[4])
                    << " r5=0x" << JniProbeHex(jit->Regs()[5])
                    << " r6=0x" << JniProbeHex(jit->Regs()[6])
                    << " r7=0x" << JniProbeHex(jit->Regs()[7]);
            }

            timeout << ".";

            result.message = timeout.str();
            Append("EXECUTION BUDGET: " + result.message);

            V46AppendControlFlowMap(
                "execution-budget",
                pc,
                lr,
                sp);

            if (jit) {
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined4);
            }
            return;
        }

        if (v111_audio_sample_due &&
            jit != nullptr &&
            V111ArmAudioSampleHalt()) {
            // The normal slice budget is still authoritative. Consume this
            // block's ticks, halt only to expose a saved PC, then the worker
            // loop resumes the same tid immediately with the remaining budget.
            ticks_left -= ticks;
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined4);
            return;
        }

        ticks_left -= ticks;
    }

    std::uint64_t GetTicksRemaining() override {
        return ticks_left;
    }

    void AppendWithClass(
        ProbeLogClass log_class,
        const std::string& line) {

        if (!ShouldKeepLogLine(
                log_class,
                line)) {
            ++v85_log_lines_suppressed;
            return;
        }

        if (V85PerformanceEnabled()) {
            ++v85_log_lines_kept;
        }

        // Guest-derived strings can contain arbitrary bytes. Keep the trace
            // valid UTF-8/ASCII so one bad Android log/method string cannot make
            // the entire diagnostic disappear in NSStringFromStd.
            constexpr char hex[] = "0123456789abcdef";
            std::string safe;
            safe.reserve(
                std::min<std::size_t>(
                    line.size() * 2u,
                    8192u));
    
            const std::size_t limit =
                std::min<std::size_t>(
                    line.size(),
                    4096u);
    
            for (std::size_t i = 0; i < limit; ++i) {
                const unsigned char ch =
                    static_cast<unsigned char>(line[i]);
    
                if ((ch >= 0x20u && ch <= 0x7eu) ||
                    ch == '\t') {
                    safe.push_back(
                        static_cast<char>(ch));
                } else {
                    safe += "\\x";
                    safe.push_back(hex[(ch >> 4) & 0x0fu]);
                    safe.push_back(hex[ch & 0x0fu]);
                }
            }
    
            if (line.size() > limit) {
                safe += "...<truncated>";
            }
    
            trace << safe << '\n';
    
            if (progress_callback) {
                progress_callback(safe);
            }
        }
    
    
    void Append(const std::string& line) {
        AppendWithClass(
            ProbeLogClass::Legacy,
            line);
    }

    void AppendDiagnostic(
        const std::string& line) {
        AppendWithClass(
            ProbeLogClass::Diagnostic,
            line);
    }

    void AppendCritical(
        const std::string& line) {
        AppendWithClass(
            ProbeLogClass::Critical,
            line);
    }

    std::string Trace() const {
        return trace.str();
    }

private:
    JniProbeGuestMemory& mem;
    PvZ2JniProbeResult& result;
    PvZ2ProbeProgress progress_callback;
    std::ostringstream trace;
};

std::uint32_t JniProbeMakeTrampoline(
    JniProbeGuestMemory& memory,
    std::uint32_t slot,
    std::uint32_t svc) {

    const std::uint32_t address =
        kJniProbeTrampolineBase +
        slot * 8u;

    auto* p = memory.Ptr(address, 8);
    if (!p) {
        return 0;
    }

    Write32(
        p + 0,
        0xEF000000u |
        (svc & 0x00ffffffu));

    Write32(
        p + 4,
        0xE12FFF1Eu);

    return address;
}


std::uint32_t JniProbeMakePthreadOnceShim(
    JniProbeGuestMemory& memory) {

    // Minimal single-threaded Android pthread_once equivalent executed
    // entirely as ARMv7 guest code. Bionic pthread_once_t uses a state
    // machine where 0 = never run and 2 = completed. We mark 1 while the
    // initializer is executing and 2 after it returns.
    //
    //   push {r4,lr}
    //   mov  r4,r0
    //   ldr  r2,[r4]
    //   cmp  r2,#2
    //   moveq r0,#0
    //   popeq {r4,pc}
    //   mov  r2,#1
    //   str  r2,[r4]
    //   blx  r1
    //   mov  r2,#2
    //   str  r2,[r4]
    //   mov  r0,#0
    //   pop  {r4,pc}
    constexpr std::uint32_t kShimAddress =
        kJniProbeTrampolineBase + 0x00080000u;

    constexpr std::uint32_t words[] = {
        0xE92D4010u,
        0xE1A04000u,
        0xE5942000u,
        0xE3520002u,
        0x03A00000u,
        0x08BD8010u,
        0xE3A02001u,
        0xE5842000u,
        0xE12FFF31u,
        0xE3A02002u,
        0xE5842000u,
        0xE3A00000u,
        0xE8BD8010u,
    };

    auto* p =
        memory.Ptr(
            kShimAddress,
            sizeof(words));

    if (!p) {
        return 0;
    }

    for (std::size_t i = 0;
         i < sizeof(words) / sizeof(words[0]);
         ++i) {

        Write32(
            p + i * 4u,
            words[i]);
    }

    return kShimAddress;
}


std::uint32_t JniProbeMakePthreadCreateShim(
    JniProbeGuestMemory& memory) {

    // Constructor-probe pthread_create: execute the guest start routine
    // synchronously in the same emulated process, store a synthetic thread id,
    // and return success. Real concurrent guest threads are a later subsystem.
    constexpr std::uint32_t kShimAddress =
        kJniProbeTrampolineBase + 0x00080100u;

    constexpr std::uint32_t words[] = {
        0xE92D4030u, // push {r4,r5,lr}
        0xE1A04000u, // mov r4,r0
        0xE1A05002u, // mov r5,r2
        0xE1A00003u, // mov r0,r3
        0xE12FFF35u, // blx r5
        0xE3A01001u, // mov r1,#1
        0xE5841000u, // str r1,[r4]
        0xE3A00000u, // mov r0,#0
        0xE8BD8030u, // pop {r4,r5,pc}
    };

    auto* p =
        memory.Ptr(
            kShimAddress,
            sizeof(words));

    if (!p) {
        return 0;
    }

    for (std::size_t i = 0;
         i < sizeof(words) / sizeof(words[0]);
         ++i) {
        Write32(
            p + i * 4u,
            words[i]);
    }

    return kShimAddress;
}

std::uint32_t JniProbeMakePthreadExitShim(
    JniProbeGuestMemory& memory) {

    constexpr std::uint32_t kShimAddress =
        kJniProbeTrampolineBase + 0x00080200u;

    auto* p =
        memory.Ptr(
            kShimAddress,
            4);

    if (!p) {
        return 0;
    }

    Write32(
        p,
        0xE12FFF1Eu); // bx lr

    return kShimAddress;
}

std::uint32_t JniProbeAllocateImportedObject(
    JniProbeGuestMemory& memory,
    const std::string& name,
    PvZ2JniCallbacks& callbacks) {

    if (name == "__stack_chk_guard") {
        const std::uint32_t address =
            memory.AllocateObject(4, 4);

        if (address) {
            memory.Write32Guest(
                address,
                0x51a7c0deu);
        }

        return address;
    }

    if (callbacks.V57CtypeEnabled() &&
        (name == "_toupper_tab_" ||
         name == "_tolower_tab_" ||
         name == "_ctype_")) {

        const std::uint32_t variable =
            memory.AllocateObject(
                4u,
                4u);

        if (variable == 0u) {
            return 0u;
        }

        std::uint32_t backing = 0u;

        if (name == "_toupper_tab_" ||
            name == "_tolower_tab_") {

            backing =
                memory.AllocateObject(
                    257u * 2u,
                    2u);

            if (backing == 0u) {
                return 0u;
            }

            // Bionic ABI: entry 0 represents EOF (-1); guest byte c is
            // read at entry c+1. Values are 16-bit signed shorts.
            memory.Write16Guest(
                backing,
                0xffffu);

            for (std::uint32_t c = 0u;
                 c <= 255u;
                 ++c) {
                std::uint32_t mapped = c;

                if (name ==
                        "_toupper_tab_" &&
                    c >=
                        static_cast<std::uint32_t>('a') &&
                    c <=
                        static_cast<std::uint32_t>('z')) {
                    mapped =
                        c -
                        static_cast<std::uint32_t>('a') +
                        static_cast<std::uint32_t>('A');
                } else if (
                    name ==
                        "_tolower_tab_" &&
                    c >=
                        static_cast<std::uint32_t>('A') &&
                    c <=
                        static_cast<std::uint32_t>('Z')) {
                    mapped =
                        c -
                        static_cast<std::uint32_t>('A') +
                        static_cast<std::uint32_t>('a');
                }

                memory.Write16Guest(
                    backing +
                        (c + 1u) * 2u,
                    static_cast<std::uint16_t>(
                        mapped));
            }
        } else {
            backing =
                memory.AllocateObject(
                    257u,
                    1u);

            if (backing == 0u) {
                return 0u;
            }

            constexpr std::uint8_t kUpper = 0x01u;
            constexpr std::uint8_t kLower = 0x02u;
            constexpr std::uint8_t kNumber = 0x04u;
            constexpr std::uint8_t kSpace = 0x08u;
            constexpr std::uint8_t kPunct = 0x10u;
            constexpr std::uint8_t kControl = 0x20u;
            constexpr std::uint8_t kHex = 0x40u;
            constexpr std::uint8_t kBlank = 0x80u;

            memory.Write8Guest(
                backing,
                0u);

            for (std::uint32_t c = 0u;
                 c <= 255u;
                 ++c) {
                std::uint8_t flags = 0u;

                // Match Android/Bionic's historical _C_ctype_
                // table used by this era of ARM binaries. In particular,
                // only ASCII space carries _B; 0x80..0x9f are control and
                // 0xa0..0xff are punctuation in the ISO-8859-oriented table.
                if (c <= 0x1fu ||
                    c == 0x7fu ||
                    (c >= 0x80u &&
                     c <= 0x9fu)) {
                    flags |= kControl;
                }

                if (c == 0x09u ||
                    c == 0x0au ||
                    c == 0x0bu ||
                    c == 0x0cu ||
                    c == 0x0du ||
                    c == 0x20u) {
                    flags |= kSpace;
                }

                if (c == 0x20u) {
                    flags |= kBlank;
                }

                if (c >=
                        static_cast<std::uint32_t>('A') &&
                    c <=
                        static_cast<std::uint32_t>('Z')) {
                    flags |= kUpper;

                    if (c <=
                        static_cast<std::uint32_t>('F')) {
                        flags |= kHex;
                    }
                } else if (
                    c >=
                        static_cast<std::uint32_t>('a') &&
                    c <=
                        static_cast<std::uint32_t>('z')) {
                    flags |= kLower;

                    if (c <=
                        static_cast<std::uint32_t>('f')) {
                        flags |= kHex;
                    }
                } else if (
                    c >=
                        static_cast<std::uint32_t>('0') &&
                    c <=
                        static_cast<std::uint32_t>('9')) {
                    flags |=
                        kNumber |
                        kHex;
                } else if (
                    (c >= 0x21u &&
                     c <= 0x7eu) ||
                    c >= 0xa0u) {
                    flags |= kPunct;
                }

                memory.Write8Guest(
                    backing +
                        c +
                        1u,
                    flags);
            }
        }

        memory.Write32Guest(
            variable,
            backing);

        if (name == "_toupper_tab_") {
            callbacks.v57_toupper_variable =
                variable;
            callbacks.v57_toupper_backing =
                backing;
        } else if (
            name == "_tolower_tab_") {
            callbacks.v57_tolower_variable =
                variable;
            callbacks.v57_tolower_backing =
                backing;
        } else {
            callbacks.v57_ctype_variable =
                variable;
            callbacks.v57_ctype_backing =
                backing;
        }

        return variable;
    }

    if (callbacks.V99Enabled() &&
        (name == "SL_IID_ENGINE" ||
         name == "SL_IID_PLAY" ||
         name == "SL_IID_BUFFERQUEUE" ||
         name == "SL_IID_ANDROIDCONFIGURATION" ||
         name == "SL_IID_AUDIOIODEVICECAPABILITIES")) {

        // OpenSL exports each IID as a pointer-valued data symbol. The ELF
        // relocation therefore needs the address of a guest variable whose
        // value is the stable IID object pointer, not the zero-filled generic
        // imported-data placeholder used by earlier probes.
        const std::uint32_t variable =
            memory.AllocateObject(
                4u,
                4u);
        const std::uint32_t backing =
            memory.AllocateObject(
                16u,
                4u);

        if (variable == 0u ||
            backing == 0u) {
            return 0u;
        }

        std::uint32_t token =
            0x534c0000u;
        for (const unsigned char ch :
             name) {
            token =
                (token * 33u) ^
                static_cast<std::uint32_t>(
                    ch);
        }

        memory.Write32Guest(
            backing + 0u,
            token);
        memory.Write32Guest(
            backing + 4u,
            token ^ 0x13579bdfu);
        memory.Write32Guest(
            backing + 8u,
            token ^ 0x2468ace0u);
        memory.Write32Guest(
            backing + 12u,
            token ^ 0xa5a5a5a5u);
        memory.Write32Guest(
            variable,
            backing);

        callbacks.V99RegisterOpenSLIID(
            name,
            backing);

        return variable;
    }

    // Deliberately preserve the v56 generic placeholder for all other
    // imported objects and for the V56_BASELINE control mode.
    return memory.AllocateObject(64, 8);
}

bool JniProbePrepareRuntime(
    JniProbeLoadedElf& loaded,
    JniProbeGuestMemory& memory,
    PvZ2JniCallbacks& callbacks,
    PvZ2JniProbeResult& result,
    std::uint32_t& return_trampoline,
    std::string& error) {

    memory.image = loaded.image;
    callbacks.loaded_elf = &loaded;
    callbacks.V91ConfigureRelro(loaded);

    callbacks.Append(
        "V46 ADDRESS MAP READY: guestBase=0x" +
        JniProbeHex(kGuestBase) +
        " imageSize=0x" +
        JniProbeHex(
            static_cast<std::uint32_t>(
                loaded.image.size())) +
        " dynsyms=" +
        std::to_string(loaded.dynsyms.size()) +
        " exidxFunctionStarts=" +
        std::to_string(loaded.function_starts.size()) +
        " regions={libPVZ2:0x10000000,stack:0x20000000,heap:0x30000000,trampoline:0x40000000,JNI:0x50000000,objects:0x51000000}");

    std::uint32_t trampoline_slot = 0;
    std::uint32_t import_svc_index = 0;

    for (const auto& rel : loaded.relocs) {
        const std::uint32_t type =
            rel.info & 0xffu;

        const std::uint32_t symbol_index =
            rel.info >> 8;

        if (!RangeOk(
                rel.offset,
                4,
                memory.image.size())) {
            error =
                "JNI probe relocation target is outside the mapped image.";
            return false;
        }

        if (type == kRArmRelative) {
            const std::uint32_t addend =
                Read32(
                    memory.image.data() +
                    rel.offset);

            Write32(
                memory.image.data() +
                rel.offset,
                kGuestBase +
                addend);
            continue;
        }

        if (type != kRArmJumpSlot &&
            type != kRArmGlobDat) {
            continue;
        }

        const std::string name =
            JniProbeSymbolName(
                loaded,
                symbol_index);

        if (name.empty()) {
            error =
                "JNI probe import relocation has an invalid symbol name.";
            return false;
        }

        if (symbol_index >=
            loaded.dynsyms.size()) {
            error =
                "JNI probe import relocation symbol index is invalid.";
            return false;
        }

        const std::uint32_t symbol_type =
            loaded.dynsyms[symbol_index].info &
            0x0fu;

        const bool function_like =
            type == kRArmJumpSlot ||
            symbol_type == 2u;

        if (function_like) {
            if (name == "pthread_once") {
                const std::uint32_t shim =
                    JniProbeMakePthreadOnceShim(
                        memory);

                if (!shim) {
                    error =
                        "JNI probe could not allocate pthread_once guest shim.";
                    return false;
                }

                Write32(
                    memory.image.data() +
                    rel.offset,
                    shim);

                callbacks.V91RegisterProtectedImport(
                    kGuestBase + rel.offset,
                    shim,
                    name,
                    type);

                callbacks.Append(
                    "installed guest-native pthread_once shim at 0x" +
                    JniProbeHex(shim));

                ++result.imports_patched;
                continue;
            }

            const std::uint32_t svc =
                kJniProbeImportSvcBase +
                import_svc_index++;

            const std::uint32_t trampoline =
                JniProbeMakeTrampoline(
                    memory,
                    trampoline_slot++,
                    svc);

            if (!trampoline) {
                error =
                    "JNI probe trampoline arena exhausted.";
                return false;
            }

            Write32(
                memory.image.data() +
                rel.offset,
                trampoline);

            callbacks.V91RegisterProtectedImport(
                kGuestBase + rel.offset,
                trampoline,
                name,
                type);

            callbacks.imports_by_svc.emplace(
                svc,
                JniProbeImportBinding{
                    trampoline,
                    name});

            ++result.imports_patched;
        } else {
            const std::uint32_t object =
                JniProbeAllocateImportedObject(
                    memory,
                    name,
                    callbacks);

            if (!object) {
                error =
                    "JNI probe imported-object arena exhausted.";
                return false;
            }

            Write32(
                memory.image.data() +
                rel.offset,
                object);

            callbacks.V91RegisterProtectedImport(
                kGuestBase + rel.offset,
                object,
                name,
                type);

            if (callbacks.V57CtypeEnabled() &&
                (name == "_toupper_tab_" ||
                 name == "_tolower_tab_" ||
                 name == "_ctype_")) {

                callbacks.Append(
                    "V57 CTYPE IMPORT symbol=" +
                    name +
                    " GOT=0x" +
                    JniProbeHex(
                        kGuestBase +
                        rel.offset) +
                    " variable=0x" +
                    JniProbeHex(object) +
                    " backing=0x" +
                    JniProbeHex(
                        memory.Read32Guest(
                            object)));
            }

            ++result.imports_patched;
        }
    }

    if (callbacks.V99Enabled()) {
        const std::array<const char*, 16> v99_methods = {{
            "__v99_sl_unsupported",
            "__v99_sl_object_realize",
            "__v99_sl_object_get_state",
            "__v99_sl_object_get_interface",
            "__v99_sl_object_register_callback",
            "__v99_sl_object_destroy",
            "__v99_sl_engine_create_audio_player",
            "__v99_sl_engine_create_output_mix",
            "__v99_sl_play_set_state",
            "__v99_sl_queue_enqueue",
            "__v99_sl_queue_clear",
            "__v99_sl_queue_get_state",
            "__v99_sl_queue_register_callback",
            "__v99_sl_android_config_set",
            "__v99_sl_caps_get_outputs",
            "__v99_sl_caps_query_output",
        }};

        for (const char* method_name :
             v99_methods) {
            const std::uint32_t svc =
                kJniProbeImportSvcBase +
                import_svc_index++;
            const std::uint32_t trampoline =
                JniProbeMakeTrampoline(
                    memory,
                    trampoline_slot++,
                    svc);

            if (trampoline == 0u) {
                error =
                    "v99 OpenSL synthetic trampoline arena exhausted.";
                return false;
            }

            callbacks.imports_by_svc.emplace(
                svc,
                JniProbeImportBinding{
                    trampoline,
                    method_name});
            callbacks.V99RegisterOpenSLMethod(
                method_name,
                trampoline);
        }

        if (!callbacks.V99EnsureOpenSLObjects()) {
            error =
                "v99 OpenSL guest object/interface construction failed.";
            return false;
        }
    }

    if (callbacks.V57CtypeEnabled() &&
        !callbacks.V57LogCtypeSelfCheck()) {
        error =
            "v57 Bionic ctype imported-data ABI self-check failed before guest startup.";
        return false;
    }

    // v61 safety proof: do not enable cooperative worker scheduling from an
    // arbitrary sampled PC. Verify the resource-stream pump's trylock/unlock
    // structure and epilogue directly in the original ARM image. Only the
    // pthread_mutex_unlock return at this verified epilogue may become a
    // worker scheduling boundary.
    const auto v61_word =
        [&](std::uint32_t offset) {
            return
                offset + 4u <= memory.image.size()
                    ? Read32(
                          memory.image.data() + offset)
                    : 0u;
        };

    callbacks.v61_res_stream_pump_signature_ok =
        v61_word(0x00868b98u) == 0xe2840068u &&
        v61_word(0x00868ba0u) == 0xebe1ffcfu &&
        v61_word(0x00868f68u) == 0xe59d0008u &&
        v61_word(0x00868f6cu) == 0xebe1fe55u &&
        v61_word(0x00868f70u) == 0xe28dd024u &&
        v61_word(0x00868f74u) == 0xe8bd8ff0u;

    if (!callbacks.v61_res_stream_pump_signature_ok) {
        error =
            "v61 resource-stream pump safety signature did not match PvZ2 1.5.252752; refusing to schedule workers at an unverified boundary.";
        return false;
    }

    callbacks.Append(
        "V61 RES-STREAM PUMP BOUNDARY: verified trylock@0x10868ba0 and unlock@0x10868f6c with epilogue@0x10868f70. During Native_onDrawFrame only, the main thread yields after this unlock and the scheduler runs at most one deferred worker slice round-robin; no worker is injected while the pump mutates its task containers.");

    // v45: keep 0x86f66c's native lookup logic intact, but observe the exact
    // entry plus all three relevant return shapes. v44 proved the group path
    // never produced a null-valued found node. The missing alternating IDs
    // instead bypass both old miss traps, so v45 additionally replaces the
    // global found-node LDR at 0x86fa84 and checks node+0x14 directly.
    auto patch_resource_native_miss =
        [&](std::uint32_t offset,
            std::uint32_t expected,
            std::uint32_t svc) {

            if (offset + 4u >
                    memory.image.size() ||
                Read32(
                    memory.image.data() +
                    offset) != expected) {
                return false;
            }

            Write32(
                memory.image.data() +
                    offset,
                0xEF000000u |
                (svc & 0x00ffffffu));

            return true;
        };

    // v85 keeps only the functional resource-registry/wrapper traps from
    // this old combined block. Startup/GameState/registry probes are skipped.
    if (!patch_resource_native_miss(
            0x0086f674u, 0xe1a04002u, kJniProbeSvcResourceRegistryEntry) ||
        !patch_resource_native_miss(
            0x0086f8a0u, 0xe3a00000u, kJniProbeSvcResourceRegistryMissGroup) ||
        !patch_resource_native_miss(
            0x0086fa78u, 0xe3a00000u, kJniProbeSvcResourceRegistryMissGlobal) ||
        !patch_resource_native_miss(
            0x0086fa84u, 0xe59a0014u, kJniProbeSvcResourceRegistryGlobalValue) ||
        !patch_resource_native_miss(
            0x0087a708u, 0xea000018u, kJniProbeSvcResourceWrapperDirectReturn) ||
        !patch_resource_native_miss(
            0x0087a76cu, 0xe3a00000u, kJniProbeSvcResourceWrapperExhausted)) {
        error =
            "v85 functional resource-registry bridge signature mismatch for PvZ2 1.5.252752.";
        return false;
    }

    if (!callbacks.V85PerformanceEnabled()) {
        if (
        !patch_resource_native_miss(
            0x002747d8u,
            0xe1a04000u,
            kJniProbeSvcGameStateApply) ||
        !patch_resource_native_miss(
            0x00274b4cu,
            0xe1a04000u,
            kJniProbeSvcGameStateRequest) ||
        !patch_resource_native_miss(
            0x000f66e4u,
            0xe28dd0b0u,
            kJniProbeSvcStartupGroupsCtorSnapshot) ||
        !patch_resource_native_miss(
            0x002c84d0u,
            0xe595064cu,
            kJniProbeSvcStartupGateAResource) ||
        !patch_resource_native_miss(
            0x002c85ccu,
            0xe1a04000u,
            kJniProbeSvcStartupGroupsLookupResult) ||
        !patch_resource_native_miss(
            0x002c85f4u,
            0xe086a00au,
            kJniProbeSvcStartupGroupsContribution) ||
        !patch_resource_native_miss(
            0x002c8620u,
            0xee00ba10u,
            kJniProbeSvcStartupGateATotals) ||
        !patch_resource_native_miss(
            0x002769d4u,
            0xee010a10u,
            kJniProbeSvcStartupGateAResult) ||
        !patch_resource_native_miss(
            0x005143a4u,
            0xe5901098u,
            kJniProbeSvcStartupGateCState) ||
        !patch_resource_native_miss(
            0x00276a30u,
            0xe5940430u,
            kJniProbeSvcStartupGateDCounter) ||
        !patch_resource_native_miss(
            0x00276a3cu,
            0xe59f03c8u,
            kJniProbeSvcStartupAfterD) ||
        !patch_resource_native_miss(
            0x00276a60u,
            0xe5d00b7au,
            kJniProbeSvcStartupGateEByte) ||
        !patch_resource_native_miss(
            0x0036bbfcu,
            0xe1a00004u,
            kJniProbeSvcStartupGateFResult) ||
        !patch_resource_native_miss(
            0x002b88ecu,
            0xe1a00004u,
            kJniProbeSvcStartupGateGResult) ||
        !patch_resource_native_miss(
            0x002b8b88u,
            0xe1a00004u,
            kJniProbeSvcStartupGateHResult) ||
        !patch_resource_native_miss(
            0x004855b0u,
            0xe1a00005u,
            kJniProbeSvcStartupGateIResult) ||
        !patch_resource_native_miss(
            0x0037d158u,
            0xe1a01000u,
            kJniProbeSvcStartupGateJObject) ||
        !patch_resource_native_miss(
            0x00276adcu,
            0xe1a00004u,
            kJniProbeSvcStartupPatchMarker) ||
        !patch_resource_native_miss(
            0x00276b20u,
            0xe1a05000u,
            kJniProbeSvcStartupMainFlow) ||
        !patch_resource_native_miss(
            0x002ef188u,
            0xe1a00004u,
            kJniProbeSvcStartupProgressResult) ||
        !patch_resource_native_miss(
            0x00423adcu,
            0xe1a00004u,
            kJniProbeSvcStartupFindResult) ||
        !patch_resource_native_miss(
            0x004ac370u,
            0xe1a00004u,
            kJniProbeSvcStartupLateResult) ||
        !patch_resource_native_miss(
            0x00276d70u,
            0xe1a00004u,
            kJniProbeSvcStartupMainMenuMarker) ||
        !patch_resource_native_miss(
            0x00867710u,
            0xe1a08000u,
            kJniProbeSvcV56RegistryPipelineEntry) ||
        !patch_resource_native_miss(
            0x00867860u,
            0xe2880028u,
            kJniProbeSvcV56RegistrySource28) ||
        !patch_resource_native_miss(
            0x00867868u,
            0xe5990048u,
            kJniProbeSvcV56RegistryPost28) ||
        !patch_resource_native_miss(
            0x00867b24u,
            0xe2880030u,
            kJniProbeSvcV56RegistrySource30) ||
        !patch_resource_native_miss(
            0x00867b2cu,
            0xe2880070u,
            kJniProbeSvcV56RegistryPost30) ||
        !patch_resource_native_miss(
            0x00867b68u,
            0xe1a00006u,
            kJniProbeSvcV56RegistryPipelineReturn) ||
        (callbacks.V56FullMatrixEnabled() &&
         (!patch_resource_native_miss(
              0x00a83ab4u,
              0xe5902004u,
              kJniProbeSvcV56TrieEntry) ||
          !patch_resource_native_miss(
              0x00a83b24u,
              0xea000005u,
              kJniProbeSvcV56TrieMissBranch) ||
          !patch_resource_native_miss(
              0x00a83b38u,
              0xe1a00002u,
              kJniProbeSvcV56TrieFound) ||
          !patch_resource_native_miss(
              0x00a83b44u,
              0xe3a00000u,
              kJniProbeSvcV56TrieMissZero))) ||
        (callbacks.V57DeepScoutEnabled() &&
         !patch_resource_native_miss(
              0x00a83af8u,
              0xe6ef0075u,
              kJniProbeSvcV57TrieCompare))
        ) {
            error =
                "v57 ctype/deep-scout resource/state/StartupLogo/registry/trie instrumentation profile did not match the verified PvZ2 1.5.252752 ARM code.";
            return false;
        }
    }

    if ((callbacks.V62Enabled() ||
         callbacks.V63Enabled()) &&
        !patch_resource_native_miss(
            0x00868cb0u,
            0xe5901014u,
            kJniProbeSvcV62TaskDispatch)) {
        error =
            "v63 TaskResource guard did not match LDR r1,[r0,#0x14] at 0x10868cb0.";
        return false;
    }

    if (callbacks.V66Enabled() &&
        (!patch_resource_native_miss(
             0x00abe79cu,
             0xe3500000u,
             kJniProbeSvcV66TaskADepResult) ||
         !patch_resource_native_miss(
             0x00abe7e8u,
             0xe3500000u,
             kJniProbeSvcV66TaskAChild78Result) ||
         !patch_resource_native_miss(
             0x00abe81cu,
             0xe3500000u,
             kJniProbeSvcV66TaskAChild84Result) ||
         !patch_resource_native_miss(
             0x00abebccu,
             0xe3500000u,
             kJniProbeSvcV66TaskBDepResult) ||
         !patch_resource_native_miss(
             0x00abec00u,
             0xe3500000u,
             kJniProbeSvcV66TaskBChildResult))) {
        error =
            "v66 TaskResource child-state instrumentation did not match the verified CMP r0,#0 sites in 0x10abe774/0x10abebb0.";
        return false;
    }

    if (callbacks.V69Enabled() &&
        !callbacks.V85PerformanceEnabled() &&
        (!patch_resource_native_miss(
             0x00abd8c8u,
             0xe1a00005u,
             kJniProbeSvcV69WorkerPreWait) ||
         !patch_resource_native_miss(
             0x00868cbcu,
             0xe3500001u,
             kJniProbeSvcV69ActiveReadyResult) ||
         !patch_resource_native_miss(
             0x00868cdcu,
             0xe3500001u,
             kJniProbeSvcV69ActivePhaseResult) ||
         !patch_resource_native_miss(
             0x00868d20u,
             0xe58d7014u,
             kJniProbeSvcV69StartWorkReturn) ||
         !patch_resource_native_miss(
             0x00868d5cu,
             0xe5940054u,
             kJniProbeSvcV69MoveCompleted) ||
         !patch_resource_native_miss(
             0x00868da0u,
             0xe5980000u,
             kJniProbeSvcV69CompletedPollReturn) ||
         !patch_resource_native_miss(
             0x00868db0u,
             0xe3500001u,
             kJniProbeSvcV69CompletedReadyResult) ||
         !patch_resource_native_miss(
             0x00868dc8u,
             0xe3500001u,
             kJniProbeSvcV69CompletedTerminalResult) ||
         !patch_resource_native_miss(
             0x00868e18u,
             0xe3580000u,
             kJniProbeSvcV69FinalizerReturn))) {

        error =
            "v69 TaskResource lifecycle instrumentation did not match the verified Android 1.5.252752 worker/pump profile.";
        return false;
    }

    if (!callbacks.V85PerformanceEnabled() &&
        (callbacks.V67Enabled() ||
         callbacks.V69Enabled()) &&
        (!patch_resource_native_miss(
             0x00abedd4u,
             0xe5801004u,
             kJniProbeSvcV67TokenIncrementStore) ||
         !patch_resource_native_miss(
             0x00abede8u,
             0xe5801004u,
             kJniProbeSvcV67TokenDecrementStore))) {

        error =
            "v67/v69 completion-token accounting did not match STR r1,[r0,#4] at 0x10abedd4/0x10abede8.";
        return false;
    }

    if (callbacks.V79ProfileProbeEnabled() &&
        (!patch_resource_native_miss(
             0x002b8494u,
             0xe1a04000u,
             kJniProbeSvcV79SetWidthHeightEntry) ||
         !patch_resource_native_miss(
             0x003095b4u,
             0xe1a0b000u,
             kJniProbeSvcV79ProfileEntry) ||
         !patch_resource_native_miss(
             0x003082d8u,
             0xe1a09000u,
             kJniProbeSvcV79CheckboxEntry) ||
         !patch_resource_native_miss(
             0x003083e8u,
             0xe3a02000u,
             kJniProbeSvcV79CheckboxRect) ||
         !patch_resource_native_miss(
             0x003085f8u,
             0xe1a09000u,
             kJniProbeSvcV79FacebookEntry) ||
         !patch_resource_native_miss(
             0x003087a8u,
             0xe1a00005u,
             kJniProbeSvcV79FacebookRect) ||
         !patch_resource_native_miss(
             0x00308b80u,
             0xe1a0a000u,
             kJniProbeSvcV79ContainerEntry) ||
         !patch_resource_native_miss(
             0x00308c5cu,
             0xed8d1a01u,
             kJniProbeSvcV79ContainerRect) ||
         !patch_resource_native_miss(
             0x0030aea8u,
             0xe1a0a000u,
             kJniProbeSvcV79TextEntry) ||
         !patch_resource_native_miss(
             0x0030b03cu,
             0xe1a00008u,
             kJniProbeSvcV79TextRectA) ||
         !patch_resource_native_miss(
             0x0030b0b0u,
             0xe1a00008u,
             kJniProbeSvcV79TextRectB) ||
         !patch_resource_native_miss(
             0x0030f930u,
             0xe1a0a000u,
             kJniProbeSvcV79GenericEntry) ||
         !patch_resource_native_miss(
             0x0030fa50u,
             0xe1a00005u,
             kJniProbeSvcV79GenericRect))) {

        error =
            "v79 first-run Profile provenance signature mismatch: refusing to patch an unverified Android 1.5.252752 instruction.";
        return false;
    }

    if (callbacks.V82Enabled() &&
        (!patch_resource_native_miss(
             0x00309f94u, 0xe59b00a0u,
             kJniProbeSvcV82Candidate5Post) ||
         !patch_resource_native_miss(
             0x0030a558u, 0xe59b0000u,
             kJniProbeSvcV82Candidate7Post) ||
         !patch_resource_native_miss(
             0x0030a68cu, 0xe1a00009u,
             kJniProbeSvcV82Candidate6Pre) ||
         !patch_resource_native_miss(
             0x0030a694u, 0xe28d8038u,
             kJniProbeSvcV82Candidate6Post))) {

        error =
            "v82 Profile widget radar signature mismatch: refusing to patch an unverified Android 1.5.252752 instruction.";
        return false;
    }

    if (callbacks.V83ButtonTrapEnabled() &&
        !patch_resource_native_miss(
            0x0030b8f8u,
            0xe1a09000u,
            kJniProbeSvcV83ButtonDispatchEntry)) {

        error =
            "v83 Profile button dispatcher signature mismatch: refusing to patch an unverified Android 1.5.252752 instruction.";
        return false;
    }

    if (callbacks.V94Enabled() &&
        (!patch_resource_native_miss(
             0x00868978u,
             0xe92d4830u,
             kJniProbeSvcV95WrapperPush) ||
         !patch_resource_native_miss(
             0x008689c4u,
             0xe8bd8830u,
             kJniProbeSvcV95WrapperPop))) {
        error =
            "caller-LR PUSH/POP signature mismatch at 0x10868978/0x108689c4.";
        return false;
    }

    if(callbacks.V89Enabled()&&(!patch_resource_native_miss(0x00894b28u,0xe5911000u,kJniProbeSvcV89BlxTarget0)||!patch_resource_native_miss(0x00894b34u,0xe591201cu,kJniProbeSvcV89BlxTarget1))){
        error="v89 BLX provenance signature mismatch at 0x10894b28/0x10894b34.";return false;
    }

    if(callbacks.V90Enabled()&&
       (!patch_resource_native_miss(
            0x00a4dc30u,
            0xe30f6fffu,
            kJniProbeSvcV90FontScanBegin) ||
        !patch_resource_native_miss(
            0x00a4dc78u,
            0xe1a00004u,
            kJniProbeSvcV90FontScanEnd))) {
        error="v90 font cmap scan signature mismatch at 0x10a4dc30/0x10a4dc78.";
        return false;
    }

    if (callbacks.V108Enabled() &&
        (!patch_resource_native_miss(0x00bc3fd0u, 0xe1a00001u, kJniProbeSvcV108KillSlotEntry) ||
         !patch_resource_native_miss(0x00bbf254u, 0xe594a008u, kJniProbeSvcV108KillBankMsg) ||
         !patch_resource_native_miss(0x00bc5478u, 0xe1a05000u, kJniProbeSvcV108UsageSlotRelease) ||
         !patch_resource_native_miss(0x00bc0e80u, 0xe590102cu, kJniProbeSvcV108UnloadCompletion) ||
         !patch_resource_native_miss(0x00bb6a50u, 0xe59d1000u, kJniProbeSvcV108DefaultBankCallback))) {
        error = "v108 Wwise bank-completion signature mismatch at KillSlot/KillBank/Release/Completion/DefaultCallback; refusing to patch an unverified PvZ2 1.5.252752 instruction.";
        return false;
    }

    if (callbacks.V105Enabled() &&
        (!patch_resource_native_miss(
             0x00c141f8u,
             0xe5c40034u,
             kJniProbeSvcV105ResamplerInitState) ||
         !patch_resource_native_miss(
             0x00c14498u,
             0xe5942014u,
             kJniProbeSvcV105SetPitchState) ||
         !patch_resource_native_miss(
             0x00c145d8u,
             0xe5c40034u,
             kJniProbeSvcV105SwitchToState))) {
        error =
            "v105 Wwise resampler signature mismatch at Init/SetPitch/SwitchTo; refusing to patch an unverified PvZ2 1.5.252752 instruction.";
        return false;
    }

    callbacks.Append(
        "V48 RESFILE WRAPPER-FINAL BRIDGE: v45 internal hooks preserved; direct-group null returns are observed at 0x1087a708 and all-groups-exhausted nulls at 0x1087a76c with the exact wrapper ID still in r6.");
    callbacks.Append(
        "V53 PASSIVE GAMESTATE TRAPS installed: ApplyState@0x102747d8 and RequestTransition@0x10274b4c. No state transition will be injected.");
    callbacks.Append(
        "V54 PASSIVE STARTUPLOGO TRAPS installed: GateA resource/totals/result, GateC state==4, GateD counter>=3, post-A-D depth, patch/main late decisions, and Patch/MainMenu request-path markers. Every replaced ARM instruction is emulated exactly; no gate or transition is forced.");
    callbacks.Append(
        "V55 PASSIVE STARTUP GROUP TRAPS installed: global four-group vector constructor snapshot@0x100f66e4, GateA native group lookup result@0x102c85cc, and per-group completed/total contribution@0x102c85f4. No resource-group index, progress value, vector entry, branch, or GameState is modified.");
    callbacks.Append(
        std::string{"V56 DIAGNOSTIC MATRIX installed mode="} +
        callbacks.V56ModeName() +
        ": ResourceManager registry builder@0x10867708 is traced at entry/source28/post28/source30/post30/return; writes to manager+0x28..+0x37 are watched. Gate-A Scout preserves the first native cycle and only then may set comparison S2=1.0 after 4/4 MISS proof. Matrix-capable modes trace selected keys through compact-trie lookup@0x10a83ab0.");

    callbacks.Append(
        std::string{"V57 CTYPE/DEEP-SCOUT profile: ctypeCompat="} +
        (callbacks.V57CtypeEnabled() ? "YES" : "NO") +
        " deepScout=" +
        (callbacks.V57DeepScoutEnabled() ? "YES" : "NO") +
        " trieHotPathTrace=" +
        (callbacks.V56FullMatrixEnabled() ? "YES" : "NO") +
        ". Ctype Native now leaves the compact-trie hot path unpatched; Deep Scout retains exact trie-node compare tracing@0x10a83af8. Gate-C scouting rules remain unchanged.");
    callbacks.Append(
        "V58 STREAM-FUTURE SCHEDULER: recognizes poll@0x109f7140..0x109f71a8 plus atomic helpers@0x109f9868..0x109f98d4 only when LR comes from a known future poll. Future snapshots include vfn+0x2c; ordinary main-thread CPU slices still never run workers.");
    callbacks.Append(
        "V59 ASYNC CALLER-POLL SCHEDULER: stream-future objects are identified dynamically by vfn+0x2c==0x109f7140. Caller-side virtual-status spin loops are recognized by ARM instruction shape plus an LR still inside the verified stream poll; ordinary CPU slices remain main-only.");
    callbacks.Append(
        "V60 FAIR ASYNC-WAIT SCHEDULER: concrete waits keep a persistent round-robin worker cursor. A worker that changes the wait object no longer permanently starves later deferred workers; ordinary CPU timeslices remain strictly main-only.");
    callbacks.Append(
        "V61 RES-STREAM PUMP COOPERATION: the verified resource-task pump yields only after its pthread_mutex_unlock epilogue. One deferred worker slice is scheduled round-robin per safe pump boundary; ordinary CPU slices and in-pump container mutation remain main-only.");
    if (callbacks.V62Enabled()) {
        callbacks.Append(
            std::string{"V62 TASKRESOURCE/POINTER PROVENANCE: mode="} +
            callbacks.V56ModeName() +
            ". Trap@0x10868cb0 emulates LDR r1,[r0,#0x14] exactly; worker this+0x30 aliases, live/retired allocation class, vector slots and the first observed bad-pointer writer are recorded.");
        callbacks.Append(
            std::string{"V62 PUMP MUTEX COHERENCE: "} +
            (callbacks.V62MutexCoherentEnabled()
                ? "ENABLED. Only verified manager+0x68 trylock/unlock ownership is modeled; a worker is not suspended while it owns that mutex."
                : "CONTROL A. v61 synthetic trylock behavior is preserved for the causal A/B comparison."));
    }
    if (callbacks.V66Enabled()) {
        callbacks.Append(
            "V66 BLOCKING-WAIT SCHEDULER: v65 condition variables are preserved; worker sem_wait/sem_timedwait, nanosleep/usleep and sched_yield are scheduler-visible instead of immediate-success hot loops. TaskResource vfnC readiness is observed at the verified post-call CMP sites without forcing any result.");
        callbacks.Append(
            "V66 LOOP SAFETY: hot mutex/TaskResource logs are heavily sampled. The continuation watchdog stops if one specific guest mutex remains continuously held across more than 128 continuation quanta; an independent TaskResource stagnation watchdog fail-fast stops an unchanged task/child vfnC==0 pair after 65536 observations. Neither path forces guest readiness.");
    }
    if (callbacks.V67Enabled()) {
        callbacks.Append(
            "V67 COMPLETION-TOKEN PROVENANCE: exact counter stores at 0x10abedd4/0x10abede8 are observed and emulated unchanged. Token logs include old/new counter, caller LR, tid, live 16/24-byte allocation creator provenance and inc/dec history. Child snapshots are capped to the tracked allocation size.");
    }
    if (callbacks.V68Enabled() &&
        !callbacks.V69Enabled()) {
        callbacks.Append(
            "V68 COMPLETION-TOKEN SEMANTICS: v67 proved vfnC@0x10abedb8 is exactly counter>0 (busy), not a readiness predicate. Repeated zero results for this verified token class are logged as IDLE_NOT_STALL and cannot trip the v66 TaskResource stagnation fail-fast. The v67 increment/decrement hot-path traps are disabled in v68; all other v66/v65/v64 safety and blocking semantics remain active.");
    }
    if (callbacks.V69Enabled()) {
        callbacks.Append(
            "V69 TASKRESOURCE LIFECYCLE: lifecycle edges, the resource-worker event flag and quiet token balance remain observational; no readiness, counter, GameState, resource or vector entry is forced.");
    }
    if (callbacks.V69Enabled() &&
        !callbacks.V70Enabled()) {
        callbacks.Append(
            "V69 LOG BUDGET: unchanged TaskSubstate, TaskGuard and release-boundary messages are aggressively sampled. The resource worker stops diagnostically after 1,048,576 active-ready observations if frame 1 has not returned, emitting a compact lifecycle summary instead of another ~100 MiB loop.");
    }
    if (callbacks.V70Enabled()) {
        callbacks.Append(
            "V70 ZLIB STREAM OWNERSHIP: v69 proves TaskResource reaches start, completed-ready and finalizer normally. Static ARM correlation identifies Task A as the ResStreams inflate worker. Host z_stream objects stay at a stable address for their initialized lifetime and real decompression progress is sampled. No guest stream result is forced.");
    }
    if (callbacks.V71Enabled()) {
        callbacks.Append(
            "V71 ETC1 TEXTURE BRIDGE: Android colorType 36196 (GL_ETC1_RGB8_OES / 0x8d64) is software-decoded to GL_RGB/UNSIGNED_BYTE on the iOS GLES2 host while PvZ2's separate 8-bit alpha texture and shader composition remain unchanged. No GameState or resource readiness is forced.");
    }
    if (callbacks.V72Enabled()) {
        callbacks.Append(
            "V72 LIVE TOUCH BRIDGE: real UIKit touches are serialized into AndroidUIEventManager::ProcessEvents using the verified 16-byte header + 48-byte touch ABI from classes.dex. Touch phases map 0=began,1=moved,3=ended,4=cancelled; no GameState, resource readiness or UI action is forced.");
    }
    if (callbacks.V73Enabled()) {
        callbacks.Append(
            "V73 KEYBOARD/FULLSCREEN BRIDGE: the v72 iPad run delivered 162/162 touch events with zero drops, then the guest called Device_ShowKeyboard while v72 still no-op'd it. classes.dex proves UITextInputEvent type=6 with UTF-8 payload/action framing, and the historical iOS 1.5 binary uses a shared UITextField delegate. v73 bridges Show/Hide/IsKeyboardShowing to UIKit, emits exact text events, and leaves zlib/ETC1/GameState/resource behavior untouched.");
    }
    if (callbacks.V74Enabled()) {
        callbacks.Append(
            "V74 RETINA/INPUT POLISH: v73 proved text delivery lossless (10/10) while its host default FBO remained 1180x820 although the JNI bridge reports 2360x1640 native pixels. v74 makes the final host surface truly 2360x1640, keeps 1180x820 logical points, and publishes a live frame in the same completed guest frame that consumes text.");
    }
    if (callbacks.V75Enabled()) {
        callbacks.Append(
            "V75 IPAD UI PACKAGE A/B: Inspector v2.2 proves host/JNI geometry is coherent (2360x1640 pixels, 1180x820 points) and the guest intentionally renders through a 2210x1536 internal target, while RESFILE_PACKAGES_UI_ANDROID is selected and UI_IPAD is not. v75 keeps v74 rendering/input/scheduler behavior byte-for-byte except for replacing the single libPVZ2.so UI_ANDROID resource-ID literal with UI_IPAD before constructors run.");
    }
    if (callbacks.V76Enabled()) {
        callbacks.Append(
            "V76 IOS SCALE CONTRACT: the decrypted iOS 1.5 binary proves CanSetGLViewScaleFactor is respondsToSelector(contentScaleFactor), Get returns EAGLView.contentScaleFactor, Set calls setContentScaleFactor:, and ES2Renderer.resizeFromLayer sizes backingWidth/backingHeight from renderbufferStorage:fromDrawable:. v76 makes that whole class functional and resizes the existing host FBO in-place when the guest changes the view scale. UI_IPAD from v75 is retained; GameState/readiness/input remain native.");
    }
    if (callbacks.V77Enabled()) {
        callbacks.Append(
            "V77 LEGACY IPAD GEOMETRY: v76 A/B is rejected for the Android guest after it requested scale=2.000666 and resized 2360x1640 to 2361x1641. v77 restores the stable CanSet=false scale bridge, retains UI_IPAD/touch/keyboard/zlib/ETC1, and exposes the exact historical Retina iPad geometry used by the 1.5 launch assets: 1024x768 points / 2048x1536 pixels. UIKit remains aspect-fit on the modern iPad.");
    }
    if (callbacks.V79ProfileProbeEnabled()) {
        callbacks.Append(
            "V79 FIRST-RUN PROFILE PROVENANCE: observation-only traps are active in this V75/V77/V80/V81/V82/V83 control. Static v2.5 matched the Android and historical-iOS Profile/Facebook/EULA layout paths and found only a localized text-entry constant difference. v79 records live parent +0x30/+0x34 dimensions, LawnApp +0x6a8 scale, branch state and bounded final geometry at the matched paths. No scale, rectangle, resource, GameState or widget state is modified.");
    }
    if (callbacks.V80Enabled()) {
        callbacks.Append(
            "V80 GLOBAL TRANSFORM PROBE: user observation shows the same oversize/crop on the EA logo, PvZ2 title/loading screen and first-run Profile, so v80 keeps v77 geometry unchanged and traces the shared GLES screenMatrix plus sampled pre-transform position bounds and host presentation. Keyboard diagnostics also separate guest Show/Hide/status from UIKit first-responder state. No matrix, vertex, viewport, FBO, widget, resource or GameState value is modified.");
    }
    if (callbacks.V81Enabled()) {
        callbacks.Append(
            "V81 HIT-TEST PROVENANCE: v72 touch mapping was validated while framebuffer and logical coordinates were both 1180x820. v74 then introduced 2360x1640 Retina pixels while keeping 1180x820 points without changing mapTouch; v77 now uses 2048x1536 pixels / 1024x768 points. V81 keeps v39 height,width surface ordering and all v77/v80 rendering unchanged, but delivers touches in 1024x768 logical point space. V80 remains the same-IPA pixel-coordinate control.");
    }
    if (callbacks.V82Enabled()) {
        callbacks.Append(
            "V82 PROFILE WIDGET/ACTION RADAR: v81 moved the physical tap needed to hit the TextEntry exactly as expected from the /2 input experiment, rejecting /2 as a final fix. The radar observes Profile candidate button IDs 5/6/7 after their verified layout calls and correlates raw +0x28/+0x2c/+0x30/+0x34 with touches, keyboard requests, Profile state and GameState. V82 delivers logical touches; v83 reuses the same radar with pixel-space touches. Candidate semantics are not guessed and no action is forced.");
    }
    if (callbacks.V83Enabled()) {
        callbacks.Append(
            "V83 PROFILE BUTTON DISPATCH: v83 restored the V80 2048x1536 pixel touch control and proved buttonId=5 can dispatch even when the raw +0x28/+0x2c/+0x30/+0x34 radar rectangle does not contain the screen-space tap. Those raw fields are therefore local/transformed, not absolute hitboxes. The passive dispatcher trap remains enabled and does not alter rendering, widget geometry or GameState.");
    }
    if (callbacks.V109Enabled()) {
        callbacks.AppendDiagnostic(
            "V109 LEAN AUDIO PERFORMANCE: preserves the v106 32 kHz sink, v107 semaphore repair and v108 SoundBank completion liveness, but deliberately does not install the v105 CAkResampler Init/SetPitch/SwitchTo SVC probes. Hot Native_onDrawFrame/OpenSL callback V88 begin/end trace lines are also suppressed. V90 frame/worker/allocator/host-cost telemetry remains enabled so the iPad can measure the real runtime cost with scheduler semantics unchanged.");
    }
    if (callbacks.V110Enabled()) {
        callbacks.AppendDiagnostic(
            std::string{
                "V110 AUDIO/PINCH/UI A-B: exact UIPinchEvent type=3 enabled; "
                "CAkAudioThread uses no-SVC AddTicks buckets; UI arm="} +
            (callbacks.V110AndroidUiControlEnabled()
                 ? "UI_ANDROID native control"
                 : "UI_IPAD v75 remap"));
    }
    if (callbacks.V111Enabled()) {
        callbacks.AppendDiagnostic(
            "V111 SAMPLED-PC AUDIO PROFILER: v110 runtime preserved. "
            "tid5 gets one private Dynarmic checkpoint every 131072 guest ticks; "
            "the saved PC is sampled, no Wwise SVC is installed, and the same "
            "worker resumes immediately without a scheduler handoff.");
    }
    if (callbacks.V112Enabled()) {
        callbacks.AppendDiagnostic(
            "V112 NATURAL AUDIO BOUNDARY PROFILER: v110 runtime preserved; "
            "v111 periodic HaltExecution sampling is disabled. Only natural "
            "tid5 import SVCs are timed. LR identifies the exact guest callsite, "
            "and wall time between imports is measured only inside the same "
            "jit.Run worker span so scheduler sleep is excluded.");
    }
    if (callbacks.V115Enabled()) {
        callbacks.AppendDiagnostic(
            "V115 DYNARMIC MAIN STACK PAGETABLE: v113 heap mapping and v114 "
            "natural main-thread telemetry remain enabled. At frame 1, guest "
            "stack 0x20000000..0x200fefff is mapped directly (255/256 pages); "
            "0x200ff000..0x200fffff stays callback-backed so the observed "
            "v94/v95 LR-slot/provenance addresses remain visible. Image/GOT/"
            "RELRO, trampolines, JNI and objects remain callbacks.");
    } else if (callbacks.V113Enabled()) {
        callbacks.AppendDiagnostic(
            "V113 DYNARMIC HEAP PAGETABLE: first real optimization after v112. "
            "The JIT starts with an all-null page table so constructors/startup "
            "retain callback memory semantics. At frame 1 only guest heap "
            "0x30000000..+128MiB becomes direct-page-table memory. Image/GOT/"
            "RELRO, main stack, trampolines, JNI and objects remain callbacks. "
            "v112 boundary telemetry stays enabled for before/after comparison.");
    }
    if (callbacks.V114Enabled()) {
        callbacks.AppendDiagnostic(
            "V114 NATURAL MAIN BOUNDARY PROFILER: v113 heap page-table stays "
            "enabled unchanged. Native_onDrawFrame main-thread jit.Run spans "
            "are timed only at existing boundaries; natural imports record "
            "exact guest LR/callsites and host cost, while no-import spans "
            "retain natural start/end PCs. No periodic halt or guest patch.");
    }
    if (callbacks.V108Enabled()) {
        callbacks.AppendDiagnostic(
            "V108 BANK COMPLETION LIVENESS: v107 proved BankMgr wakes and dequeues the final UnloadBank command, but the synchronous completion callback can remain pending after KillBank while CAkUsageSlot still owns live references. Exact traps trace KillSlot -> ProcessMsgQueue(KillBank) -> CAkUsageSlot::Release -> UnloadCompletionNotification -> DefaultBankCallbackFunc. If and only if that real teardown is pending, the OpenSL ring is empty, no guest buffer callback is pending, and CAkAudioThread is asleep on its own event semaphore, a 32 ms liveness pulse wakes only CAkAudioThread so Wwise itself can finish releasing voices; the main UnloadBank completion semaphore is never fabricated.");
    }
    if (callbacks.V107Enabled()) {
        callbacks.AppendDiagnostic(
            "V107 SEMAPHORE WAKE REPAIR: v106 audio-rate correction remains unchanged. Cooperative sem_post keeps real token accounting but reconciles a divergent FIFO waiter index from the authoritative semaphore-wait map, and a thread that actually reaches a new sem_wait discards impossible stale semaphore/mutex wait records. Exact QueueBankCommand sem_post and BankThreadFunc sem_wait calls log BankMgr object, wake semaphore, queue depth and notified state; no UnloadBank completion is fabricated.");
    }
    if (callbacks.V106Enabled()) {
        callbacks.AppendDiagnostic(
            "V106 AUDIO RATE + BANK WAIT: OpenSL output capabilities expose discrete 24/32/48 kHz rates, preserving PvZ2's intentional 32 kHz Wwise pipeline while AVAudioEngine performs downstream hardware conversion. The real CAkBankMgr::BankThreadFunc worker remains prioritized during synchronous UnloadBank sem_wait.");
    }
    if (callbacks.V105Enabled()) {
        callbacks.AppendDiagnostic(
            "V105 WWISE RESAMPLER PROBE: v104 audio scheduling remains active. Verified observational traps log CAkResampler::Init after sourceHz/targetHz ratio plus DSP selection, CAkResampler::SetPitch after fixed-point step calculation, and CAkResampler::SwitchTo after source-format transition plus DSP reselection.");
    }
    if (callbacks.V104Enabled()) {
        callbacks.AppendDiagnostic(
            "V104 AUDIO WORKER HANDSHAKE: static libPVZ2 analysis proves CAkSinkOpenSL::EnqueueBufferCallback ends by WakeupEventsConsumer and CAkAudioThread::EventMgrThreadFunc@+0x00bfdb70 runs CAkAudioMgr::Perform then sem_wait. Each realtime completion is therefore delivered one-at-a-time and immediately hands the cooperative scheduler to that exact Wwise worker. PCM FNV fingerprints detect non-zero stale-buffer repetition.");
    }
    if (callbacks.V103Enabled()) {
        callbacks.AppendDiagnostic(
            "V103 AUDIO DRAW-FRAME GATE: v102 real-time CoreAudio completion telemetry is preserved, but asynchronous OpenSL guest callback injection is allowed only inside Native_onDrawFrame. Native_onSurfaceCreated and all other startup lifecycles retain the validated v101 scheduler/interleaving behavior; pre-frame/frame-boundary drains remain fallback.");
    }
    if (callbacks.V102Enabled()) {
        callbacks.AppendDiagnostic(
            "V102 AUDIO REALTIME PUMP: CoreAudio completion counters are polled during eligible guest lifecycles and can request a soft Dynarmic checkpoint. OpenSL completion callbacks run only on the guest scheduler thread, with a private guest stack/thread id; frame boundaries remain fallback drains.");
    }
    if (callbacks.V101Enabled()) {
        callbacks.AppendDiagnostic(
            "V101 AUDIO CLOCK CONTRACT: AVAudioSourceNode is explicitly format-pinned to Wwise PCM rate; AVAudioEngine may convert only downstream toward the session/mixer rate. Requested/session/source/mixer clocks are logged after engine start.");
    }
    if (callbacks.V100Enabled()) {
        callbacks.AppendDiagnostic(
            "V100 OPENSL CALLBACK ABI: v99 proved Engine/Player/AVAudioEngine/PCM enqueue. BufferQueue completion now enters CAkSinkOpenSL::EnqueueBufferCallback with raw ARM C ABI r0=SLAndroidSimpleBufferQueueItf, r1=CAkSinkOpenSL context; JNI env injection is disabled only for this callback class.");
    }
    if (callbacks.V99Enabled()) {
        callbacks.AppendDiagnostic(
            "V99 AUDIO OPENSL BRIDGE: v98 playable runtime preserved. Wwise CAkSinkOpenSL receives functional Engine/Object/Play/BufferQueue/AndroidConfiguration/AudioIODeviceCapabilities interfaces; mixed PCM16 is copied to a bounded AVAudioEngine ring and buffer-complete callbacks return to Dynarmic only at scheduler-safe lifecycle/frame boundaries.");
    }
    if (callbacks.V98Enabled()) {
        callbacks.AppendDiagnostic(
            "V98 PRESENTATION RGB FIDELITY: host display and diagnostic copies preserve the guest framebuffer's already-composited RGB verbatim and force only output alpha opaque; the v40/v90 rgb/alpha unpremultiply workaround is disabled.");
    }
    if (callbacks.V97Enabled()) {
        callbacks.AppendDiagnostic(
            "V97 MUTEX WAIT GRAPH: a V87 wait record with granted=true is a handoff/resume token, not a live wait-for dependency. Deadlock traversal stops at granted owners and preferred-owner traversal schedules them instead of following their stale bookkeeping edge.");
    }
    if (callbacks.V96Enabled()) {
        callbacks.AppendDiagnostic(
            "V96 MAIN BLOCKING: lifecycle tid=0 now uses real cooperative sem_wait/sem_timedwait, pthread_cond_wait/pthread_cond_timedwait and nanosleep/usleep blocking. While main is blocked only deferred workers run; condition resume is prepared before sem/sleep and generic mutex resume. v95 precise LR provenance remains active.");
    }
    if(callbacks.V95Enabled()){
        callbacks.AppendDiagnostic("V95 PRECISE CALLER LR WATCH: v94 performance regression removed. Exact traps emulate PUSH@0x10868978 and POP@0x108689c4; only incoming LR=0x1086f1fc arms the saved-LR slot. STR/STREX and host SVC writes are observed only against that exact slot. Observation only: no stack repair, return rewrite or guest-code recovery.");
    } else if(callbacks.V94Enabled()){
        callbacks.AppendDiagnostic("V94 CALLER LR WATCH: exact PUSH/POP trap implementation active; legacy v94 mode retained internally for diagnostic control.");
    } else if(callbacks.V93Enabled()){
        callbacks.Append("V93 RETURN PROVENANCE: complete v92 long-run runtime preserved. The exact delete->free path returning through 0x10868b30 is observed non-invasively inside the host free callback: saved PC at guest SP+36 is captured before and after FreeHeap. No guest instruction, return address, allocator result, scheduler state or recovery behavior is changed.");
    } else if(callbacks.V92Enabled()){
        callbacks.Append("V92 LONG-RUN: complete v91 allocator/RELRO/direct-GPU/input runtime preserved; the legacy 600-frame probe ceiling is disabled and execution continues until Hard Stop or a real failure. Periodic performance logging is throttled for sustained play.");
    } else if(callbacks.V91Enabled()){
        callbacks.Append("V91 RUNTIME: v90 direct GPU/scheduler/resource/input behavior preserved; guest allocator uses exact-first-fit address indexing; ELF GNU_RELRO/import GOT is sealed after synthetic relocation with bounded first-writer provenance.");
    } else if(callbacks.V90Enabled()){
        callbacks.Append("V90 PROFILER: v88 scheduler + 128 MiB heap + functional resource/input path preserved; v89 BLX/quantum hot probes disabled; direct 1:1 shared-EAGL presentation, total-frame pacing, cmap full-scan timing, allocator fragmentation counters and worker wall-time aggregation enabled.");
    } else if(callbacks.V89Enabled()){
        callbacks.Append("V89 PROFILER: v88 scheduler/heap/resource/audio/render/input semantics preserved; Hard Stop, quantum PC/LR/tid aggregation, ETC1/VFS/zlib/GLES host-cost buckets and BLX target provenance enabled.");
    } else if (callbacks.V88Enabled()) {
        callbacks.Append(
            "V88 SCHEDULER: v87 blocking mutex/waiter semantics preserved; concrete startup waits allow a bounded 8-quantum (6M tick) critical-section burst before preemption, replacing v87 one-quantum over-preemption. Startup wall-clock phase markers are enabled.");
    } else if (callbacks.V87Enabled()) {
        callbacks.Append(
            "V87 SCHEDULER: v86 128 MiB heap/perf baseline preserved; mutex owners are preemptible; blocking locks sleep in FIFO waiter queues; unlock performs ownership handoff; explicit Bionic mutexattr types are retained; wait-for cycles fail-fast.");
    } else if (callbacks.V86Enabled()) {
        callbacks.Append(
            "V86 PERF HEAP: Points=Pixels 2048x1536 permanent; guest heap=128 MiB (v85 was 64 MiB); functional scheduler/resource/zlib/ETC1/GLES/UI_IPAD/touch/keyboard/USERFS bridges kept; scheduler semantics unchanged; residual V22/V30/V38/V61 hot slice logs disabled before formatting.");
    } else if (callbacks.V85PerformanceEnabled()) {
        callbacks.Append(
            "V85 PERF BASELINE: Points=Pixels 2048x1536 permanent; functional scheduler/resource/zlib/ETC1/GLES/UI_IPAD/touch/keyboard/USERFS bridges kept; historical render/Profile/startup probes disabled; heap and scheduler semantics unchanged.");
    }

    if (callbacks.V84FinalBlitEnabled()) {
        callbacks.Append(
            "V84 FINAL-BLIT TRACE: v80 intentionally ignored guest FBO 0. v83 showed a 1024x768 screenMatrix upload immediately before rebinding guest FBO 0 while the viewport stayed 2048x1536. v84 records the actual final/default-FBO vertex bounds, textures and active screenMatrix without changing GL state.");
        if (callbacks.V84PointsPixelsEnabled()) {
            callbacks.Append(
                "V84 POINTS=PIXELS: Graphics_GetScreenSizeInPoints now returns 2048x1536, matching the APK AndroidSurfaceView method which forces an effective density divisor of 1.0 before using view getWidth/getHeight. Pixels, FBO, viewport and v39 surface order remain 2048x1536.");
        }
        if (callbacks.V84AndroidContractEnabled()) {
            callbacks.Append(
                "V84 ANDROID GRAPHICS CONTRACT: additionally matches the APK AndroidSurfaceView scale field: CanSet=true; initial mViewScaleFactor=0.5; Get reads the field; Set stores the float only and NEVER resizes the host FBO. Graphics_GetPointSizeInPixels remains 2.0, representing the iPad host display density.");
        }
    }

    if (callbacks.V87Enabled()) {
        callbacks.Append(
            "V87 MUTEX POLICY: a boundary worker stops after one normal quantum even when it still owns guest mutexes. Contenders block instead of receiving EBUSY/fatal; the blocked main thread temporarily prioritizes the direct mutex owner until unlock handoff.");
    } else if (callbacks.V64Enabled()) {
        callbacks.Append(
            "V64 RELEASE-BOUNDARY SCHEDULER: v63 guest pthread mutex ownership tracking is preserved, but a worker whose quantum expires while holding a mutex is armed to stop at the first later unlock that makes heldMutexes=0. It no longer waits for another whole quantum to happen to sample zero.");
        callbacks.Append(
            "V64 WATCHDOG/LOGGING: the continuation guard advances only across consecutive continuation quanta with no guest mutex release at all; any unlock resets it. Ordinary mutex-release logs are sampled instead of logging every held=0 hot-loop transition. The v63 TaskResource dispatch guard remains fail-fast and observational.");
    } else if (callbacks.V63Enabled()) {
        callbacks.Append(
            "V63 CRITICAL-SECTION-AWARE SCHEDULER: every guest pthread_mutex_lock/trylock/unlock is ownership-tracked. A deferred worker whose quantum expires while holding any guest mutex continues on the same worker until a later quantum ends with heldMutexes=0. Cross-owner blocking locks fail-fast instead of fabricating success.");
        callbacks.Append(
            "V63 TASKRESOURCE GUARD: dispatch@0x10868cb0 is observational except for fail-fast on unreadable object/vtable or non-executable vfn+0x14. No TaskResource pointer, vtable, GameState, resource, or UI package is repaired or forced. v62 global pointer-write provenance is disabled from the ARM hot path.");
    }

    return_trampoline =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcReturn);

    const std::uint32_t get_env =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcGetEnv);

    const std::uint32_t find_class =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcFindClass);

    const std::uint32_t register_natives =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcRegisterNatives);

    const std::uint32_t new_global_ref =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcNewGlobalRef);

    const std::uint32_t get_object_class =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcGetObjectClass);

    const std::uint32_t get_method_id =
        JniProbeMakeTrampoline(
            memory,
            trampoline_slot++,
            kJniProbeSvcGetMethodID);

    if (!return_trampoline ||
        !get_env ||
        !find_class ||
        !register_natives ||
        !new_global_ref ||
        !get_object_class ||
        !get_method_id) {
        error =
            "JNI probe could not allocate control trampolines.";
        return false;
    }

    const std::uint32_t vm_table =
        kJniProbeJniBase +
        0x0000u;

    const std::uint32_t vm_object =
        kJniProbeJniBase +
        0x0100u;

    memory.Write32Guest(
        vm_object,
        vm_table);

    memory.Write32Guest(
        vm_table + 0x18u,
        get_env);

    const std::uint32_t env_table =
        kJniProbeJniBase +
        0x1000u;

    const std::uint32_t env_object =
        kJniProbeJniBase +
        0x2000u;

    memory.Write32Guest(
        env_object,
        env_table);

    // Populate every JNIEnv slot with a controlled trap first. This turns an
    // unimplemented JNI call into a precise slot/offset diagnostic instead of
    // a jump through a null pointer.
    for (std::uint32_t slot = 0;
         slot < kJniProbeJniSlotCount;
         ++slot) {

        const std::uint32_t generic =
            JniProbeMakeTrampoline(
                memory,
                trampoline_slot++,
                kJniProbeSvcUnsupportedJniBase +
                    slot);

        if (!generic) {
            error =
                "JNI probe could not allocate generic JNIEnv trampolines.";
            return false;
        }

        memory.Write32Guest(
            env_table + slot * 4u,
            generic);
    }

    // JNI function-table slots from jni.h.
    memory.Write32Guest(
        env_table + 6u * 4u,
        find_class);

    memory.Write32Guest(
        env_table + 21u * 4u,
        new_global_ref);

    memory.Write32Guest(
        env_table + 31u * 4u,
        get_object_class);

    memory.Write32Guest(
        env_table + 33u * 4u,
        get_method_id);

    memory.Write32Guest(
        env_table + 215u * 4u,
        register_natives);

    callbacks.vm_object = vm_object;
    callbacks.env_object = env_object;

    if (callbacks.V91Enabled() &&
        !callbacks.V91ArmRelro()) {
        error =
            "v91 could not arm the ELF GNU_RELRO protection.";
        return false;
    }

    return true;
}

} // namespace

void PvZ2ResetInteractiveInput() {
    {
        std::lock_guard<std::mutex> lock(
            gV72TouchMutex);
        gV72TouchQueue.clear();
    }

    {
        std::lock_guard<std::mutex> lock(
            gV73TextMutex);
        gV73TextQueue.clear();
    }
    {
        std::lock_guard<std::mutex> lock(gV110PinchMutex);
        gV110PinchQueue.clear();
    }
    gV110QueuedPinches.store(0u, std::memory_order_release);
    gV110DroppedPinches.store(0u, std::memory_order_release);

    gV72StopRequested.store(
        false,
        std::memory_order_release);
    gV72TouchGeneration.store(
        0u,
        std::memory_order_release);
    gV72QueuedTouches.store(
        0u,
        std::memory_order_release);
    gV72DroppedTouches.store(
        0u,
        std::memory_order_release);
    gV73QueuedTextEvents.store(
        0u,
        std::memory_order_release);
    gV73DroppedTextEvents.store(
        0u,
        std::memory_order_release);
}

void PvZ2QueueTouchEvent(
    std::uint32_t pointer_id,
    std::int32_t x,
    std::int32_t y,
    std::int32_t previous_x,
    std::int32_t previous_y,
    std::uint32_t phase,
    double timestamp_ms) {

    if (phase > 4u) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(
            gV72TouchMutex);

        if (gV72TouchQueue.size() >=
            kV72MaxQueuedTouches) {

            // Keep the newest state transitions. A diagnostic UI that stalls
            // for a few frames should not replay seconds of obsolete moves.
            gV72TouchQueue.pop_front();
            gV72DroppedTouches.fetch_add(
                1u,
                std::memory_order_relaxed);
        }

        gV72TouchQueue.push_back(
            V72TouchEvent{
                pointer_id,
                x,
                y,
                previous_x,
                previous_y,
                phase,
                timestamp_ms,
                V85SteadyNowNs()});
    }

    gV72QueuedTouches.fetch_add(
        1u,
        std::memory_order_relaxed);
    gV72TouchGeneration.fetch_add(
        1u,
        std::memory_order_release);
}

void PvZ2QueuePinchEvent(
    std::int32_t x,
    std::int32_t y,
    float scale_dist_sq,
    float scale_delta) {

    if (!std::isfinite(scale_dist_sq) ||
        !std::isfinite(scale_delta) ||
        scale_dist_sq < 0.0f) {
        return;
    }

    V110PinchEvent event;
    event.x = x;
    event.y = y;
    event.scale_dist_sq = scale_dist_sq;
    event.scale_delta = scale_delta;

    {
        std::lock_guard<std::mutex> lock(gV110PinchMutex);
        if (gV110PinchQueue.size() >= kV110MaxQueuedPinches) {
            gV110PinchQueue.pop_front();
            gV110DroppedPinches.fetch_add(
                1u, std::memory_order_relaxed);
        }
        gV110PinchQueue.push_back(event);
    }
    gV110QueuedPinches.fetch_add(1u, std::memory_order_relaxed);
}

void PvZ2QueueTextInputEvent(
    std::uint32_t action,
    const std::uint8_t* utf8,
    std::size_t utf8_size) {

    // These are the two actions emitted by Android's EditInputConnection for
    // ordinary committed text and deleteSurroundingText respectively.
    if (action != 0u &&
        action != 3u) {
        return;
    }

    if (utf8_size != 0u &&
        utf8 == nullptr) {
        return;
    }

    V73TextInputEvent event;
    event.action = action;

    if (utf8_size != 0u) {
        event.utf8.assign(
            utf8,
            utf8 + utf8_size);
    }

    {
        std::lock_guard<std::mutex> lock(
            gV73TextMutex);

        if (gV73TextQueue.size() >=
            kV73MaxQueuedTextEvents) {
            gV73TextQueue.pop_front();
            gV73DroppedTextEvents.fetch_add(
                1u,
                std::memory_order_relaxed);
        }

        gV73TextQueue.push_back(
            std::move(event));
    }

    gV73QueuedTextEvents.fetch_add(
        1u,
        std::memory_order_relaxed);

    // Reuse the v72 generation wake-up so a typed character also requests an
    // immediate live presentation refresh instead of waiting three frames.
    gV72TouchGeneration.fetch_add(
        1u,
        std::memory_order_release);
}

void PvZ2RequestInteractiveStop() {
    gV72StopRequested.store(
        true,
        std::memory_order_release);
}

PvZ2JniProbeResult RunPvZ2JniOnLoadProbe(
    const std::uint8_t* apk_data,
    std::size_t apk_size) {

    PvZ2JniProbeResult result;

    if (!apk_data || apk_size == 0) {
        result.message =
            "No APK data was supplied.";
        return result;
    }

    try {
        ZipEntry entry;
        std::string error;

        if (!FindZipEntry(
                apk_data,
                apk_size,
                kPvZ2Path,
                entry,
                error)) {
            result.message = error;
            return result;
        }

        std::vector<std::uint8_t> elf;
        if (!ExtractZipEntry(
                apk_data,
                apk_size,
                entry,
                elf,
                error)) {
            result.message = error;
            return result;
        }

        JniProbeLoadedElf loaded;
        if (!BuildJniProbeElf(
                elf,
                loaded,
                error)) {
            result.message = error;
            return result;
        }

        JniProbeGuestMemory memory;
        PvZ2JniCallbacks callbacks(
            memory,
            result);

        std::uint32_t return_trampoline = 0;

        if (!JniProbePrepareRuntime(
                loaded,
                memory,
                callbacks,
                result,
                return_trampoline,
                error)) {
            result.message = error;
            return result;
        }

        Dynarmic::ExclusiveMonitor exclusive_monitor{1};

        Dynarmic::A32::UserConfig config;
        config.callbacks = &callbacks;
        config.processor_id = 0;
        config.global_monitor = &exclusive_monitor;
        config.arch_version =
            Dynarmic::A32::ArchVersion::v7;
        config.always_little_endian = true;
        config.enable_cycle_counting = true;
        config.check_halt_on_memory_access = true;
        config.code_cache_size =
            16 * 1024 * 1024;

        Dynarmic::A32::Jit jit{config};
        callbacks.jit = &jit;

        jit.Regs().fill(0);

        jit.Regs()[0] =
            callbacks.vm_object;

        jit.Regs()[1] = 0;

        jit.Regs()[13] =
            kJniProbeStackBase +
            kJniProbeStackSize -
            0x100u;

        jit.Regs()[14] =
            return_trampoline;

        jit.Regs()[15] =
            kGuestBase +
            loaded.jni_onload;

        jit.SetCpsr(0x10u);

        result.reached_jni_onload = true;

        callbacks.Append(
            "Entering real PvZ2 JNI_OnLoad at guest 0x" +
            JniProbeHex(
                kGuestBase +
                loaded.jni_onload));

        const Dynarmic::HaltReason halt =
            jit.Run();

        result.final_pc =
            jit.Regs()[15];

        result.halt_reason =
            static_cast<std::uint32_t>(halt);

        result.supported_import_calls =
            callbacks.supported_calls;

        result.trace =
            callbacks.Trace();

        if (result.returned_from_jni_onload) {
            if (result.return_value ==
                    kJniVersion14 ||
                result.return_value ==
                    kJniVersion16) {

                result.ok = true;

                result.message =
                    "Real PvZ2 JNI_OnLoad completed under Dynarmic and returned JNI version 0x" +
                    JniProbeHex(
                        result.return_value) +
                    ".";
            } else {
                result.message =
                    "JNI_OnLoad returned unexpected value 0x" +
                    JniProbeHex(
                        result.return_value) +
                    ".";
            }
        } else if (result.message.empty()) {
            result.message =
                "JNI_OnLoad halted before returning.";
        }

        return result;
    } catch (const std::exception& e) {
        result.message =
            std::string{
                "JNI probe exception: "} +
            e.what();
        return result;
    } catch (...) {
        result.message =
            "JNI probe failed with an unknown native exception.";
        return result;
    }
}


PvZ2JniProbeResult RunPvZ2FullLoadProbe(
    const std::uint8_t* apk_data,
    std::size_t apk_size,
    const std::uint8_t* obb_data,
    std::size_t obb_size,
    PvZ2ProbeProgress progress,
    PvZ2DiagnosticMode diagnostic_mode,
    PvZ2LiveFrameCallback live_frame) {

    PvZ2JniProbeResult result;
    result.diagnostic_mode =
        diagnostic_mode;

    struct V99HostAudioRunGuard {
        V99HostAudioRunGuard() {
            PvZ2HostAudioShutdown();
        }
        ~V99HostAudioRunGuard() {
            PvZ2HostAudioShutdown();
        }
    } v99_host_audio_run_guard;

    if (!apk_data || apk_size == 0) {
        result.message =
            "No APK data was supplied.";
        return result;
    }

    try {
        ZipEntry entry;
        std::string error;

        if (!FindZipEntry(
                apk_data,
                apk_size,
                kPvZ2Path,
                entry,
                error)) {
            result.message = error;
            return result;
        }

        std::vector<std::uint8_t> elf;
        if (!ExtractZipEntry(
                apk_data,
                apk_size,
                entry,
                elf,
                error)) {
            result.message = error;
            return result;
        }

        JniProbeLoadedElf loaded;
        if (!BuildJniProbeElf(
                elf,
                loaded,
                error)) {
            result.message = error;
            return result;
        }

        const bool use_heap_128 =
            PvZ2DiagnosticModeHasCapability(
                diagnostic_mode,
                PvZ2ProbeCapability::Heap128);
        const bool use_allocator_profile =
            PvZ2DiagnosticModeHasCapability(
                diagnostic_mode,
                PvZ2ProbeCapability::AllocatorProfiling);
        const bool use_allocator_index =
            PvZ2DiagnosticModeHasCapability(
                diagnostic_mode,
                PvZ2ProbeCapability::IndexedAllocatorRelro);

        const std::uint32_t guest_heap_size =
            use_heap_128
                ? kJniProbeHeapSizeV86
                : kJniProbeHeapSize;

        JniProbeGuestMemory memory(
            guest_heap_size);
        memory.EnableV90AllocatorProfiling(
            use_allocator_profile);
        memory.EnableV91AllocatorIndex(
            use_allocator_index);

        PvZ2JniCallbacks callbacks(
            memory,
            result,
            std::move(progress),
            obb_data,
            obb_size,
            diagnostic_mode);

        if (callbacks.V95Enabled()) {
            const bool config_ok =
                memory.heap.size() ==
                    kJniProbeHeapSizeV86 &&
                memory.v90_allocator_profile &&
                memory.v91_allocator_index_enabled;

            callbacks.AppendDiagnostic(
                std::string{"V95 RUNTIME CONFIG heapBytes="} +
                std::to_string(
                    memory.heap.size()) +
                " allocatorProfile=" +
                (memory.v90_allocator_profile
                     ? "YES"
                     : "NO") +
                " allocatorIndex=" +
                (memory.v91_allocator_index_enabled
                     ? "YES"
                     : "NO"));

            if (!config_ok) {
                result.message =
                    "V95 runtime capability self-check failed before guest execution.";
                result.trace =
                    callbacks.Trace();
                return result;
            }
        }

        std::uint32_t return_trampoline = 0;

        if (!JniProbePrepareRuntime(
                loaded,
                memory,
                callbacks,
                result,
                return_trampoline,
                error)) {
            result.message = error;
            return result;
        }

        if (callbacks.V75Enabled()) {
            // Exact PvZ2 1.5.252752 .rodata literal. The APK contains exactly
            // one occurrence at ELF file/vaddr 0x00c73f0a. The iPad ID is
            // shorter, so clear the complete original C string then write the
            // replacement. This changes package selection only; the RSB bytes
            // and ResourceManager logic remain native.
            constexpr std::uint32_t kUiAndroidIdGuest =
                kGuestBase + 0x00c73f0au;
            constexpr char kUiAndroidId[] =
                "RESFILE_PACKAGES_UI_ANDROID";
            constexpr char kUiIpadId[] =
                "RESFILE_PACKAGES_UI_IPAD";

            std::uint8_t* literal =
                memory.Ptr(
                    kUiAndroidIdGuest,
                    sizeof(kUiAndroidId));

            if (literal == nullptr ||
                std::memcmp(
                    literal,
                    kUiAndroidId,
                    sizeof(kUiAndroidId)) != 0) {

                result.message =
                    "V75 refused UI package remap: exact UI_ANDROID literal was not present at guest 0x10c73f0a.";
                return result;
            }

            std::memset(
                literal,
                0,
                sizeof(kUiAndroidId));
            std::memcpy(
                literal,
                kUiIpadId,
                sizeof(kUiIpadId) - 1u);

            callbacks.Append(
                "V75 UI PACKAGE REMAP: guest literal 0x10c73f0a RESFILE_PACKAGES_UI_ANDROID -> RESFILE_PACKAGES_UI_IPAD (single exact .rodata patch before constructors).");
        }

        result.init_array_slots =
            loaded.init_array_size / 4u;

        std::vector<std::uint32_t> constructors;
        constructors.reserve(result.init_array_slots);

        for (std::uint32_t slot = 0;
             slot < result.init_array_slots;
             ++slot) {

            const std::uint32_t address =
                memory.Read32Guest(
                    kGuestBase +
                    loaded.init_array +
                    slot * 4u);

            if (address == 0 ||
                address == 0xffffffffu) {
                continue;
            }

            constructors.push_back(address);
        }

        result.constructors_total =
            static_cast<std::uint32_t>(
                constructors.size());

        Dynarmic::ExclusiveMonitor exclusive_monitor{1};

        Dynarmic::A32::UserConfig config;
        config.callbacks = &callbacks;
        config.processor_id = 0;
        config.global_monitor = &exclusive_monitor;
        config.arch_version =
            Dynarmic::A32::ArchVersion::v7;
        config.always_little_endian = true;
        config.enable_cycle_counting = true;
        config.check_halt_on_memory_access = true;
        config.code_cache_size =
            32 * 1024 * 1024;

        std::unique_ptr<PvZ2JniCallbacks::V113PageTable>
            v113_page_table;
        if (callbacks.V113Enabled()) {
            v113_page_table =
                std::make_unique<
                    PvZ2JniCallbacks::V113PageTable>();
            v113_page_table->fill(nullptr);
            config.page_table = v113_page_table.get();
            config.absolute_offset_page_table = false;
            callbacks.V113AttachPageTable(
                v113_page_table.get());
        }

        Dynarmic::A32::Jit jit{config};
        callbacks.jit = &jit;

        callbacks.Append(
            "PvZ2 full-load probe: .init_array slots=" +
            std::to_string(result.init_array_slots) +
            ", non-null constructors=" +
            std::to_string(result.constructors_total));

        const std::uint64_t v88_constructors_begin_ns =
            callbacks.V88Enabled()
                ? V85SteadyNowNs()
                : 0u;

        if (callbacks.V88Enabled()) {
            callbacks.Append(
                "V88 STARTUP BEGIN phase=constructors count=" +
                std::to_string(result.constructors_total));
        }

        for (std::uint32_t index = 0;
             index < constructors.size();
             ++index) {

            const std::uint32_t function =
                constructors[index];

            callbacks.Append(
                "CHECKPOINT constructor[" +
                std::to_string(index) +
                "] begin @ 0x" +
                JniProbeHex(function));

            callbacks.return_mode =
                PvZ2JniCallbacks::ReturnMode::Constructor;

            callbacks.control_returned = false;
            callbacks.current_constructor_index = index;
            callbacks.current_constructor_address = function;
            callbacks.ticks_left = 50000000ull;
            callbacks.ticks_consumed = 0;
            callbacks.next_tick_report = 5000000ull;

            result.message.clear();
            result.first_unsupported_import.clear();

            jit.Regs().fill(0);

            jit.Regs()[13] =
                kJniProbeStackBase +
                kJniProbeStackSize -
                0x100u;

            jit.Regs()[14] =
                return_trampoline;

            jit.Regs()[15] =
                function & ~1u;

            const std::uint32_t cpsr =
                (function & 1u)
                    ? 0x30u
                    : 0x10u;

            jit.SetCpsr(cpsr);

            if (index < 8 ||
                (index % 50u) == 0u ||
                index + 1 == constructors.size()) {

                callbacks.Append(
                    "enter constructor[" +
                    std::to_string(index) +
                    "/" +
                    std::to_string(constructors.size()) +
                    "] @ 0x" +
                    JniProbeHex(function));
            }

            const Dynarmic::HaltReason halt =
                jit.Run();

            result.final_pc =
                jit.Regs()[15];

            result.halt_reason =
                static_cast<std::uint32_t>(halt);

            if (callbacks.control_returned &&
                Dynarmic::Has(
                    halt,
                    Dynarmic::HaltReason::UserDefined1)) {

                ++result.constructors_completed;
                jit.ClearHalt(
                    Dynarmic::HaltReason::UserDefined1);
                continue;
            }

            result.constructor_failure_index =
                index;

            result.constructor_failure_address =
                function;

            if (result.message.empty()) {
                result.message =
                    "Constructor[" +
                    std::to_string(index) +
                    "] at 0x" +
                    JniProbeHex(function) +
                    " halted before returning.";
            }

            callbacks.Append(
                "CONSTRUCTOR STOP: index=" +
                std::to_string(index) +
                " address=0x" +
                JniProbeHex(function) +
                " reason=" +
                result.message);

            result.supported_import_calls =
                callbacks.supported_calls;

            result.trace =
                callbacks.Trace();

            return result;
        }

        callbacks.Append(
            "All " +
            std::to_string(result.constructors_completed) +
            " non-null .init_array constructors returned successfully.");

        if (callbacks.V88Enabled()) {
            callbacks.Append(
                "V88 STARTUP END phase=constructors wallMs=" +
                std::to_string(
                    (V85SteadyNowNs() -
                     v88_constructors_begin_ns) /
                    1000000ull));
        }

        callbacks.return_mode =
            PvZ2JniCallbacks::ReturnMode::JniOnLoad;

        callbacks.control_returned = false;
        callbacks.ticks_left = 5000000ull;
        callbacks.ticks_consumed = 0;
        callbacks.next_tick_report = 5000000ull;

        result.message.clear();
        result.first_unsupported_import.clear();

        jit.Regs().fill(0);

        jit.Regs()[0] =
            callbacks.vm_object;

        jit.Regs()[1] = 0;

        jit.Regs()[13] =
            kJniProbeStackBase +
            kJniProbeStackSize -
            0x100u;

        jit.Regs()[14] =
            return_trampoline;

        jit.Regs()[15] =
            kGuestBase +
            loaded.jni_onload;

        jit.SetCpsr(0x10u);

        result.reached_jni_onload = true;

        callbacks.Append(
            "Entering real PvZ2 JNI_OnLoad after constructors at guest 0x" +
            JniProbeHex(
                kGuestBase +
                loaded.jni_onload));

        const std::uint64_t v88_jni_begin_ns =
            callbacks.V88Enabled()
                ? V85SteadyNowNs()
                : 0u;

        if (callbacks.V88Enabled()) {
            callbacks.Append(
                "V88 STARTUP BEGIN phase=JNI_OnLoad");
        }

        const Dynarmic::HaltReason halt =
            jit.Run();

        if (callbacks.V88Enabled()) {
            callbacks.Append(
                "V88 STARTUP END phase=JNI_OnLoad wallMs=" +
                std::to_string(
                    (V85SteadyNowNs() -
                     v88_jni_begin_ns) /
                    1000000ull));
        }

        result.final_pc =
            jit.Regs()[15];

        result.halt_reason =
            static_cast<std::uint32_t>(halt);

        result.supported_import_calls =
            callbacks.supported_calls;

        result.trace =
            callbacks.Trace();

        if (result.returned_from_jni_onload &&
            (result.return_value == kJniVersion14 ||
             result.return_value == kJniVersion16)) {

            callbacks.Append(
                "Full shared-library startup complete; preparing registered Native_GameAppInitialize.");

            if (result.game_app_initialize_address == 0) {
                result.message =
                    "JNI_OnLoad completed, but Native_GameAppInitialize was not captured from RegisterNatives.";
                result.trace =
                    callbacks.Trace();
                return result;
            }

            callbacks.Append(
                "Native_GameAppInitialize captured at 0x" +
                JniProbeHex(result.game_app_initialize_address) +
                " signature=" +
                result.game_app_initialize_signature);

            callbacks.return_mode =
                PvZ2JniCallbacks::ReturnMode::GameAppInitialize;

            callbacks.control_returned = false;
            callbacks.ticks_left = 50000000ull;
            callbacks.ticks_consumed = 0;
            callbacks.next_tick_report = 5000000ull;

            result.message.clear();
            result.first_unsupported_import.clear();
            result.unsupported_jni_slot = 0xffffffffu;

            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined1);
            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined2);
            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined3);
            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined4);

            jit.Regs().fill(0);

            constexpr std::uint32_t kAndroidGameApp =
                0x52010000u;
            constexpr std::uint32_t kAndroidSurfaceView =
                0x52010100u;
            constexpr std::uint32_t kAndroidHttpProxy =
                0x52010200u;
            constexpr std::uint32_t kAndroidFacebookDriver =
                0x52010300u;
            constexpr std::uint32_t kCloud =
                0x52010400u;
            constexpr std::uint32_t kGooglePlayConnect =
                0x52010500u;
            constexpr std::uint32_t kGooglePlayAchievements =
                0x52010600u;
            constexpr std::uint32_t kGooglePlayLeaderboard =
                0x52010700u;
            constexpr std::uint32_t kAndroidNotification =
                0x52010800u;

            const std::uint32_t app_init_sp =
                kJniProbeStackBase +
                kJniProbeStackSize -
                0x200u;

            // AAPCS32: r0-r3 carry JNIEnv*, thiz, and the first two Java
            // arguments. The remaining six jobject arguments are on the
            // caller stack in signature order.
            memory.Write32Guest(
                app_init_sp + 0u,
                kAndroidFacebookDriver);
            memory.Write32Guest(
                app_init_sp + 4u,
                kCloud);
            memory.Write32Guest(
                app_init_sp + 8u,
                kGooglePlayConnect);
            memory.Write32Guest(
                app_init_sp + 12u,
                kGooglePlayAchievements);
            memory.Write32Guest(
                app_init_sp + 16u,
                kGooglePlayLeaderboard);
            memory.Write32Guest(
                app_init_sp + 20u,
                kAndroidNotification);

            jit.Regs()[0] =
                callbacks.env_object;
            jit.Regs()[1] =
                kAndroidGameApp;
            jit.Regs()[2] =
                kAndroidSurfaceView;
            jit.Regs()[3] =
                kAndroidHttpProxy;
            jit.Regs()[13] =
                app_init_sp;
            jit.Regs()[14] =
                return_trampoline;
            jit.Regs()[15] =
                result.game_app_initialize_address & ~1u;

            jit.SetCpsr(
                (result.game_app_initialize_address & 1u)
                    ? 0x30u
                    : 0x10u);

            result.reached_game_app_initialize = true;

            callbacks.Append(
                "Entering real Native_GameAppInitialize with 8 synthetic Android object handles.");

            const std::uint64_t v88_app_init_begin_ns =
                callbacks.V88Enabled()
                    ? V85SteadyNowNs()
                    : 0u;

            if (callbacks.V88Enabled()) {
                callbacks.Append(
                    "V88 STARTUP BEGIN phase=Native_GameAppInitialize");
            }

            const Dynarmic::HaltReason app_halt =
                jit.Run();

            if (callbacks.V88Enabled()) {
                callbacks.Append(
                    "V88 STARTUP END phase=Native_GameAppInitialize wallMs=" +
                    std::to_string(
                        (V85SteadyNowNs() -
                         v88_app_init_begin_ns) /
                        1000000ull));
            }

            result.final_pc =
                jit.Regs()[15];

            result.halt_reason =
                static_cast<std::uint32_t>(
                    app_halt);

            result.supported_import_calls =
                callbacks.supported_calls;

            result.trace =
                callbacks.Trace();

            if (result.returned_game_app_initialize) {
                if ((result.game_app_initialize_return & 0xffu) == 0u) {
                    result.message =
                        "Native_GameAppInitialize returned JNI_FALSE; lifecycle probe not started.";
                    return result;
                }

                callbacks.Append(
                    "Native_GameAppInitialize returned JNI_TRUE; entering real PvZ2 lifecycle/surface sequence.");

                auto run_lifecycle =
                    [&](const char* name,
                        std::uint32_t function,
                        std::uint32_t thiz,
                        std::uint32_t arg2,
                        std::uint32_t arg3,
                        bool first_draw,
                        bool raw_arm_abi = false) -> bool {

                        auto clear_probe_halts =
                            [&]() {
                                jit.ClearHalt(
                                    Dynarmic::HaltReason::UserDefined1);
                                jit.ClearHalt(
                                    Dynarmic::HaltReason::UserDefined2);
                                jit.ClearHalt(
                                    Dynarmic::HaltReason::UserDefined3);
                                jit.ClearHalt(
                                    Dynarmic::HaltReason::UserDefined4);
                            };

                        auto async_future_snapshot =
                            [&](std::uint32_t future) {
                                const std::uint32_t vtable =
                                    memory.Read32Guest(future);

                                std::ostringstream out;
                                out
                                    << "future=0x"
                                    << JniProbeHex(future)
                                    << " vtable=0x"
                                    << JniProbeHex(vtable)
                                    << " vfn8=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x08u))
                                    << " vfnC=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x0cu))
                                    << " vfn10=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x10u))
                                    << " vfn2C=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x2cu))
                                    << " done="
                                    << static_cast<unsigned>(
                                        memory.Read8(
                                            future + 0x14u))
                                    << " failed="
                                    << static_cast<unsigned>(
                                        memory.Read8(
                                            future + 0x15u))
                                    << " w18=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x18u))
                                    << " w1C=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x1cu))
                                    << " w20=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x20u))
                                    << " w24=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x24u))
                                    << " w28=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x28u))
                                    << " w2C=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x2cu))
                                    << " w30=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x30u));

                                return out.str();
                            };

                        auto is_legacy_future_poll_pc =
                            [&](std::uint32_t pc) {
                                return
                                    pc >=
                                        kGuestBase + 0x009f6f24u &&
                                    pc <=
                                        kGuestBase + 0x009f7050u;
                            };

                        auto is_stream_future_poll_pc =
                            [&](std::uint32_t pc) {
                                return
                                    pc >=
                                        kGuestBase + 0x009f7140u &&
                                    pc <=
                                        kGuestBase + 0x009f71a8u;
                            };

                        auto is_future_atomic_helper_pc =
                            [&](std::uint32_t pc) {
                                return
                                    pc >=
                                        kGuestBase + 0x009f9868u &&
                                    pc <=
                                        kGuestBase + 0x009f98d4u;
                            };

                        auto is_known_future_poll_lr =
                            [&](std::uint32_t lr) {
                                const std::uint32_t clean_lr =
                                    lr & ~1u;

                                return
                                    is_legacy_future_poll_pc(
                                        clean_lr) ||
                                    is_stream_future_poll_pc(
                                        clean_lr);
                            };

                        // v59: identify the stream-future class from the
                        // guest object's virtual status method, rather than
                        // assuming that a particular caller preserves the
                        // object in r4. At the 0x9f7140 entry the object is
                        // still in r0; inside its atomic helper it is in r4;
                        // caller-side status spins can preserve it elsewhere.
                        auto is_stream_future_object =
                            [&](std::uint32_t candidate) {
                                if (candidate == 0u ||
                                    memory.Ptr(
                                        candidate,
                                        4u) == nullptr) {
                                    return false;
                                }

                                const std::uint32_t vtable =
                                    memory.Read32Guest(
                                        candidate);

                                if (vtable == 0u ||
                                    vtable >
                                        0xffffffffu - 0x2cu ||
                                    memory.Ptr(
                                        vtable + 0x2cu,
                                        4u) == nullptr) {
                                    return false;
                                }

                                return
                                    (memory.Read32Guest(
                                         vtable + 0x2cu) &
                                     ~1u) ==
                                    kGuestBase + 0x009f7140u;
                            };

                        auto find_stream_future_object =
                            [&](std::uint32_t& reg_index) {
                                static constexpr
                                    std::array<std::uint32_t, 8>
                                        kCandidateRegs = {
                                            0u,
                                            4u,
                                            5u,
                                            1u,
                                            2u,
                                            3u,
                                            6u,
                                            7u};

                                for (const std::uint32_t ri :
                                     kCandidateRegs) {
                                    const std::uint32_t candidate =
                                        jit.Regs()[ri];

                                    if (is_stream_future_object(
                                            candidate)) {
                                        reg_index = ri;
                                        return candidate;
                                    }
                                }

                                reg_index = 0xffffffffu;
                                return 0u;
                            };

                        // Detect the whole caller-side status-spin class. The
                        // verified ARM shape is:
                        //   LDR vt,[obj] ; LDR fn,[vt,#0x2c]
                        //   MOV r0,obj  ; BLX fn
                        //   CMP r0,#1   ; BEQ <loop-start>
                        // We scan up to five instructions behind the current
                        // PC so a Dynarmic timeslice may land anywhere inside
                        // the six-instruction loop. LR must still point back
                        // into the verified stream poll, and the live object
                        // must advertise that poll in vfn+0x2c.
                        auto stream_future_caller_poll_object =
                            [&](std::uint32_t pc,
                                std::uint32_t lr,
                                std::uint32_t& reg_index) {
                                reg_index = 0xffffffffu;

                                if (!is_stream_future_poll_pc(
                                        lr & ~1u)) {
                                    return 0u;
                                }

                                for (std::uint32_t back = 0u;
                                     back <= 20u;
                                     back += 4u) {
                                    if (pc <
                                        kGuestBase + back) {
                                        continue;
                                    }

                                    const std::uint32_t start =
                                        pc - back;

                                    if (memory.Ptr(
                                            start,
                                            24u) == nullptr) {
                                        continue;
                                    }

                                    const std::uint32_t i0 =
                                        memory.Read32Guest(
                                            start + 0u);
                                    const std::uint32_t i1 =
                                        memory.Read32Guest(
                                            start + 4u);
                                    const std::uint32_t i2 =
                                        memory.Read32Guest(
                                            start + 8u);
                                    const std::uint32_t i3 =
                                        memory.Read32Guest(
                                            start + 12u);
                                    const std::uint32_t i4 =
                                        memory.Read32Guest(
                                            start + 16u);
                                    const std::uint32_t i5 =
                                        memory.Read32Guest(
                                            start + 20u);

                                    if ((i0 & 0x0ff00fffu) !=
                                            0x05900000u ||
                                        (i1 & 0x0ff00fffu) !=
                                            0x0590002cu) {
                                        continue;
                                    }

                                    const std::uint32_t object_reg =
                                        (i0 >> 16u) & 0x0fu;
                                    const std::uint32_t vtable_reg =
                                        (i0 >> 12u) & 0x0fu;
                                    const std::uint32_t i1_base =
                                        (i1 >> 16u) & 0x0fu;
                                    const std::uint32_t call_reg =
                                        (i1 >> 12u) & 0x0fu;

                                    if (i1_base != vtable_reg ||
                                        (i2 & 0x0ffffff0u) !=
                                            0x01a00000u ||
                                        (i2 & 0x0fu) !=
                                            object_reg ||
                                        (i3 & 0x0ffffff0u) !=
                                            0x012fff30u ||
                                        (i3 & 0x0fu) !=
                                            call_reg ||
                                        (i4 & 0x0fffffffu) !=
                                            0x03500001u ||
                                        (i5 & 0xff000000u) !=
                                            0x0a000000u) {
                                        continue;
                                    }

                                    const std::int32_t branch_delta =
                                        static_cast<std::int32_t>(
                                            (i5 &
                                             0x00ffffffu)
                                            << 8u) >>
                                        6u;

                                    const std::int64_t branch_target =
                                        static_cast<std::int64_t>(
                                            start + 20u + 8u) +
                                        static_cast<std::int64_t>(
                                            branch_delta);

                                    if (branch_target !=
                                        static_cast<std::int64_t>(
                                            start) ||
                                        object_reg >=
                                            jit.Regs().size()) {
                                        continue;
                                    }

                                    const std::uint32_t object =
                                        jit.Regs()[object_reg];

                                    if (!is_stream_future_object(
                                            object)) {
                                        continue;
                                    }

                                    reg_index = object_reg;
                                    return object;
                                }

                                return 0u;
                            };

                        auto wait_kind =
                            [&](std::uint32_t pc,
                                std::uint32_t lr) -> const char* {
                                if (callbacks
                                        .v61_res_stream_pump_boundary_pending) {
                                    return "res-stream-pump-boundary";
                                }

                                if (is_legacy_future_poll_pc(pc)) {
                                    return "future-poll";
                                }

                                // v58: 0x9f7140 is the stream-future status
                                // poll reached naturally after the ctype fix.
                                // It returns pending while its atomic state
                                // remains EINPROGRESS (115).
                                if (is_stream_future_poll_pc(pc)) {
                                    return "stream-future-poll";
                                }

                                // 0x9f9868 / 0x9f98a0 are generic atomic
                                // helpers, so they are only a scheduler wait
                                // when LR proves they were entered from one
                                // of the already-known future poll routines.
                                if (is_future_atomic_helper_pc(pc) &&
                                    is_known_future_poll_lr(lr)) {
                                    return "stream-future-poll";
                                }

                                // Verified by disassembly of 1.5.252752:
                                // 0x864968 and 0x864a40 repeatedly invoke the
                                // async stream status virtual at +0x2c while
                                // reading the 1bsr resource header/body.
                                if ((pc >=
                                         kGuestBase + 0x00864960u &&
                                     pc <=
                                         kGuestBase + 0x00864998u) ||
                                    (pc >=
                                         kGuestBase + 0x00864a38u &&
                                     pc <=
                                         kGuestBase + 0x00864a70u)) {
                                    return "rsb-read-wait";
                                }

                                std::uint32_t caller_reg =
                                    0xffffffffu;

                                if (stream_future_caller_poll_object(
                                        pc,
                                        lr,
                                        caller_reg) != 0u) {
                                    return "stream-future-caller-poll";
                                }

                                return "timeslice";
                            };

                        auto wait_object_for_pc =
                            [&](std::uint32_t pc,
                                std::uint32_t lr,
                                std::uint32_t& reg_index) {
                                const char* kind =
                                    wait_kind(
                                        pc,
                                        lr);

                                if (std::strcmp(
                                        kind,
                                        "res-stream-pump-boundary") ==
                                    0) {
                                    reg_index = 0xffffffffu;
                                    return 0u;
                                }

                                if (std::strcmp(
                                        kind,
                                        "rsb-read-wait") == 0) {
                                    reg_index = 5u;
                                    return jit.Regs()[5];
                                }

                                if (std::strcmp(
                                        kind,
                                        "stream-future-caller-poll") ==
                                    0) {
                                    const std::uint32_t object =
                                        stream_future_caller_poll_object(
                                            pc,
                                            lr,
                                            reg_index);

                                    if (object != 0u) {
                                        return object;
                                    }
                                }

                                if (std::strcmp(
                                        kind,
                                        "stream-future-poll") == 0) {
                                    const std::uint32_t object =
                                        find_stream_future_object(
                                            reg_index);

                                    if (object != 0u) {
                                        return object;
                                    }
                                }

                                reg_index = 4u;
                                return jit.Regs()[4];
                            };

                        callbacks.return_mode =
                            PvZ2JniCallbacks::ReturnMode::Lifecycle;
                        callbacks.current_lifecycle_name =
                            name;
                        callbacks.current_probe_thread_id = 0;
                        callbacks.control_returned = false;
                        callbacks.soft_slice_timeout = true;

                        result.message.clear();
                        result.first_unsupported_import.clear();
                        result.unsupported_jni_slot = 0xffffffffu;

                        clear_probe_halts();

                        jit.Regs().fill(0);
                        jit.ExtRegs().fill(0);

                        if (raw_arm_abi) {
                            // Native C callback ABI: do not insert JNIEnv*.
                            // v99 entered OpenSL callbacks through the JNI
                            // lifecycle convention and shifted every argument:
                            // r0=env, r1=BufferQueue, r2=context. Wwise expects
                            // r0=BufferQueue and r1=context.
                            jit.Regs()[0] = thiz;
                            jit.Regs()[1] = arg2;
                            jit.Regs()[2] = arg3;
                            jit.Regs()[3] = 0u;
                        } else {
                            jit.Regs()[0] =
                                callbacks.env_object;
                            jit.Regs()[1] =
                                thiz;
                            jit.Regs()[2] =
                                arg2;
                            jit.Regs()[3] =
                                arg3;
                        }
                        jit.Regs()[13] =
                            kJniProbeStackBase +
                            kJniProbeStackSize -
                            0x200u;
                        jit.Regs()[14] =
                            return_trampoline;
                        jit.Regs()[15] =
                            function & ~1u;

                        jit.SetCpsr(
                            (function & 1u)
                                ? 0x30u
                                : 0x10u);
                        jit.SetFpscr(0u);
                        jit.ClearExclusiveState();

                        if (first_draw) {
                            result.reached_first_draw_frame = true;
                        }

                        callbacks.Append(
                            "Entering " +
                            std::string{name} +
                            " at 0x" +
                            JniProbeHex(function) +
                            " with v22 general cooperative worker scheduling; deferred_threads=" +
                            std::to_string(
                                callbacks.deferred_threads.size()));

                        constexpr std::uint64_t kMainSliceTicks =
                            1000000ull;
                        constexpr std::uint64_t kWorkerSliceTicks =
                            750000ull;
                        // v26 proved that onSurfaceCreated can still be doing
                        // real CPU/resource work after 200M main-thread ticks.
                        // Keep a large absolute safety ceiling, but report
                        // concrete progress instead of treating 200M as a
                        // deadlock by itself.
                        constexpr std::uint64_t kLifecycleTotalBudget =
                            2000000000ull;
                        constexpr std::uint32_t kWorkerStackSize =
                            64u * 1024u;
                        constexpr std::uint32_t
                            kV102AudioCallbackStackSize =
                                64u * 1024u;
                        constexpr std::uint32_t
                            kV102AudioCallbackTid =
                                0x7fff0102u;
                        constexpr std::uint64_t
                            kV102AudioCallbackBudget =
                                250000ull;

                        auto service_v102_audio =
                            [&](const char* phase) -> bool {
                                if (!callbacks.V102Enabled() ||
                                    raw_arm_abi ||
                                    callbacks.v102_audio_inline_active) {
                                    return true;
                                }

                                const std::uint32_t newly_consumed =
                                    PvZ2HostAudioTakeConsumedBufferCount();
                                callbacks.v99_audio_host_consumed +=
                                    newly_consumed;
                                callbacks.v99_audio_pending_callbacks +=
                                    newly_consumed;

                                if (callbacks.v99_audio_pending_callbacks ==
                                        0u ||
                                    callbacks.v99_queue_callback == 0u ||
                                    callbacks.v99_queue_itf == 0u) {
                                    callbacks.v102_audio_service_requested =
                                        false;
                                    return true;
                                }

                                if (!callbacks.V102AudioSinkMutexAvailable(
                                        true)) {
                                    callbacks.v102_audio_service_requested =
                                        false;
                                    return true;
                                }

                                if (callbacks.v102_audio_callback_stack_top ==
                                    0u) {
                                    const std::uint32_t stack_base =
                                        memory.AllocateHeap(
                                            kV102AudioCallbackStackSize,
                                            16u);
                                    if (stack_base == 0u) {
                                        result.message =
                                            "v102 unable to allocate dedicated OpenSL callback guest stack.";
                                        callbacks.AppendCritical(
                                            "V102 AUDIO INLINE ERROR " +
                                            result.message);
                                        return false;
                                    }
                                    callbacks.v102_audio_callback_stack_top =
                                        stack_base +
                                        kV102AudioCallbackStackSize -
                                        0x100u;
                                    callbacks.AppendDiagnostic(
                                        "V102 AUDIO CALLBACK STACK top=" +
                                        callbacks.V46DescribeGuestAddress(
                                            callbacks
                                                .v102_audio_callback_stack_top));
                                }

                                const auto saved_regs =
                                    jit.Regs();
                                const auto saved_ext_regs =
                                    jit.ExtRegs();
                                const std::uint32_t saved_cpsr =
                                    jit.Cpsr();
                                const std::uint32_t saved_fpscr =
                                    jit.Fpscr();
                                const auto saved_return_mode =
                                    callbacks.return_mode;
                                const std::string saved_lifecycle_name =
                                    callbacks.current_lifecycle_name;
                                const std::uint32_t saved_thread_id =
                                    callbacks.current_probe_thread_id;
                                const bool saved_control_returned =
                                    callbacks.control_returned;
                                const bool saved_soft_slice =
                                    callbacks.soft_slice_timeout;
                                const std::uint64_t saved_ticks_left =
                                    callbacks.ticks_left;
                                const std::uint64_t saved_ticks_consumed =
                                    callbacks.ticks_consumed;
                                const std::uint64_t saved_next_tick_report =
                                    callbacks.next_tick_report;
                                const std::string saved_message =
                                    result.message;

                                callbacks.v102_audio_inline_active = true;
                                callbacks.v102_audio_service_requested = false;
                                callbacks.v102_audio_forced_halt_pending = false;
                                ++callbacks.v102_audio_inline_services;

                                const std::uint32_t
                                    kMaxInlineCallbacks =
                                        callbacks.V104Enabled()
                                            ? 1u
                                            : 8u;
                                std::uint32_t delivered = 0u;
                                bool success = true;

                                while (
                                    callbacks
                                        .v99_audio_pending_callbacks != 0u &&
                                    delivered <
                                        kMaxInlineCallbacks) {

                                    if (!callbacks
                                             .V102AudioSinkMutexAvailable(
                                                 true)) {
                                        break;
                                    }

                                    const std::uint64_t callback_number =
                                        callbacks
                                            .v99_audio_callback_deliveries +
                                        1u;

                                    clear_probe_halts();
                                    jit.Regs().fill(0u);
                                    jit.ExtRegs().fill(0u);
                                    jit.Regs()[0] =
                                        callbacks.v99_queue_itf;
                                    jit.Regs()[1] =
                                        callbacks.v99_queue_context;
                                    jit.Regs()[13] =
                                        callbacks
                                            .v102_audio_callback_stack_top;
                                    jit.Regs()[14] =
                                        return_trampoline;
                                    jit.Regs()[15] =
                                        callbacks.v99_queue_callback &
                                        ~1u;
                                    jit.SetCpsr(
                                        (callbacks.v99_queue_callback &
                                         1u)
                                            ? 0x30u
                                            : 0x10u);
                                    jit.SetFpscr(0u);
                                    jit.ClearExclusiveState();

                                    callbacks.return_mode =
                                        PvZ2JniCallbacks::ReturnMode::
                                            AudioCallback;
                                    callbacks.current_lifecycle_name =
                                        "V102_OpenSL_AsyncCallback";
                                    callbacks.current_probe_thread_id =
                                        kV102AudioCallbackTid;
                                    callbacks.control_returned = false;
                                    callbacks.soft_slice_timeout = true;
                                    callbacks.ticks_left =
                                        kV102AudioCallbackBudget;
                                    callbacks.ticks_consumed = 0u;
                                    callbacks.next_tick_report =
                                        std::numeric_limits<
                                            std::uint64_t>::max();
                                    result.message.clear();

                                    const Dynarmic::HaltReason audio_halt =
                                        jit.Run();

                                    const bool returned =
                                        callbacks.control_returned &&
                                        Dynarmic::Has(
                                            audio_halt,
                                            Dynarmic::HaltReason::
                                                UserDefined1);
                                    const bool fatal =
                                        Dynarmic::Has(
                                            audio_halt,
                                            Dynarmic::HaltReason::
                                                UserDefined2) ||
                                        Dynarmic::Has(
                                            audio_halt,
                                            Dynarmic::HaltReason::
                                                UserDefined3);

                                    if (!returned ||
                                        fatal ||
                                        callbacks.V63HeldMutexCount(
                                            kV102AudioCallbackTid) !=
                                            0u) {
                                        if (result.message.empty()) {
                                            result.message =
                                                "v102 OpenSL async callback did not return cleanly; PC=" +
                                                callbacks
                                                    .V46DescribeGuestAddress(
                                                        jit.Regs()[15]) +
                                                " heldMutexes={" +
                                                callbacks
                                                    .V63HeldMutexSummary(
                                                        kV102AudioCallbackTid) +
                                                "}.";
                                        }
                                        callbacks.AppendCritical(
                                            "V102 AUDIO INLINE ERROR " +
                                            result.message);
                                        success = false;
                                        break;
                                    }

                                    --callbacks
                                         .v99_audio_pending_callbacks;
                                    ++callbacks
                                          .v99_audio_callback_deliveries;
                                    ++callbacks
                                          .v102_audio_inline_callbacks;
                                    ++delivered;

                                    if (callbacks.V99ShouldLogCounter(
                                            callbacks
                                                .v102_audio_inline_callbacks)) {
                                        callbacks.AppendDiagnostic(
                                            "V102 AUDIO INLINE #" +
                                            std::to_string(
                                                callbacks
                                                    .v102_audio_inline_callbacks) +
                                            " phase=" +
                                            std::string{
                                                phase != nullptr
                                                    ? phase
                                                    : "n/a"} +
                                            " callback=" +
                                            std::to_string(
                                                callback_number) +
                                            " queued=" +
                                            std::to_string(
                                                PvZ2HostAudioQueuedBufferCount()) +
                                            " pending=" +
                                            std::to_string(
                                                callbacks
                                                    .v99_audio_pending_callbacks));
                                    }
                                }

                                callbacks.v102_audio_inline_active = false;

                                clear_probe_halts();
                                jit.Regs() = saved_regs;
                                jit.ExtRegs() = saved_ext_regs;
                                jit.SetCpsr(saved_cpsr);
                                jit.SetFpscr(saved_fpscr);
                                jit.ClearExclusiveState();
                                callbacks.return_mode =
                                    saved_return_mode;
                                callbacks.current_lifecycle_name =
                                    saved_lifecycle_name;
                                callbacks.current_probe_thread_id =
                                    saved_thread_id;
                                callbacks.control_returned =
                                    saved_control_returned;
                                callbacks.soft_slice_timeout =
                                    saved_soft_slice;
                                callbacks.ticks_left =
                                    saved_ticks_left;
                                callbacks.ticks_consumed =
                                    saved_ticks_consumed;
                                callbacks.next_tick_report =
                                    saved_next_tick_report;

                                if (success) {
                                    result.message = saved_message;
                                }

                                if (callbacks.V99ShouldLogCounter(
                                        callbacks
                                            .v102_audio_inline_services)) {
                                    callbacks.V102LogAudioPacer(
                                        phase);
                                }

                                callbacks.V102RefreshAudioServiceRequest(
                                    false);
                                return success;
                            };

                        std::uint64_t lifecycle_ticks = 0;
                        std::uint32_t async_round = 0;

                        const bool v109_hot_lifecycle =
                            callbacks.V109Enabled() &&
                            (std::strcmp(name, "Native_onDrawFrame") == 0 ||
                             std::strcmp(name, "V100_OpenSL_BufferQueueCallback") == 0 ||
                             std::strcmp(name, "V99_OpenSL_BufferQueueCallback") == 0);
                        const bool v88_trace_lifecycle =
                            callbacks.V88Enabled() &&
                            !v109_hot_lifecycle;
                        const std::uint64_t v88_lifecycle_begin_ns =
                            v88_trace_lifecycle
                                ? V85SteadyNowNs()
                                : 0u;

                        if (v88_trace_lifecycle) {
                            callbacks.Append(
                                "V88 STARTUP BEGIN phase=" +
                                std::string{name});
                        }

                        // v60: v59 proved that every verified stream-future
                        // wait restarted worker scanning at index 0. The first
                        // worker (tid=1) normally changed the future object,
                        // causing an immediate break and starving workers
                        // created later (notably tid=7 during first draw).
                        // Persist the next worker index for this lifecycle.
                        // This cursor is consulted ONLY after wait_kind()
                        // proves a concrete async wait; ordinary main-thread
                        // CPU slices remain main-only.
                        std::size_t scheduler_worker_cursor = 0u;

                        while (lifecycle_ticks <
                               kLifecycleTotalBudget) {

                            callbacks.return_mode =
                                PvZ2JniCallbacks::ReturnMode::Lifecycle;
                            callbacks.current_lifecycle_name =
                                name;
                            callbacks.current_probe_thread_id = 0;
                            callbacks.control_returned = false;
                            callbacks.soft_slice_timeout = true;
                            callbacks.ticks_left =
                                kMainSliceTicks;
                            callbacks.ticks_consumed = 0;
                            callbacks.next_tick_report =
                                kMainSliceTicks;

                            result.message.clear();
                            clear_probe_halts();

                            callbacks.V114BeginMainRun(jit.Regs()[15]);
                            const Dynarmic::HaltReason lifecycle_halt =
                                jit.Run();
                            callbacks.V114EndMainRun(jit.Regs()[15]);

                            lifecycle_ticks +=
                                callbacks.ticks_consumed;

                            result.final_pc =
                                jit.Regs()[15];

                            result.halt_reason =
                                static_cast<std::uint32_t>(
                                    lifecycle_halt);

                            result.supported_import_calls =
                                callbacks.supported_calls;

                            const bool lifecycle_fatal =
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined2) ||
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined3);

                            if (callbacks.control_returned &&
                                !lifecycle_fatal &&
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined1)) {

                                callbacks.soft_slice_timeout = false;

                                ++result.lifecycle_calls_completed;

                                if (first_draw) {
                                    result.returned_first_draw_frame =
                                        true;
                                }

                                callbacks.Append(
                                    "V22 LIFECYCLE RETURN: " +
                                    std::string{name} +
                                    " completed after " +
                                    std::to_string(
                                        lifecycle_ticks) +
                                    " scheduled ticks.");

                                if (v88_trace_lifecycle) {
                                    callbacks.Append(
                                        "V88 STARTUP END phase=" +
                                        std::string{name} +
                                        " wallMs=" +
                                        std::to_string(
                                            (V85SteadyNowNs() -
                                             v88_lifecycle_begin_ns) /
                                            1000000ull) +
                                        " mainTicks=" +
                                        std::to_string(lifecycle_ticks) +
                                        " asyncRounds=" +
                                        std::to_string(async_round));
                                }

                                result.trace =
                                    callbacks.Trace();

                                return true;
                            }

                            if (lifecycle_fatal) {
                                callbacks.soft_slice_timeout = false;
                                result.lifecycle_failure_name =
                                    name;
                                result.trace =
                                    callbacks.Trace();

                                if (result.message.empty()) {
