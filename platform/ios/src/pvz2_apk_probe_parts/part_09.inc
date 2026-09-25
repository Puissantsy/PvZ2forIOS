                                    result.message =
                                        std::string{name} +
                                        " halted fatally at guest PC 0x" +
                                        JniProbeHex(
                                            result.final_pc) +
                                        ".";
                                }

                                return false;
                            }

                            const bool hit_slice =
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined4);

                            if (!hit_slice) {
                                callbacks.soft_slice_timeout = false;
                                result.lifecycle_failure_name =
                                    name;
                                result.trace =
                                    callbacks.Trace();

                                result.message =
                                    std::string{name} +
                                    " halted unexpectedly at guest PC 0x" +
                                    JniProbeHex(
                                        result.final_pc) +
                                    ".";

                                return false;
                            }

                            // v102/v104: a real CoreAudio buffer completion may
                            // have requested this soft halt. Service it before the
                            // older wait/worker classifier so a long
                            // Native_onDrawFrame cannot starve Wwise until the
                            // visual frame returns. If this halt was caused by a
                            // different scheduler boundary, refresh the atomic
                            // host completion total here as well.
                            bool v104_audio_wakeup_round = false;

                            if (callbacks.V102Enabled() &&
                                !raw_arm_abi) {
                                const bool audio_only_halt =
                                    callbacks
                                        .v102_audio_forced_halt_pending;
                                callbacks
                                    .v102_audio_forced_halt_pending =
                                    false;

                                callbacks.V102RefreshAudioServiceRequest(
                                    true);
                                if (callbacks
                                        .v102_audio_service_requested) {
                                    if (!service_v102_audio(
                                            audio_only_halt
                                                ? "audio-preempt"
                                                : "scheduler-checkpoint")) {
                                        callbacks.soft_slice_timeout =
                                            false;
                                        result.lifecycle_failure_name =
                                            name;
                                        result.trace =
                                            callbacks.Trace();
                                        return false;
                                    }

                                    // v104 prioritized CAkAudioThread only when
                                    // the checkpoint itself was audio-forced.
                                    // v119 extends that handshake to every
                                    // scheduler service that actually delivered
                                    // one or more real consumed-buffer callbacks.
                                    const bool v119_service_handoff =
                                        callbacks.V119Enabled() &&
                                        callbacks
                                            .v119_audio_callbacks_last_service !=
                                            0u;
                                    if (audio_only_halt ||
                                        v119_service_handoff) {
                                        if (callbacks.V104Enabled() &&
                                            callbacks.v104_audio_worker_tid !=
                                                0u) {
                                            v104_audio_wakeup_round = true;
                                            if (v119_service_handoff) {
                                                ++callbacks
                                                     .v119_audio_scheduler_handoffs;
                                            }
                                        } else {
                                            if (callbacks.V104Enabled()) {
                                                ++callbacks
                                                     .v104_audio_worker_misses;
                                            }
                                            continue;
                                        }
                                    }
                                }
                            }

                            // v29 exposed a scheduler correctness issue. Guest
                            // pthread mutex/cond primitives are still synthetic,
                            // so running background workers after *every* plain
                            // CPU quantum can create interleavings that cannot
                            // occur safely with the current compatibility layer.
                            // In particular, a worker ran while
                            // Native_onSurfaceCreated was mutating a
                            // std::vector<unsigned char>, and the main thread
                            // later observed begin==NULL with end!=NULL.
                            //
                            // Keep cooperative workers available for *real*
                            // async waits (future-poll / known wait PCs), where
                            // the main thread is intentionally blocked and a
                            // worker must make progress. For an ordinary
                            // timeslice, resume the main guest immediately and
                            // do not inject a synthetic worker interleaving.
                            const bool v96_main_blocking_wait =
                                callbacks.V96Enabled() &&
                                callbacks.V96MainBlockingPending();

                            if (callbacks.deferred_threads.empty() &&
                                !v96_main_blocking_wait) {
                                continue;
                            }

                            ++async_round;

                            const std::uint32_t wait_lr =
                                jit.Regs()[14];

                            constexpr std::uint32_t
                                kV106UnloadBankSemWaitReturn =
                                    kGuestBase + 0x00bb9afcu;
                            const bool v106_bank_unload_wait =
                                callbacks.V106Enabled() &&
                                v96_main_blocking_wait &&
                                wait_lr ==
                                    kV106UnloadBankSemWaitReturn;

                            const bool v87_main_mutex_wait =
                                callbacks.V87Enabled() &&
                                callbacks.V87MutexWaitPending(0u);

                            const char* current_wait_kind =
                                v104_audio_wakeup_round
                                    ? "audio-thread-wakeup"
                                    : (v96_main_blocking_wait
                                    ? callbacks.V96MainBlockingKind()
                                    : (v87_main_mutex_wait
                                           ? "mutex-wait"
                                           : wait_kind(
                                                 result.final_pc,
                                                 wait_lr)));

                            const bool concrete_wait =
                                v96_main_blocking_wait ||
                                v87_main_mutex_wait ||
                                std::strcmp(
                                    current_wait_kind,
                                    "timeslice") != 0;

                            const bool res_stream_pump_boundary =
                                std::strcmp(
                                    current_wait_kind,
                                    "res-stream-pump-boundary") ==
                                0;

                            // Consume the import-triggered marker exactly once.
                            // The kind string above retains the meaning for this
                            // scheduling round while worker execution proceeds.
                            if (res_stream_pump_boundary) {
                                callbacks
                                    .v61_res_stream_pump_boundary_pending =
                                    false;
                            }

                            std::uint32_t wait_object_reg =
                                0xffffffffu;

                            const std::uint32_t future =
                                concrete_wait &&
                                !v104_audio_wakeup_round &&
                                !res_stream_pump_boundary &&
                                !v87_main_mutex_wait &&
                                !v96_main_blocking_wait
                                    ? wait_object_for_pc(
                                          result.final_pc,
                                          wait_lr,
                                          wait_object_reg)
                                    : 0u;

                            const std::string wait_reg_label =
                                wait_object_reg ==
                                        0xffffffffu
                                    ? "n/a"
                                    : "r" +
                                        std::to_string(
                                            wait_object_reg);

                            std::array<std::uint8_t, 64> future_before{};
                            if (concrete_wait &&
                                future != 0u) {
                                for (std::size_t bi = 0;
                                     bi < future_before.size();
                                     ++bi) {
                                    future_before[bi] =
                                        memory.Read8(
                                            future +
                                            static_cast<std::uint32_t>(bi));
                                }
                            }

                            if (concrete_wait) {
                                const bool compact_probe =
                                    callbacks.V62Enabled() ||
                                    callbacks.V63Enabled();
                                const bool log_wait =
                                    !callbacks.V85PerformanceEnabled() &&
                                    (!res_stream_pump_boundary ||
                                     !compact_probe ||
                                     async_round <= 32u ||
                                     (async_round % 5000u) == 0u);

                                if (log_wait) {
                                    callbacks.Append(
                                        "V30 SCHED WAIT " +
                                        std::to_string(async_round) +
                                        ": kind=" +
                                        current_wait_kind +
                                        " main PC=0x" +
                                        JniProbeHex(
                                            result.final_pc) +
                                        " LR=0x" +
                                        JniProbeHex(
                                            wait_lr) +
                                        " waitReg=" +
                                        wait_reg_label +
                                        " wait_object{" +
                                        (future != 0u
                                            ? async_future_snapshot(
                                                  future)
                                            : std::string{"none"}) +
                                        "} workers=" +
                                        std::to_string(
                                            callbacks.deferred_threads.size()) +
                                        " nextWorkerIndex=" +
                                        std::to_string(
                                            scheduler_worker_cursor));
                                }
                            } else {
                                if (async_round <= 8u ||
                                    (async_round % 50u) == 0u) {
                                    callbacks.Append(
                                        "V30 MAIN-ONLY CPU round=" +
                                        std::to_string(async_round) +
                                        " main PC=0x" +
                                        JniProbeHex(
                                            result.final_pc) +
                                        " r0=0x" +
                                        JniProbeHex(jit.Regs()[0]) +
                                        " r4=0x" +
                                        JniProbeHex(jit.Regs()[4]) +
                                        " r5=0x" +
                                        JniProbeHex(jit.Regs()[5]) +
                                        " r6=0x" +
                                        JniProbeHex(jit.Regs()[6]) +
                                        " r7=0x" +
                                        JniProbeHex(jit.Regs()[7]) +
                                        " heapHighWater=" +
                                        std::to_string(
                                            memory.HeapHighWater()) +
                                        " heapLive=" +
                                        std::to_string(
                                            memory.HeapLiveBytes()) +
                                        " supportedCalls=" +
                                        std::to_string(
                                            callbacks.supported_calls) +
                                        " deferredWorkers=" +
                                        std::to_string(
                                            callbacks.deferred_threads.size()));
                                }

                                // No worker switch on a plain CPU quantum.
                                // This keeps guest object mutation atomic with
                                // respect to synthetic pthread synchronization.
                                continue;
                            }

                            auto main_regs =
                                jit.Regs();
                            const auto main_ext_regs =
                                jit.ExtRegs();
                            const std::uint32_t main_cpsr =
                                jit.Cpsr();
                            const std::uint32_t main_fpscr =
                                jit.Fpscr();

                            if (v96_main_blocking_wait) {
                                callbacks.AppendDiagnostic(
                                    "V96 MAIN BLOCK ENTER kind=" +
                                    std::string{current_wait_kind} +
                                    " PC=0x" +
                                    JniProbeHex(result.final_pc) +
                                    " LR=0x" +
                                    JniProbeHex(wait_lr));
                            }

                            bool future_changed = false;
                            bool any_worker_ran = false;
                            std::size_t worker_slices_this_round = 0u;
                            std::uint64_t v96_workers_only_rounds = 0u;
                            std::uint64_t v106_bank_wait_rounds = 0u;

                            for (;;) {
                                future_changed = false;
                                any_worker_ran = false;
                                worker_slices_this_round = 0u;

                                if (callbacks.V102Enabled() &&
                                    !raw_arm_abi) {
                                    callbacks.V102RefreshAudioServiceRequest(
                                        true);
                                    if (callbacks
                                            .v102_audio_service_requested &&
                                        !service_v102_audio(
                                            "blocked-wait")) {
                                        callbacks.soft_slice_timeout =
                                            false;
                                        callbacks.current_probe_thread_id =
                                            0u;
                                        result.lifecycle_failure_name =
                                            name;
                                        result.trace =
                                            callbacks.Trace();
                                        return false;
                                    }

                                    if (callbacks.V119Enabled() &&
                                        callbacks
                                            .v119_audio_callbacks_last_service !=
                                            0u &&
                                        callbacks.v104_audio_worker_tid !=
                                            0u) {
                                        v104_audio_wakeup_round = true;
                                        ++callbacks
                                             .v119_audio_scheduler_handoffs;
                                    }
                                }

                                if (v106_bank_unload_wait && callbacks.V108Enabled()) {
                                    callbacks.V108MaybePulseAudioLiveness();
                                }

                                if (v96_main_blocking_wait) {
                                    ++v96_workers_only_rounds;
                                }

                                if (v106_bank_unload_wait) {
                                    ++v106_bank_wait_rounds;
                                    const bool log_bank_wait =
                                        v106_bank_wait_rounds <= 8u ||
                                        (v106_bank_wait_rounds != 0u &&
                                         (v106_bank_wait_rounds &
                                          (v106_bank_wait_rounds - 1u)) == 0u);

                                    if (log_bank_wait) {
                                        const std::uint32_t wait_sem =
                                            callbacks
                                                .V106MainSemaphoreWaitAddress();
                                        std::ostringstream state;
                                        state
                                            << "V106 BANK WAIT ROUND #"
                                            << v106_bank_wait_rounds
                                            << " sem="
                                            << callbacks.V46DescribeGuestAddress(
                                                   wait_sem)
                                            << " semCount="
                                            << (wait_sem != 0u
                                                    ? memory.Read32Guest(
                                                          wait_sem)
                                                    : 0u)
                                            << " bankTid="
                                            << callbacks.v106_bank_worker_tid
                                            << " cursor="
                                            << scheduler_worker_cursor
                                            << " "
                                            << callbacks
                                                   .V107BankWorkerWaitSummary()
                                            << " "
                                            << (callbacks.V108Enabled()
                                                    ? callbacks.V108BankCompletionSummary()
                                                    : std::string{"v108=OFF"})
                                            << " workers={";

                                        const std::size_t summary_limit =
                                            std::min<std::size_t>(
                                                callbacks
                                                    .deferred_threads.size(),
                                                64u);

                                        for (std::size_t si = 0u;
                                             si < summary_limit;
                                             ++si) {
                                            const auto& ws =
                                                callbacks
                                                    .deferred_threads[si];
                                            if (si != 0u) {
                                                state << ",";
                                            }
                                            state
                                                << "tid="
                                                << ws.id
                                                << ":pc="
                                                << callbacks
                                                       .V46DescribeGuestAddress(
                                                           ws.regs[15])
                                                << ":started="
                                                << (ws.runtime_started
                                                        ? "Y"
                                                        : "N")
                                                << ":done="
                                                << (ws.runtime_completed
                                                        ? "Y"
                                                        : "N")
                                                << ":blocked="
                                                << ((callbacks
                                                         .V66ThreadBlocked(
                                                             ws.id) ||
                                                     callbacks
                                                         .V65ThreadBlocked(
                                                             ws.id) ||
                                                     callbacks
                                                         .V87MutexWaitPending(
                                                             ws.id))
                                                        ? "Y"
                                                        : "N")
                                                << ":held="
                                                << callbacks
                                                       .V63HeldMutexCount(
                                                           ws.id);
                                        }
                                        state << "}";
                                        callbacks.AppendDiagnostic(
                                            state.str());
                                    }
                                }

                            const std::size_t worker_limit =
                                std::min<std::size_t>(
                                    callbacks.deferred_threads.size(),
                                    64u);

                            std::size_t worker_start =
                                worker_limit == 0u
                                    ? 0u
                                    : scheduler_worker_cursor %
                                          worker_limit;
                            bool v104_audio_worker_selected = false;

                            if (v104_audio_wakeup_round &&
                                worker_limit != 0u) {
                                for (std::size_t candidate = 0u;
                                     candidate < worker_limit;
                                     ++candidate) {
                                    if (candidate <
                                            callbacks.deferred_threads.size() &&
                                        callbacks.deferred_threads[candidate].id ==
                                            callbacks.v104_audio_worker_tid) {
                                        worker_start = candidate;
                                        v104_audio_worker_selected = true;
                                        break;
                                    }
                                }
                            }

                            if (!v104_audio_wakeup_round &&
                                v106_bank_unload_wait &&
                                callbacks.v106_bank_worker_tid != 0u &&
                                worker_limit != 0u) {

                                for (std::size_t candidate = 0u;
                                     candidate < worker_limit;
                                     ++candidate) {
                                    if (candidate <
                                            callbacks.deferred_threads.size() &&
                                        callbacks.deferred_threads[candidate].id ==
                                            callbacks.v106_bank_worker_tid) {
                                        worker_start = candidate;
                                        ++callbacks
                                             .v106_bank_wait_priorities;
                                        if (callbacks
                                                .v106_bank_wait_priorities <=
                                                16u ||
                                            (callbacks
                                                 .v106_bank_wait_priorities &
                                             (callbacks
                                                  .v106_bank_wait_priorities -
                                              1u)) == 0u) {
                                            callbacks.AppendDiagnostic(
                                                "V106 BANK WORKER PRIORITY #" +
                                                std::to_string(
                                                    callbacks
                                                        .v106_bank_wait_priorities) +
                                                " tid=" +
                                                std::to_string(
                                                    callbacks
                                                        .v106_bank_worker_tid) +
                                                " waitLR=" +
                                                callbacks
                                                    .V46DescribeGuestAddress(
                                                        wait_lr));
                                        }
                                        break;
                                    }
                                }
                            }

                            if (!v104_audio_wakeup_round &&
                                callbacks.V87Enabled() &&
                                callbacks.V87MutexWaitPending(0u) &&
                                worker_limit != 0u) {

                                const std::uint32_t preferred_tid =
                                    callbacks.V87PreferredMutexOwner(0u);

                                for (std::size_t candidate = 0u;
                                     candidate < worker_limit;
                                     ++candidate) {

                                    if (candidate <
                                            callbacks.deferred_threads.size() &&
                                        callbacks.deferred_threads[candidate].id ==
                                            preferred_tid) {
                                        worker_start = candidate;
                                        break;
                                    }
                                }
                            }

                            const std::size_t worker_scan_limit =
                                v104_audio_wakeup_round
                                    ? (v104_audio_worker_selected
                                           ? 1u
                                           : 0u)
                                    : worker_limit;

                            for (std::size_t worker_offset = 0u;
                                 worker_offset < worker_scan_limit;
                                 ++worker_offset) {

                                const std::size_t wi =
                                    (worker_start + worker_offset) %
                                    worker_limit;

                                if (wi >=
                                    callbacks.deferred_threads.size()) {
                                    break;
                                }

                                auto worker_state =
                                    callbacks.deferred_threads[wi];

                                if (worker_state.runtime_completed ||
                                    worker_state.runtime_failed) {
                                    continue;
                                }

                                if (callbacks.V87Enabled() &&
                                    worker_state.runtime_started) {

                                    bool mutex_resumed = false;
                                    std::uint32_t mutex_result = 0u;

                                    if (!callbacks.V87PrepareMutexResume(
                                            worker_state.id,
                                            mutex_resumed,
                                            mutex_result)) {
                                        continue;
                                    }

                                    if (mutex_resumed) {
                                        worker_state.regs[0] =
                                            mutex_result;
                                    }
                                }

                                if (callbacks.V66Enabled() &&
                                    worker_state.runtime_started) {

                                    bool blocking_resumed = false;
                                    std::uint32_t blocking_result = 0u;

                                    if (!callbacks.V66PrepareBlockingResume(
                                            worker_state.id,
                                            blocking_resumed,
                                            blocking_result)) {
                                        continue;
                                    }

                                    if (blocking_resumed) {
                                        worker_state.regs[0] =
                                            blocking_result;
                                    }
                                }

                                if (callbacks.V65Enabled() &&
                                    worker_state.runtime_started) {

                                    bool cond_resumed = false;
                                    std::uint32_t cond_result = 0u;

                                    if (!callbacks.V65PrepareCondResume(
                                            worker_state.id,
                                            cond_resumed,
                                            cond_result)) {
                                        continue;
                                    }

                                    if (cond_resumed) {
                                        worker_state.regs[0] =
                                            cond_result;
                                    }
                                }

                                if (!worker_state.runtime_started) {
                                    const std::uint32_t stack_base =
                                        memory.AllocateHeap(
                                            kWorkerStackSize,
                                            16u);

                                    if (!stack_base) {
                                        callbacks.Append(
                                            "V21 WORKER: unable to allocate persistent guest stack for tid=" +
                                            std::to_string(
                                                worker_state.id));
                                        worker_state.runtime_failed =
                                            true;
                                        callbacks.deferred_threads[wi] =
                                            worker_state;
                                        continue;
                                    }

                                    worker_state.stack_top =
                                        stack_base +
                                        kWorkerStackSize -
                                        0x100u;

                                    worker_state.regs.fill(0);
                                    worker_state.ext_regs.fill(0);
                                    worker_state.regs[0] =
                                        worker_state.argument;
                                    worker_state.regs[13] =
                                        worker_state.stack_top;
                                    worker_state.regs[14] =
                                        return_trampoline;
                                    worker_state.regs[15] =
                                        worker_state.start_routine &
                                        ~1u;
                                    worker_state.cpsr =
                                        (worker_state.start_routine &
                                         1u)
                                            ? 0x30u
                                            : 0x10u;
                                    worker_state.fpscr = 0u;
                                    worker_state.runtime_started =
                                        true;

                                    callbacks.Append(
                                        "V22 WORKER START tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        " start=0x" +
                                        JniProbeHex(
                                            worker_state.start_routine) +
                                        " arg=0x" +
                                        JniProbeHex(
                                            worker_state.argument) +
                                        " created_in=" +
                                        worker_state.created_in +
                                        " stack=0x" +
                                        JniProbeHex(
                                            worker_state.stack_top));
                                }

                                jit.Regs() =
                                    worker_state.regs;
                                jit.ExtRegs() =
                                    worker_state.ext_regs;
                                jit.SetCpsr(
                                    worker_state.cpsr);
                                jit.SetFpscr(
                                    worker_state.fpscr);
                                jit.ClearExclusiveState();

                                callbacks.return_mode =
                                    PvZ2JniCallbacks::ReturnMode::Lifecycle;
                                callbacks.current_lifecycle_name =
                                    "V21_worker_tid_" +
                                    std::to_string(
                                        worker_state.id);
                                callbacks.current_probe_thread_id =
                                    worker_state.id;
                                callbacks.control_returned = false;
                                callbacks.soft_slice_timeout = true;
                                callbacks.ticks_left =
                                    kWorkerSliceTicks;
                                callbacks.ticks_consumed = 0;
                                callbacks.next_tick_report =
                                    (callbacks.V62Enabled() ||
                                     callbacks.V63Enabled()) &&
                                    res_stream_pump_boundary
                                        ? std::numeric_limits<
                                              std::uint64_t>::max()
                                        : kWorkerSliceTicks;

                                result.message.clear();
                                clear_probe_halts();

                                any_worker_ran = true;
                                ++worker_slices_this_round;

                                bool worker_returned = false;
                                bool worker_fatal = false;
                                std::uint32_t coherence_chunks = 0u;
                                std::uint32_t no_unlock_chunks = 0u;
                                std::uint64_t last_mutex_release_count =
                                    callbacks.v63_mutex_releases;
                                std::vector<std::uint32_t>
                                    persistent_held_mutexes =
                                        callbacks.V66Enabled()
                                            ? callbacks.V63HeldMutexAddresses(
                                                  worker_state.id)
                                            : std::vector<std::uint32_t>{};
                                std::uint32_t persistent_held_chunks = 0u;

                                for (;;) {
                                    const std::uint32_t v110_start_pc =
                                        callbacks.V110ProfilingEnabled()
                                            ? jit.Regs()[15] : 0u;
                                    callbacks.V110BeginAudioQuantum(
                                        worker_state.id);
                                    const std::uint64_t v90_worker_begin_ns =
                                        callbacks.V90Enabled() ? V85SteadyNowNs() : 0u;
                                    callbacks.V112BeginAudioRun(worker_state.id);
                                    const Dynarmic::HaltReason worker_halt =
                                        jit.Run();
                                    callbacks.V112EndAudioRun(worker_state.id);
                                    const bool v111_sample_checkpoint =
                                        callbacks.V111ConsumeAudioSampleCheckpoint(
                                            worker_state.id,
                                            jit.Regs()[15]);
                                    if (callbacks.V90Enabled()) {
                                        const std::uint64_t elapsed_ns =
                                            V85SteadyNowNs() - v90_worker_begin_ns;
                                        callbacks.V90RecordWorkerWall(
                                            worker_state.id, elapsed_ns, false);
                                        callbacks.V110FinishAudioQuantum(
                                            worker_state.id,
                                            v110_start_pc,
                                            jit.Regs()[15],
                                            elapsed_ns);
                                    }

                                    worker_state.regs = jit.Regs();
                                    worker_state.ext_regs = jit.ExtRegs();
                                    worker_state.cpsr = jit.Cpsr();
                                    worker_state.fpscr = jit.Fpscr();
                                    worker_state.runtime_ticks +=
                                        callbacks.ticks_consumed;

                                    worker_returned =
                                        callbacks.control_returned &&
                                        Dynarmic::Has(
                                            worker_halt,
                                            Dynarmic::HaltReason::UserDefined1);
                                    worker_fatal =
                                        Dynarmic::Has(
                                            worker_halt,
                                            Dynarmic::HaltReason::UserDefined2) ||
                                        Dynarmic::Has(
                                            worker_halt,
                                            Dynarmic::HaltReason::UserDefined3);

                                    if (v111_sample_checkpoint &&
                                        !worker_returned &&
                                        !worker_fatal) {
                                        callbacks.control_returned = false;
                                        callbacks.soft_slice_timeout = true;
                                        callbacks.ticks_consumed = 0u;
                                        callbacks.next_tick_report =
                                            std::numeric_limits<
                                                std::uint64_t>::max();
                                        result.message.clear();
                                        clear_probe_halts();
                                        continue;
                                    }

                                    if (worker_returned)
                                        worker_state.runtime_completed = true;
                                    if (worker_fatal)
                                        worker_state.runtime_failed = true;

                                    const bool owns_pump_mutex =
                                        callbacks.V62MutexCoherentEnabled() &&
                                        callbacks.v62_pump_mutex_locked &&
                                        callbacks.v62_pump_mutex_owner ==
                                            worker_state.id;

                                    const std::uint32_t
                                        v63_held_mutexes =
                                            callbacks.V63Enabled()
                                                ? callbacks.V63HeldMutexCount(
                                                      worker_state.id)
                                                : 0u;
                                    const bool
                                        owns_any_v63_mutex =
                                            callbacks.V63Enabled() &&
                                            v63_held_mutexes != 0u;

                                    if (worker_returned ||
                                        worker_fatal) {
                                        break;
                                    }

                                    if (callbacks.V87Enabled()) {
                                        if (callbacks.V87MutexWaitGranted(0u)) {
                                            break;
                                        }

                                        const bool worker_blocked =
                                            callbacks.V87MutexWaitPending(
                                                worker_state.id) ||
                                            callbacks.V65ThreadBlocked(
                                                worker_state.id) ||
                                            callbacks.V66ThreadBlocked(
                                                worker_state.id);

                                        if (callbacks.V88Enabled()) {
                                            constexpr std::uint32_t
                                                kV88CriticalBurstQuanta = 8u;

                                            const bool dependency_wait =
                                                concrete_wait &&
                                                !res_stream_pump_boundary;

                                            const bool burst_continue =
                                                dependency_wait &&
                                                owns_any_v63_mutex &&
                                                !worker_blocked &&
                                                coherence_chunks <
                                                    kV88CriticalBurstQuanta;

                                            if (burst_continue) {
                                                ++coherence_chunks;
                                                ++callbacks
                                                    .v88_burst_continuations;

                                                callbacks.control_returned =
                                                    false;
                                                callbacks.soft_slice_timeout =
                                                    true;
                                                callbacks.ticks_left =
                                                    kWorkerSliceTicks;
                                                callbacks.ticks_consumed = 0u;
                                                callbacks.next_tick_report =
                                                    std::numeric_limits<
                                                        std::uint64_t>::max();

                                                result.message.clear();
                                                clear_probe_halts();
                                                continue;
                                            }

                                            if (owns_any_v63_mutex) {
                                                callbacks.V87RecordOwnerPreemption(
                                                    worker_state.id);
                                            }

                                            break;
                                        }

                                        const bool priority_owner_continue =
                                            callbacks.V87MutexWaitPending(0u) &&
                                            owns_any_v63_mutex &&
                                            !worker_blocked;

                                        if (!priority_owner_continue) {
                                            if (owns_any_v63_mutex) {
                                                callbacks.V87RecordOwnerPreemption(
                                                    worker_state.id);
                                            }
                                            break;
                                        }

                                        ++callbacks.v87_priority_continuations;

                                        callbacks.control_returned = false;
                                        callbacks.soft_slice_timeout = true;
                                        callbacks.ticks_left =
                                            kWorkerSliceTicks;
                                        callbacks.ticks_consumed = 0u;
                                        callbacks.next_tick_report =
                                            std::numeric_limits<
                                                std::uint64_t>::max();

                                        result.message.clear();
                                        clear_probe_halts();
                                        continue;
                                    }

                                    if (!owns_pump_mutex &&
                                        !owns_any_v63_mutex) {
                                        break;
                                    }

                                    ++coherence_chunks;

                                    if (owns_any_v63_mutex) {
                                        ++callbacks
                                            .v63_critical_continuations;
                                    } else {
                                        ++callbacks
                                            .v62_mutex_coherence_continuations;
                                    }

                                    if (callbacks.V66Enabled() &&
                                        owns_any_v63_mutex) {

                                        const auto held_now =
                                            callbacks.V63HeldMutexAddresses(
                                                worker_state.id);

                                        std::vector<std::uint32_t> intersection;
                                        std::set_intersection(
                                            persistent_held_mutexes.begin(),
                                            persistent_held_mutexes.end(),
                                            held_now.begin(),
                                            held_now.end(),
                                            std::back_inserter(intersection));

                                        if (intersection.empty()) {
                                            persistent_held_mutexes =
                                                held_now;
                                            persistent_held_chunks = 0u;
                                        } else {
                                            persistent_held_mutexes =
                                                std::move(intersection);
                                            ++persistent_held_chunks;
                                        }

                                        if (!persistent_held_mutexes.empty() &&
                                            persistent_held_chunks > 128u) {
                                            worker_fatal = true;
                                            worker_state.runtime_failed = true;
                                            result.message =
                                                "v66 worker tid=" +
                                                std::to_string(
                                                    worker_state.id) +
                                                " continuously held the same guest mutex(es) for more than 128 continuation quanta: {" +
                                                callbacks.V63DescribeMutexAddresses(
                                                    persistent_held_mutexes) +
                                                "}.";
                                            callbacks.Append(
                                                "V66 STICKY-MUTEX STOP: " +
                                                result.message);
                                            break;
                                        }
                                    }

                                    if (callbacks.V64Enabled()) {
                                        const std::uint64_t releases_now =
                                            callbacks.v63_mutex_releases;
                                        if (releases_now ==
                                            last_mutex_release_count) {
                                            ++no_unlock_chunks;
                                        } else {
                                            no_unlock_chunks = 0u;
                                            last_mutex_release_count =
                                                releases_now;
                                        }

                                        // Unlike v63's sampled held-state
                                        // watchdog, this can only fire after
                                        // 128 whole continuation quanta with
                                        // no guest mutex_unlock whatsoever.
                                        if (no_unlock_chunks > 128u) {
                                            worker_fatal = true;
                                            worker_state.runtime_failed = true;
                                            result.message =
                                                "v64 worker tid=" +
                                                std::to_string(
                                                    worker_state.id) +
                                                " made no guest mutex-release progress for more than 128 continuation quanta while held={" +
                                                callbacks.V63HeldMutexSummary(
                                                    worker_state.id) +
                                                "}.";
                                            callbacks.Append(
                                                "V64 NO-UNLOCK STOP: " +
                                                result.message);
                                            break;
                                        }
                                    } else {
                                        const std::uint32_t
                                            continuation_limit =
                                                callbacks.V63Enabled()
                                                    ? 128u
                                                    : 64u;

                                        if (coherence_chunks >
                                            continuation_limit) {
                                            worker_fatal = true;
                                            worker_state.runtime_failed = true;

                                            if (callbacks.V63Enabled()) {
                                                result.message =
                                                    "v63 worker tid=" +
                                                    std::to_string(
                                                        worker_state.id) +
                                                    " remained inside guest critical sections for more than " +
                                                    std::to_string(
                                                        continuation_limit) +
                                                    " continuation quanta; held={" +
                                                    callbacks.V63HeldMutexSummary(
                                                        worker_state.id) +
                                                    "}.";
                                                callbacks.Append(
                                                    "V63 CRITICAL CONTINUATION STOP: " +
                                                    result.message);
                                            } else {
                                                result.message =
                                                    "v62 worker tid=" +
                                                    std::to_string(
                                                        worker_state.id) +
                                                    " held verified manager+0x68 for more than 64 continuation quanta; main was not restored.";
                                                callbacks.Append(
                                                    "V62 MUTEX COHERENCE STOP: " +
                                                    result.message);
                                            }
                                            break;
                                        }
                                    }

                                    if (callbacks.V64Enabled()) {
                                        const std::uint64_t
                                            release_arm_index =
                                                callbacks
                                                    .v64_release_boundary_arms +
                                                1u;
                                        const bool log_release_wait =
                                            callbacks.V69Enabled()
                                                ? callbacks.V69ShouldSample(
                                                      release_arm_index)
                                                : (coherence_chunks <= 4u ||
                                                   (coherence_chunks % 64u) == 0u);
                                        if (log_release_wait) {
                                            callbacks.Append(
                                                "V64 RELEASE-BOUNDARY WAIT tid=" +
                                                std::to_string(
                                                    worker_state.id) +
                                                " chunk=" +
                                                std::to_string(
                                                    coherence_chunks) +
                                                " PC=" +
                                                callbacks.V46DescribeGuestAddress(
                                                    worker_state.regs[15]) +
                                                " heldCount=" +
                                                std::to_string(
                                                    v63_held_mutexes) +
                                                " noUnlockChunks=" +
                                                std::to_string(
                                                    no_unlock_chunks) +
                                                " held={" +
                                                callbacks.V63HeldMutexSummary(
                                                    worker_state.id) +
                                                "}");
                                        }
                                        callbacks.V64ArmReleaseBoundary(
                                            worker_state.id);
                                    } else if (callbacks.V63Enabled()) {
                                        if (coherence_chunks <= 8u ||
                                            (coherence_chunks % 16u) == 0u) {
                                            callbacks.Append(
                                                "V63 CRITICAL CONTINUE tid=" +
                                                std::to_string(
                                                    worker_state.id) +
                                                " chunk=" +
                                                std::to_string(
                                                    coherence_chunks) +
                                                " PC=" +
                                                callbacks.V46DescribeGuestAddress(
                                                    worker_state.regs[15]) +
                                                " heldCount=" +
                                                std::to_string(
                                                    v63_held_mutexes) +
                                                " held={" +
                                                callbacks.V63HeldMutexSummary(
                                                    worker_state.id) +
                                                "}");
                                        }
                                    } else if (
                                        coherence_chunks <= 8u ||
                                        (coherence_chunks % 8u) == 0u) {
                                        callbacks.Append(
                                            "V62 MUTEX CONTINUE tid=" +
                                            std::to_string(
                                                worker_state.id) +
                                            " chunk=" +
                                            std::to_string(
                                                coherence_chunks) +
                                            " PC=" +
                                            callbacks.V46DescribeGuestAddress(
                                                worker_state.regs[15]) +
                                            " mutexOwner=" +
                                            std::to_string(
                                                callbacks
                                                    .v62_pump_mutex_owner));
                                    }

                                    callbacks.control_returned = false;
                                    callbacks.soft_slice_timeout = true;
                                    callbacks.ticks_left = kWorkerSliceTicks;
                                    callbacks.ticks_consumed = 0u;
                                    callbacks.next_tick_report =
                                        std::numeric_limits<
                                            std::uint64_t>::max();
                                    result.message.clear();
                                    clear_probe_halts();
                                }

                                if (callbacks.V64Enabled() &&
                                    coherence_chunks != 0u &&
                                    !worker_fatal &&
                                    !worker_returned &&
                                    callbacks.V63HeldMutexCount(
                                        worker_state.id) == 0u &&
                                    (!callbacks.V69Enabled() ||
                                     callbacks.V69ShouldSample(
                                         callbacks
                                             .v64_release_boundary_yields))) {
                                    callbacks.Append(
                                        "V64 SAFE SWITCH tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        " afterChunks=" +
                                        std::to_string(
                                            coherence_chunks) +
                                        " safeReleaseYields=" +
                                        std::to_string(
                                            callbacks
                                                .v64_release_boundary_yields) +
                                        " PC=" +
                                        callbacks.V46DescribeGuestAddress(
                                            worker_state.regs[15]) +
                                        " heldMutexes=0");
                                } else if (
                                    callbacks.V63Enabled() &&
                                    coherence_chunks != 0u &&
                                    !worker_fatal &&
                                    !worker_returned &&
                                    callbacks.V63HeldMutexCount(
                                        worker_state.id) == 0u) {
                                    callbacks.Append(
                                        "V63 SAFE SWITCH tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        " afterChunks=" +
                                        std::to_string(
                                            coherence_chunks) +
                                        " PC=" +
                                        callbacks.V46DescribeGuestAddress(
                                            worker_state.regs[15]) +
                                        " heldMutexes=0");
                                }

                                callbacks.V64DisarmReleaseBoundary(
                                    worker_state.id);

                                // Re-acquire by index after jit.Run(): guest
                                // pthread_create may have appended more
                                // deferred threads and reallocated the vector.
                                if (wi <
                                    callbacks.deferred_threads.size()) {
                                    callbacks.deferred_threads[wi] =
                                        worker_state;
                                }

                                // v60 fairness: the next verified wait starts
                                // after the worker we just ran. If this worker
                                // resolves the current wait and we break below,
                                // later deferred workers still receive the
                                // first chance at the next concrete wait.
                                if (!callbacks.deferred_threads.empty()) {
                                    scheduler_worker_cursor =
                                        (wi + 1u) %
                                        callbacks.deferred_threads.size();
                                }

                                const bool compact_worker_log =
                                    callbacks.V62Enabled() ||
                                    callbacks.V63Enabled();
                                const bool log_worker_slice =
                                    !callbacks.V86Enabled() &&
                                    (!compact_worker_log ||
                                     !res_stream_pump_boundary ||
                                     worker_state.runtime_completed ||
                                     worker_state.runtime_failed ||
                                     async_round <= 32u ||
                                     (async_round % 5000u) == 0u);

                                if (log_worker_slice) {
                                    callbacks.Append(
                                        "V22 WORKER SLICE tid=" +
                                        std::to_string(worker_state.id) +
                                        " PC=0x" +
                                        JniProbeHex(worker_state.regs[15]) +
                                        " total_ticks=" +
                                        std::to_string(
                                            worker_state.runtime_ticks) +
                                        " returned=" +
                                        (worker_state.runtime_completed
                                            ? "YES" : "NO") +
                                        " failed=" +
                                        (worker_state.runtime_failed
                                            ? "YES" : "NO"));
                                }

                                if (v104_audio_wakeup_round &&
                                    worker_state.id ==
                                        callbacks.v104_audio_worker_tid &&
                                    !worker_fatal) {
                                    ++callbacks.v104_audio_worker_handshakes;
                                    if (callbacks.V99ShouldLogCounter(
                                            callbacks
                                                .v104_audio_worker_handshakes)) {
                                        callbacks.AppendDiagnostic(
                                            "V104 AUDIO HANDSHAKE #" +
                                            std::to_string(
                                                callbacks
                                                    .v104_audio_worker_handshakes) +
                                            " workerTid=" +
                                            std::to_string(worker_state.id) +
                                            " PC=" +
                                            callbacks
                                                .V46DescribeGuestAddress(
                                                    worker_state.regs[15]) +
                                            " blocked=" +
                                            std::string{
                                                callbacks.V66ThreadBlocked(
                                                    worker_state.id)
                                                    ? "YES"
                                                    : "NO"} +
                                            " held={" +
                                            callbacks.V63HeldMutexSummary(
                                                worker_state.id) +
                                            "} pendingCallbacks=" +
                                            std::to_string(
                                                callbacks
                                                    .v99_audio_pending_callbacks));
                                    }
                                }

                                if ((callbacks.V62Enabled() ||
                                     callbacks.V63Enabled()) &&
                                    worker_fatal) {

                                    if (callbacks.V63Enabled()) {
                                        callbacks.Append(
                                            "V63 FAIL-FAST: fatal deferred worker tid=" +
                                            std::to_string(
                                                worker_state.id) +
                                            " PC=" +
                                            callbacks.V46DescribeGuestAddress(
                                                worker_state.regs[15]) +
                                            " heldCount=" +
                                            std::to_string(
                                                callbacks.V63HeldMutexCount(
                                                    worker_state.id)) +
                                            " held={" +
                                            callbacks.V63HeldMutexSummary(
                                                worker_state.id) +
                                            "} taskGuardFailures=" +
                                            std::to_string(
                                                callbacks
                                                    .v63_task_guard_failures) +
                                            " mutexConflicts=" +
                                            std::to_string(
                                                callbacks
                                                    .v63_mutex_conflicts));
                                    } else {
                                        callbacks.Append(
                                            "V62 FAIL-FAST: first fatal deferred worker tid=" +
                                            std::to_string(
                                                worker_state.id) +
                                            " PC=" +
                                            callbacks.V46DescribeGuestAddress(
                                                worker_state.regs[15]) +
                                            " pumpMutexLocked=" +
                                            (callbacks.v62_pump_mutex_locked
                                                ? "YES"
                                                : "NO") +
                                            " pumpMutexOwner=" +
                                            std::to_string(
                                                callbacks
                                                    .v62_pump_mutex_owner) +
                                            " firstBadWriterSeen=" +
                                            (callbacks
                                                 .v62_first_bad_pointer_writer_seen
                                                ? "YES"
                                                : "NO"));
                                    }

                                    callbacks.soft_slice_timeout = false;
                                    callbacks.current_probe_thread_id = 0u;
                                    result.lifecycle_failure_name =
                                        std::string{name} +
                                        "/worker_tid_" +
                                        std::to_string(
                                            worker_state.id);
                                    if (result.message.empty()) {
                                        if (callbacks.V66Enabled() &&
                                            !callbacks.v66_failure_message.empty()) {
                                            result.message =
                                                callbacks.v66_failure_message;
                                        } else {
                                            result.message =
                                                std::string{
                                                    callbacks.V63Enabled()
                                                        ? "v63"
                                                        : "v62"} +
                                                " fail-fast after fatal worker tid=" +
                                                std::to_string(
                                                    worker_state.id) +
                                                ".";
                                        }
                                    }
                                    result.trace = callbacks.Trace();
                                    return false;
                                }

                                bool object_changed = false;

                                if (concrete_wait &&
                                    future != 0u) {
                                    for (std::size_t bi = 0;
                                         bi < future_before.size();
                                         ++bi) {
                                        if (memory.Read8(
                                                future +
                                                static_cast<std::uint32_t>(bi)) !=
                                            future_before[bi]) {
                                            object_changed = true;
                                            break;
                                        }
                                    }
                                }

                                if (v104_audio_wakeup_round &&
                                    worker_state.id ==
                                        callbacks.v104_audio_worker_tid) {
                                    break;
                                }

                                if (callbacks.V87MutexWaitPending(0u) &&
                                    callbacks.V87MutexWaitGranted(0u)) {
                                    break;
                                }

                                if (object_changed) {
                                    future_changed = true;

                                    if (!callbacks.V86Enabled()) {
                                        callbacks.Append(
                                        "V30 WAIT OBJECT PROGRESS by tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        ": " +
                                        async_future_snapshot(
                                            future));
                                    }

                                    break;
                                }

                                if (res_stream_pump_boundary &&
                                    worker_slices_this_round >= 1u) {
                                    if (!callbacks.V86Enabled() &&
                                        (!(callbacks.V62Enabled() ||
                                           callbacks.V63Enabled()) ||
                                         async_round <= 32u ||
                                         (async_round % 5000u) == 0u)) {
                                        callbacks.Append(
                                            "V61 RES-STREAM PUMP SLICE tid=" +
                                            std::to_string(worker_state.id) +
                                            " nextWorkerIndex=" +
                                            std::to_string(
                                                scheduler_worker_cursor));
                                    }
                                    break;
                                }
                            }

                            if (v96_main_blocking_wait) {
                                bool main_resumed = false;
                                std::uint32_t main_result = 0u;

                                if (!callbacks.V96PrepareMainBlockingResume(
                                        main_resumed,
                                        main_result)) {
                                    callbacks.soft_slice_timeout = false;
                                    callbacks.current_probe_thread_id = 0u;
                                    result.lifecycle_failure_name = name;

                                    if (result.message.empty()) {
                                        result.message =
                                            "v96 main blocking resume invariant failed.";
                                    }

                                    callbacks.AppendCritical(
                                        "V96 MAIN BLOCK ERROR " +
                                        result.message);
                                    result.trace = callbacks.Trace();
                                    return false;
                                }

                                if (main_resumed) {
                                    main_regs[0] = main_result;
                                    callbacks.AppendDiagnostic(
                                        "V96 MAIN BLOCK RESUME kind=" +
                                        std::string{current_wait_kind} +
                                        " rc=0x" +
                                        JniProbeHex(main_result) +
                                        " workersOnlyRounds=" +
                                        std::to_string(
                                            v96_workers_only_rounds));
                                    break;
                                }

                                if (!any_worker_ran) {
                                    if (callbacks.HasTimedBlockingWait()) {
                                        std::this_thread::sleep_for(
                                            std::chrono::milliseconds(1));
                                        continue;
                                    }

                                    callbacks.soft_slice_timeout = false;
                                    callbacks.current_probe_thread_id = 0u;
                                    result.lifecycle_failure_name = name;
                                    result.message =
                                        "v96 main thread is blocked with no runnable deferred worker and no pending deadline; kind=" +
                                        std::string{
                                            callbacks.V96MainBlockingKind()} +
                                        ".";
                                    callbacks.AppendCritical(
                                        "V96 MAIN BLOCK DEADLOCK " +
                                        result.message);
                                    result.trace = callbacks.Trace();
                                    return false;
                                }

                                if (v96_workers_only_rounds >= 1000000ull) {
                                    callbacks.soft_slice_timeout = false;
                                    callbacks.current_probe_thread_id = 0u;
                                    result.lifecycle_failure_name = name;
                                    result.message =
                                        "v96 workers-only wait exceeded 1000000 scheduling rounds; kind=" +
                                        std::string{
                                            callbacks.V96MainBlockingKind()} +
                                        ".";
                                    callbacks.AppendCritical(
                                        "V96 MAIN BLOCK SAFETY STOP " +
                                        result.message);
                                    result.trace = callbacks.Trace();
                                    return false;
                                }

                                // Main registers/CPSR/FPSCR remain frozen.
                                // Run another worker-only scheduling round.
                                continue;
                            }

                            if (v87_main_mutex_wait) {
                                bool mutex_resumed = false;
                                std::uint32_t mutex_result = 0u;

                                if (!callbacks.V87PrepareMutexResume(
                                        0u,
                                        mutex_resumed,
                                        mutex_result) ||
                                    !mutex_resumed) {

                                    callbacks.soft_slice_timeout = false;
                                    callbacks.current_probe_thread_id = 0u;
                                    result.lifecycle_failure_name =
                                        name;

                                    if (result.message.empty()) {
                                        result.message =
                                            "v87 main thread mutex wait made no handoff progress; preferredOwnerTid=" +
                                            std::to_string(
                                                callbacks.V87PreferredMutexOwner(
                                                    0u)) +
                                            ".";
                                    }

                                    callbacks.Append(
                                        "V87 MUTEX MAIN-WAIT STOP " +
                                        result.message);

                                    result.trace =
                                        callbacks.Trace();

                                    return false;
                                }

                                main_regs[0] =
                                    mutex_result;
                            }

                            // Non-v96 waits intentionally schedule only one
                            // cooperative round before returning main a slice.
                            break;
                            }

                            clear_probe_halts();

                            jit.Regs() =
                                main_regs;
                            jit.ExtRegs() =
                                main_ext_regs;
                            jit.SetCpsr(
                                main_cpsr);
                            jit.SetFpscr(
                                main_fpscr);
                            jit.ClearExclusiveState();

                            callbacks.return_mode =
                                PvZ2JniCallbacks::ReturnMode::Lifecycle;
                            callbacks.current_lifecycle_name =
                                name;
                            callbacks.current_probe_thread_id = 0;
                            callbacks.control_returned = false;
                            callbacks.soft_slice_timeout = true;

                            if (v96_main_blocking_wait) {
                                // The hard-wait loop above proved the blocking
                                // primitive complete before restoring main.
                                continue;
                            }

                            if (!any_worker_ran) {
                                if (callbacks.HasTimedBlockingWait()) {
                                    // All runnable workers may legitimately be
                                    // sleeping until a short host deadline.
                                    // Give steady/realtime clocks a chance to
                                    // advance, then rescan before declaring a
                                    // concrete-wait deadlock.
                                    std::this_thread::sleep_for(
                                        std::chrono::milliseconds(1));
                                    continue;
                                }

                                if (res_stream_pump_boundary) {
                                    // This boundary is an opportunity to run a
                                    // worker, not a dependency. If every worker
                                    // has completed/failed, let main continue.
                                    continue;
                                }

                                if (concrete_wait) {
                                    callbacks.soft_slice_timeout = false;
                                    result.lifecycle_failure_name =
                                        name;
                                    result.message =
                                        "v30 reached a concrete async wait with no runnable deferred guest worker. " +
                                        async_future_snapshot(
                                            future);
                                    callbacks.Append(
                                        "V30 SCHEDULER STOP: " +
                                        result.message);
                                    result.trace =
                                        callbacks.Trace();
                                    return false;
                                }

                                // A plain CPU timeslice is not an async wait.
                                // If background workers have completed, the
                                // main guest thread is still allowed to keep
                                // executing normally.
                                continue;
                            }

                            if (concrete_wait &&
                                !res_stream_pump_boundary &&
                                !future_changed) {
                                callbacks.Append(
                                    "V30 SCHED WAIT " +
                                    std::to_string(async_round) +
                                    ": wait object unchanged after one persistent worker slice; main thread will receive another slice before retrying.");
                            }
                        }

                        callbacks.soft_slice_timeout = false;
                        callbacks.current_probe_thread_id = 0;

                        result.lifecycle_failure_name =
                            name;

                        std::ostringstream timeout;
                        timeout
                            << name
                            << " exceeded the v30 2B-tick safety ceiling at PC=0x"
                            << JniProbeHex(jit.Regs()[15])
                            << " after "
                            << lifecycle_ticks
                            << " main-thread ticks and "
                            << async_round
                            << " scheduling rounds"
                            << "; r4=0x"
                            << JniProbeHex(jit.Regs()[4])
                            << " r5=0x"
                            << JniProbeHex(jit.Regs()[5])
                            << " r6=0x"
                            << JniProbeHex(jit.Regs()[6])
                            << " heapHighWater="
                            << memory.HeapHighWater()
                            << " heapLive="
                            << memory.HeapLiveBytes()
                            << " supportedCalls="
                            << callbacks.supported_calls
                            << ".";

                        result.message =
                            timeout.str();

                        callbacks.Append(
                            "V30 SCHEDULER TIMEOUT: " +
                            result.message);

                        result.trace =
                            callbacks.Trace();

                        return false;
                    };

                // v35: v30 intentionally stopped running deferred workers during
                // ordinary main-thread timeslices because synthetic pthread
                // synchronization made mid-lifecycle interleavings unsafe.
                // That fixed corruption, but it also meant workers created
                // after the last concrete async wait (tid=2..6 in v34) could
                // remain deferred forever. Run them cooperatively only at
                // lifecycle/frame boundaries, where the main guest is not
                // mutating game state.
                std::size_t boundary_worker_cursor = 0u;
                std::uint64_t boundary_worker_slices = 0u;

                auto run_boundary_workers =
                    [&](const char* phase,
                        std::size_t max_slices) -> bool {

                        if (callbacks.deferred_threads.empty() ||
                            max_slices == 0u) {
                            return true;
                        }

                        constexpr std::uint32_t
                            kBoundaryWorkerStackSize =
                                64u * 1024u;
                        constexpr std::uint64_t
                            kBoundaryWorkerSliceTicks =
                                100000ull;

                        const auto saved_regs =
                            jit.Regs();
                        const auto saved_ext_regs =
                            jit.ExtRegs();
                        const std::uint32_t saved_cpsr =
                            jit.Cpsr();
                        const std::uint32_t saved_fpscr =
                            jit.Fpscr();

                        auto clear_boundary_halts =
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

                        std::size_t ran = 0u;
                        std::size_t inspected = 0u;
                        bool v63_boundary_fatal = false;

                        if (callbacks.V119Enabled() &&
                            callbacks.v119_audio_boundary_wakeup_pending &&
                            callbacks.v104_audio_worker_tid != 0u) {
                            for (std::size_t i = 0u;
                                 i < callbacks.deferred_threads.size();
                                 ++i) {
                                if (callbacks.deferred_threads[i].id ==
                                    callbacks.v104_audio_worker_tid) {
                                    boundary_worker_cursor = i;
                                    break;
                                }
                            }
                        }

                        while (ran < max_slices &&
                               inspected <
                                   callbacks
                                       .deferred_threads
                                       .size()) {

                            if (callbacks.deferred_threads.empty()) {
                                break;
                            }

                            boundary_worker_cursor %=
                                callbacks
                                    .deferred_threads
                                    .size();

                            const std::size_t wi =
                                boundary_worker_cursor++;

                            ++inspected;

                            auto worker_state =
                                callbacks
                                    .deferred_threads[wi];

                            if (worker_state.runtime_completed ||
                                worker_state.runtime_failed) {
                                continue;
                            }

                            if (callbacks.V87Enabled() &&
                                worker_state.runtime_started) {

                                bool mutex_resumed = false;
                                std::uint32_t mutex_result = 0u;

                                if (!callbacks.V87PrepareMutexResume(
                                        worker_state.id,
                                        mutex_resumed,
                                        mutex_result)) {
                                    continue;
                                }

                                if (mutex_resumed) {
                                    worker_state.regs[0] =
                                        mutex_result;
                                }
                            }

                            if (callbacks.V66Enabled() &&
                                worker_state.runtime_started) {

                                bool blocking_resumed = false;
                                std::uint32_t blocking_result = 0u;

                                if (!callbacks.V66PrepareBlockingResume(
                                        worker_state.id,
                                        blocking_resumed,
                                        blocking_result)) {
                                    continue;
                                }

                                if (blocking_resumed) {
                                    worker_state.regs[0] =
                                        blocking_result;
                                }
                            }

                            if (callbacks.V65Enabled() &&
                                worker_state.runtime_started) {

                                bool cond_resumed = false;
                                std::uint32_t cond_result = 0u;

                                if (!callbacks.V65PrepareCondResume(
                                        worker_state.id,
                                        cond_resumed,
                                        cond_result)) {
                                    continue;
                                }

                                if (cond_resumed) {
                                    worker_state.regs[0] =
                                        cond_result;
                                }
                            }

                            if (!worker_state.runtime_started) {
                                const std::uint32_t stack_base =
                                    memory.AllocateHeap(
                                        kBoundaryWorkerStackSize,
                                        16u);

                                if (!stack_base) {
                                    callbacks.Append(
                                        "V38 BOUNDARY WORKER: unable to allocate stack for tid=" +
                                        std::to_string(
                                            worker_state.id));
                                    worker_state.runtime_failed =
                                        true;

                                    if (wi <
                                        callbacks
                                            .deferred_threads
                                            .size()) {
                                        callbacks
                                            .deferred_threads[wi] =
                                                worker_state;
                                    }
                                    continue;
                                }

                                worker_state.stack_top =
                                    stack_base +
                                    kBoundaryWorkerStackSize -
                                    0x100u;

                                worker_state.regs.fill(0);
                                worker_state.ext_regs.fill(0);
                                worker_state.regs[0] =
                                    worker_state.argument;
                                worker_state.regs[13] =
                                    worker_state.stack_top;
                                worker_state.regs[14] =
                                    return_trampoline;
                                worker_state.regs[15] =
                                    worker_state.start_routine &
                                    ~1u;
                                worker_state.cpsr =
                                    (worker_state.start_routine &
                                     1u)
                                        ? 0x30u
                                        : 0x10u;
                                worker_state.fpscr = 0u;
                                worker_state.runtime_started =
                                    true;

                                callbacks.Append(
                                    "V38 BOUNDARY WORKER START tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " start=0x" +
                                    JniProbeHex(
                                        worker_state.start_routine) +
                                    " created_in=" +
                                    worker_state.created_in +
                                    " phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"});
                            }

                            jit.Regs() =
                                worker_state.regs;
                            jit.ExtRegs() =
                                worker_state.ext_regs;
                            jit.SetCpsr(
                                worker_state.cpsr);
                            jit.SetFpscr(
                                worker_state.fpscr);
                            jit.ClearExclusiveState();

                            callbacks.return_mode =
                                PvZ2JniCallbacks::ReturnMode::Lifecycle;
                            callbacks.current_lifecycle_name =
                                "V38_boundary_worker_tid_" +
                                std::to_string(
                                    worker_state.id);
                            callbacks.current_probe_thread_id =
                                worker_state.id;
                            callbacks.control_returned = false;
                            callbacks.soft_slice_timeout = true;
                            callbacks.ticks_left =
                                kBoundaryWorkerSliceTicks;
                            callbacks.ticks_consumed = 0u;
                            callbacks.next_tick_report =
                                kBoundaryWorkerSliceTicks;

                            result.message.clear();
                            clear_boundary_halts();

                            const std::uint64_t calls_before =
                                callbacks.supported_calls;

                            bool worker_returned = false;
                            bool worker_fatal = false;
                            std::uint32_t critical_chunks = 0u;
                            std::uint32_t no_unlock_chunks = 0u;
                            std::uint64_t last_mutex_release_count =
                                callbacks.v63_mutex_releases;
                            std::vector<std::uint32_t>
                                persistent_held_mutexes =
                                    callbacks.V66Enabled()
                                        ? callbacks.V63HeldMutexAddresses(
                                              worker_state.id)
                                        : std::vector<std::uint32_t>{};
                            std::uint32_t persistent_held_chunks = 0u;

                            for (;;) {
                                const std::uint32_t v110_start_pc =
                                    callbacks.V110ProfilingEnabled()
                                        ? jit.Regs()[15] : 0u;
                                callbacks.V110BeginAudioQuantum(
                                    worker_state.id);
                                const std::uint64_t v90_worker_begin_ns =
                                    callbacks.V90Enabled() ? V85SteadyNowNs() : 0u;
                                callbacks.V112BeginAudioRun(worker_state.id);
                                const Dynarmic::HaltReason worker_halt =
                                    jit.Run();
                                callbacks.V112EndAudioRun(worker_state.id);
                                const bool v111_sample_checkpoint =
                                    callbacks.V111ConsumeAudioSampleCheckpoint(
                                        worker_state.id,
                                        jit.Regs()[15]);
                                if (callbacks.V90Enabled()) {
                                    const std::uint64_t elapsed_ns =
                                        V85SteadyNowNs() - v90_worker_begin_ns;
                                    callbacks.V90RecordWorkerWall(
                                        worker_state.id, elapsed_ns, true);
                                    callbacks.V110FinishAudioQuantum(
                                        worker_state.id,
                                        v110_start_pc,
                                        jit.Regs()[15],
                                        elapsed_ns);
                                }

                                worker_state.regs =
                                    jit.Regs();
                                worker_state.ext_regs =
                                    jit.ExtRegs();
                                worker_state.cpsr =
                                    jit.Cpsr();
                                worker_state.fpscr =
                                    jit.Fpscr();
                                worker_state.runtime_ticks +=
                                    callbacks.ticks_consumed;

                                worker_returned =
                                    callbacks.control_returned &&
                                    Dynarmic::Has(
                                        worker_halt,
                                        Dynarmic::HaltReason::UserDefined1);

                                worker_fatal =
                                    Dynarmic::Has(
                                        worker_halt,
                                        Dynarmic::HaltReason::UserDefined2) ||
                                    Dynarmic::Has(
                                        worker_halt,
                                        Dynarmic::HaltReason::UserDefined3);

                                if (v111_sample_checkpoint &&
                                    !worker_returned &&
                                    !worker_fatal) {
                                    callbacks.control_returned = false;
                                    callbacks.soft_slice_timeout = true;
                                    callbacks.ticks_consumed = 0u;
                                    callbacks.next_tick_report =
                                        std::numeric_limits<
                                            std::uint64_t>::max();
                                    result.message.clear();
                                    clear_boundary_halts();
                                    continue;
                                }

                                if (worker_returned) {
                                    worker_state.runtime_completed =
                                        true;
                                }

                                if (worker_fatal) {
                                    worker_state.runtime_failed =
                                        true;
                                }

                                const std::uint32_t held =
                                    callbacks.V63Enabled()
                                        ? callbacks.V63HeldMutexCount(
                                              worker_state.id)
                                        : 0u;

                                if (worker_returned ||
                                    worker_fatal) {
                                    break;
                                }

                                if (callbacks.V87Enabled()) {
                                    if (held != 0u) {
                                        callbacks.V87RecordOwnerPreemption(
                                            worker_state.id);
                                    }
                                    break;
                                }

                                if (!callbacks.V63Enabled() ||
                                    held == 0u) {
                                    break;
                                }

                                ++critical_chunks;
                                ++callbacks.v63_critical_continuations;

                                if (callbacks.V66Enabled()) {
                                    const auto held_now =
                                        callbacks.V63HeldMutexAddresses(
                                            worker_state.id);

                                    std::vector<std::uint32_t> intersection;
                                    std::set_intersection(
                                        persistent_held_mutexes.begin(),
                                        persistent_held_mutexes.end(),
                                        held_now.begin(),
                                        held_now.end(),
                                        std::back_inserter(intersection));

                                    if (intersection.empty()) {
                                        persistent_held_mutexes =
                                            held_now;
                                        persistent_held_chunks = 0u;
                                    } else {
                                        persistent_held_mutexes =
                                            std::move(intersection);
                                        ++persistent_held_chunks;
                                    }

                                    if (!persistent_held_mutexes.empty() &&
                                        persistent_held_chunks > 128u) {
                                        worker_fatal = true;
                                        worker_state.runtime_failed = true;
                                        result.message =
                                            "v66 boundary worker tid=" +
                                            std::to_string(
                                                worker_state.id) +
                                            " continuously held the same guest mutex(es) for more than 128 continuation quanta: {" +
                                            callbacks.V63DescribeMutexAddresses(
                                                persistent_held_mutexes) +
                                            "}.";
                                        callbacks.Append(
                                            "V66 BOUNDARY STICKY-MUTEX STOP: " +
                                            result.message);
                                        break;
                                    }
                                }

                                if (callbacks.V64Enabled()) {
                                    const std::uint64_t releases_now =
                                        callbacks.v63_mutex_releases;
                                    if (releases_now ==
                                        last_mutex_release_count) {
                                        ++no_unlock_chunks;
                                    } else {
                                        no_unlock_chunks = 0u;
                                        last_mutex_release_count =
                                            releases_now;
                                    }

                                    if (no_unlock_chunks > 128u) {
                                        worker_fatal = true;
                                        worker_state.runtime_failed = true;
                                        result.message =
                                            "v64 boundary worker tid=" +
                                            std::to_string(
                                                worker_state.id) +
                                            " made no guest mutex-release progress for more than 128 continuation quanta while held={" +
                                            callbacks.V63HeldMutexSummary(
                                                worker_state.id) +
                                            "}.";
                                        callbacks.Append(
                                            "V64 BOUNDARY NO-UNLOCK STOP: " +
                                            result.message);
                                        break;
                                    }
                                } else if (critical_chunks > 128u) {
                                    worker_fatal = true;
                                    worker_state.runtime_failed = true;
                                    result.message =
                                        "v63 boundary worker tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        " remained inside guest critical sections for more than 128 continuation quanta; held={" +
                                        callbacks.V63HeldMutexSummary(
                                            worker_state.id) +
                                        "}.";
                                    callbacks.Append(
                                        "V63 BOUNDARY CRITICAL STOP: " +
                                        result.message);
                                    break;
                                }

                                if (callbacks.V64Enabled()) {
                                    if (critical_chunks <= 4u ||
                                        (critical_chunks % 64u) == 0u) {
                                        callbacks.Append(
                                            "V64 BOUNDARY RELEASE-WAIT tid=" +
                                            std::to_string(
                                                worker_state.id) +
                                            " chunk=" +
                                            std::to_string(
                                                critical_chunks) +
                                            " phase=" +
                                            std::string{
                                                phase != nullptr
                                                    ? phase
                                                    : "n/a"} +
                                            " PC=" +
                                            callbacks.V46DescribeGuestAddress(
                                                worker_state.regs[15]) +
                                            " heldCount=" +
                                            std::to_string(held) +
                                            " noUnlockChunks=" +
                                            std::to_string(
                                                no_unlock_chunks) +
                                            " held={" +
                                            callbacks.V63HeldMutexSummary(
                                                worker_state.id) +
                                            "}");
                                    }
                                    callbacks.V64ArmReleaseBoundary(
                                        worker_state.id);
                                } else if (
                                    critical_chunks <= 8u ||
                                    (critical_chunks % 16u) == 0u) {
                                    callbacks.Append(
                                        "V63 BOUNDARY CRITICAL CONTINUE tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        " chunk=" +
                                        std::to_string(
                                            critical_chunks) +
                                        " phase=" +
                                        std::string{
                                            phase != nullptr
                                                ? phase
                                                : "n/a"} +
                                        " PC=" +
                                        callbacks.V46DescribeGuestAddress(
                                            worker_state.regs[15]) +
                                        " heldCount=" +
                                        std::to_string(held) +
                                        " held={" +
                                        callbacks.V63HeldMutexSummary(
                                            worker_state.id) +
                                        "}");
                                }

                                callbacks.control_returned = false;
                                callbacks.soft_slice_timeout = true;
                                callbacks.ticks_left =
                                    kBoundaryWorkerSliceTicks;
                                callbacks.ticks_consumed = 0u;
                                callbacks.next_tick_report =
                                    std::numeric_limits<
                                        std::uint64_t>::max();
                                result.message.clear();
                                clear_boundary_halts();
                            }

                            if (callbacks.V64Enabled() &&
                                critical_chunks != 0u &&
                                !worker_fatal &&
                                !worker_returned &&
                                callbacks.V63HeldMutexCount(
                                    worker_state.id) == 0u) {
                                callbacks.Append(
                                    "V64 BOUNDARY SAFE SWITCH tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " afterChunks=" +
                                    std::to_string(
                                        critical_chunks) +
                                    " phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"} +
                                    " safeReleaseYields=" +
                                    std::to_string(
                                        callbacks
                                            .v64_release_boundary_yields) +
                                    " PC=" +
                                    callbacks.V46DescribeGuestAddress(
                                        worker_state.regs[15]) +
                                    " heldMutexes=0");
                            } else if (
                                callbacks.V63Enabled() &&
                                critical_chunks != 0u &&
                                !worker_fatal &&
                                !worker_returned &&
                                callbacks.V63HeldMutexCount(
                                    worker_state.id) == 0u) {
                                callbacks.Append(
                                    "V63 BOUNDARY SAFE SWITCH tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " afterChunks=" +
                                    std::to_string(
                                        critical_chunks) +
                                    " phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"} +
                                    " PC=" +
                                    callbacks.V46DescribeGuestAddress(
                                        worker_state.regs[15]) +
                                    " heldMutexes=0");
                            }

                            callbacks.V64DisarmReleaseBoundary(
                                worker_state.id);

                            if (wi <
                                callbacks
                                    .deferred_threads
                                    .size()) {
                                callbacks
                                    .deferred_threads[wi] =
                                        worker_state;
                            }

                            ++ran;
                            ++boundary_worker_slices;

                            if (callbacks.V119Enabled() &&
                                callbacks.v119_audio_boundary_wakeup_pending &&
                                worker_state.id ==
                                    callbacks.v104_audio_worker_tid &&
                                !worker_fatal) {
                                callbacks.v119_audio_boundary_wakeup_pending =
                                    false;
                                ++callbacks.v119_audio_boundary_handoffs;
                            }

                            if (!callbacks.V86Enabled() &&
                                (boundary_worker_slices <= 24u ||
                                 (boundary_worker_slices %
                                  100u) == 0u ||
                                 worker_state.runtime_completed ||
                                 worker_state.runtime_failed)) {

                                callbacks.Append(
                                    "V38 BOUNDARY WORKER SLICE phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"} +
                                    " tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " PC=0x" +
                                    JniProbeHex(
                                        worker_state.regs[15]) +
                                    " ticks=" +
                                    std::to_string(
                                        callbacks.ticks_consumed) +
                                    " total=" +
                                    std::to_string(
                                        worker_state.runtime_ticks) +
                                    " calls+=" +
                                    std::to_string(
                                        callbacks.supported_calls -
                                        calls_before) +
                                    " returned=" +
                                    (worker_state.runtime_completed
                                        ? "YES"
                                        : "NO") +
                                    " failed=" +
                                    (worker_state.runtime_failed
                                        ? "YES"
                                        : "NO"));
                            }

                            if (worker_fatal) {
                                callbacks.Append(
                                    std::string{
                                        callbacks.V63Enabled()
                                            ? "V63 BOUNDARY WORKER FAIL-FAST: tid="
                                            : "V38 BOUNDARY WORKER STOP: tid="} +
                                    std::to_string(
                                        worker_state.id) +
                                    (callbacks.V63Enabled()
                                        ? " halted fatally; restoring main runtime before aborting boundary drain."
                                        : " halted fatally; preserving main runtime and continuing other diagnostics."));

                                if (callbacks.V63Enabled()) {
                                    v63_boundary_fatal = true;
                                    break;
                                }
                            }
                        }

                        clear_boundary_halts();

                        jit.Regs() =
                            saved_regs;
                        jit.ExtRegs() =
                            saved_ext_regs;
                        jit.SetCpsr(
                            saved_cpsr);
                        jit.SetFpscr(
                            saved_fpscr);
                        jit.ClearExclusiveState();

                        callbacks.return_mode =
                            PvZ2JniCallbacks::ReturnMode::Lifecycle;
                        callbacks.current_probe_thread_id = 0u;
                        callbacks.control_returned = false;
                        callbacks.soft_slice_timeout = true;

                        if (v63_boundary_fatal) {
                            result.trace =
                                callbacks.Trace();
                            if (result.message.empty()) {
                                if (callbacks.V66Enabled() &&
                                    !callbacks.v66_failure_message.empty()) {
                                    result.message =
                                        callbacks.v66_failure_message;
                                } else {
                                    result.message =
                                        "v63 fail-fast after fatal boundary worker.";
                                }
                            }
                            return false;
                        }

                        return true;
                    };

                auto drain_cloud_state_callback =
                    [&](const char* phase) -> bool {

                        if (!callbacks.pending_cloud_state_loaded ||
                            callbacks.cloud_state_loaded_delivered) {
                            return true;
                        }

                        if (callbacks.native_cloud_state_loaded_address ==
                            0u) {
                            callbacks.Append(
                                "V49 CLOUD HANDSHAKE: completion pending but Native_CloudStateLoaded was not captured; retaining previous behavior.");
                            return true;
                        }

                        callbacks.Append(
                            "V49 CLOUD DELIVER phase=" +
                            std::string{
                                phase != nullptr
                                    ? phase
                                    : "n/a"} +
                            " callback=0x" +
                            JniProbeHex(
                                callbacks
                                    .native_cloud_state_loaded_address));

                        // Verified in PvZ2 1.5.252752: this callback does not
                        // consume its Java String argument; it signals the
                        // native cloud singleton. Null therefore completes the
                        // async handshake without fabricating cloud payload.
                        if (!run_lifecycle(
                                "V49_Native_CloudStateLoaded",
                                callbacks
                                    .native_cloud_state_loaded_address,
                                kCloud,
                                0u,
                                0u,
                                false)) {
                            callbacks.Append(
                                "V49 CLOUD DELIVER failed.");
                            return false;
                        }

                        callbacks.cloud_state_loaded_delivered =
                            true;
                        callbacks.pending_cloud_state_loaded =
                            false;
                        callbacks.Append(
                            "V49 CLOUD DELIVER returned successfully.");
                        return true;
                    };

                std::size_t http_delivery_cursor = 0u;

                auto drain_offline_http_callbacks =
                    [&](const char* phase) -> bool {

                        constexpr std::uint32_t
                            kHttpTransactionError =
                                kGuestBase +
                                0x00a03410u;
                        constexpr std::size_t
                            kMaxHttpCallbacks = 32u;

                        std::size_t delivered = 0u;

                        while (http_delivery_cursor <
                                   callbacks
                                       .pending_http_failures
                                       .size() &&
                               delivered <
                                   kMaxHttpCallbacks) {

                            const auto item =
                                callbacks
                                    .pending_http_failures[
                                        http_delivery_cursor++];

                            ++callbacks.v52_http_deliveries;

                            callbacks.Append(
                                "V34 HTTP OFFLINE DELIVER phase=" +
                                std::string{
                                    phase != nullptr
                                        ? phase
                                        : "n/a"} +
                                " java=0x" +
                                JniProbeHex(
                                    item.first) +
                                " nativePeer=0x" +
                                JniProbeHex(
                                    item.second));

                            if (!run_lifecycle(
                                    "V34_HttpTransactionError",
                                    kHttpTransactionError,
                                    item.first,
                                    item.second,
                                    0u,
                                    false)) {
                                callbacks.Append(
                                    "V34 HTTP OFFLINE DELIVER failed for nativePeer=0x" +
                                    JniProbeHex(
                                        item.second));
                                return false;
                            }

                            ++delivered;
                        }

                        if (http_delivery_cursor <
                            callbacks
                                .pending_http_failures
                                .size()) {

                            callbacks.Append(
                                "V34 HTTP OFFLINE DELIVER: callback batch capped; remaining=" +
                                std::to_string(
                                    callbacks
                                        .pending_http_failures
                                        .size() -
                                    http_delivery_cursor));
                        }

                        return true;
                    };


                auto drain_audio_callbacks =
                    [&](const char* phase) -> bool {
                        if (!callbacks.V99Enabled()) {
                            return true;
                        }

                        const std::uint32_t newly_consumed =
                            PvZ2HostAudioTakeConsumedBufferCount();

                        callbacks.v99_audio_host_consumed +=
                            newly_consumed;
                        callbacks.v99_audio_pending_callbacks +=
                            newly_consumed;

                        if (callbacks.v99_audio_pending_callbacks == 0u) {
                            return true;
                        }

                        if (callbacks.v99_queue_callback == 0u ||
                            callbacks.v99_queue_itf == 0u) {
                            if (newly_consumed != 0u) {
                                callbacks.AppendDiagnostic(
                                    "V99 AUDIO CALLBACK DEFERRED phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"} +
                                    " pending=" +
                                    std::to_string(
                                        callbacks
                                            .v99_audio_pending_callbacks) +
                                    " callbackRegistered=NO");
                            }
                            return true;
                        }

                        const std::uint32_t
                            kMaxAudioCallbacksPerBoundary =
                                callbacks.V119Enabled()
                                    ? std::max<std::uint32_t>(
                                          1u,
                                          callbacks.v99_audio_queue_capacity)
                                    : (callbacks.V104Enabled()
                                           ? 1u
                                           : 8u);
                        std::uint32_t delivered = 0u;

                        while (callbacks.v99_audio_pending_callbacks != 0u &&
                               delivered <
                                   kMaxAudioCallbacksPerBoundary) {
                            const std::uint64_t callback_number =
                                callbacks.v99_audio_callback_deliveries +
                                1u;

                            if (callbacks.V99ShouldLogCounter(
                                    callback_number)) {
                                callbacks.AppendDiagnostic(
                                    "V99 AUDIO CALLBACK #" +
                                    std::to_string(
                                        callback_number) +
                                    " phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"} +
                                    " pendingBefore=" +
                                    std::to_string(
                                        callbacks
                                            .v99_audio_pending_callbacks) +
                                    " hostQueued=" +
                                    std::to_string(
                                        PvZ2HostAudioQueuedBufferCount()));
                            }

                            if (callbacks.V100Enabled() &&
                                callbacks.V99ShouldLogCounter(
                                    callback_number)) {
                                callbacks.AppendDiagnostic(
                                    "V100 AUDIO CALLBACK ABI #" +
                                    std::to_string(callback_number) +
                                    " r0(queue)=" +
                                    callbacks.V46DescribeGuestAddress(
                                        callbacks.v99_queue_itf) +
                                    " r1(context)=" +
                                    callbacks.V46DescribeGuestAddress(
                                        callbacks.v99_queue_context));
                            }

                            if (!run_lifecycle(
                                    callbacks.V100Enabled()
                                        ? "V100_OpenSL_BufferQueueCallback"
                                        : "V99_OpenSL_BufferQueueCallback",
                                    callbacks.v99_queue_callback,
                                    callbacks.v99_queue_itf,
                                    callbacks.v99_queue_context,
                                    0u,
                                    false,
                                    callbacks.V100Enabled())) {
                                callbacks.AppendCritical(
                                    "V99 AUDIO CALLBACK guest delivery failed.");
                                return false;
                            }

                            --callbacks.v99_audio_pending_callbacks;
                            ++callbacks.v99_audio_callback_deliveries;
                            ++delivered;
                            if (callbacks.V119Enabled()) {
                                ++callbacks.v119_audio_catchup_callbacks;
                            }
                        }

                        if (callbacks.V119Enabled() &&
                            delivered != 0u &&
                            callbacks.v104_audio_worker_tid != 0u) {
                            callbacks.v119_audio_boundary_wakeup_pending = true;
                            ++callbacks.v119_audio_catchup_services;
                            callbacks.v119_audio_max_pending =
                                std::max<std::uint64_t>(
                                    callbacks.v119_audio_max_pending,
                                    callbacks.v99_audio_pending_callbacks +
                                        delivered);
                            callbacks.v119_audio_max_batch =
                                std::max<std::uint64_t>(
                                    callbacks.v119_audio_max_batch,
                                    delivered);
                        }

                        if (callbacks.V102Enabled() &&
                            newly_consumed != 0u &&
                            callbacks.V99ShouldLogCounter(
                                callbacks
                                    .v99_audio_host_consumed)) {
                            callbacks.V102LogAudioPacer(
                                phase);
                        }

                        if (callbacks.v99_audio_pending_callbacks != 0u &&
                            callbacks.V99ShouldLogCounter(
                                callbacks
                                    .v99_audio_callback_deliveries)) {
                            callbacks.AppendDiagnostic(
                                "V99 AUDIO CALLBACK BACKLOG pending=" +
                                std::to_string(
                                    callbacks
                                        .v99_audio_pending_callbacks));
                        }

                        return true;
                    };

                constexpr std::uint32_t kGameAppThis =
                    kAndroidGameApp;
                constexpr std::uint32_t kSurfaceThis =
                    kAndroidSurfaceView;

                constexpr std::uint32_t kNativeWillFinishLaunching =
                    kGuestBase + 0x009ebf80u;
                constexpr std::uint32_t kNativeDidFinishLaunching =
                    kGuestBase + 0x009ec0a0u;
                constexpr std::uint32_t kNativeWillBecomeForeground =
                    kGuestBase + 0x009ec0bcu;
                constexpr std::uint32_t kNativeDidBecomeActive =
                    kGuestBase + 0x009ec0c8u;
                constexpr std::uint32_t kNativeOnSurfaceCreated =
                    kGuestBase + 0x009f1840u;
                constexpr std::uint32_t kNativeOnSurfaceChanged =
                    kGuestBase + 0x009f18dcu;
                constexpr std::uint32_t kNativeOnDrawFrame =
                    kGuestBase + 0x009f190cu;

                callbacks.host_surface_width =
                    callbacks.V77Enabled()
                        ? 2048u
                        : (callbacks.V74Enabled()
                               ? 2360u
                               : 1180u);
                callbacks.host_surface_height =
                    callbacks.V77Enabled()
                        ? 1536u
                        : (callbacks.V74Enabled()
                               ? 1640u
                               : 820u);

                callbacks.host_gles_ready =
                    PvZ2HostGLESBegin(
                        callbacks.host_surface_width,
                        callbacks.host_surface_height);

                callbacks.host_default_framebuffer =
                    callbacks.host_gles_ready
                        ? PvZ2HostGLESDefaultFramebuffer()
                        : 0u;

                result.host_gles_active =
                    callbacks.host_gles_ready;

                callbacks.gles_bound_guest_framebuffer =
                    0u;
                callbacks.gles_bound_host_framebuffer =
                    callbacks.host_default_framebuffer;

                callbacks.Append(
                    std::string{
                        "V31 HOST GLES: "} +
                    (callbacks.host_gles_ready
                        ? "READY offscreen=" +
                            std::to_string(
                                callbacks.host_surface_width) +
                            "x" +
                            std::to_string(
                                callbacks.host_surface_height) +
                            " hostFBO=0x" +
                            JniProbeHex(
                                callbacks.host_default_framebuffer)
                        : "UNAVAILABLE; retaining synthetic GLES probe fallback"));

                struct HostGLESGuard {
                    bool active = false;
                    ~HostGLESGuard() {
                        if (active) {
                            PvZ2HostGLESEnd();
                        }
                    }
                } host_gles_guard{
                    callbacks.host_gles_ready};

                // Null launch-string is an accepted path in the original
                // native function and avoids inventing a fake Java String.
                if (!run_lifecycle(
                        "Native_applicationWillFinishLaunching",
                        kNativeWillFinishLaunching,
                        kGameAppThis,
                        0,
                        0,
                        false)) {
                    return result;
                }

                if (!run_lifecycle(
                        "Native_applicationDidFinishLaunching",
                        kNativeDidFinishLaunching,
                        kGameAppThis,
                        0,
                        0,
                        false)) {
                    return result;
                }

                if (!run_lifecycle(
                        "Native_applicationWillBecomeForeground",
                        kNativeWillBecomeForeground,
                        kGameAppThis,
                        0,
                        0,
                        false)) {
                    return result;
                }

                if (!run_lifecycle(
                        "Native_applicationDidBecomeActive",
                        kNativeDidBecomeActive,
                        kGameAppThis,
                        0,
                        0,
                        false)) {
                    return result;
                }

                if (!run_lifecycle(
                        "Native_onSurfaceCreated",
                        kNativeOnSurfaceCreated,
                        kSurfaceThis,
                        0,
                        0,
                        false)) {
                    return result;
                }

                // v39 proved this Android native entry consumes dimensions in
                // height,width order. v74 keeps that verified ABI but finally
                // gives the guest the same native pixel surface advertised by
                // Graphics_GetScreenSizeInPixels (2360x1640) instead of a
                // half-resolution 1180x820 host FBO.
                callbacks.Append(
                    std::string{
                        callbacks.V77Enabled()
                            ? "V77 LEGACY IPAD SURFACE GEOMETRY: "
                            : "V74 SURFACE GEOMETRY: "} +
                    "calling Native_onSurfaceChanged with native-order height=" +
                    std::to_string(
                        callbacks.host_surface_height) +
                    " width=" +
                    std::to_string(
                        callbacks.host_surface_width) +
                    " for hostFBO=" +
                    std::to_string(
                        callbacks.host_surface_width) +
                    "x" +
                    std::to_string(
                        callbacks.host_surface_height) +
                    (callbacks.V77Enabled()
                        ? " (historical iPad Retina 4:3)."
                        : (callbacks.V74Enabled()
                               ? " (Retina native pixels)."
                               : " (legacy logical surface).")));

                if (!run_lifecycle(
                        "Native_onSurfaceChanged",
                        kNativeOnSurfaceChanged,
                        kSurfaceThis,
                        callbacks.host_surface_height,
                        callbacks.host_surface_width,
                        false)) {
                    return result;
                }

                // v49: finish the Java-side silent cloud sync handshake now
                // that startup + surface setup are complete, before rendering
                // the first frame.
                if (!drain_cloud_state_callback(
                        "pre-frame")) {
                    return result;
                }

                // Android's Java HTTP layer normally resolves Start()
                // asynchronously and calls one of the registered native
                // callbacks. The probe has no Android networking backend, so
                // finish queued startup requests as deterministic offline
                // errors at this lifecycle-safe boundary. This avoids leaving
                // the native transactions permanently "in flight".
                if (!drain_offline_http_callbacks(
                        "pre-frame")) {
                    return result;
                }

                // Give every deferred worker one short slice before rendering.
                // This is the first safe point after surface setup and starts
                // workers that v30 deliberately refused to interleave inside
                // Native_onSurfaceCreated.
                if (!run_boundary_workers(
                        "pre-frame",
                        callbacks.deferred_threads.size())) {
                    return result;
                }

                if (!drain_audio_callbacks(
                        "pre-frame")) {
                    return result;
                }

                constexpr std::uint32_t
                    kV36FrameCount = 600u;
                const bool v92_long_run =
                    callbacks.V92Enabled();

                auto should_sample_frame =
                    [v92_long_run](std::uint32_t frame) {
                        if (v92_long_run) {
                            return
                                frame <= 3u ||
                                frame == 5u ||
                                frame == 10u ||
                                frame == 15u ||
                                frame == 30u ||
                                frame == 60u ||
                                frame == 120u ||
                                frame == 300u ||
                                frame == 600u ||
                                (frame >= 3600u &&
                                 (frame % 3600u) == 0u);
                        }
                        return
                            frame <= 3u ||
                            frame == 5u ||
                            frame == 10u ||
                            frame == 15u ||
                            frame == 20u ||
                            frame == 30u ||
                            frame == 45u ||
                            (frame >= 55u &&
                             frame <= 90u) ||
                            frame == 120u ||
                            frame == 150u ||
                            frame == 180u ||
                            frame == 240u ||
                            frame == 300u ||
                            frame == 360u ||
                            frame == 420u ||
                            frame == 480u ||
                            frame == 540u ||
                            frame == 600u ||
                            (frame >= 90u &&
                             (frame % 10u) == 0u);
                    };

                auto should_probe_framebuffers =
                    [](std::uint32_t frame) {
                        return
                            frame == 15u ||
                            frame == 60u ||
                            frame == 70u ||
                            frame == 74u ||
                            frame == 75u ||
                            frame == 76u ||
                            frame == 80u ||
                            frame == 90u ||
                            frame == 120u ||
                            frame == 600u;
                    };

                std::uint64_t best_non_black = 0u;
                std::uint32_t best_frame = 0u;
                std::uint64_t post_ea_best_non_black = 0u;
                std::uint32_t post_ea_best_frame = 0u;
                std::string post_ea_best_path;

                auto should_capture_state_graph =
                    [](std::uint32_t frame) {
                        return
                            frame == 1u ||
                            frame == 15u ||
                            frame == 60u ||
                            frame == 70u ||
                            frame == 74u ||
                            frame == 75u ||
                            frame == 76u ||
                            frame == 80u ||
                            frame == 90u ||
                            frame == 120u ||
                            frame == 180u ||
                            frame == 300u ||
                            frame == 600u;
                    };

                std::uint32_t
                    v52_last_progress_frame = 0u;
                std::uint64_t
                    v52_last_sample_non_black =
                        std::numeric_limits<
                            std::uint64_t>::max();
                std::uint64_t
                    v52_last_texture_uploads =
                        callbacks
                            .gles_texture_uploads;
                std::uint32_t
                    v52_last_resource_lookups =
                        result
                            .resource_registry_lookup_calls;
                std::uint64_t
                    v52_last_http_activity =
                        callbacks.v52_http_starts +
                        callbacks.v52_http_deliveries;
                std::int32_t
                    v53_last_game_state =
                        callbacks.V53CurrentGameState();

                std::uint64_t v72_live_frames = 0u;
                std::uint64_t v72_last_touch_generation =
                    gV72TouchGeneration.load(
                        std::memory_order_acquire);

                for (std::uint32_t frame = 0u;
                     v92_long_run ||
                         frame < kV36FrameCount;
                     ++frame) {

                    const std::uint32_t frame_number =
                        frame + 1u;

                    const std::uint64_t v90_frame_loop_begin_ns =
                        callbacks.V90Enabled() ? V85SteadyNowNs() : 0u;

                    if (callbacks.V72Enabled() &&
                        gV72StopRequested.load(
                            std::memory_order_acquire)) {

                        if (v92_long_run) {
                            result.hard_stop_requested = true;
                            result.message =
                                std::string{
                                    callbacks.RuntimeModeTag()} +
                                " Hard Stop requested by user.";
                        }

                        callbacks.Append(
                            "V72 INTERACTIVE STOP before frame " +
                            std::to_string(
                                frame_number) +
                            " completed=" +
                            std::to_string(
                                result.draw_frames_completed));
                        break;
                    }

                    const bool sample =
                        should_sample_frame(
                            frame_number);

                    callbacks.current_frame_number =
                        frame_number;
                    callbacks.V90BeginFrame(frame_number);

                    if (sample) {
                        callbacks.Append(
                            "V39 FRAME SOAK: begin frame " +
                            std::to_string(
                                frame_number) +
                            (v92_long_run
                                ? std::string{" (long-run)"}
                                : std::string{"/"} +
                                      std::to_string(
                                          kV36FrameCount)));
                    }

                    const std::uint64_t
                        v74_text_delivered_before_frame =
                            callbacks
                                .v73_text_events_delivered;

                    const std::uint64_t v85_draw_begin_ns =
                        callbacks.V85PerformanceEnabled() ? V85SteadyNowNs() : 0u;
                    const bool draw_ok =
                        run_lifecycle(
                            "Native_onDrawFrame",
                            kNativeOnDrawFrame,
                            kSurfaceThis,
                            0,
                            0,
                            true);
                    const std::uint64_t v85_draw_elapsed_ns =
                        callbacks.V85PerformanceEnabled()
                            ? V85SteadyNowNs() - v85_draw_begin_ns
                            : 0u;
                    if (callbacks.V85PerformanceEnabled()) {
                        callbacks.V85RecordGuestDraw(
                            frame_number,
                            v85_draw_elapsed_ns);
                    }

                    if (!draw_ok) {

                        if (callbacks.host_gles_ready) {
                            const char* partial =
                                PvZ2HostGLESCapturePNGNamed(
                                    "pvz2-v36-stopped-frame.png");

                            if (partial != nullptr &&
                                *partial != '\0') {
                                result.host_frame_png_path =
                                    partial;
                            }
                        }

                        return result;
                    }

                    result.draw_frames_completed =
                        frame_number;

                    if (callbacks.V90Enabled() &&
                        callbacks.host_gles_ready) {
                        std::uint32_t drawable_width = 0u;
                        std::uint32_t drawable_height = 0u;
                        const std::uint64_t present_begin_ns = V85SteadyNowNs();
                        const bool presented =
                            PvZ2HostGLESPresent(
                                &drawable_width,
                                &drawable_height);
                        callbacks.V90RecordPresent(
                            frame_number,
                            V85SteadyNowNs() - present_begin_ns,
                            presented,
                            drawable_width,
                            drawable_height);
                        if (presented) {
                            ++v72_live_frames;
                            PvZ2HostNotifyDirectFrame(
                                frame_number,
                                callbacks.host_surface_width,
                                callbacks.host_surface_height);
                        }
                    }

                    // Start() can be reached while a frame is executing
                    // (analytics/live-config/telemetry requests do this).
                    // Deliver any newly queued terminal callbacks only after
                    // Native_onDrawFrame has returned, never in the middle of
                    // guest rendering/state mutation.
                    if (!drain_offline_http_callbacks(
                            "frame-boundary")) {
                        return result;
                    }

                    if (!drain_audio_callbacks(
                            "frame-boundary")) {
                        return result;
                    }

                    // One fair background slice per completed frame. No worker
                    // runs while Native_onDrawFrame itself is active.
                    if (!run_boundary_workers(
                            "frame-boundary",
                            1u)) {
                        return result;
                    }

                    if (!callbacks.V85PerformanceEnabled() &&
                        should_capture_state_graph(
                            frame_number)) {
                        callbacks.V52CaptureStateGraph(
                            frame_number);
                        callbacks.V53AppendGameStateSnapshot(
                            "frame-" +
                            std::to_string(
                                frame_number));
                    }

                    if (!callbacks.V85PerformanceEnabled() &&
                        callbacks.host_gles_ready &&
                        sample) {

                        const char* stats =
                            PvZ2HostGLESFrameStats();
                        const std::uint64_t non_black =
                            PvZ2HostGLESLastNonBlackPixels();

                        if (non_black > 0u) {
                            result.last_nonblack_frame_number =
                                frame_number;
                            result.last_nonblack_pixels =
                                non_black;
                        }

                        const std::uint64_t
                            v52_http_activity =
                                callbacks.v52_http_starts +
                                callbacks.v52_http_deliveries;
                        const std::int32_t
                            v53_game_state =
                                callbacks.V53CurrentGameState();

                        if (v52_last_sample_non_black !=
                                non_black ||
                            v52_last_texture_uploads !=
                                callbacks
                                    .gles_texture_uploads ||
                            v52_last_resource_lookups !=
                                result
                                    .resource_registry_lookup_calls ||
                            v52_last_http_activity !=
                                v52_http_activity ||
                            v53_last_game_state !=
                                v53_game_state ||
                            callbacks
                                .v50_mainmenu_background_seen ||
                            callbacks
                                .v50_ui_mainmenu_seen) {

                            v52_last_progress_frame =
                                frame_number;
                        }

                        v52_last_sample_non_black =
                            non_black;
                        v52_last_texture_uploads =
                            callbacks
                                .gles_texture_uploads;
                        v52_last_resource_lookups =
                            result
                                .resource_registry_lookup_calls;
                        v52_last_http_activity =
                            v52_http_activity;
                        v53_last_game_state =
                            v53_game_state;

                        callbacks.Append(
                            "V39 FRAME STATS #" +
                            std::to_string(
                                frame_number) +
                            ": " +
                            (stats != nullptr
                                ? stats
                                : "unavailable") +
                            " GL{draws=" +
                            std::to_string(
                                callbacks.gles_draw_calls) +
                            ",clears=" +
                            std::to_string(
                                callbacks.gles_clear_calls) +
                            ",uploads=" +
                            std::to_string(
                                callbacks.gles_texture_uploads) +
                            "}");

                        if (should_probe_framebuffers(
                                frame_number)) {

                            callbacks.Append(
                                "V47 FBO SNAPSHOT #" +
                                std::to_string(
                                    frame_number) +
                                " default guest=0 host=" +
                                std::to_string(
                                    callbacks
                                        .host_default_framebuffer) +
                                " draws=" +
                                std::to_string(
                                    callbacks
                                        .gles_draws_by_framebuffer[
                                            callbacks
                                                .host_default_framebuffer]) +
                                " stats={" +
                                (stats != nullptr
                                    ? std::string{stats}
                                    : std::string{"unavailable"}) +
                                "}");

                            std::vector<GLuint>
                                framebuffers(
                                    callbacks
                                        .gles_generated_framebuffers
                                        .begin(),
                                    callbacks
                                        .gles_generated_framebuffers
                                        .end());

                            std::sort(
                                framebuffers.begin(),
                                framebuffers.end());

                            for (const GLuint framebuffer :
                                 framebuffers) {

                                const auto attached =
                                    callbacks
                                        .gles_framebuffer_color_texture
                                        .find(
                                            framebuffer);

                                if (attached ==
                                    callbacks
                                        .gles_framebuffer_color_texture
                                        .end()) {

                                    callbacks.Append(
                                        "V47 FBO SNAPSHOT #" +
                                        std::to_string(
                                            frame_number) +
                                        " host=" +
                                        std::to_string(
                                            framebuffer) +
                                        " no-color-texture draws=" +
                                        std::to_string(
                                            callbacks
                                                .gles_draws_by_framebuffer[
                                                    framebuffer]));
                                    continue;
                                }

                                const auto info =
                                    callbacks
                                        .gles_texture_info
                                        .find(
                                            attached->second);

                                if (info ==
                                        callbacks
                                            .gles_texture_info
                                            .end() ||
                                    info->second.width <= 0 ||
                                    info->second.height <= 0) {

                                    callbacks.Append(
                                        "V47 FBO SNAPSHOT #" +
                                        std::to_string(
                                            frame_number) +
                                        " host=" +
                                        std::to_string(
                                            framebuffer) +
                                        " colorTex=" +
                                        std::to_string(
                                            attached->second) +
                                        " unknown-size draws=" +
                                        std::to_string(
                                            callbacks
                                                .gles_draws_by_framebuffer[
                                                    framebuffer]));
                                    continue;
                                }

                                const char* internal_stats =
                                    PvZ2HostGLESFramebufferStats(
                                        static_cast<std::uint32_t>(
                                            framebuffer),
                                        static_cast<std::uint32_t>(
                                            info->second.width),
                                        static_cast<std::uint32_t>(
                                            info->second.height));

                                callbacks.Append(
                                    "V47 FBO SNAPSHOT #" +
                                    std::to_string(
                                        frame_number) +
                                    " guest/host=" +
                                    std::to_string(
                                        framebuffer) +
                                    " colorTex=" +
                                    std::to_string(
                                        attached->second) +
                                    " draws=" +
                                    std::to_string(
                                        callbacks
                                            .gles_draws_by_framebuffer[
                                                framebuffer]) +
                                    " stats={" +
                                    (internal_stats != nullptr
                                        ? std::string{
                                              internal_stats}
                                        : std::string{
                                              "unavailable"}) +
                                    "}");
                            }
                        }

                        if (non_black > best_non_black) {
                            const char* best =
                                PvZ2HostGLESCapturePNGNamed(
                                    "pvz2-v48-best-frame.png");

                            if (best != nullptr &&
                                *best != '\0') {
                                best_non_black =
                                    non_black;
                                best_frame =
                                    frame_number;
                                result.best_frame_number =
                                    best_frame;
                                result.best_frame_nonblack =
                                    best_non_black;
                                result.best_frame_png_path =
                                    best;

                                callbacks.Append(
                                    "V48 BEST FRAME: #" +
                                    std::to_string(
                                        best_frame) +
                                    " nonBlack=" +
                                    std::to_string(
                                        best_non_black) +
                                    " path=" +
                                    result.best_frame_png_path);
                            }
                        }

                        // Preserve the richest frame after the EA animation
                        // separately. The globally richest image is EA itself,
                        // so without this a later menu/loading screen with
                        // fewer lit pixels would never be shown to the tester.
                        if (frame_number >= 90u &&
                            non_black >
                                post_ea_best_non_black) {

                            const char* post_ea =
                                PvZ2HostGLESCapturePNGNamed(
                                    "pvz2-v48-post-ea-best.png");

                            if (post_ea != nullptr &&
                                *post_ea != '\0') {
                                post_ea_best_non_black =
                                    non_black;
                                post_ea_best_frame =
                                    frame_number;
                                post_ea_best_path =
                                    post_ea;

                                callbacks.Append(
                                    "V39 POST-EA FRAME: #" +
                                    std::to_string(
                                        post_ea_best_frame) +
                                    " nonBlack=" +
                                    std::to_string(
                                        post_ea_best_non_black) +
                                    " path=" +
                                    post_ea_best_path);
                            }
                        }

                        callbacks.Append(
                            "V39 FRAME SOAK: returned frame " +
                            std::to_string(
                                frame_number) +
                            (v92_long_run
                                ? std::string{" (long-run)"}
                                : std::string{"/"} +
                                      std::to_string(
                                          kV36FrameCount)));

                        // v52 adaptive stop: 600 remains the safety ceiling,
                        // not a mandatory wait. Once EA is fully black and 45
                        // sampled frames have produced no new pixels, texture
                        // uploads, resource lookups, HTTP activity or menu
                        // milestone, additional identical frames are not useful.
                        if (frame_number >= 120u &&
                            non_black == 0u &&
                            !callbacks
                                 .v50_mainmenu_background_seen &&
                            !callbacks
                                 .v50_ui_mainmenu_seen &&
                            !callbacks
                                 .pending_cloud_state_loaded &&
                            callbacks.v52_http_starts ==
                                callbacks
                                    .v52_http_deliveries &&
                            frame_number >=
                                v52_last_progress_frame +
                                    45u) {

                            result.adaptive_frame_stop =
                                true;

                            callbacks.Append(
                                "V52 ADAPTIVE STOP frame=" +
                                std::to_string(
                                    frame_number) +
                                " lastProgressFrame=" +
                                std::to_string(
                                    v52_last_progress_frame) +
                                " exactState=" +
                                std::to_string(
                                    callbacks
                                        .V53CurrentGameState()) +
                                "(" +
                                PvZ2JniCallbacks::
                                    V53GameStateName(
                                        callbacks
                                            .V53CurrentGameState()) +
                                ") reason=post-EA framebuffer/resource/HTTP/GameState stable");
                            break;
                        }
                    }

                    if (callbacks.V72Enabled() &&
                        !callbacks.V90Enabled() &&
                        callbacks.host_gles_ready &&
                        live_frame) {

                        const std::uint64_t touch_generation =
                            gV72TouchGeneration.load(
                                std::memory_order_acquire);

                        const bool input_changed =
                            touch_generation !=
                            v72_last_touch_generation;

                        // v73 wakes presentation when UIKit queues text, but
                        // a key can arrive after this frame's UI_ProcessEvents:
                        // that refresh still shows the previous framebuffer.
                        // Publish again on the exact frame that actually
                        // consumes text so the newly rendered character is not
                        // delayed until the next 3-frame sampling interval.
                        const bool text_consumed_this_frame =
                            callbacks.V74Enabled() &&
                            callbacks
                                .v73_text_events_delivered !=
                            v74_text_delivered_before_frame;

                        const bool publish_live =
                            frame_number == 1u ||
                            (frame_number % 3u) == 0u ||
                            input_changed ||
                            text_consumed_this_frame;

                        if (publish_live) {
                            std::uint32_t live_width = 0u;
                            std::uint32_t live_height = 0u;
                            std::size_t live_size = 0u;

                            const std::uint64_t v85_capture_begin_ns =
                                callbacks.V85PerformanceEnabled() ? V85SteadyNowNs() : 0u;
                            const std::uint8_t* live_rgba =
                                PvZ2HostGLESCopyDisplayRGBA(
                                    &live_width,
                                    &live_height,
                                    &live_size);
                            if (callbacks.V85PerformanceEnabled()) {
                                callbacks.V85RecordCapture(
                                    frame_number,
                                    V85SteadyNowNs() - v85_capture_begin_ns,
                                    live_size);
                            }

                            if (live_rgba != nullptr &&
                                live_size != 0u) {

                                live_frame(
                                    frame_number,
                                    live_width,
                                    live_height,
                                    live_rgba,
                                    live_size);

                                ++v72_live_frames;
                            }

                            v72_last_touch_generation =
                                touch_generation;
                        }
                    }

                    if (callbacks.V90Enabled()) {
                        callbacks.V90EndFrame(
                            frame_number,
                            v85_draw_elapsed_ns,
                            V85SteadyNowNs() - v90_frame_loop_begin_ns);
                    }

                    if (callbacks.V72Enabled() &&
                        gV72StopRequested.load(
                            std::memory_order_acquire)) {

                        if (v92_long_run) {
                            result.hard_stop_requested = true;
                            result.message =
                                std::string{
                                    callbacks.RuntimeModeTag()} +
                                " Hard Stop requested by user.";
                        }

                        callbacks.Append(
                            "V72 INTERACTIVE STOP after frame " +
                            std::to_string(
                                frame_number) +
                            " touchDelivered=" +
                            std::to_string(
                                callbacks
                                    .v72_touch_events_delivered));
                        break;
                    }

                    if (v92_long_run ||
                        frame_number !=
                            kV36FrameCount) {
                        if (callbacks.V90Enabled()) {
                            constexpr std::uint64_t kV90TargetFrameNs =
                                16666667ull;
                            const std::uint64_t elapsed_ns =
                                V85SteadyNowNs() - v90_frame_loop_begin_ns;
                            if (elapsed_ns < kV90TargetFrameNs) {
                                std::this_thread::sleep_for(
                                    std::chrono::nanoseconds(
                                        kV90TargetFrameNs - elapsed_ns));
                            }
                        } else {
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(16));
                        }
                    }
                }

                const char* frame_loop_reason =
                    v92_long_run &&
                    gV72StopRequested.load(
                        std::memory_order_acquire)
                        ? "user-stop-frame-boundary"
                        : "normal-frame-loop-exit";
                if(callbacks.V89Enabled())callbacks.V89EmitTerminalSummaries(frame_loop_reason);
                if(callbacks.V90Enabled())callbacks.V90EmitTerminalSummaries(frame_loop_reason);
                if(callbacks.V91Enabled())callbacks.V91EmitTerminalSummary(frame_loop_reason);
                if (callbacks.V87Enabled()) {
                    callbacks.Append(
                        callbacks.V87MutexSummary());
                }

                if (callbacks.V85PerformanceEnabled()) {
                    callbacks.Append(callbacks.V85PerformanceSummary());
                }

                if (callbacks.V72Enabled()) {
                    callbacks.Append(
                        "V72 INTERACTIVE SUMMARY: queued=" +
                        std::to_string(
                            gV72QueuedTouches.load(
                                std::memory_order_relaxed)) +
                        " delivered=" +
                        std::to_string(
                            callbacks
                                .v72_touch_events_delivered) +
                        " batches=" +
                        std::to_string(
                            callbacks
                                .v72_touch_batches) +
                        " remaining=" +
                        std::to_string(
                            V72PendingTouchCount()) +
                        " dropped=" +
                        std::to_string(
                            gV72DroppedTouches.load(
                                std::memory_order_relaxed)) +
                        " invalidBuffers=" +
                        std::to_string(
                            callbacks
                                .v72_invalid_event_buffers) +
                        " liveFrames=" +
                        std::to_string(
                            v72_live_frames) +
                        " stopRequested=" +
                        (gV72StopRequested.load(
                             std::memory_order_relaxed)
                            ? std::string{"YES"}
                            : std::string{"NO"}));
                }

                if (callbacks.V79ProfileProbeEnabled()) {
                    callbacks.Append(
                        callbacks.V79ProfileSummary());
                }

                if (callbacks.V80Enabled()) {
                    callbacks.Append(
                        callbacks.V80TransformSummary());
                    callbacks.Append(
                        std::string{"V81 HITTEST SUMMARY mode="} +
                        (callbacks.V81Enabled()
                            ? "LOGICAL_POINTS"
                            : "PIXEL_CONTROL") +
                        " guestTouchSpace=" +
                        (callbacks.V81Enabled()
                            ? "1024x768"
                            : "2048x1536") +
                        " detailedEvents=" +
                        std::to_string(callbacks.v81_touch_events_logged) +
                        " totalDelivered=" +
                        std::to_string(callbacks.v72_touch_events_delivered));

                    if (callbacks.V82Enabled()) {
                        callbacks.Append(
                            callbacks.V82RadarSummary());
                    }
                    if (callbacks.V83Enabled()) {
                        callbacks.Append(
                            callbacks.V83ButtonSummary());
                    }
                    if (callbacks.V84FinalBlitEnabled()) {
                        callbacks.Append(
                            callbacks.V84RenderContractSummary());
                    }
                }

                if (callbacks.V73Enabled()) {
                    callbacks.Append(
                        "V73 KEYBOARD SUMMARY: textQueued=" +
                        std::to_string(
                            gV73QueuedTextEvents.load(
                                std::memory_order_relaxed)) +
                        " textDelivered=" +
                        std::to_string(
                            callbacks
                                .v73_text_events_delivered) +
                        " textBytes=" +
                        std::to_string(
                            callbacks
                                .v73_text_bytes_delivered) +
                        " textBatches=" +
                        std::to_string(
                            callbacks
                                .v73_text_batches) +
                        " textRemaining=" +
                        std::to_string(
                            V73PendingTextCount()) +
                        " textDropped=" +
                        std::to_string(
                            gV73DroppedTextEvents.load(
                                std::memory_order_relaxed)) +
                        " show=" +
                        std::to_string(
                            callbacks
                                .v73_keyboard_show_calls) +
                        " hide=" +
                        std::to_string(
                            callbacks
                                .v73_keyboard_hide_calls) +
                        " status=" +
                        std::to_string(
                            callbacks
                                .v73_keyboard_status_calls) +
                        " hostVisible=" +
                        (PvZ2HostKeyboardVisible()
                            ? std::string{"YES"}
                            : std::string{"NO"}));
                }

                if (callbacks.host_gles_ready) {
                    const char* final_capture =
                        PvZ2HostGLESCapturePNGNamed(
                            "pvz2-v48-final-frame.png");

                    callbacks.Append(
                        std::string{
                            "V48 FINAL GLES CAPTURE: "} +
                        (final_capture != nullptr &&
                         *final_capture != '\0'
                            ? final_capture
                            : "failed"));

                    if (final_capture != nullptr &&
                        *final_capture != '\0') {
                        result.final_frame_png_path =
                            final_capture;

                        // v52 deliberately displays the final framebuffer,
                        // not the visually richest splash frame.
                        result.host_frame_png_path =
                            final_capture;
                    }
                }

                callbacks.V53AppendGameStateSnapshot(
                    "final");
                callbacks.V52FinalizeDiagnostics();

                callbacks.Append(
                    "V52 FRAME SUMMARY: frame=" +
                    std::to_string(
                        best_frame) +
                    " nonBlack=" +
                    std::to_string(
                        best_non_black) +
                    " | postEA=" +
                    std::to_string(
                        post_ea_best_frame) +
                    " nonBlack=" +
                    std::to_string(
                        post_ea_best_non_black) +
                    " | boundaryWorkerSlices=" +
                    std::to_string(
                        boundary_worker_slices) +
                    " | wrapperDirectNulls=" +
                    std::to_string(
                        callbacks.resource_wrapper_direct_nulls) +
                    " wrapperExhaustedNulls=" +
                    std::to_string(
                        callbacks.resource_wrapper_exhausted_nulls) +
                    " wrapperRecoveries=" +
                    std::to_string(
                        callbacks.resource_wrapper_recoveries) +
                    " | cloudPending=" +
                    (callbacks.pending_cloud_state_loaded
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " cloudDelivered=" +
                    (callbacks.cloud_state_loaded_delivered
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " | networkStatusCalls=" +
                    std::to_string(
                        callbacks.v50_network_status_calls) +
                    " uiAndroid=" +
                    (callbacks.v50_ui_android_seen
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " uiIPad=" +
                    (callbacks.v50_ui_ipad_seen
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " mainMenuBg=" +
                    (callbacks.v50_mainmenu_background_seen
                        ? std::string{"YES@"} +
                              std::to_string(
                                  callbacks
                                      .v50_mainmenu_background_first_frame)
                        : std::string{"NO"}) +
                    " uiMainMenu=" +
                    (callbacks.v50_ui_mainmenu_seen
                        ? std::string{"YES@"} +
                              std::to_string(
                                  callbacks
                                      .v50_ui_mainmenu_first_frame)
                        : std::string{"NO"}) +
                    " initAtlas=" +
                    (callbacks.v50_init_atlas_seen
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " | userFsFiles=" +
                    std::to_string(
                        callbacks
                            .v51_writable_files
                            .size()) +
                    " userFsWrites=" +
                    std::to_string(
                        callbacks
                            .v51_userfs_write_calls) +
                    " userFsBytes=" +
                    std::to_string(
                        callbacks
                            .v51_userfs_bytes_written) +
                    " snapshot2Bytes=" +
                    std::to_string(
                        callbacks
                            .v51_snapshot2_bytes) +
                    " configKeys=" +
                    std::to_string(
                        callbacks
                            .v51_config_keys
                            .size()));

                result.startup_logo_summary =
                    callbacks.V54StartupLogoSummary();
                callbacks.Append(
                    "V54 STARTUPLOGO SUMMARY: " +
                    result.startup_logo_summary);

                result.startup_resource_group_summary =
                    callbacks.V55StartupResourceGroupSummary();
                callbacks.Append(
                    "V55 STARTUP GROUP SUMMARY: " +
                    result.startup_resource_group_summary);

                result.diagnostic_matrix_summary =
                    callbacks.V56DiagnosticMatrixSummary();
                result.gate_a_scout_activated =
                    callbacks.v56_gate_a_scout_activated;
                callbacks.Append(
                    "V56 DIAGNOSTIC MATRIX SUMMARY: " +
                    result.diagnostic_matrix_summary);

                result.ctype_deep_scout_summary =
                    callbacks.V57CtypeDeepScoutSummary();
                result.ctype_self_check_passed =
                    callbacks.v57_ctype_self_check_passed;
                result.gate_c_scout_activated =
                    callbacks.v57_gate_c_scout_activated;
                callbacks.Append(
                    "V57 SUMMARY: " +
                    result.ctype_deep_scout_summary);

                result.ok = true;
                result.message =
                    std::string{"PvZ2 completed v57 mode "} +
                    callbacks.V56ModeName() +
                    " on top of stable v52-v56 diagnostics. V56_BASELINE preserves the old import behavior. Ctype modes use ABI-correct Bionic ctype imported data. Deep Scout never fabricates registry entries or GameState transitions; Gate-A is only scouted after legacy 4/4-MISS proof and Gate-C only after a delayed no-write proof.";
                return result;
            }

            if (result.message.empty()) {
                result.message =
                    "Native_GameAppInitialize halted before returning.";
            }

            return result;
        }

        if (result.message.empty()) {
            result.message =
                "Constructors completed, but JNI_OnLoad halted before returning.";
        }

        return result;
    } catch (const std::exception& e) {
        result.message =
            std::string{
                "Full-load probe exception: "} +
            e.what();
        return result;
    } catch (...) {
        result.message =
            "Full-load probe failed with an unknown native exception.";
        return result;
    }
}

