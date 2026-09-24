            v64_release_boundary_armed &&
            v64_release_boundary_thread ==
                current_probe_thread_id &&
            held_after == 0u;

        if (v64_safe_release) {
            ++v64_release_boundary_yields;
            v64_release_boundary_armed = false;
            v64_release_boundary_thread = 0xffffffffu;

            if (v64_release_boundary_yields <= 24u ||
                (v64_release_boundary_yields % 1000u) == 0u) {
                Append(
                    "V64 SAFE RELEASE #" +
                    std::to_string(
                        v64_release_boundary_yields) +
                    " tid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex) +
                    " releaseCount=" +
                    std::to_string(v63_mutex_releases) +
                    " -> end worker continuation at heldMutexes=0");
            }

            // This is the same soft cooperative halt already proven by the
            // v62 verified-pump unlock path. The import callback still
            // returns pthread_mutex_unlock success before the worker state is
            // snapshotted by the scheduler.
            if (jit) {
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined4);
            }
        }

        return true;
    }

    std::string V62HeapPointerClass(std::uint32_t address) const {
        for (const auto& item : mem.heap_allocations) {
            const std::uint32_t base = item.first;
            const std::uint32_t size = item.second;
            const std::uint64_t end = static_cast<std::uint64_t>(base) + size;
            if (address >= base && static_cast<std::uint64_t>(address) < end) {
                const std::uint32_t offset = address - base;
                return std::string{offset == 0u ? "live-allocation-start" : "live-interior"} +
                    "{base=0x" + JniProbeHex(base) +
                    ",size=" + std::to_string(size) +
                    ",offset=+0x" + JniProbeHex(offset) + "}";
            }
        }

        for (auto it = mem.heap_retired_allocations.rbegin();
             it != mem.heap_retired_allocations.rend(); ++it) {
            const std::uint32_t base = it->first;
            const std::uint32_t size = it->second;
            const std::uint64_t end = static_cast<std::uint64_t>(base) + size;
            if (address >= base && static_cast<std::uint64_t>(address) < end) {
                return "retired-allocation{base=0x" + JniProbeHex(base) +
                    ",size=" + std::to_string(size) +
                    ",offset=+0x" + JniProbeHex(address - base) + "}";
            }
        }
        return "not-in-tracked-allocation";
    }

    std::string V62WorkerAlias(std::uint32_t address) const {
        for (const auto& item : v62_worker_payloads) {
            if (address == item.second.object)
                return "tid=" + std::to_string(item.first) + ".this";
            if (address == item.second.sentinel30)
                return "tid=" + std::to_string(item.first) + ".this+0x30";
        }
        return {};
    }

    void V62RefreshPumpVector() {
        if (v62_pump_manager == 0u ||
            mem.Ptr(v62_pump_manager + 0x58u, 4u) == nullptr) return;
        v62_pump_vector_begin = mem.Read32Guest(v62_pump_manager + 0x50u);
        v62_pump_vector_end = mem.Read32Guest(v62_pump_manager + 0x54u);
        v62_pump_vector_cap = mem.Read32Guest(v62_pump_manager + 0x58u);
    }

    void V62ScanPumpVector(const char* reason) {
        if (!V62Enabled()) return;
        V62RefreshPumpVector();
        if (v62_pump_vector_begin == 0u ||
            v62_pump_vector_end < v62_pump_vector_begin ||
            v62_pump_vector_cap < v62_pump_vector_end) {
            Append(std::string{"V62 VECTOR SNAPSHOT "} +
                   (reason ? reason : "?") + " invalid begin=0x" +
                   JniProbeHex(v62_pump_vector_begin) + " end=0x" +
                   JniProbeHex(v62_pump_vector_end) + " cap=0x" +
                   JniProbeHex(v62_pump_vector_cap));
            return;
        }

        const std::uint32_t count = std::min<std::uint32_t>(
            (v62_pump_vector_end - v62_pump_vector_begin) / 4u, 16384u);
        std::uint32_t aliases = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint32_t value =
                mem.Read32Guest(v62_pump_vector_begin + i * 4u);
            const std::string alias = V62WorkerAlias(value);
            if (alias.empty()) continue;
            ++aliases;
            Append(std::string{"V62 VECTOR ALIAS "} + (reason ? reason : "?") +
                   " slot=" + std::to_string(i) +
                   " value=" + V46DescribeGuestAddress(value) +
                   " alias=" + alias +
                   " class=" + V62HeapPointerClass(value));
        }
        Append(std::string{"V62 VECTOR SNAPSHOT "} + (reason ? reason : "?") +
               " begin=0x" + JniProbeHex(v62_pump_vector_begin) +
               " end=0x" + JniProbeHex(v62_pump_vector_end) +
               " cap=0x" + JniProbeHex(v62_pump_vector_cap) +
               " count=" + std::to_string(count) +
               " workerAliases=" + std::to_string(aliases));
    }

    void V62ObserveWrite(
        std::uint32_t address,
        std::uint32_t width,
        std::uint64_t old_value,
        std::uint64_t new_value,
        const char* source = "guest-store") {

        if (!V62Enabled() || width != 4u) return;

        const std::uint32_t old32 = static_cast<std::uint32_t>(old_value);
        const std::uint32_t new32 = static_cast<std::uint32_t>(new_value);
        const std::string alias = V62WorkerAlias(new32);
        const bool metadata =
            v62_pump_manager != 0u &&
            (address == v62_pump_manager + 0x50u ||
             address == v62_pump_manager + 0x54u ||
             address == v62_pump_manager + 0x58u);

        // MemoryWrite32 is called after the guest store. Update the cached
        // vector triplet directly instead of rereading manager+0x50/+0x54/+0x58
        // on every unrelated store in the process.
        if (metadata) {
            if (address == v62_pump_manager + 0x50u)
                v62_pump_vector_begin = new32;
            else if (address == v62_pump_manager + 0x54u)
                v62_pump_vector_end = new32;
            else
                v62_pump_vector_cap = new32;
        }

        const bool vector_slot =
            v62_pump_vector_begin != 0u &&
            v62_pump_vector_cap >= v62_pump_vector_begin &&
            address >= v62_pump_vector_begin &&
            address + 4u <= v62_pump_vector_cap &&
            ((address - v62_pump_vector_begin) % 4u) == 0u;

        if (alias.empty() && !metadata && !vector_slot) return;
        ++v62_pointer_write_events;

        const bool bad_tid1 =
            v62_tid1_sentinel != 0u && new32 == v62_tid1_sentinel &&
            (vector_slot || metadata);
        const std::uint32_t pc = jit ? jit->Regs()[15] : 0u;
        const std::uint32_t lr = jit ? jit->Regs()[14] : 0u;

        if (bad_tid1 && !v62_first_bad_pointer_writer_seen) {
            v62_first_bad_pointer_writer_seen = true;
            v62_first_bad_pointer_writer_pc = pc;
            v62_first_bad_pointer_writer_lr = lr;
            v62_first_bad_pointer_writer_dst = address;
            Append("V62 FIRST BAD POINTER INSERT: value=0x" + JniProbeHex(new32) +
                   " alias=" + V62WorkerAlias(new32) +
                   " dst=" + V46DescribeGuestAddress(address) +
                   " old=0x" + JniProbeHex(old32) +
                   " PC=" + V46DescribeGuestAddress(pc) +
                   " LR=" + V46DescribeGuestAddress(lr) +
                   " thread=" + std::to_string(current_probe_thread_id) +
                   " source=" + (source ? source : "?"));
        }

        const bool alias_important =
            !alias.empty() &&
            (vector_slot || metadata ||
             v62_pointer_write_events <= 128u ||
             (v62_pointer_write_events % 512u) == 0u);

        if (!(bad_tid1 || alias_important ||
              v62_pointer_write_events <= 64u ||
              (v62_pointer_write_events % 512u) == 0u)) return;

        std::ostringstream out;
        out << "V62 POINTER WRITE #" << v62_pointer_write_events
            << " source=" << (source ? source : "?")
            << " thread=" << current_probe_thread_id
            << " dst=" << V46DescribeGuestAddress(address)
            << " old=0x" << JniProbeHex(old32)
            << " new=0x" << JniProbeHex(new32)
            << " newClass=" << V62HeapPointerClass(new32);
        if (!alias.empty()) out << " alias=" << alias;
        if (vector_slot)
            out << " vectorSlot=" << ((address - v62_pump_vector_begin) / 4u);
        if (metadata) out << " managerMetadata=YES";
        out << " vector={begin=0x" << JniProbeHex(v62_pump_vector_begin)
            << ",end=0x" << JniProbeHex(v62_pump_vector_end)
            << ",cap=0x" << JniProbeHex(v62_pump_vector_cap)
            << "} PC=" << V46DescribeGuestAddress(pc)
            << " LR=" << V46DescribeGuestAddress(lr);
        Append(out.str());
    }

    static std::string V53GameStateName(
        std::int32_t state) {

        switch (state) {
        case -1:
            return "NONE";
        case 1:
            return "GAME_Initializing";
        case 2:
            return "GAME_LogoScreen";
        case 3:
            return "GAME_PatchScreen";
        case 4:
            return "GAME_MainMenu";
        case 5:
            return "GAME_Game";
        case 6:
            return "GAME_WorldMap";
        case 7:
            return "GAME_ContentUpdateScreen";
        case 8:
            return "GAME_Almanac";
        case 9:
            return "GAME_Store";
        case 10:
            return "GAME_WaitForNetworkLoad";
        default:
            return "UNKNOWN_" +
                std::to_string(state);
        }
    }

    bool V53IsGameStateManager(
        std::uint32_t address) {

        constexpr std::uint32_t kGameStateManagerVtable =
            kGuestBase + 0x00cdb7d8u;

        return
            address != 0u &&
            mem.Ptr(address, 0x45cu) != nullptr &&
            mem.Read32Guest(address) ==
                kGameStateManagerVtable;
    }

    void V53CacheGameStateManager(
        std::uint32_t address,
        const char* source) {

        if (!V53IsGameStateManager(address)) {
            return;
        }

        if (v53_game_state_manager != address) {
            v53_game_state_manager = address;
            result.game_state_manager = address;

            Append(
                "V53 GAMESTATE MANAGER source=" +
                std::string{
                    source != nullptr
                        ? source
                        : "?"} +
                " object=" +
                V46DescribeGuestAddress(address) +
                " vtable=" +
                V46DescribeGuestAddress(
                    mem.Read32Guest(address)));
        }
    }

    std::int32_t V53CurrentGameState() {
        if (!V53IsGameStateManager(
                v53_game_state_manager)) {
            return -999;
        }

        return static_cast<std::int32_t>(
            mem.Read32Guest(
                v53_game_state_manager +
                0x374u));
    }

    std::int32_t V53PendingGameState() {
        if (!V53IsGameStateManager(
                v53_game_state_manager)) {
            return -999;
        }

        return static_cast<std::int32_t>(
            mem.Read32Guest(
                v53_game_state_manager +
                0x41cu));
    }

    void V53AppendGameStateSnapshot(
        const std::string& phase) {

        result.game_state_manager =
            v53_game_state_manager;
        result.game_state_request_calls =
            v53_state_request_calls;
        result.game_state_apply_calls =
            v53_state_apply_calls;

        if (!V53IsGameStateManager(
                v53_game_state_manager)) {
            result.game_state_current = -999;
            result.game_state_pending = -999;
            Append(
                "V53 GAMESTATE SNAPSHOT phase=" +
                phase +
                " manager=NOT_FOUND requests=" +
                std::to_string(
                    v53_state_request_calls) +
                " applies=" +
                std::to_string(
                    v53_state_apply_calls));
            return;
        }

        const std::int32_t current =
            V53CurrentGameState();
        const std::int32_t pending =
            V53PendingGameState();

        result.game_state_current = current;
        result.game_state_pending = pending;

        std::ostringstream out;
        out
            << "V53 GAMESTATE SNAPSHOT phase="
            << phase
            << " manager=0x"
            << JniProbeHex(
                   v53_game_state_manager)
            << " current="
            << current
            << "("
            << V53GameStateName(current)
            << ") pending="
            << pending
            << "("
            << V53GameStateName(pending)
            << ") requests="
            << v53_state_request_calls
            << " applies="
            << v53_state_apply_calls
            << " transitionArgA=0x"
            << JniProbeHex(
                   mem.Read32Guest(
                       v53_game_state_manager +
                       0x414u))
            << " transitionArgB=0x"
            << JniProbeHex(
                   mem.Read32Guest(
                       v53_game_state_manager +
                       0x418u))
            << " transitionMode="
            << mem.Read32Guest(
                   v53_game_state_manager +
                   0x424u)
            << " flag428="
            << static_cast<unsigned>(
                   mem.Read8(
                       v53_game_state_manager +
                       0x428u))
            << " startup429="
            << static_cast<unsigned>(
                   mem.Read8(
                       v53_game_state_manager +
                       0x429u))
            << " startup42A="
            << static_cast<unsigned>(
                   mem.Read8(
                       v53_game_state_manager +
                       0x42au))
            << " startup430="
            << mem.Read32Guest(
                   v53_game_state_manager +
                   0x430u)
            << " field434=0x"
            << JniProbeHex(
                   mem.Read32Guest(
                       v53_game_state_manager +
                       0x434u))
            << " field438=0x"
            << JniProbeHex(
                   mem.Read32Guest(
                       v53_game_state_manager +
                       0x438u))
            << " byte43C="
            << static_cast<unsigned>(
                   mem.Read8(
                       v53_game_state_manager +
                       0x43cu))
            << " field458=0x"
            << JniProbeHex(
                   mem.Read32Guest(
                       v53_game_state_manager +
                       0x458u));

        Append(out.str());
    }

    std::string V54StartupLogoSummary() const {
        float gate_a_ratio = 0.0f;
        std::memcpy(
            &gate_a_ratio,
            &v54_gate_a_result_bits,
            sizeof(gate_a_ratio));

        std::ostringstream out;
        out
            << "V54 StartupLogo"
            << " A{resourceHits=" << v54_gate_a_resource_hits
            << ",resource=0x" << JniProbeHex(v54_gate_a_resource)
            << ",totalsHits=" << v54_gate_a_totals_hits
            << ",completed=" << v54_gate_a_completed
            << ",total=" << v54_gate_a_total
            << ",resultHits=" << v54_gate_a_result_hits
            << ",ratio=" << gate_a_ratio
            << ",pass=" << (gate_a_ratio >= 1.0f ? "YES" : "NO")
            << "}"
            << " B{staticReturn=1,pass=YES}"
            << " C{hits=" << v54_gate_c_hits
            << ",object=0x" << JniProbeHex(v54_gate_c_object)
            << ",state=" << v54_gate_c_state
            << ",pass=" << (v54_gate_c_state == 4u ? "YES" : "NO")
            << "}"
            << " D{hits=" << v54_gate_d_hits
            << ",counter=" << v54_gate_d_counter
            << ",pass=" << (v54_gate_d_counter >= 3u ? "YES" : "NO")
            << "}"
            << " afterD=" << v54_after_d_hits
            << " E{hits=" << v54_gate_e_hits
            << ",b7a=" << v54_gate_e_value << "}"
            << " F=" << v54_gate_f_hits << "/" << v54_gate_f_value
            << " G=" << v54_gate_g_hits << "/" << v54_gate_g_value
            << " H=" << v54_gate_h_hits << "/" << v54_gate_h_value
            << " I=" << v54_gate_i_hits << "/" << v54_gate_i_value
            << " J{hits=" << v54_gate_j_hits
            << ",byte20=" << v54_gate_j_byte20
            << ",byte02=" << v54_gate_j_byte02 << "}"
            << " mainFlow=" << v54_main_flow_hits
            << " progress=" << v54_progress_result_hits
            << "/" << v54_progress_value
            << " find=" << v54_find_result_hits
            << "/" << v54_find_value
            << " late=" << v54_late_result_hits
            << "/" << v54_late_value
            << " patchReqMarker=" << v54_patch_marker_hits
            << " mainMenuReqMarker=" << v54_mainmenu_marker_hits;

        return out.str();
    }

    int V55StartupGroupSlot(
        const std::string& name) const {

        static constexpr std::array<const char*, 4>
            kNames = {
                "AlwaysLoaded",
                "DelayLoad_Dialog",
                "UIImages",
                "RenderEffects"};

        for (std::size_t i = 0u;
             i < kNames.size();
             ++i) {
            if (name == kNames[i]) {
                return static_cast<int>(i);
            }
        }

        return -1;
    }

    std::string V55StartupGroupVectorState() {
        std::ostringstream out;

        if (mem.Ptr(
                kV55StartupGroupsVectorGuest,
                12u) == nullptr) {
            v55_last_vector_count =
                0xffffffffu;
            return "vector-unmapped";
        }

        const std::uint32_t begin =
            mem.Read32Guest(
                kV55StartupGroupsVectorGuest);
        const std::uint32_t end =
            mem.Read32Guest(
                kV55StartupGroupsVectorGuest +
                4u);
        const std::uint32_t capacity =
            mem.Read32Guest(
                kV55StartupGroupsVectorGuest +
                8u);

        out
            << "vector@0x"
            << JniProbeHex(
                   kV55StartupGroupsVectorGuest)
            << "{begin=0x"
            << JniProbeHex(begin)
            << ",end=0x"
            << JniProbeHex(end)
            << ",cap=0x"
            << JniProbeHex(capacity);

        if (end < begin ||
            capacity < end ||
            ((end - begin) & 3u) != 0u) {
            v55_last_vector_count =
                0xffffffffu;
            out << ",INVALID}";
            return out.str();
        }

        const std::uint32_t count =
            (end - begin) / 4u;
        const std::uint32_t capacity_count =
            (capacity - begin) / 4u;

        v55_last_vector_count = count;

        out
            << ",count=" << count
            << ",capacityCount="
            << capacity_count
            << ",entries=[";

        const std::uint32_t inspect_count =
            std::min<std::uint32_t>(
                count,
                16u);

        for (std::uint32_t i = 0u;
             i < inspect_count;
             ++i) {
            if (i != 0u) {
                out << ",";
            }

            const std::uint32_t object =
                begin + i * 4u;
            const std::uint32_t chars =
                mem.Ptr(object, 4u) != nullptr
                    ? mem.Read32Guest(object)
                    : 0u;

            out
                << i
                << ":\""
                << ReadGuestStdStringObject(
                       object)
                << "\"@0x"
                << JniProbeHex(chars);
        }

        if (count > inspect_count) {
            out << ",...";
        }

        out << "]}";
        return out.str();
    }

    std::string V55CurrentGateAGroup(
        std::uint32_t vector_object,
        std::uint32_t byte_offset) {

        if (mem.Ptr(
                vector_object,
                8u) == nullptr) {
            return "<vector-unmapped>";
        }

        const std::uint32_t begin =
            mem.Read32Guest(
                vector_object);
        const std::uint32_t end =
            mem.Read32Guest(
                vector_object + 4u);

        if (end < begin ||
            (byte_offset & 3u) != 0u ||
            byte_offset >= end - begin) {
            return "<group-out-of-range>";
        }

        return ReadGuestStdStringObject(
            begin + byte_offset);
    }

    std::string V55StartupResourceGroupSummary() {
        static constexpr std::array<const char*, 4>
            kNames = {
                "AlwaysLoaded",
                "DelayLoad_Dialog",
                "UIImages",
                "RenderEffects"};

        std::ostringstream out;
        out
            << "V55 StartupGroups"
            << " ctor={"
            << (v55_ctor_vector_snapshot.empty()
                    ? std::string{"NONE"}
                    : v55_ctor_vector_snapshot)
            << "}"
            << " gate={"
            << (v55_gate_vector_snapshot.empty()
                    ? std::string{"NONE"}
                    : v55_gate_vector_snapshot)
            << "}"
            << " lookups="
            << v55_lookup_total
            << " unknown="
            << v55_lookup_unknown
            << " contributions="
            << v55_contribution_total;

        bool all_four_seen = true;
        bool all_four_miss = true;
        bool any_contribution = false;

        for (std::size_t i = 0u;
             i < kNames.size();
             ++i) {
            const auto& stat =
                v55_group_stats[i];

            all_four_seen &=
                stat.lookup_hits != 0u;
            all_four_miss &=
                stat.lookup_hits != 0u &&
                stat.lookup_misses ==
                    stat.lookup_hits;
            any_contribution |=
                stat.contribution_hits != 0u;

            out
                << " | "
                << kNames[i]
                << "{lookups="
                << stat.lookup_hits
                << ",misses="
                << stat.lookup_misses
                << ",lastIndex=0x"
                << JniProbeHex(
                       stat.last_lookup)
                << ",samples="
                << stat.contribution_hits
                << ",completed="
                << stat.last_completed
                << ",total="
                << stat.last_total
                << "}";
        }

        out << " | diagnosis=";

        if (v55_lookup_total == 0u &&
            v54_gate_a_resource_hits != 0u) {
            out
                << "NO_GROUP_LOOKUPS"
                << "(vector-empty-or-loop-not-entered)";
        } else if (all_four_seen &&
                   all_four_miss) {
            out
                << "ALL_4_GROUPS_MISS_RESOURCE_MANAGER";
        } else if (any_contribution) {
            out
                << "GROUP_LOOKUP_SUCCEEDS"
                << "(inspect-per-group-progress)";
        } else {
            out
                << "MIXED_OR_UNKNOWN";
        }

        return out.str();
    }

    const char* V56ModeName() const {
        const auto* descriptor =
            PvZ2DescribeDiagnosticMode(
                diagnostic_mode);
        return descriptor != nullptr
            ? descriptor->internal_name
            : "UNKNOWN";
    }

    bool V79ProfileProbeEnabled() const {
        return HasCapability(
            PvZ2ProbeCapability::ProfileProbe);
    }

    bool HasCapability(
        PvZ2ProbeCapability capability) const {
        const std::uint64_t mask =
            static_cast<std::uint64_t>(capability);
        return mask == 0u ||
            (diagnostic_capabilities & mask) == mask;
    }

    const char* V79ProfileSiteName(
        std::uint32_t svc) const {

        switch (svc) {
        case kJniProbeSvcV79SetWidthHeightEntry: return "SetWidthHeight.entry";
        case kJniProbeSvcV79ProfileEntry: return "Profile.entry";
        case kJniProbeSvcV79CheckboxEntry: return "Checkbox.entry";
        case kJniProbeSvcV79CheckboxRect: return "Checkbox.rect";
        case kJniProbeSvcV79FacebookEntry: return "FacebookButton.entry";
        case kJniProbeSvcV79FacebookRect: return "FacebookButton.rect";
        case kJniProbeSvcV79ContainerEntry: return "FacebookContainer.entry";
        case kJniProbeSvcV79ContainerRect: return "FacebookContainer.rect";
        case kJniProbeSvcV79TextEntry: return "TextEntry.entry";
        case kJniProbeSvcV79TextRectA: return "TextEntry.rectA";
        case kJniProbeSvcV79TextRectB: return "TextEntry.rectB";
        case kJniProbeSvcV79GenericEntry: return "GenericProfile.entry";
        case kJniProbeSvcV79GenericRect: return "GenericProfile.rect";
        default: return "unknown";
        }
    }

    std::string V79ProfileSummary() const {
        std::ostringstream out;
        out
            << "V79 PROFILE SUMMARY mode="
            << V56ModeName()
            << " totalEvents="
            << v79_profile_total_events;

        const std::array<std::uint32_t, 13> sites = {{
            kJniProbeSvcV79SetWidthHeightEntry,
            kJniProbeSvcV79ProfileEntry,
            kJniProbeSvcV79CheckboxEntry,
            kJniProbeSvcV79CheckboxRect,
            kJniProbeSvcV79FacebookEntry,
            kJniProbeSvcV79FacebookRect,
            kJniProbeSvcV79ContainerEntry,
            kJniProbeSvcV79ContainerRect,
            kJniProbeSvcV79TextEntry,
            kJniProbeSvcV79TextRectA,
            kJniProbeSvcV79TextRectB,
            kJniProbeSvcV79GenericEntry,
            kJniProbeSvcV79GenericRect
        }};

        for (const auto svc : sites) {
            const auto it =
                v79_profile_hits.find(svc);
            out
                << " | "
                << V79ProfileSiteName(svc)
                << "="
                << (it == v79_profile_hits.end()
                        ? 0u
                        : it->second);
        }

        return out.str();
    }


    bool V110Enabled() const {
        return
            diagnostic_mode == PvZ2DiagnosticMode::V110AudioPinchUiAndroid ||
            diagnostic_mode == PvZ2DiagnosticMode::V110AudioPinchUiIpad;
    }

    bool V110AndroidUiControlEnabled() const {
        return diagnostic_mode ==
            PvZ2DiagnosticMode::V110AudioPinchUiAndroid;
    }

    V110AudioBucket V110AudioBucketForPc(std::uint32_t pc) const {
        if (pc < kGuestBase || pc >= kGuestBase + 0x01000000u) {
            return V110AudioBucket::Other;
        }
        const std::uint32_t offset = pc - kGuestBase;
        auto inside = [&](std::uint32_t begin, std::uint32_t size) {
            return offset >= begin && offset < begin + size;
        };
        if (inside(0x00bfdb70u,100u) || inside(0x00bc001cu,336u))
            return V110AudioBucket::AudioMgr;
        if (inside(0x00baff7cu,24u) || inside(0x00bafea4u,216u) ||
            inside(0x00c00934u,612u) || inside(0x00c0050cu,1064u) ||
            inside(0x00c05904u,1324u) || inside(0x00c03ff4u,136u) ||
            inside(0x00c022bcu,232u))
            return V110AudioBucket::VplMixer;
        if (inside(0x00c02bc0u,848u) || inside(0x00c14200u,172u))
            return V110AudioBucket::ResamplerPitch;
        if (inside(0x00c1e0b8u,188u) || inside(0x00c1eefcu,828u) ||
            inside(0x00c1fcd0u,372u) || inside(0x00c1ff7cu,556u) ||
            inside(0x00c201a8u,340u) || inside(0x00c20b1cu,984u) ||
            inside(0x00c213e0u,1592u) || inside(0x00c221d0u,832u) ||
            inside(0x00c22510u,460u) || inside(0x00c226dcu,4592u) ||
            inside(0x00c24cfcu,684u))
            return V110AudioBucket::VorbisMdct;
        return V110AudioBucket::Other;
    }

    static const char* V110AudioBucketName(std::size_t index) {
        static constexpr const char* names[] = {
            "audioMgr","vplMixer","resamplerPitch","vorbisMdct","other"};
        return index < 5u ? names[index] : "unknown";
    }

    bool V110IsAudioWorker(std::uint32_t tid) const {
        if (!V110Enabled() || tid == 0u) return false;
        return v104_audio_worker_tid != 0u
            ? tid == v104_audio_worker_tid
            : tid == 5u;
    }

    void V110BeginAudioQuantum(std::uint32_t tid) {
        if (V110IsAudioWorker(tid)) v110_quantum_guest_ticks.fill(0u);
    }

    void V110RecordAudioTicks(std::uint64_t ticks) {
        if (!V110IsAudioWorker(current_probe_thread_id) || jit == nullptr)
            return;
        const std::size_t bucket = static_cast<std::size_t>(
            V110AudioBucketForPc(jit->Regs()[15]));
        v110_quantum_guest_ticks[bucket] += ticks;
    }

    void V110FinishAudioQuantum(
        std::uint32_t tid,
        std::uint32_t start_pc,
        std::uint32_t end_pc,
        std::uint64_t elapsed_ns) {
        if (!V110IsAudioWorker(tid)) return;

        std::size_t dominant = 4u;
        std::uint64_t dominant_ticks = 0u;
        std::uint64_t total_ticks = 0u;
        for (std::size_t i = 0u; i < 5u; ++i) {
            total_ticks += v110_quantum_guest_ticks[i];
            v110_audio_guest_ticks[i] += v110_quantum_guest_ticks[i];
            if (v110_quantum_guest_ticks[i] > dominant_ticks) {
                dominant_ticks = v110_quantum_guest_ticks[i];
                dominant = i;
            }
        }
        if (total_ticks == 0u) {
            const auto start_bucket = V110AudioBucketForPc(start_pc);
            const auto end_bucket = V110AudioBucketForPc(end_pc);
            dominant = static_cast<std::size_t>(
                start_bucket != V110AudioBucket::Other
                    ? start_bucket
                    : end_bucket);
        }
        v110_audio_wall_ns[dominant] += elapsed_ns;
        ++v110_audio_quanta[dominant];
        ++v110_audio_quantum_count;
        v110_audio_max_quantum_ns =
            std::max(v110_audio_max_quantum_ns, elapsed_ns);
        if (current_frame_number == v90_profile_frame) {
            v110_frame_audio_ns[dominant] += elapsed_ns;
            ++v110_frame_audio_quanta[dominant];
        }
    }

    std::uint64_t V110FrameAudioNs() const {
        std::uint64_t total = 0u;
        for (const auto value : v110_frame_audio_ns) total += value;
        return total;
    }

    std::string V110FrameAudioSummary() const {
        std::ostringstream out;
        out << std::fixed << std::setprecision(3)
            << " audio110Ms=" << double(V110FrameAudioNs()) / 1e6
            << " audio110={";
        for (std::size_t i = 0u; i < 5u; ++i) {
            if (i != 0u) out << ",";
            out << V110AudioBucketName(i) << ":"
                << double(v110_frame_audio_ns[i]) / 1e6 << "ms/"
                << v110_frame_audio_quanta[i] << "q";
        }
        out << "}";
        return out.str();
    }

    std::string V110AudioSummary() const {
        std::ostringstream out;
        out << std::fixed << std::setprecision(3)
            << "V110 AUDIO QUANTUM SUMMARY"
            << " quanta=" << v110_audio_quantum_count
            << " maxQuantumMs=" << double(v110_audio_max_quantum_ns) / 1e6
            << " pinch{queued="
            << gV110QueuedPinches.load(std::memory_order_relaxed)
            << ",dropped="
            << gV110DroppedPinches.load(std::memory_order_relaxed)
            << ",delivered=" << v110_pinch_events_delivered << "}"
            << " buckets={";
        for (std::size_t i = 0u; i < 5u; ++i) {
            if (i != 0u) out << ",";
            out << V110AudioBucketName(i)
                << ":wallMs=" << double(v110_audio_wall_ns[i]) / 1e6
                << "/q=" << v110_audio_quanta[i]
                << "/guestTicks=" << v110_audio_guest_ticks[i];
        }
        out << "}";
        return out.str();
    }

    bool V109Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::LeanAudioPerformance);
    }

    bool V108Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::BankCompletionLiveness);
    }

    std::string V108BankCompletionSummary() {
        std::ostringstream out;
        const std::uint32_t slot = v108_active_kill_slot;
        const std::uint32_t callback = slot != 0u ? mem.Read32Guest(slot + 0x2cu) : 0u;
        const std::uint32_t cookie = slot != 0u ? mem.Read32Guest(slot + 0x30u) : 0u;
        const std::int32_t refs = slot != 0u ? static_cast<std::int32_t>(mem.Read32Guest(slot + 0x40u)) : 0;
        const std::int32_t prepare_refs = slot != 0u ? static_cast<std::int32_t>(mem.Read32Guest(slot + 0x44u)) : 0;
        const std::uint32_t flags = slot != 0u ? mem.Read8(slot + 0x48u) : 0u;
        const std::uint32_t audio_count = v108_audio_event_sem != 0u ? mem.Read32Guest(v108_audio_event_sem) : 0u;
        const auto audio_wait = v66_sem_waits.find(v104_audio_worker_tid);

        out << "killSlot=" << V46DescribeGuestAddress(slot)
            << " killMsgSeen=" << (v108_active_kill_msg_seen ? "YES" : "NO")
            << " refs=" << refs << " prepareRefs=" << prepare_refs
            << " flags=0x" << JniProbeHex(flags)
            << " callback=" << V46DescribeGuestAddress(callback)
            << " cookie=" << V46DescribeGuestAddress(cookie)
            << " audioTid=" << v104_audio_worker_tid
            << " audioSem=" << V46DescribeGuestAddress(v108_audio_event_sem)
            << " audioSemCount=" << audio_count;

        if (audio_wait != v66_sem_waits.end()) {
            out << " audioWaitSem=" << V46DescribeGuestAddress(audio_wait->second.sem)
                << " audioNotified=" << (audio_wait->second.notified ? "YES" : "NO");
        } else {
            out << " audioWaitSem=NONE audioNotified=NO";
        }

        out << " hostQueued=" << PvZ2HostAudioQueuedBufferCount()
            << " pendingGuestCallbacks=" << v99_audio_pending_callbacks
            << " consumedTotal=" << PvZ2HostAudioConsumedBufferTotal()
            << " renderCallbacks=" << PvZ2HostAudioRenderCallbackCount()
            << " renderedPCM=" << PvZ2HostAudioRenderedPCMFrames()
            << " underrunEvents=" << PvZ2HostAudioUnderrunEvents();
        return out.str();
    }

    bool V108MaybePulseAudioLiveness() {
        if (!V108Enabled() || v108_active_kill_slot == 0u ||
            !v108_active_kill_msg_seen || v104_audio_worker_tid == 0u ||
            v108_audio_event_sem == 0u) {
            return false;
        }

        const std::uint32_t callback = mem.Read32Guest(v108_active_kill_slot + 0x2cu);
        if (callback == 0u) {
            v108_active_kill_slot = 0u;
            v108_active_kill_msg_seen = false;
            return false;
        }

        // Preserve natural CoreAudio/OpenSL completions. Synthesize only the
        // Wwise event-thread wake when teardown is pending and PCM has drained.
        if (PvZ2HostAudioQueuedBufferCount() != 0u || v99_audio_pending_callbacks != 0u) {
            return false;
        }

        auto wait = v66_sem_waits.find(v104_audio_worker_tid);
        if (wait == v66_sem_waits.end() || wait->second.sem != v108_audio_event_sem ||
            wait->second.notified || mem.Read32Guest(v108_audio_event_sem) != 0u) {
            return false;
        }

        const std::uint64_t now = V66SteadyNowNs();
        constexpr std::uint64_t kPulsePeriodNs = 32000000ull; // 1024 / 32 kHz
        if (v108_last_audio_liveness_pulse_ns != 0u &&
            now - v108_last_audio_liveness_pulse_ns < kPulsePeriodNs) {
            return false;
        }

        mem.Write32Guest(v108_audio_event_sem, 1u);
        const std::uint32_t woke = V66NotifySemaphore(v108_audio_event_sem);
        v108_last_audio_liveness_pulse_ns = now;
        ++v108_audio_liveness_pulses;
        AppendDiagnostic("V108 AUDIO LIVENESS PULSE #" +
                         std::to_string(v108_audio_liveness_pulses) +
                         " woke=" + std::to_string(woke) + " " +
                         V108BankCompletionSummary());
        return woke != 0u;
    }

    bool V107Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::SemaphoreWakeRepair);
    }

    bool V106Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AudioRateBankWait);
    }

    std::uint32_t V106BankWakeSemaphoreAddress() const {
        return
            v106_bank_worker_object != 0u
                ? v106_bank_worker_object + 0x28u
                : 0u;
    }

    std::string V107BankWorkerWaitSummary() {
        std::ostringstream out;

        const std::uint32_t wake_sem =
            V106BankWakeSemaphoreAddress();

        out
            << "bankTid="
            << v106_bank_worker_tid
            << " bankObject="
            << V46DescribeGuestAddress(
                   v106_bank_worker_object)
            << " wakeSem="
            << V46DescribeGuestAddress(
                   wake_sem)
            << " wakeCount="
            << (wake_sem != 0u
                    ? mem.Read32Guest(wake_sem)
                    : 0u)
            << " queueDepth="
            << (v106_bank_worker_object != 0u
                    ? mem.Read32Guest(
                          v106_bank_worker_object +
                          0x4cu)
                    : 0u);

        const auto sem_wait =
            v66_sem_waits.find(
                v106_bank_worker_tid);

        if (sem_wait !=
            v66_sem_waits.end()) {
            out
                << " bankSemWait="
                << V46DescribeGuestAddress(
                       sem_wait->second.sem)
                << " bankNotified="
                << (sem_wait->second.notified
                        ? "YES"
                        : "NO")
                << " bankTimed="
                << (sem_wait->second.timed
                        ? "YES"
                        : "NO");
        } else {
            out
                << " bankSemWait=NONE"
                << " bankNotified=NO"
                << " bankTimed=NO";
        }

        out
            << " bankMutexPending="
            << (V87MutexWaitPending(
                    v106_bank_worker_tid)
                    ? "YES"
                    : "NO")
            << " bankMutexGranted="
            << (V87MutexWaitGranted(
                    v106_bank_worker_tid)
                    ? "YES"
                    : "NO")
            << " bankCondPending="
            << (V65ThreadBlocked(
                    v106_bank_worker_tid)
                    ? "YES"
                    : "NO");

        return out.str();
    }

    std::uint32_t V106MainSemaphoreWaitAddress() const {
        if (!V106Enabled()) {
            return 0u;
        }

        const auto found =
            v66_sem_waits.find(0u);
        return
            found != v66_sem_waits.end()
                ? found->second.sem
                : 0u;
    }

    bool V105Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::WwiseResamplerProbe);
    }

    float V105FloatFromBits(
        std::uint32_t bits) const {
        float value = 0.0f;
        std::memcpy(
            &value,
            &bits,
            sizeof(value));
        return value;
    }

    bool V105ShouldLogCounter(
        std::uint64_t value) const {
        return
            value <= 128u ||
            (value != 0u &&
             (value & (value - 1u)) == 0u);
    }

    void V105LogResamplerState(
        const char* site,
        std::uint64_t count,
        std::uint32_t resampler,
        std::uint32_t format,
        std::uint32_t target_hint,
        std::uint32_t next_state_hint) {

        if (!V105Enabled() ||
            !V105ShouldLogCounter(count)) {
            return;
        }

        constexpr std::uint32_t kPipelineRateGuest =
            kGuestBase + 0x00d47d14u;

        const std::uint32_t pbi =
            resampler != 0u
                ? mem.Read32Guest(
                      resampler + 0x8cu)
                : 0u;
        const std::uint32_t pbi_rate =
            pbi != 0u
                ? mem.Read32Guest(
                      pbi + 0x70u)
                : 0u;
        const std::uint32_t source =
            pbi != 0u
                ? mem.Read32Guest(
                      pbi + 0x64u)
                : 0u;
        const std::uint32_t source_id =
            source != 0u
                ? mem.Read32Guest(source)
                : 0u;
        const std::uint32_t source_field18 =
            source != 0u
                ? mem.Read32Guest(
                      source + 0x18u)
                : 0u;
        const std::uint32_t sound_context =
            pbi != 0u
                ? mem.Read32Guest(
                      pbi + 0x60u)
                : 0u;
        const std::uint32_t sound_id =
            sound_context != 0u
                ? mem.Read32Guest(
                      sound_context + 0x0cu)
                : 0u;

        const std::uint32_t format_rate =
            format != 0u
                ? mem.Read32Guest(format)
                : pbi_rate;
        const std::uint32_t pipeline_rate =
            mem.Read32Guest(
                kPipelineRateGuest);
        const std::uint32_t ratio_bits =
            resampler != 0u
                ? mem.Read32Guest(
                      resampler + 0x2cu)
                : 0u;
        const std::uint32_t pitch_bits =
            resampler != 0u
                ? mem.Read32Guest(
                      resampler + 0x30u)
                : 0u;
        const std::uint32_t step_a =
            resampler != 0u
                ? mem.Read32Guest(
                      resampler + 0x14u)
                : 0u;
        const std::uint32_t step_b =
            resampler != 0u
                ? mem.Read32Guest(
                      resampler + 0x18u)
                : 0u;
        const std::uint32_t state =
            resampler != 0u
                ? mem.Read32Guest(
                      resampler + 0x28u)
                : 0u;
        const std::uint32_t dsp_index =
            resampler != 0u
                ? mem.Read8(
                      resampler + 0x34u)
                : 0u;

        AppendDiagnostic(
            "V105 WWISE RESAMPLER " +
            std::string{
                site != nullptr
                    ? site
                    : "?"} +
            " #" +
            std::to_string(count) +
            " frame=" +
            std::to_string(
                current_frame_number) +
            " tid=" +
            std::to_string(
                current_probe_thread_id) +
            " this=" +
            V46DescribeGuestAddress(
                resampler) +
            " format=" +
            V46DescribeGuestAddress(
                format) +
            " sourceHz=" +
            std::to_string(format_rate) +
            " pbiHz=" +
            std::to_string(pbi_rate) +
            " targetHintHz=" +
            std::to_string(target_hint) +
            " pipelineHz=" +
            std::to_string(pipeline_rate) +
            " ratio=" +
            std::to_string(
                V105FloatFromBits(
                    ratio_bits)) +
            " ratioBits=0x" +
            JniProbeHex(ratio_bits) +
            " pitchCents=" +
            std::to_string(
                V105FloatFromBits(
                    pitch_bits)) +
            " pitchBits=0x" +
            JniProbeHex(pitch_bits) +
            " stepA=" +
            std::to_string(step_a) +
            " stepB=" +
            std::to_string(step_b) +
            " stateNow=0x" +
            JniProbeHex(state) +
            " nextState=" +
            (next_state_hint == 0xffffffffu
                 ? std::string{"n/a"}
                 : std::to_string(
                       next_state_hint)) +
            " dspIndex=" +
            std::to_string(dsp_index) +
            " pbi=" +
            V46DescribeGuestAddress(pbi) +
            " source=" +
            V46DescribeGuestAddress(source) +
            " sourceId=" +
            std::to_string(source_id) +
            " sourceField18=0x" +
            JniProbeHex(source_field18) +
            " soundId=" +
            std::to_string(sound_id));
    }

    bool V104Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AudioWorkerHandshake);
    }

    bool V103Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AudioDrawFramePump);
    }

    bool V103AudioRealtimeWindow() const {
        if (!V103Enabled()) {
            return true;
        }

        return
            return_mode == ReturnMode::Lifecycle &&
            current_lifecycle_name == "Native_onDrawFrame";
    }

    bool V102Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AudioRealtimePump);
    }

    bool V102AudioSinkMutexAvailable(
        bool count_deferral = false) {
        if (!V63Enabled() ||
            v99_queue_context == 0u) {
            return true;
        }

        const std::uint32_t sink_mutex =
            v99_queue_context + 0x20u;
        const auto found =
            v63_mutexes.find(sink_mutex);

        const bool available =
            found == v63_mutexes.end() ||
            found->second.depth == 0u;

        if (!available && count_deferral) {
            ++v102_audio_sink_busy_deferrals;
        }
        return available;
    }

    bool V102RefreshAudioServiceRequest(
        bool count_deferral = false) {
        if (!V102Enabled() ||
            !V103AudioRealtimeWindow() ||
            v102_audio_inline_active ||
            !v99_audio_configured ||
            v99_play_state != 3u ||
            v99_queue_callback == 0u ||
            v99_queue_itf == 0u) {
            return false;
        }

        const bool completion_waiting =
            v99_audio_pending_callbacks != 0u ||
            PvZ2HostAudioConsumedBufferTotal() >
                v99_audio_host_consumed;

        if (!completion_waiting) {
            return false;
        }

        if (!V102AudioSinkMutexAvailable(
                count_deferral)) {
            return false;
        }

        v102_audio_service_requested = true;
        return true;
    }

    void V102LogAudioPacer(
        const char* phase) {
        if (!V102Enabled()) {
            return;
        }

        const std::uint64_t now =
            V85SteadyNowNs();
        const std::uint64_t elapsed_ns =
            v102_audio_play_begin_ns != 0u &&
                    now >= v102_audio_play_begin_ns
                ? now - v102_audio_play_begin_ns
                : 0u;

        const std::uint64_t requested =
            PvZ2HostAudioRenderRequestedFrames();
        const std::uint64_t rendered =
            PvZ2HostAudioRenderedPCMFrames();
        const std::uint64_t underrun =
            PvZ2HostAudioUnderrunFrames();
        const std::uint64_t effective_hz =
            elapsed_ns != 0u
                ? (requested * 1000000000ull) /
                      elapsed_ns
                : 0u;

        AppendDiagnostic(
            "V102 AUDIO PACER phase=" +
            std::string{
                phase != nullptr
                    ? phase
                    : "n/a"} +
            " elapsedMs=" +
            std::to_string(
                elapsed_ns / 1000000ull) +
            " renderCallbacks=" +
            std::to_string(
                PvZ2HostAudioRenderCallbackCount()) +
            " requestedFrames=" +
            std::to_string(requested) +
            " pcmFrames=" +
            std::to_string(rendered) +
            " underrunFrames=" +
            std::to_string(underrun) +
            " underrunEvents=" +
            std::to_string(
                PvZ2HostAudioUnderrunEvents()) +
            " effectiveRequestedHz=" +
            std::to_string(effective_hz) +
            " queued=" +
            std::to_string(
                PvZ2HostAudioQueuedBufferCount()) +
            " pendingGuestCallbacks=" +
            std::to_string(
                v99_audio_pending_callbacks));
    }

    bool V101Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AudioClockContract);
    }

    bool V100Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::RawGuestCallbackABI);
    }

    bool V99Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AudioOpenSLBridge);
    }

    bool V99ShouldLogCounter(
        std::uint64_t value) const {
        return
            value <= 16u ||
            (value != 0u &&
             (value & (value - 1u)) == 0u);
    }

    void V99RegisterOpenSLIID(
        const std::string& name,
        std::uint32_t iid) {
        v99_opensl_iids[name] = iid;
    }

    void V99RegisterOpenSLMethod(
        const std::string& name,
        std::uint32_t trampoline) {
        v99_opensl_methods[name] = trampoline;
    }

    std::uint32_t V99OpenSLMethod(
        const char* name) const {
        const auto found =
            v99_opensl_methods.find(
                name != nullptr
                    ? std::string{name}
                    : std::string{});
        return found == v99_opensl_methods.end()
            ? 0u
            : found->second;
    }

    std::uint32_t V99OpenSLIID(
        const char* name) const {
        const auto found =
            v99_opensl_iids.find(
                name != nullptr
                    ? std::string{name}
                    : std::string{});
        return found == v99_opensl_iids.end()
            ? 0u
            : found->second;
    }

    bool V99EnsureOpenSLObjects() {
        if (!V99Enabled()) {
            return false;
        }

        if (v99_engine_object != 0u) {
            return true;
        }

        const std::uint32_t unsupported =
            V99OpenSLMethod("__v99_sl_unsupported");
        const std::uint32_t object_realize =
            V99OpenSLMethod("__v99_sl_object_realize");
        const std::uint32_t object_get_state =
            V99OpenSLMethod("__v99_sl_object_get_state");
        const std::uint32_t object_get_interface =
            V99OpenSLMethod("__v99_sl_object_get_interface");
        const std::uint32_t object_register_callback =
            V99OpenSLMethod("__v99_sl_object_register_callback");
        const std::uint32_t object_destroy =
            V99OpenSLMethod("__v99_sl_object_destroy");
        const std::uint32_t create_player =
            V99OpenSLMethod("__v99_sl_engine_create_audio_player");
        const std::uint32_t create_mix =
            V99OpenSLMethod("__v99_sl_engine_create_output_mix");
        const std::uint32_t set_play_state =
            V99OpenSLMethod("__v99_sl_play_set_state");
        const std::uint32_t queue_enqueue =
            V99OpenSLMethod("__v99_sl_queue_enqueue");
        const std::uint32_t queue_clear =
            V99OpenSLMethod("__v99_sl_queue_clear");
        const std::uint32_t queue_get_state =
            V99OpenSLMethod("__v99_sl_queue_get_state");
        const std::uint32_t queue_register =
            V99OpenSLMethod("__v99_sl_queue_register_callback");
        const std::uint32_t config_set =
            V99OpenSLMethod("__v99_sl_android_config_set");
        const std::uint32_t caps_outputs =
            V99OpenSLMethod("__v99_sl_caps_get_outputs");
        const std::uint32_t caps_query =
            V99OpenSLMethod("__v99_sl_caps_query_output");

        if (unsupported == 0u ||
            object_realize == 0u ||
            object_get_state == 0u ||
            object_get_interface == 0u ||
            object_register_callback == 0u ||
            object_destroy == 0u ||
            create_player == 0u ||
            create_mix == 0u ||
            set_play_state == 0u ||
            queue_enqueue == 0u ||
            queue_clear == 0u ||
            queue_get_state == 0u ||
            queue_register == 0u ||
            config_set == 0u ||
            caps_outputs == 0u ||
            caps_query == 0u) {
            AppendCritical(
                "V99 AUDIO ERROR synthetic OpenSL method table is incomplete.");
            return false;
        }

        const std::array<const char*, 5> required_iids = {{
            "SL_IID_ENGINE",
            "SL_IID_PLAY",
            "SL_IID_BUFFERQUEUE",
            "SL_IID_ANDROIDCONFIGURATION",
            "SL_IID_AUDIOIODEVICECAPABILITIES",
        }};

        for (const char* iid_name : required_iids) {
            if (V99OpenSLIID(iid_name) == 0u) {
                AppendCritical(
                    "V99 AUDIO ERROR missing imported IID " +
                    std::string{iid_name});
                return false;
            }
        }

        auto make_vtable =
            [&](std::size_t slots) -> std::uint32_t {
                const std::uint32_t table =
                    mem.AllocateObject(
                        static_cast<std::uint32_t>(
                            slots * 4u),
                        4u);
                if (table == 0u) {
                    return 0u;
                }
                for (std::size_t i = 0u;
                     i < slots;
                     ++i) {
                    mem.Write32Guest(
                        table +
                            static_cast<std::uint32_t>(
                                i * 4u),
                        unsupported);
                }
                return table;
            };

        auto make_handle =
            [&](std::uint32_t table) -> std::uint32_t {
                if (table == 0u) {
                    return 0u;
                }
                const std::uint32_t handle =
                    mem.AllocateObject(4u, 4u);
                if (handle != 0u) {
                    mem.Write32Guest(
                        handle,
                        table);
                }
                return handle;
            };

        const std::uint32_t object_vtable =
            make_vtable(12u);
        const std::uint32_t engine_vtable =
            make_vtable(15u);
        const std::uint32_t play_vtable =
            make_vtable(16u);
        const std::uint32_t queue_vtable =
            make_vtable(4u);
        const std::uint32_t config_vtable =
            make_vtable(4u);
        const std::uint32_t caps_vtable =
            make_vtable(12u);

        if (object_vtable == 0u ||
            engine_vtable == 0u ||
            play_vtable == 0u ||
            queue_vtable == 0u ||
            config_vtable == 0u ||
            caps_vtable == 0u) {
            AppendCritical(
                "V99 AUDIO ERROR unable to allocate OpenSL guest vtables.");
            return false;
        }

        // SLObjectItf: Realize, GetState, GetInterface,
        // RegisterCallback, Destroy.
        mem.Write32Guest(object_vtable + 0u * 4u, object_realize);
        mem.Write32Guest(object_vtable + 2u * 4u, object_get_state);
        mem.Write32Guest(object_vtable + 3u * 4u, object_get_interface);
        mem.Write32Guest(object_vtable + 4u * 4u, object_register_callback);
        mem.Write32Guest(object_vtable + 6u * 4u, object_destroy);

        // SLEngineItf: CreateAudioPlayer is slot 2,
        // CreateOutputMix is slot 7.
        mem.Write32Guest(engine_vtable + 2u * 4u, create_player);
        mem.Write32Guest(engine_vtable + 7u * 4u, create_mix);

        // SLPlayItf: SetPlayState is slot 0.
        mem.Write32Guest(play_vtable + 0u * 4u, set_play_state);

        // SL(AndroidSimple)BufferQueueItf.
        mem.Write32Guest(queue_vtable + 0u * 4u, queue_enqueue);
        mem.Write32Guest(queue_vtable + 1u * 4u, queue_clear);
        mem.Write32Guest(queue_vtable + 2u * 4u, queue_get_state);
        mem.Write32Guest(queue_vtable + 3u * 4u, queue_register);

        // SLAndroidConfigurationItf::SetConfiguration.
        mem.Write32Guest(config_vtable + 0u * 4u, config_set);

        // SLAudioIODeviceCapabilitiesItf.
        mem.Write32Guest(caps_vtable + 3u * 4u, caps_outputs);
        mem.Write32Guest(caps_vtable + 4u * 4u, caps_query);

        v99_engine_object = make_handle(object_vtable);
        v99_output_mix_object = make_handle(object_vtable);
        v99_player_object = make_handle(object_vtable);
        v99_engine_itf = make_handle(engine_vtable);
        v99_play_itf = make_handle(play_vtable);
        v99_queue_itf = make_handle(queue_vtable);
        v99_config_itf = make_handle(config_vtable);
        v99_caps_itf = make_handle(caps_vtable);
        v99_audio_rate_array =
            mem.AllocateObject(
                V106Enabled() ? 12u : 4u,
                4u);

        if (v99_engine_object == 0u ||
            v99_output_mix_object == 0u ||
            v99_player_object == 0u ||
            v99_engine_itf == 0u ||
            v99_play_itf == 0u ||
            v99_queue_itf == 0u ||
            v99_config_itf == 0u ||
            v99_caps_itf == 0u ||
            v99_audio_rate_array == 0u) {
            AppendCritical(
                "V99 AUDIO ERROR unable to allocate OpenSL guest handles.");
            return false;
        }

        // OpenSL sampling-rate constants are expressed in milliHertz.
        // v99-v105 incorrectly advertised only 48 kHz. PvZ2 1.5 explicitly
        // selects a 32 kHz Wwise platform rate (24 kHz on its alternate path)
        // before CAkLEngine::Init; forcing the OpenSL sink to 48 kHz therefore
        // left g_pipelineCoreFrequency at 32 kHz while the host consumed PCM at
        // 48 kHz. v106 advertises the discrete rates the game can request and
        // lets AVAudioEngine convert the selected source rate downstream.
        if (V106Enabled()) {
            mem.Write32Guest(
                v99_audio_rate_array + 0u,
                24000000u);
            mem.Write32Guest(
                v99_audio_rate_array + 4u,
                32000000u);
            mem.Write32Guest(
                v99_audio_rate_array + 8u,
                48000000u);
        } else {
            mem.Write32Guest(
                v99_audio_rate_array,
                48000000u);
        }

        AppendDiagnostic(
            "V99 AUDIO OPENSL OBJECTS READY engineObject=" +
            V46DescribeGuestAddress(v99_engine_object) +
            " engineItf=" +
            V46DescribeGuestAddress(v99_engine_itf) +
            " queueItf=" +
            V46DescribeGuestAddress(v99_queue_itf));
        return true;
    }

    bool V99HandleSlCreateEngine(
        std::array<std::uint32_t, 16>& regs) {
        if (!V99Enabled()) {
            return false;
        }

        ++v99_engine_create_calls;

        if (regs[0] == 0u ||
            !V99EnsureOpenSLObjects()) {
            regs[0] = 1u;
            return true;
        }

        mem.Write32Guest(
            regs[0],
            v99_engine_object);
        regs[0] = 0u;

        if (V99ShouldLogCounter(
                v99_engine_create_calls)) {
            AppendDiagnostic(
                "V99 AUDIO ENGINE CREATE #" +
                std::to_string(
                    v99_engine_create_calls) +
                " object=" +
                V46DescribeGuestAddress(
                    v99_engine_object));
        }
        return true;
    }

    bool V99HandleOpenSLSvc(
        const std::string& name,
        std::array<std::uint32_t, 16>& regs) {
        if (!V99Enabled() ||
            name.rfind("__v99_sl_", 0u) != 0u) {
            return false;
        }

        if (name == "__v99_sl_unsupported") {
            regs[0] = 1u;
            return true;
        }

        if (name == "__v99_sl_object_realize") {
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_object_get_state") {
            if (regs[1] != 0u) {
                // SL_OBJECT_STATE_REALIZED
                mem.Write32Guest(
                    regs[1],
                    2u);
            }
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_object_get_interface") {
            const std::uint32_t object = regs[0];
            const std::uint32_t iid = regs[1];
            const std::uint32_t out = regs[2];
            std::uint32_t interface_handle = 0u;

            if (object == v99_engine_object) {
                if (iid ==
                    V99OpenSLIID(
                        "SL_IID_ENGINE")) {
                    interface_handle =
                        v99_engine_itf;
                } else if (
                    iid ==
                    V99OpenSLIID(
                        "SL_IID_AUDIOIODEVICECAPABILITIES")) {
                    interface_handle =
                        v99_caps_itf;
                }
            } else if (
                object == v99_player_object) {
                if (iid ==
                    V99OpenSLIID(
                        "SL_IID_PLAY")) {
                    interface_handle =
                        v99_play_itf;
                } else if (
                    iid ==
                    V99OpenSLIID(
                        "SL_IID_BUFFERQUEUE")) {
                    interface_handle =
                        v99_queue_itf;
                } else if (
                    iid ==
                    V99OpenSLIID(
                        "SL_IID_ANDROIDCONFIGURATION")) {
                    interface_handle =
                        v99_config_itf;
                }
            }

            if (out != 0u) {
                mem.Write32Guest(
                    out,
                    interface_handle);
            }

            if (interface_handle == 0u) {
                ++v99_audio_interface_misses;
                if (V99ShouldLogCounter(
                        v99_audio_interface_misses)) {
                    AppendDiagnostic(
                        "V99 AUDIO GETINTERFACE MISS #" +
                        std::to_string(
                            v99_audio_interface_misses) +
                        " object=" +
                        V46DescribeGuestAddress(
                            object) +
                        " iid=" +
                        V46DescribeGuestAddress(
                            iid));
                }
                regs[0] = 1u;
            } else {
                regs[0] = 0u;
            }
            return true;
        }

        if (name == "__v99_sl_object_register_callback") {
            // CAkSinkOpenSL registers object callbacks even though all
            // v99 Realize calls are synchronous. No async object event
            // needs to be manufactured.
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_object_destroy") {
            if (regs[0] == v99_player_object ||
                regs[0] == v99_engine_object) {
                PvZ2HostAudioSetPlaying(false);
                PvZ2HostAudioClear();
                PvZ2HostAudioShutdown();
                v99_audio_configured = false;
            }
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_engine_create_output_mix") {
            if (!V99EnsureOpenSLObjects() ||
                regs[1] == 0u) {
                regs[0] = 1u;
                return true;
            }
            mem.Write32Guest(
                regs[1],
                v99_output_mix_object);
            regs[0] = 0u;
            AppendDiagnostic(
                "V99 AUDIO OUTPUT MIX CREATE object=" +
                V46DescribeGuestAddress(
                    v99_output_mix_object));
            return true;
        }

        if (name == "__v99_sl_engine_create_audio_player") {
            const std::uint32_t out_player =
                regs[1];
            const std::uint32_t source =
                regs[2];

            if (out_player == 0u ||
                source == 0u) {
                regs[0] = 1u;
                return true;
            }

            const std::uint32_t locator =
                mem.Read32Guest(
                    source + 0u);
            const std::uint32_t format =
                mem.Read32Guest(
                    source + 4u);

            if (locator == 0u ||
                format == 0u) {
                regs[0] = 1u;
                return true;
            }

            const std::uint32_t locator_type =
                mem.Read32Guest(
                    locator + 0u);
            const std::uint32_t requested_buffers =
                mem.Read32Guest(
                    locator + 4u);
            const std::uint32_t format_type =
                mem.Read32Guest(
                    format + 0u);
            const std::uint32_t channels =
                mem.Read32Guest(
                    format + 4u);
            const std::uint32_t rate_millihz =
                mem.Read32Guest(
                    format + 8u);
            const std::uint32_t bits =
                mem.Read32Guest(
                    format + 12u);
            const std::uint32_t container_bits =
                mem.Read32Guest(
                    format + 16u);
            const std::uint32_t channel_mask =
                mem.Read32Guest(
                    format + 20u);
            const std::uint32_t endianness =
                mem.Read32Guest(
                    format + 24u);

            const std::uint32_t sample_rate =
                rate_millihz >= 1000u
                    ? rate_millihz / 1000u
                    : 0u;

            if (format_type != 2u ||
                sample_rate == 0u ||
                (channels != 1u &&
                 channels != 2u) ||
                bits != 16u ||
                container_bits != 16u) {
                AppendCritical(
                    "V99 AUDIO PLAYER unsupported PCM contract format=" +
                    std::to_string(format_type) +
                    " rateMilliHz=" +
                    std::to_string(rate_millihz) +
                    " channels=" +
                    std::to_string(channels) +
                    " bits=" +
                    std::to_string(bits) +
                    " container=" +
                    std::to_string(
                        container_bits));
                regs[0] = 1u;
                return true;
            }

            const std::uint32_t queue_capacity =
                requested_buffers == 0u
                    ? 4u
                    : std::clamp<std::uint32_t>(
                          requested_buffers,
                          1u,
                          64u);

            if (!PvZ2HostAudioConfigure(
                    sample_rate,
                    channels)) {
                const char* host_error =
                    PvZ2HostAudioLastError();
                AppendCritical(
                    "V99 AUDIO HOST START FAILED: " +
                    std::string{
                        host_error != nullptr
                            ? host_error
                            : "unknown AVAudioEngine error"});
                regs[0] = 1u;
                return true;
            }

            v99_audio_sample_rate =
                sample_rate;
            v99_audio_channels =
                channels;
            v99_audio_queue_capacity =
                queue_capacity;
            v99_audio_configured = true;
            v99_play_state = 1u;
            PvZ2HostAudioSetPlaying(false);
            PvZ2HostAudioClear();

            mem.Write32Guest(
                out_player,
                v99_player_object);
            regs[0] = 0u;

            AppendDiagnostic(
                "V99 AUDIO PLAYER " +
                std::to_string(sample_rate) +
                " Hz channels=" +
                std::to_string(channels) +
                " buffers=" +
                std::to_string(
                    queue_capacity) +
                " bits=" +
                std::to_string(bits) +
                " locator=0x" +
                JniProbeHex(locator_type) +
                " channelMask=0x" +
                JniProbeHex(channel_mask) +
                " endian=" +
                std::to_string(
                    endianness));
            AppendDiagnostic(
                "V99 AUDIO HOST START backend=AVAudioEngine ringFrames=" +
                std::to_string(
                    PvZ2HostAudioRingCapacityFrames()));
            if (V101Enabled()) {
                AppendDiagnostic(
                    "V101 AUDIO CLOCK requested=" +
                    std::to_string(
                        PvZ2HostAudioRequestedSampleRate()) +
                    " session=" +
                    std::to_string(
                        PvZ2HostAudioSessionSampleRate()) +
                    " source=" +
                    std::to_string(
                        PvZ2HostAudioSourceSampleRate()) +
                    " mixer=" +
                    std::to_string(
                        PvZ2HostAudioMixerSampleRate()));
            }
            return true;
        }

        if (name == "__v99_sl_play_set_state") {
            const std::uint32_t state =
                regs[1];
            const bool changed =
                state != v99_play_state;
            v99_play_state = state;

            PvZ2HostAudioSetPlaying(
                state == 3u);

            if (V102Enabled() &&
                changed &&
                state == 3u) {
                v102_audio_play_begin_ns =
                    V85SteadyNowNs();
                v102_audio_poll_ticks = 0u;
                v102_audio_service_requested = false;
                AppendDiagnostic(
                    V103Enabled()
                        ? "V103 AUDIO REALTIME CLOCK armed at PLAYING; preemption is gated until Native_onDrawFrame, with startup using fallback drains."
                        : "V102 AUDIO REALTIME CLOCK armed at PLAYING; CoreAudio completions will preempt long guest lifecycles at scheduler checkpoints.");
            }

            if (changed) {
                AppendDiagnostic(
                    "V99 AUDIO PLAY STATE " +
                    std::to_string(state) +
                    (state == 3u
                        ? " PLAYING"
                        : (state == 2u
                               ? " PAUSED"
                               : " STOPPED")));
            }

            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_queue_enqueue") {
            const std::uint32_t guest_buffer =
                regs[1];
            const std::uint32_t bytes =
                regs[2];

            if (!v99_audio_configured ||
                guest_buffer == 0u ||
                bytes == 0u ||
                PvZ2HostAudioQueuedBufferCount() >=
                    v99_audio_queue_capacity) {
                regs[0] = 1u;
                return true;
            }

            const std::uint8_t* pcm =
                mem.Ptr(
                    guest_buffer,
                    bytes);

            std::uint32_t v104_pcm_hash = 2166136261u;
            bool v104_pcm_nonzero = false;
            if (V104Enabled() && pcm != nullptr) {
                for (std::uint32_t i = 0u; i < bytes; ++i) {
                    const std::uint8_t value = pcm[i];
                    v104_pcm_nonzero =
                        v104_pcm_nonzero || value != 0u;
                    v104_pcm_hash ^= value;
                    v104_pcm_hash *= 16777619u;
                }
            }

            if (pcm == nullptr ||
                !PvZ2HostAudioEnqueuePCM16(
                    pcm,
                    bytes)) {
                regs[0] = 1u;
                return true;
            }

            ++v99_audio_enqueues;

            if (V104Enabled()) {
                const bool repeated_nonzero =
                    v104_pcm_nonzero &&
                    v104_pcm_prev_nonzero &&
                    v104_pcm_hash == v104_pcm_prev_hash;

                if (repeated_nonzero) {
                    ++v104_pcm_repeat_run;
                    ++v104_pcm_repeat_total;
                    if (V99ShouldLogCounter(v104_pcm_repeat_run)) {
                        AppendDiagnostic(
                            "V104 AUDIO PCM REPEAT run=" +
                            std::to_string(v104_pcm_repeat_run) +
                            " total=" +
                            std::to_string(v104_pcm_repeat_total) +
                            " hash=0x" +
                            JniProbeHex(v104_pcm_hash) +
                            " src=" +
                            V46DescribeGuestAddress(guest_buffer) +
                            " bytes=" +
                            std::to_string(bytes) +
                            " frame=" +
                            std::to_string(current_frame_number) +
                            " tid=" +
                            std::to_string(current_probe_thread_id));
                    }
                } else {
                    v104_pcm_repeat_run = 1u;
                }

                v104_pcm_prev_hash = v104_pcm_hash;
                v104_pcm_prev_nonzero = v104_pcm_nonzero;
            }

            if (V99ShouldLogCounter(
                    v99_audio_enqueues)) {
                const std::uint32_t frame_bytes =
                    std::max<std::uint32_t>(
                        1u,
                        v99_audio_channels *
                            2u);
                AppendDiagnostic(
                    "V99 AUDIO ENQUEUE #" +
                    std::to_string(
                        v99_audio_enqueues) +
                    " frames=" +
                    std::to_string(
                        bytes /
                        frame_bytes) +
                    " bytes=" +
                    std::to_string(bytes) +
                    " queued=" +
                    std::to_string(
                        PvZ2HostAudioQueuedBufferCount()) +
                    (V104Enabled()
                         ? " src=" +
                               V46DescribeGuestAddress(guest_buffer) +
                               " hash=0x" +
                               JniProbeHex(v104_pcm_hash) +
                               " nonzero=" +
                               std::string{
                                   v104_pcm_nonzero
                                       ? "YES"
                                       : "NO"} +
                               " frame=" +
                               std::to_string(current_frame_number)
                         : std::string{}));
            }

            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_queue_clear") {
            PvZ2HostAudioClear();
            ++v99_audio_clears;
            if (V99ShouldLogCounter(
                    v99_audio_clears)) {
                AppendDiagnostic(
                    "V99 AUDIO QUEUE CLEAR #" +
                    std::to_string(
                        v99_audio_clears));
            }
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_queue_get_state") {
            ++v99_audio_getstate_calls;
            if (regs[1] != 0u) {
                mem.Write32Guest(
                    regs[1] + 0u,
                    PvZ2HostAudioQueuedBufferCount());
                mem.Write32Guest(
                    regs[1] + 4u,
                    static_cast<std::uint32_t>(
                        PvZ2HostAudioConsumedBufferTotal()));
            }
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_queue_register_callback") {
            v99_queue_callback =
                regs[1];
            v99_queue_context =
                regs[2];

            AppendDiagnostic(
                "V99 AUDIO BUFFERQUEUE CALLBACK registered fn=" +
                V46DescribeGuestAddress(
                    v99_queue_callback) +
                " context=" +
                V46DescribeGuestAddress(
                    v99_queue_context));
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_android_config_set") {
            const std::string key =
                regs[1] != 0u
                    ? mem.ReadCStringGuest(
                          regs[1],
                          128u)
                    : std::string{};
            const std::uint32_t value =
                regs[2] != 0u &&
                        regs[3] >= 4u
                    ? mem.Read32Guest(
                          regs[2])
                    : 0u;

            AppendDiagnostic(
                "V99 AUDIO ANDROID CONFIG key=\"" +
                key +
                "\" value=" +
                std::to_string(value) +
                " bytes=" +
                std::to_string(
                    regs[3]));
            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_caps_get_outputs") {
            if (regs[1] == 0u) {
                regs[0] = 1u;
                return true;
            }

            const std::uint32_t requested =
                mem.Read32Guest(
                    regs[1]);
            mem.Write32Guest(
                regs[1],
                1u);

            if (regs[2] != 0u &&
                requested != 0u) {
                mem.Write32Guest(
                    regs[2],
                    1u);
            }

            regs[0] = 0u;
            return true;
        }

        if (name == "__v99_sl_caps_query_output") {
            if (regs[2] == 0u) {
                regs[0] = 1u;
                return true;
            }

            const std::uint32_t descriptor =
                regs[2];

            for (std::uint32_t i = 0u;
                 i < 36u;
                 ++i) {
                mem.Write8Guest(
                    descriptor + i,
                    0u);
            }

            // SLAudioOutputDescriptor, ARM32 ABI. v106 exposes a discrete
            // 24/32/48 kHz device contract. The game's normal 32 kHz request
            // now matches instead of falling back to our old 48 kHz-only sink.
            mem.Write16Guest(
                descriptor + 4u,
                1u);
            mem.Write16Guest(
                descriptor + 6u,
                2u);
            mem.Write16Guest(
                descriptor + 8u,
                1u);
            mem.Write32Guest(
                descriptor + 16u,
                V106Enabled()
                    ? 24000000u
                    : 48000000u);
            mem.Write32Guest(
                descriptor + 20u,
                48000000u);
            mem.Write32Guest(
                descriptor + 24u,
                0u);
            mem.Write32Guest(
                descriptor + 28u,
                v99_audio_rate_array);
            mem.Write16Guest(
                descriptor + 32u,
                V106Enabled()
                    ? 3u
                    : 1u);
            mem.Write16Guest(
                descriptor + 34u,
                2u);

            regs[0] = 0u;
            return true;
        }

        regs[0] = 1u;
        return true;
    }

    bool V98Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::PresentationRgbFidelity);
    }

    bool V97Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::GrantedMutexWaitGraph);
    }

    bool V96Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::MainThreadBlocking);
    }

    bool V95Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::PreciseCallerReturnWatch);
    }

    bool V94Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::CallerReturnWatch);
    }

    const char* RuntimeModeTag() const {
        if (V109Enabled()) return "V109";
        if (V108Enabled()) return "V108";
        if (V107Enabled()) return "V107";
        if (V106Enabled()) return "V106";
        if (V105Enabled()) return "V105";
        if (V104Enabled()) return "V104";
        if (V103Enabled()) return "V103";
        if (V102Enabled()) return "V102";
        if (V101Enabled()) return "V101";
        if (V100Enabled()) return "V100";
        if (V99Enabled()) return "V99";
        if (V98Enabled()) return "V98";
        if (V97Enabled()) return "V97";
        if (V96Enabled()) return "V96";
        if (V95Enabled()) return "V95";
        if (V94Enabled()) return "V94";
        if (V93Enabled()) return "V93";
        if (V92Enabled()) return "V92";
        if (V91Enabled()) return "V91";
        if (V90Enabled()) return "V90";
        return "V89";
    }

    bool V93Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::ReturnProvenance);
    }

    bool V92Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::LongRunInteractive);
    }

    bool V91Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::IndexedAllocatorRelro);
    }

    bool V90Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::DirectPresentation);
    }

    bool V89Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::HeavyPerformanceProfiler);
    }

    bool V89HostCostEnabled() const {
        return HasCapability(
            PvZ2ProbeCapability::HostCostProfiler);
    }

    bool V88Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::AdaptiveMutex);
    }

    bool V87Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::PreemptiveMutex);
    }

    bool V86Enabled() const {
        return HasCapability(
            PvZ2ProbeCapability::Heap128);
    }

    bool V85PerformanceEnabled() const {
        return HasCapability(
            PvZ2ProbeCapability::PerformanceBaseline);
    }

    std::string V85FormatMs(std::uint64_t ns) const {
        std::ostringstream out;
        out << std::fixed << std::setprecision(3)
            << (static_cast<double>(ns) / 1000000.0);
        return out.str();
    }

    enum class ProbeLogClass {
        Legacy,
        Critical,
        Diagnostic,
        Telemetry,
        Verbose,
    };

    bool KeepLegacyPerformanceLogLine(
        const std::string& line) const {

        if (V86Enabled()) {
            if (line.rfind("V85 PERF", 0u) == 0u ||
                line.rfind("V86 PERF", 0u) == 0u ||
                line.rfind("V87 MUTEX", 0u) == 0u ||
                line.rfind("V87 SCHEDULER", 0u) == 0u ||
                line.rfind("V88 STARTUP", 0u) == 0u ||
                line.rfind("V88 SCHEDULER", 0u) == 0u ||
                line.rfind("V89 ", 0u) == 0u ||
                line.rfind("V90 ", 0u) == 0u ||
                line.rfind("V91 ", 0u) == 0u ||
                line.rfind("V92 ", 0u) == 0u ||
                line.rfind("V93 ", 0u) == 0u ||
                line.rfind("V94 ", 0u) == 0u ||
                line.rfind("V95 ", 0u) == 0u ||
                line.rfind("V96 ", 0u) == 0u ||
                line.rfind("V97 ", 0u) == 0u ||
                line.rfind("V98 ", 0u) == 0u ||
                line.rfind("V99 ", 0u) == 0u ||
                line.rfind("V100 ", 0u) == 0u ||
                line.rfind("V101 ", 0u) == 0u ||
                line.rfind("V102 ", 0u) == 0u ||
                line.rfind("V103 ", 0u) == 0u ||
                line.rfind("V104 ", 0u) == 0u ||
                line.rfind("V105 ", 0u) == 0u ||
                line.rfind("V106 ", 0u) == 0u ||
                line.rfind("V107 ", 0u) == 0u ||
                line.rfind("V108 ", 0u) == 0u) {
                return true;
            }

            if (line.rfind("V27 HEAP", 0u) == 0u &&
                line.find(" -> 0x00000000") !=
                    std::string::npos) {
                return true;
            }

            return
                line.find("failed=YES") != std::string::npos ||
                line.find("FAILED") != std::string::npos ||
                line.find("FAIL-FAST") != std::string::npos ||
                line.find("ERROR") != std::string::npos ||
                line.find("EXCEPTION") != std::string::npos ||
                line.find("exception") != std::string::npos ||
                line.find("EXECUTION BUDGET") != std::string::npos ||
                line.find("attempted to write outside") != std::string::npos ||
                line.find("guest-memory fault") != std::string::npos ||
                line.find("unsupported") != std::string::npos ||
                line.find("UNSUPPORTED") != std::string::npos ||
                line.find("V75 UI PACKAGE REMAP") != std::string::npos ||
                line.find("V72 INTERACTIVE SUMMARY") != std::string::npos ||
                line.find("V73 KEYBOARD SUMMARY") != std::string::npos;
        }

        return
            line.rfind("V85 PERF", 0u) == 0u ||
            line.find("FAILED") != std::string::npos ||
            line.find("failed") != std::string::npos ||
            line.find("ERROR") != std::string::npos ||
            line.find("error") != std::string::npos ||
            line.find("exception") != std::string::npos ||
            line.find("EXCEPTION") != std::string::npos ||
            line.find("EXECUTION BUDGET") != std::string::npos ||
            line.find("unsupported") != std::string::npos ||
            line.find("UNSUPPORTED") != std::string::npos ||
            line.find(" out of ") != std::string::npos ||
            line.find("NULL") != std::string::npos ||
            line.find("V75 UI PACKAGE REMAP") != std::string::npos ||
            line.find("V72 INTERACTIVE SUMMARY") != std::string::npos ||
            line.find("V73 KEYBOARD SUMMARY") != std::string::npos ||
            line.find("USERFS") != std::string::npos;
    }

    bool ShouldKeepLogLine(
        ProbeLogClass log_class,
        const std::string& line) const {

        if (log_class == ProbeLogClass::Critical ||
            log_class == ProbeLogClass::Diagnostic) {
            return true;
        }

        if (!V85PerformanceEnabled()) {
            return log_class != ProbeLogClass::Verbose;
        }

        if (log_class == ProbeLogClass::Verbose) {
            return false;
        }

        return KeepLegacyPerformanceLogLine(line);
    }

    void V85RecordGuestDraw(std::uint32_t frame, std::uint64_t elapsed_ns) {
        if (!V85PerformanceEnabled()) return;
        ++v85_guest_draw_samples;
        v85_guest_draw_total_ns += elapsed_ns;
        v85_guest_draw_max_ns = std::max(v85_guest_draw_max_ns, elapsed_ns);
        const bool interesting =
            V92Enabled()
                ? (frame <= 5u ||
                   (frame % 600u) == 0u ||
                   elapsed_ns >= 250000000ull)
                : (frame <= 5u ||
                   (frame % 30u) == 0u);
        if (interesting) {
            Append("V85 PERF guest frame=" + std::to_string(frame) +
                   " guestDrawMs=" + V85FormatMs(elapsed_ns));
        }
    }

    void V85RecordCapture(std::uint32_t frame, std::uint64_t elapsed_ns, std::size_t bytes) {
        if (!V85PerformanceEnabled()) return;
        ++v85_capture_samples;
        v85_capture_total_ns += elapsed_ns;
        v85_capture_max_ns = std::max(v85_capture_max_ns, elapsed_ns);
        if (frame <= 5u || (frame % 30u) == 0u) {
            Append("V85 PERF capture frame=" + std::to_string(frame) +
                   " frameCaptureMs=" + V85FormatMs(elapsed_ns) +
                   " bytes=" + std::to_string(bytes));
        }
    }

    void V85RecordTouchProcess(const V72TouchEvent& event) {
        if (!V85PerformanceEnabled() || event.queued_steady_ns == 0u) return;
        const std::uint64_t now = V85SteadyNowNs();
        const std::uint64_t elapsed_ns =
            now >= event.queued_steady_ns ? now - event.queued_steady_ns : 0u;
        ++v85_touch_process_samples;
        v85_touch_process_total_ns += elapsed_ns;
        v85_touch_process_max_ns = std::max(v85_touch_process_max_ns, elapsed_ns);
        v85_last_touch_queued_ns = event.queued_steady_ns;
        v85_last_touch_phase = event.phase;
        v85_last_touch_x = event.x;
        v85_last_touch_y = event.y;
        if (event.phase == 0u || event.phase == 3u || event.phase == 4u) {
            Append("V85 PERF input stage=UI_ProcessEvents frame=" +
                   std::to_string(current_frame_number) +
                   " phase=" + std::to_string(event.phase) +
                   " xy=" + std::to_string(event.x) + "," + std::to_string(event.y) +
                   " touchToUIProcessMs=" + V85FormatMs(elapsed_ns));
        }
    }

    void V85RecordGuestAction(const std::string& action) {
        if (!V85PerformanceEnabled() || v85_last_touch_queued_ns == 0u) return;
        const std::uint64_t now = V85SteadyNowNs();
        const std::uint64_t elapsed_ns =
            now >= v85_last_touch_queued_ns ? now - v85_last_touch_queued_ns : 0u;
        ++v85_touch_action_samples;
        v85_touch_action_total_ns += elapsed_ns;
        v85_touch_action_max_ns = std::max(v85_touch_action_max_ns, elapsed_ns);
        Append("V85 PERF input stage=guestAction frame=" +
               std::to_string(current_frame_number) +
               " action=" + action +
               " lastTouch{phase=" + std::to_string(v85_last_touch_phase) +
               ",xy=" + std::to_string(v85_last_touch_x) + "," +
               std::to_string(v85_last_touch_y) +
               "} touchToGuestActionMs=" + V85FormatMs(elapsed_ns));
    }

    std::string V85PerformanceSummary() const {
        auto average = [](std::uint64_t total, std::uint64_t samples) {
            return samples == 0u ? 0.0 :
                static_cast<double>(total) / static_cast<double>(samples) / 1000000.0;
        };
        std::ostringstream out;
        out << std::fixed << std::setprecision(3)
            << "V85 PERF SUMMARY"
            << " guestDraw{samples=" << v85_guest_draw_samples
            << ",avgMs=" << average(v85_guest_draw_total_ns, v85_guest_draw_samples)
            << ",maxMs=" << (static_cast<double>(v85_guest_draw_max_ns) / 1000000.0)
            << "} capture{samples=" << v85_capture_samples
            << ",avgMs=" << average(v85_capture_total_ns, v85_capture_samples)
            << ",maxMs=" << (static_cast<double>(v85_capture_max_ns) / 1000000.0)
            << "} touchToUIProcess{samples=" << v85_touch_process_samples
            << ",avgMs=" << average(v85_touch_process_total_ns, v85_touch_process_samples)
            << ",maxMs=" << (static_cast<double>(v85_touch_process_max_ns) / 1000000.0)
            << "} touchToGuestAction{samples=" << v85_touch_action_samples
            << ",avgMs=" << average(v85_touch_action_total_ns, v85_touch_action_samples)
            << ",maxMs=" << (static_cast<double>(v85_touch_action_max_ns) / 1000000.0)
            << "} logLines{kept=" << v85_log_lines_kept
            << ",suppressed=" << v85_log_lines_suppressed << "}";
        return out.str();
    }

    void V89RecordHostCost(const char* name,std::uint64_t begin,std::uint64_t bytes=0u) {
        if(!V89HostCostEnabled()||begin==0u||name==nullptr)return;
        const auto now=V85SteadyNowNs(),ns=now>=begin?now-begin:0u;
        auto& b=v89_host_buckets[std::string{name}];
        ++b.calls;b.total_ns+=ns;b.max_ns=std::max(b.max_ns,ns);b.bytes+=bytes;
    }
    void V89RecordQuantumSample() {
        if(!V89Enabled()||jit==nullptr)return;
        V89PcSample s;s.pc=jit->Regs()[15];s.lr=jit->Regs()[14];s.tid=current_probe_thread_id;
        s.phase=current_lifecycle_name.empty()?"n/a":current_lifecycle_name;
        std::ostringstream k;k<<s.phase<<"|"<<s.tid<<"|"<<JniProbeHex(s.pc)<<"|"<<JniProbeHex(s.lr);
        auto& d=v89_pc_samples[k.str()];++d.count;d.pc=s.pc;d.lr=s.lr;d.tid=s.tid;d.phase=s.phase;
        ++v89_tid_samples[s.tid];++v89_quantum_samples;
    }
    std::string V89HotPcSummary() const {
        std::vector<V89PcSample> v;v.reserve(v89_pc_samples.size());for(const auto&e:v89_pc_samples)v.push_back(e.second);
        std::sort(v.begin(),v.end(),[](const auto&a,const auto&b){if(a.count!=b.count)return a.count>b.count;if(a.tid!=b.tid)return a.tid<b.tid;return a.pc<b.pc;});
        std::ostringstream o;o<<"V89 HOTPC SUMMARY samples="<<v89_quantum_samples<<" unique="<<v.size()<<" tids={";
        bool first=true;for(const auto&[tid,count]:v89_tid_samples){if(!first)o<<",";first=false;o<<tid<<":"<<count;}o<<"}";
        const auto lim=std::min<std::size_t>(48u,v.size());
        for(std::size_t i=0;i<lim;++i)o<<"\nV89 HOTPC #"<<i+1<<" count="<<v[i].count<<" tid="<<v[i].tid<<" phase="<<v[i].phase<<" PC="<<V46DescribeGuestAddress(v[i].pc)<<" LR="<<V46DescribeGuestAddress(v[i].lr);
        return o.str();
    }
    std::string V89HostCostSummary() const {
        std::vector<std::pair<std::string,V89HostBucket>> v(v89_host_buckets.begin(),v89_host_buckets.end());
        std::sort(v.begin(),v.end(),[](const auto&a,const auto&b){return a.second.total_ns>b.second.total_ns;});
        std::ostringstream o;o<<std::fixed<<std::setprecision(3)<<"V89 HOSTCOST SUMMARY buckets="<<v.size();
        for(const auto&[n,b]:v)o<<"\nV89 HOSTCOST bucket="<<n<<" calls="<<b.calls<<" totalMs="<<double(b.total_ns)/1e6<<" maxMs="<<double(b.max_ns)/1e6<<" bytes="<<b.bytes;
        return o.str();
    }
    void V89RecordIndirectBlx(std::uint32_t src,std::uint32_t obj,std::uint32_t vt,std::uint32_t slot,std::uint32_t target) {
        if(!V89Enabled())return;++v89_blx_events;const bool odd=(target&1u)!=0u;if(odd)++v89_blx_odd_targets;
        if(!odd&&v89_blx_events>32u&&(v89_blx_events&(v89_blx_events-1u))!=0u)return;
        const auto cpsr=jit?jit->Cpsr():0u;std::ostringstream o;
        o<<"V89 INDIRECT BLX #"<<v89_blx_events<<(odd?" ODD-TARGET":"")<<" frame="<<current_frame_number<<" tid="<<current_probe_thread_id
         <<" phase="<<(current_lifecycle_name.empty()?"n/a":current_lifecycle_name)<<" source="<<V46DescribeGuestAddress(src)
         <<" object="<<V46DescribeGuestAddress(obj)<<" vtable="<<V46DescribeGuestAddress(vt)<<" slot=0x"<<JniProbeHex(slot)
         <<" target="<<V46DescribeGuestAddress(target)<<" targetBit0="<<(target&1u)<<" cpsrT="<<((cpsr&0x20u)?1u:0u);
        Append(o.str());
    }
    void V89EmitTerminalSummaries(const char* reason) {
        if(!V89Enabled()||v89_terminal_summaries_emitted)return;v89_terminal_summaries_emitted=true;
        Append(std::string{"V89 TERMINAL reason="}+(reason?reason:"unknown")+" blxEvents="+std::to_string(v89_blx_events)+" oddTargets="+std::to_string(v89_blx_odd_targets));
        Append(V89HotPcSummary());Append(V89HostCostSummary());
    }

    std::string V90HostCostSummary() const {
        std::vector<std::pair<std::string,V89HostBucket>> v(
            v89_host_buckets.begin(),
            v89_host_buckets.end());
        std::sort(
            v.begin(),
            v.end(),
            [](const auto& a,const auto& b){
                return a.second.total_ns>b.second.total_ns;
            });
        std::ostringstream o;
        o<<std::fixed<<std::setprecision(3)
         <<"V90 HOSTCOST SUMMARY buckets="<<v.size();
        for(const auto& [n,b]:v) {
            o<<"\nV90 HOSTCOST bucket="<<n
             <<" calls="<<b.calls
             <<" totalMs="<<double(b.total_ns)/1e6
             <<" maxMs="<<double(b.max_ns)/1e6
             <<" bytes="<<b.bytes;
        }
        return o.str();
    }

    void V90BeginFrame(std::uint32_t frame) {
        if(!V90Enabled())return;
        v90_profile_frame=frame;
        v90_frame_worker_wait_ns=0u;
        v90_frame_boundary_worker_ns=0u;
        v90_frame_present_ns=0u;
        v90_frame_font_ns=0u;
        if (V110Enabled()) {
            v110_frame_audio_ns.fill(0u);
            v110_frame_audio_quanta.fill(0u);
        }
        v90_frame_alloc_calls_begin=
            mem.v90_alloc_calls_internal;
        v90_frame_alloc_scan_begin=
            mem.v90_alloc_scan_total;
    }

    void V90RecordWorkerWall(
        std::uint32_t tid,
        std::uint64_t elapsed_ns,
        bool boundary) {

        if(!V90Enabled())return;
        v90_worker_ns_by_tid[tid]+=elapsed_ns;
        if(boundary){
            v90_boundary_worker_ns_total+=elapsed_ns;
            if(current_frame_number==v90_profile_frame)
                v90_frame_boundary_worker_ns+=elapsed_ns;
        } else {
            v90_worker_wait_ns_total+=elapsed_ns;
            if(current_frame_number==v90_profile_frame)
                v90_frame_worker_wait_ns+=elapsed_ns;
        }
    }

    void V90FontScanBegin() {
        if(!V90Enabled())return;
        v90_font_begin_ns[current_probe_thread_id]=
            V85SteadyNowNs();
    }

    void V90FontScanEnd() {
        if(!V90Enabled())return;
        const auto it=
            v90_font_begin_ns.find(
                current_probe_thread_id);
        if(it==v90_font_begin_ns.end()){
            ++v90_font_unmatched;
            return;
        }

        const auto now=V85SteadyNowNs();
        const auto elapsed=
            now>=it->second?now-it->second:0u;
        v90_font_begin_ns.erase(it);
        ++v90_font_scans;
        v90_font_total_ns+=elapsed;
        v90_font_max_ns=
            std::max(v90_font_max_ns,elapsed);

        const std::string phase=
            current_lifecycle_name.empty()
                ?"n/a"
                :current_lifecycle_name;
        auto& phase_bucket=
            v90_font_by_phase[phase];
        ++phase_bucket.first;
        phase_bucket.second+=elapsed;

        if(current_frame_number==v90_profile_frame)
            v90_frame_font_ns+=elapsed;
    }

    void V90RecordPresent(
        std::uint32_t frame,
        std::uint64_t elapsed_ns,
        bool ok,
        std::uint32_t drawable_width,
        std::uint32_t drawable_height) {

        if(!V90Enabled())return;
        ++v90_present_calls;
        if(!ok)++v90_present_failures;
        v90_present_ns_total+=elapsed_ns;
        v90_present_max_ns=
            std::max(
                v90_present_max_ns,
                elapsed_ns);
        v90_last_drawable_width=
            drawable_width;
        v90_last_drawable_height=
            drawable_height;
        if(frame==v90_profile_frame)
            v90_frame_present_ns+=elapsed_ns;

        if(!ok &&
           (v90_present_failures<=4u ||
            (v90_present_failures&
             (v90_present_failures-1u))==0u)) {
            Append(
                "V90 PRESENT FAIL frame="+
                std::to_string(frame)+
                " failures="+
                std::to_string(v90_present_failures));
        }
    }

    void V90EndFrame(
        std::uint32_t frame,
        std::uint64_t guest_ns,
        std::uint64_t active_ns) {

        if(!V90Enabled())return;
        ++v90_frames_profiled;
        v90_guest_ns_total+=guest_ns;
        v90_active_ns_total+=active_ns;

        const std::uint64_t main_approx_ns=
            guest_ns>=v90_frame_worker_wait_ns
                ?guest_ns-v90_frame_worker_wait_ns
                :0u;
        const std::uint64_t alloc_calls=
            mem.v90_alloc_calls_internal>=
                    v90_frame_alloc_calls_begin
                ?mem.v90_alloc_calls_internal-
                    v90_frame_alloc_calls_begin
                :0u;
        const std::uint64_t alloc_scan_steps=
            mem.v90_alloc_scan_total>=
                    v90_frame_alloc_scan_begin
                ?mem.v90_alloc_scan_total-
                    v90_frame_alloc_scan_begin
                :0u;

        const std::uint64_t v110_audio_frame_ns =
            V110Enabled() ? V110FrameAudioNs() : 0u;
        const bool v110_slow_frame =
            V110Enabled() &&
            (guest_ns >= 100000000ull ||
             v110_audio_frame_ns >= 50000000ull);

        const bool interesting=
            V92Enabled()
                ? (frame<=5u ||
                   (frame%600u)==0u ||
                   guest_ns>=250000000ull ||
                   v90_frame_worker_wait_ns>=250000000ull ||
                   v90_frame_boundary_worker_ns>=250000000ull ||
                   v90_frame_font_ns>=250000000ull ||
                   v110_slow_frame)
                : (frame<=5u ||
                   (frame%30u)==0u ||
                   guest_ns>=250000000ull ||
                   v90_frame_worker_wait_ns>=250000000ull ||
                   v90_frame_boundary_worker_ns>=250000000ull ||
                   v90_frame_font_ns!=0u ||
                   alloc_scan_steps>=4096u ||
                   v110_slow_frame);

        if(interesting){
            std::ostringstream o;
            o<<std::fixed<<std::setprecision(3)
             <<"V90 FRAME frame="<<frame
             <<" guestMs="<<double(guest_ns)/1e6
             <<" mainApproxMs="<<double(main_approx_ns)/1e6
             <<" waitWorkerMs="<<double(v90_frame_worker_wait_ns)/1e6
             <<" boundaryWorkerMs="<<double(v90_frame_boundary_worker_ns)/1e6
             <<" fontMs="<<double(v90_frame_font_ns)/1e6
             <<" presentMs="<<double(v90_frame_present_ns)/1e6
             <<" activeFrameMs="<<double(active_ns)/1e6
             <<" allocCalls="<<alloc_calls
             <<" allocScanSteps="<<alloc_scan_steps
             <<" freeBlocks="<<mem.heap_free_blocks.size();
            if (v110_slow_frame) {
                o << V110FrameAudioSummary();
            }
            Append(o.str());
        }
    }

    std::string V90FrameSummary() const {
        std::ostringstream o;
        o<<std::fixed<<std::setprecision(3)
         <<"V90 FRAME SUMMARY frames="<<v90_frames_profiled
         <<" guestTotalMs="<<double(v90_guest_ns_total)/1e6
         <<" activeTotalMs="<<double(v90_active_ns_total)/1e6
         <<" waitWorkerTotalMs="<<double(v90_worker_wait_ns_total)/1e6
         <<" boundaryWorkerTotalMs="<<double(v90_boundary_worker_ns_total)/1e6
         <<" present{calls="<<v90_present_calls
         <<",failures="<<v90_present_failures
         <<",totalMs="<<double(v90_present_ns_total)/1e6
         <<",maxMs="<<double(v90_present_max_ns)/1e6
         <<",drawable="<<v90_last_drawable_width
         <<"x"<<v90_last_drawable_height
         <<"} workers={";
        bool first=true;
        for(const auto& [tid,ns]:v90_worker_ns_by_tid){
            if(!first)o<<",";
            first=false;
            o<<tid<<":"<<double(ns)/1e6<<"ms";
        }
        o<<"}";
        return o.str();
    }

    std::string V90FontSummary() const {
        std::ostringstream o;
        o<<std::fixed<<std::setprecision(3)
         <<"V90 FONT SUMMARY scans="<<v90_font_scans
         <<" totalMs="<<double(v90_font_total_ns)/1e6
         <<" maxMs="<<double(v90_font_max_ns)/1e6
         <<" unmatched="<<v90_font_unmatched
         <<" phases={";
        bool first=true;
        for(const auto& [phase,bucket]:v90_font_by_phase){
            if(!first)o<<",";
            first=false;
            o<<phase<<":"<<bucket.first
             <<"/"<<double(bucket.second)/1e6<<"ms";
        }
        o<<"}";
        return o.str();
    }

    void V91ConfigureRelro(
        const JniProbeLoadedElf& loaded) {

        if (!V91Enabled() ||
            loaded.gnu_relro_size == 0u) {
            return;
        }

        v91_relro_begin =
            kGuestBase +
            loaded.gnu_relro_vaddr;
        v91_relro_end =
            v91_relro_begin +
            loaded.gnu_relro_size;

        mem.V91ConfigureRelro(
            v91_relro_begin,
            loaded.gnu_relro_size);

        Append(
            "V91 RELRO CONFIG range=0x" +
            JniProbeHex(v91_relro_begin) +
            "..0x" +
            JniProbeHex(v91_relro_end) +
            " size=" +
            std::to_string(
                loaded.gnu_relro_size));
    }

    void V91RegisterProtectedImport(
        std::uint32_t address,
        std::uint32_t expected,
        const std::string& name,
        std::uint32_t relocation_type) {

        if (!V91Enabled()) {
            return;
        }

        const std::uint64_t end =
            static_cast<std::uint64_t>(
                address) +
            4u;

        if (address <
                v91_relro_begin ||
            end >
                v91_relro_end) {
            return;
        }

        v91_protected_imports[address] =
            V91ProtectedImport{
                expected,
                name,
                relocation_type};

        if (name == "free") {
            v91_free_got =
                address;
            v91_free_expected =
                expected;
        }
    }

    std::string V91PhaseName() const {
        switch (return_mode) {
        case ReturnMode::Constructor:
            return
                "constructor[" +
                std::to_string(
                    current_constructor_index) +
                "]";
        case ReturnMode::GameAppInitialize:
            return "Native_GameAppInitialize";
        case ReturnMode::Lifecycle:
            return
                current_lifecycle_name.empty()
                    ? "lifecycle"
                    : current_lifecycle_name;
        case ReturnMode::JniOnLoad:
        default:
            return "JNI_OnLoad";
        }
    }

    const V91ProtectedImport*
    V91ImportAt(
        std::uint32_t address,
        std::size_t size,
        std::uint32_t* slot_address = nullptr) const {

        if (size == 0u ||
            v91_protected_imports.empty()) {
            return nullptr;
        }

        const std::uint64_t begin =
            address;
        const std::uint64_t end =
            begin + size;

        auto it =
            v91_protected_imports.lower_bound(
                address >= 3u
                    ? address - 3u
                    : 0u);

        for (; it !=
                 v91_protected_imports.end();
             ++it) {

            const std::uint64_t slot_begin =
                it->first;
            const std::uint64_t slot_end =
                slot_begin + 4u;

            if (slot_begin >= end) {
                break;
            }

            if (slot_end > begin) {
                if (slot_address != nullptr) {
                    *slot_address =
                        it->first;
                }
                return &it->second;
            }
        }

        return nullptr;
    }

    bool V91AllowRelroWrite(
        std::uint32_t address,
        std::size_t size,
        const char* kind,
        std::uint64_t value = 0u,
        bool value_known = false) {

        if (!V91Enabled() ||
            !v91_relro_armed ||
            !mem.V91OverlapsRelro(
                address,
                size)) {
            return true;
        }

        ++v91_relro_write_attempts;

        if (!v91_first_relro_write_seen) {
            v91_first_relro_write_seen =
                true;
            v91_first_write_pc =
                jit != nullptr
                    ? jit->Regs()[15]
                    : 0u;
            v91_first_write_lr =
                jit != nullptr
                    ? jit->Regs()[14]
                    : 0u;
            v91_first_write_tid =
                current_probe_thread_id;
            v91_first_write_dst =
                address;
            v91_first_write_size =
                static_cast<std::uint32_t>(
                    std::min<std::size_t>(
                        size,
                        0xffffffffu));
            v91_first_write_value =
                value;
            v91_first_write_value_known =
                value_known;
            v91_first_write_kind =
                kind != nullptr
                    ? kind
                    : "unknown";
            v91_first_write_phase =
                V91PhaseName();

            std::uint32_t slot_address = 0u;
            const auto* slot =
                V91ImportAt(
                    address,
                    size,
                    &slot_address);

            std::ostringstream out;
            out
                << "V91 RELRO BLOCK first kind="
                << v91_first_write_kind
                << " phase="
                << v91_first_write_phase
                << " tid="
                << v91_first_write_tid
                << " PC=0x"
                << JniProbeHex(
                    v91_first_write_pc)
                << " LR=0x"
                << JniProbeHex(
                    v91_first_write_lr)
                << " dst=0x"
                << JniProbeHex(address)
                << " size="
                << size;

            if (value_known) {
                out
                    << " new=0x"
                    << std::hex
                    << value
                    << std::dec;
            }

            if (slot != nullptr) {
                out
                    << " import="
                    << slot->name
                    << " slot=0x"
                    << JniProbeHex(
                        slot_address)
                    << " expected=0x"
                    << JniProbeHex(
                        slot->expected)
                    << " current=0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            slot_address));
            }

            Append(out.str());
        }

        // GNU_RELRO is read-only in the real Bionic process after relocation.
        // Suppressing this synthetic write is therefore an ABI-fidelity fix,
        // not a resource/game-state fabrication.
        return false;
    }

    void V91RepairImportIntegrity(
        const char* reason) {

        if (!V91Enabled() ||
            !v91_relro_armed) {
            return;
        }

        for (const auto& entry :
             v91_protected_imports) {

            const std::uint32_t current =
                mem.Read32Guest(
                    entry.first);

            if (current ==
                entry.second.expected) {
                continue;
            }

            ++v91_integrity_repairs;

            Append(
                "V91 RELRO REPAIR reason=" +
                std::string{
                    reason != nullptr
                        ? reason
                        : "unknown"} +
                " import=" +
                entry.second.name +
                " slot=0x" +
                JniProbeHex(entry.first) +
                " current=0x" +
                JniProbeHex(current) +
                " expected=0x" +
                JniProbeHex(
                    entry.second.expected));

            mem.Write32GuestUnchecked(
                entry.first,
                entry.second.expected);
        }
    }

    bool V91ArmRelro() {

        if (!V91Enabled()) {
            return true;
        }

        if (v91_relro_begin == 0u ||
            v91_relro_end <=
                v91_relro_begin) {

            Append(
                "V91 RELRO ERROR: missing/invalid PT_GNU_RELRO metadata.");
            return false;
        }

        if (v91_free_got == 0u ||
            v91_free_expected == 0u) {
            Append(
                "V91 RELRO ERROR: free R_ARM_JUMP_SLOT was not registered.");
            return false;
        }

        // Exact 1.5.252752 signature recovered from the supplied APK.
        if (v91_free_got !=
            kGuestBase + 0x00d01c20u) {
            Append(
                "V91 RELRO ERROR: free GOT moved unexpectedly to 0x" +
                JniProbeHex(v91_free_got));
            return false;
        }

        // Verify/repair once before sealing, then reject later writes.
        for (const auto& entry :
             v91_protected_imports) {
            const std::uint32_t current =
                mem.Read32Guest(
                    entry.first);

            if (current !=
                entry.second.expected) {

                ++v91_integrity_repairs;
                Append(
                    "V91 RELRO PREARM REPAIR import=" +
                    entry.second.name +
                    " slot=0x" +
                    JniProbeHex(entry.first) +
                    " current=0x" +
                    JniProbeHex(current) +
                    " expected=0x" +
                    JniProbeHex(
                        entry.second.expected));

                mem.Write32GuestUnchecked(
                    entry.first,
                    entry.second.expected);
            }
        }

        mem.V91ArmRelro();
        v91_relro_armed =
            mem.V91RelroArmed();

        Append(
            "V91 RELRO ARMED range=0x" +
            JniProbeHex(v91_relro_begin) +
            "..0x" +
            JniProbeHex(v91_relro_end) +
            " protectedImports=" +
            std::to_string(
                v91_protected_imports.size()) +
            " freeGOT=0x" +
            JniProbeHex(v91_free_got) +
            " freeExpected=0x" +
            JniProbeHex(
                v91_free_expected));

        return v91_relro_armed;
    }

    std::string V91RelroSummary() const {
        std::ostringstream out;
        const std::uint32_t free_current =
            v91_free_got != 0u
                ? mem.Read32Guest(
                      v91_free_got)
                : 0u;

        out
            << "V91 RELRO SUMMARY armed="
            << (v91_relro_armed
                    ? "YES"
                    : "NO")
            << " range=0x"
            << JniProbeHex(v91_relro_begin)
            << "..0x"
            << JniProbeHex(v91_relro_end)
            << " imports="
            << v91_protected_imports.size()
            << " attempts="
            << v91_relro_write_attempts
            << " memBlocked="
            << mem.v91_memory_blocked_writes
            << " repairs="
            << v91_integrity_repairs
            << " free{slot=0x"
            << JniProbeHex(v91_free_got)
            << ",expected=0x"
            << JniProbeHex(v91_free_expected)
            << ",current=0x"
            << JniProbeHex(free_current)
            << "}";

        if (v91_first_relro_write_seen) {
            out
                << " first{kind="
                << v91_first_write_kind
                << ",phase="
                << v91_first_write_phase
                << ",tid="
                << v91_first_write_tid
                << ",PC=0x"
                << JniProbeHex(
                    v91_first_write_pc)
                << ",LR=0x"
                << JniProbeHex(
                    v91_first_write_lr)
                << ",dst=0x"
                << JniProbeHex(
                    v91_first_write_dst)
                << ",size="
                << v91_first_write_size
                << "}";
        } else if (
            mem.v91_memory_blocked_writes !=
                0u) {
            out
                << " firstMemOnly{dst=0x"
                << JniProbeHex(
                    mem.v91_first_blocked_address)
                << ",size="
                << mem.v91_first_blocked_size
                << "}";
        }

        return out.str();
    }

    bool V93GuestImageTarget(
        std::uint32_t raw_address) const {

        if (loaded_elf == nullptr) {
            return false;
        }

        const std::uint32_t address =
            raw_address & ~1u;
        if (address < kGuestBase) {
            return false;
        }

        const std::uint64_t offset =
            static_cast<std::uint64_t>(
                address - kGuestBase);
        return
            offset <
            static_cast<std::uint64_t>(
                loaded_elf->image.size());
    }

    std::string V93ReturnSummary() const {
        std::ostringstream out;
        out
            << "V93 RETURN SUMMARY targetFreeCalls="
            << v93_target_free_calls
            << " oddSavedPC="
            << v93_odd_saved_pc_calls
            << " invalidSavedPC="
            << v93_invalid_saved_pc_calls
            << " changedByFree="
            << v93_saved_pc_changed_by_free;

        if (!v93_last_sample_valid) {
            out << " last=NONE";
            return out.str();
        }

        const bool before_in_image =
            V93GuestImageTarget(
                v93_last_saved_pc_before);
        const bool after_in_image =
            V93GuestImageTarget(
                v93_last_saved_pc_after);

        out
            << " last{frame="
            << v93_last_frame
            << ",freePtr=0x"
            << JniProbeHex(v93_last_free_ptr)
            << ",SP=0x"
            << JniProbeHex(v93_last_sp)
            << ",LR=0x"
            << JniProbeHex(v93_last_lr)
            << ",CPSR=0x"
            << JniProbeHex(v93_last_cpsr)
            << ",savedBefore=0x"
            << JniProbeHex(
                v93_last_saved_pc_before)
            << ",beforeBit0="
            << (v93_last_saved_pc_before & 1u)
            << ",beforeInImage="
            << (before_in_image ? "YES" : "NO")
            << ",savedAfter=0x"
            << JniProbeHex(
                v93_last_saved_pc_after)
            << ",afterBit0="
            << (v93_last_saved_pc_after & 1u)
            << ",afterInImage="
            << (after_in_image ? "YES" : "NO")
            << ",stackBase=0x"
            << JniProbeHex(v93_last_stack_base)
            << ",stackWords={";

        for (std::size_t i = 0u;
             i < v93_last_stack_words.size();
             ++i) {
            if (i != 0u) {
                out << ",";
            }
            out
                << "0x"
                << JniProbeHex(
                    v93_last_stack_words[i]);
        }

        out << "}";

        if (v93_last_exception_valid) {
            out
                << ",exception{PC=0x"
                << JniProbeHex(
                    v93_last_exception_pc)
                << ",SP=0x"
                << JniProbeHex(
                    v93_last_exception_sp)
                << ",CPSR=0x"
                << JniProbeHex(
                    v93_last_exception_cpsr)
                << ",SPminus4=0x"
                << JniProbeHex(
                    v93_last_exception_sp_minus_4)
                << ",bit0="
                << (v93_last_exception_sp_minus_4 & 1u)
                << ",inImage="
                << (V93GuestImageTarget(
                        v93_last_exception_sp_minus_4)
                        ? "YES"
                        : "NO")
                << "}";
        }

        out << "}";
        return out.str();
    }

    std::string V93DiagnosticCheck() const {
        std::ostringstream out;
        out
            << "V93 DIAGNOSTIC CHECK returnProvenance="
            << (v93_target_free_calls != 0u
                    ? "SEEN"
                    : "NOT_TRIGGERED")
            << " exceptionReturnWord="
            << (v93_last_exception_valid
                    ? "SEEN"
                    : "NOT_TRIGGERED");
        return out.str();
    }

    std::string V94CallerReturnSummary() const {
        std::ostringstream out;
        out
            << RuntimeModeTag()
            << " CALLER-LR SUMMARY wrapperEntries="
            << v94_wrapper_entries
            << " watchedGuestWrites="
            << v94_watched_guest_writes
            << " armed="
            << (v94_watch_armed
                    ? "YES"
                    : "NO")
            << " slot=0x"
            << JniProbeHex(v94_watch_slot)
            << " entryLR=0x"
            << JniProbeHex(v94_entry_lr)
            << " outerAtFree=0x"
            << JniProbeHex(
                v94_last_outer_at_free)
            << " firstChange=";

        if (!v94_first_change_seen) {
            out << "NONE";
            return out.str();
        }

        out
            << "{frame="
            << v94_first_change_frame
            << ",slot=0x"
            << JniProbeHex(
                v94_first_change_slot)
            << ",write=0x"
            << JniProbeHex(
                v94_first_change_address)
            << ",width="
            << v94_first_change_width
            << ",old=0x"
            << JniProbeHex(
                v94_first_change_old)
            << ",new=0x"
            << JniProbeHex(
                v94_first_change_new)
            << ",PC=0x"
            << JniProbeHex(
                v94_first_change_pc)
            << ",LR=0x"
            << JniProbeHex(
                v94_first_change_lr)
            << ",SP=0x"
            << JniProbeHex(
                v94_first_change_sp)
            << ",CPSR=0x"
            << JniProbeHex(
                v94_first_change_cpsr)
            << ",tid="
            << v94_first_change_tid
            << ",phase="
            << v94_first_change_phase
            << "}";
        return out.str();
    }

    void V91EmitTerminalSummary(
        const char* reason) {

        if (!V91Enabled() ||
            v91_terminal_summary_emitted) {
            return;
        }

        v91_terminal_summary_emitted =
            true;

        V91RepairImportIntegrity(
            reason);

        AppendDiagnostic(
            std::string{RuntimeModeTag()} +
            " TERMINAL reason=" +
            (reason != nullptr
                ? reason
                : "unknown"));
        AppendDiagnostic(
            mem.V91AllocatorIndexSummary());
        AppendDiagnostic(
            V91RelroSummary());
        if (V93Enabled()) {
            AppendDiagnostic(
                V93ReturnSummary());
            AppendDiagnostic(
                V93DiagnosticCheck());
        }
        if (V94Enabled()) {
            AppendDiagnostic(
                V94CallerReturnSummary());
        }
    }

    void V90EmitTerminalSummaries(const char* reason) {
        if(!V90Enabled()||
           v90_terminal_summaries_emitted)return;
        v90_terminal_summaries_emitted=true;
        Append(
            std::string{"V90 TERMINAL reason="}+
            (reason?reason:"unknown"));
        Append(V90FontSummary());
        Append(V90FrameSummary());
        if (V110Enabled()) Append(V110AudioSummary());
        Append(mem.V90AllocatorSummary());
        Append(V90HostCostSummary());
    }

    bool V84FinalBlitEnabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V84FinalBlitTrace ||
            diagnostic_mode ==
                PvZ2DiagnosticMode::V84PointsEqualPixels ||
            diagnostic_mode ==
                PvZ2DiagnosticMode::V84AndroidGraphicsContract;
    }

    bool V84PointsPixelsEnabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V84PointsEqualPixels ||
            diagnostic_mode ==
                PvZ2DiagnosticMode::V84AndroidGraphicsContract ||
            V85PerformanceEnabled();
    }

    bool V84AndroidContractEnabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V84AndroidGraphicsContract;
    }

    bool V83Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V83ProfileButtonDispatch ||
            V84FinalBlitEnabled();
    }

    bool V83ButtonTrapEnabled() const {
        return V83Enabled() || V85PerformanceEnabled();
    }

    bool V82Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V82ProfileLayoutRadar ||
            V83Enabled();
    }

    std::string V82TouchContext() const {
        std::ostringstream out;
        out << "touch#" << v82_touch_serial
            << "{frame=" << v82_last_touch_frame
            << ",phase=" << v82_last_touch_phase
            << ",xy=" << v82_last_touch_x << "," << v82_last_touch_y
            << ",prev=" << v82_last_touch_previous_x << ","
            << v82_last_touch_previous_y << "}";
        return out.str();
    }

    std::string V82WidgetRaw(
        const char* label,
        std::uint32_t object,
        std::int32_t test_x,
        std::int32_t test_y) {

        std::ostringstream out;
        out << label << "{ptr=0x" << JniProbeHex(object);

        if (object == 0u || mem.Ptr(object, 0x38u) == nullptr) {
            out << ",invalid}";
            return out.str();
        }

        const std::int32_t x =
            static_cast<std::int32_t>(mem.Read32Guest(object + 0x28u));
        const std::int32_t y =
            static_cast<std::int32_t>(mem.Read32Guest(object + 0x2cu));
        const std::int32_t w =
            static_cast<std::int32_t>(mem.Read32Guest(object + 0x30u));
        const std::int32_t h =
            static_cast<std::int32_t>(mem.Read32Guest(object + 0x34u));

        const bool inside =
            w > 0 && h > 0 &&
            test_x >= x && test_y >= y &&
            static_cast<std::int64_t>(test_x) <
                static_cast<std::int64_t>(x) + w &&
            static_cast<std::int64_t>(test_y) <
                static_cast<std::int64_t>(y) + h;

        out << ",vtable=0x" << JniProbeHex(mem.Read32Guest(object))
            << ",rawXYWH=" << x << "," << y << "," << w << "," << h
            << ",containsTouch=" << (inside ? "YES" : "NO") << "}";
        return out.str();
    }

    std::string V82RadarSnapshot(
        std::int32_t test_x,
        std::int32_t test_y) {

        std::ostringstream out;
        out << V82WidgetRaw("profile", v82_profile_object, test_x, test_y)
            << " " << V82WidgetRaw("candidate5", v82_candidate5, test_x, test_y)
            << " " << V82WidgetRaw("candidate6", v82_candidate6, test_x, test_y)
            << " " << V82WidgetRaw("candidate7", v82_candidate7, test_x, test_y);

        if (v82_profile_object != 0u &&
            mem.Ptr(v82_profile_object, 0xccu) != nullptr) {
            out << " profileFields{c8=0x"
                << JniProbeHex(mem.Read32Guest(v82_profile_object + 0xc8u))
                << ",a0=0x"
                << JniProbeHex(mem.Read32Guest(v82_profile_object + 0xa0u))
                << ",a4=0x"
                << JniProbeHex(mem.Read32Guest(v82_profile_object + 0xa4u))
                << ",a8=0x"
                << JniProbeHex(mem.Read32Guest(v82_profile_object + 0xa8u))
                << "}";
        }
        return out.str();
    }

    void V82ObserveProfileState(const char* reason) {
        if (!V82Enabled() ||
            v82_profile_object == 0u ||
            mem.Ptr(v82_profile_object, 0xccu) == nullptr) {
            return;
        }

        const std::uint32_t c8 = mem.Read32Guest(v82_profile_object + 0xc8u);
        const std::uint32_t a0 = mem.Read32Guest(v82_profile_object + 0xa0u);
        const std::uint32_t a4 = mem.Read32Guest(v82_profile_object + 0xa4u);
        const std::uint32_t a8 = mem.Read32Guest(v82_profile_object + 0xa8u);

        const bool changed =
            !v82_profile_state_initialized ||
            c8 != v82_last_profile_c8 ||
            a0 != v82_last_profile_a0 ||
            a4 != v82_last_profile_a4 ||
            a8 != v82_last_profile_a8;

        if (!changed) return;

        ++v82_profile_state_changes;
        Append(
            std::string{"V82 PROFILE STATE #"} +
            std::to_string(v82_profile_state_changes) +
            " frame=" + std::to_string(current_frame_number) +
            " reason=" + (reason != nullptr ? reason : "?") +
            " c8=0x" + JniProbeHex(c8) +
            " a0=0x" + JniProbeHex(a0) +
            " a4=0x" + JniProbeHex(a4) +
            " a8=0x" + JniProbeHex(a8) +
            " " + V82TouchContext());

        v82_profile_state_initialized = true;
        v82_last_profile_c8 = c8;
        v82_last_profile_a0 = a0;
        v82_last_profile_a4 = a4;
        v82_last_profile_a8 = a8;
    }

    std::string V82RadarSummary() {
        std::ostringstream out;
        out << "V82 PROFILE RADAR SUMMARY mode=" << V56ModeName()
            << " profile=0x" << JniProbeHex(v82_profile_object)
            << " candidate5=0x" << JniProbeHex(v82_candidate5)
            << " candidate6=0x" << JniProbeHex(v82_candidate6)
            << " candidate7=0x" << JniProbeHex(v82_candidate7)
            << " candidateHits{5=" << v82_candidate5_hits
            << ",6pre=" << v82_candidate6_pre_hits
            << ",6post=" << v82_candidate6_post_hits
            << ",7=" << v82_candidate7_hits << "}"
            << " touches=" << v82_touch_serial
            << " radarLogs=" << v82_touch_radar_logs
            << " keyboardActions=" << v82_keyboard_correlations
            << " gameStateActions=" << v82_gamestate_correlations
            << " profileStateChanges=" << v82_profile_state_changes
            << " last=" << V82TouchContext()
            << " " << V82RadarSnapshot(v82_last_touch_x, v82_last_touch_y);
        return out.str();
    }

    const char* V83StaticCase(std::uint32_t id) const {
        switch (id) {
        case 5u: return "id5->0x1030b958";
        case 6u: return "id6->0x1030ba88";
        case 7u: return "id7->0x1030bbc4";
        case 8u: return "id8->0x1030be34";
        case 18u: return "id18->0x1030bf40";
        case 19u: return "id19->0x1030bf60";
        case 20u: return "id20->0x1030bf80";
        default:
            if (id >= 9u && id <= 17u) {
                return "id9-17->common-return";
            }
            return "outside-switch/default";
        }
    }

    std::string V83ButtonSummary() const {
        std::ostringstream out;
        out << "V83 BUTTON DISPATCH SUMMARY"
            << " total=" << v83_button_dispatch_calls
            << " hits{5=" << v83_button_id_hits[5]
            << ",6=" << v83_button_id_hits[6]
            << ",7=" << v83_button_id_hits[7]
            << ",8=" << v83_button_id_hits[8]
            << ",18=" << v83_button_id_hits[18]
            << ",19=" << v83_button_id_hits[19]
            << ",20=" << v83_button_id_hits[20]
            << "} last{id=" << v83_last_button_id
            << ",this=0x" << JniProbeHex(v83_last_button_this)
            << ",frame=" << v83_last_button_frame
            << ",lr=0x" << JniProbeHex(v83_last_button_lr)
            << ",case=" << V83StaticCase(v83_last_button_id)
            << "} " << V82TouchContext();
        return out.str();
    }

    bool V81Enabled() const {
        // Only v81/v82 actually deliver logical 1024x768 touch coordinates.
        // v83 keeps the tracing but returns to the v80 2048x1536 pixel control.
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V81HitTestLogicalPoints ||
            diagnostic_mode ==
                PvZ2DiagnosticMode::V82ProfileLayoutRadar;
    }

    bool V80Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V80GlobalTransformProbe ||
            V81Enabled() ||
            V83Enabled();
    }

    bool V77Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V77LegacyIpadGeometry ||
            V80Enabled() ||
            V85PerformanceEnabled();
    }

    bool V76Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V76IosScaleContract;
    }

    bool V75Enabled() const {
        // v110 Android is the clean no-remap control. V85+ inheritance still
        // supplies the validated runtime below this point.
        if (V110AndroidUiControlEnabled()) return false;
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V75IpadUiPackage ||
            V76Enabled() ||
            V77Enabled();
    }

    bool V74Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V74RetinaInputPolish ||
            V110AndroidUiControlEnabled() ||
            V75Enabled();
    }

    bool V73Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V73KeyboardFullscreenBridge ||
            V74Enabled();
    }

    bool V72Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V72LiveTouchBridge ||
            V73Enabled();
    }

    bool V71Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V71Etc1TextureBridge ||
            V72Enabled();
    }

    bool V70Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V70ZlibStreamOwnership ||
            V71Enabled();
    }

    bool V69Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V69TaskResourceLifecycle ||
            V70Enabled();
    }

    bool V68Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V68CompletionTokenSemantics ||
            V69Enabled();
    }

    bool V67Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V67CompletionTokenProvenance;
    }

    bool V66Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V66BlockingWaitScheduler ||
            V67Enabled() ||
            V68Enabled();
    }

    bool V65Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V65ConditionVariableScheduler ||
            V66Enabled();
    }

    bool V64Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V64ReleaseBoundaryScheduler ||
            V65Enabled();
    }

    bool V63Enabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::V63CriticalSectionScheduler ||
            V64Enabled();
    }

    bool V62Enabled() const {
        return diagnostic_mode == PvZ2DiagnosticMode::V62TaskProvenanceControlA ||
               diagnostic_mode == PvZ2DiagnosticMode::V62PumpMutexCoherentB;
    }

    bool V62MutexCoherentEnabled() const {
        return diagnostic_mode == PvZ2DiagnosticMode::V62PumpMutexCoherentB;
    }

    bool V57CtypeEnabled() const {
        return
            diagnostic_mode == PvZ2DiagnosticMode::CtypeCompatNativePath ||
            diagnostic_mode == PvZ2DiagnosticMode::CtypeCompatDeepScout ||
            V62Enabled() ||
            V63Enabled();
    }

    bool V57DeepScoutEnabled() const {
        return diagnostic_mode == PvZ2DiagnosticMode::CtypeCompatDeepScout;
    }

    bool V56ScoutEnabled() const {
        return
            diagnostic_mode == PvZ2DiagnosticMode::GateAScout ||
            diagnostic_mode == PvZ2DiagnosticMode::FullMatrix ||
            diagnostic_mode == PvZ2DiagnosticMode::CtypeCompatDeepScout;
    }

    bool V56FullMatrixEnabled() const {
        return
            diagnostic_mode == PvZ2DiagnosticMode::FullMatrix ||
            diagnostic_mode == PvZ2DiagnosticMode::CtypeCompatDeepScout;
    }

    bool V56IsTargetLookupKey(
