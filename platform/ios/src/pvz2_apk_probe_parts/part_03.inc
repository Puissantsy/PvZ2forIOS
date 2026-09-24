        const std::string& key) const {

        static constexpr std::array<const char*, 7>
            kTargets = {
                "AlwaysLoaded",
                "DelayLoad_Dialog",
                "UIImages",
                "RenderEffects",
                "StartupMusic",
                "UI_MainMenu",
                "MainMenu_Background"};

        return std::find(
                   kTargets.begin(),
                   kTargets.end(),
                   key) !=
            kTargets.end();
    }

    std::string V56RegistrySnapshot(
        const std::string& label) {

        std::ostringstream out;
        out
            << label
            << " manager=0x"
            << JniProbeHex(
                   v56_resource_manager);

        if (v56_resource_manager == 0u ||
            mem.Ptr(
                v56_resource_manager +
                    0x28u,
                16u) == nullptr) {
            out << " tables=UNAVAILABLE";
            return out.str();
        }

        v56_table28_root =
            mem.Read32Guest(
                v56_resource_manager +
                0x28u);
        v56_table28_count =
            mem.Read32Guest(
                v56_resource_manager +
                0x2cu);
        v56_table30_root =
            mem.Read32Guest(
                v56_resource_manager +
                0x30u);
        v56_table30_count =
            mem.Read32Guest(
                v56_resource_manager +
                0x34u);

        out
            << " table28{root=0x"
            << JniProbeHex(
                   v56_table28_root)
            << ",count="
            << v56_table28_count
            << "} table30{root=0x"
            << JniProbeHex(
                   v56_table30_root)
            << ",count="
            << v56_table30_count
            << "}";

        v56_last_registry_snapshot =
            out.str();
        return out.str();
    }

    void V56AppendRegistrySnapshot(
        const std::string& label) {

        Append(
            "V56 REGISTRY DIAGNOSIS " +
            V56RegistrySnapshot(label));
    }

    void V56ObserveRegistryWrite(
        std::uint32_t address,
        std::uint32_t width,
        std::uint64_t old_value,
        std::uint64_t new_value) {

        if (v56_resource_manager == 0u ||
            old_value == new_value) {
            return;
        }

        const std::uint32_t start =
            v56_resource_manager +
            0x28u;
        const std::uint32_t end =
            v56_resource_manager +
            0x38u;

        const std::uint64_t write_start =
            address;
        const std::uint64_t write_end =
            write_start +
            width;

        if (write_end <= start ||
            write_start >= end) {
            return;
        }

        ++v56_registry_write_events;

        if (write_start < 
                v56_resource_manager +
                    0x30u &&
            write_end >
                v56_resource_manager +
                    0x28u) {
            ++v56_table28_write_events;
        }

        if (write_start <
                v56_resource_manager +
                    0x38u &&
            write_end >
                v56_resource_manager +
                    0x30u) {
            ++v56_table30_write_events;
        }

        const std::uint32_t pc =
            jit != nullptr
                ? jit->Regs()[15]
                : 0u;
        const std::uint32_t lr =
            jit != nullptr
                ? jit->Regs()[14]
                : 0u;

        std::ostringstream line;
        line
            << "V56 REGISTRY WRITE #"
            << v56_registry_write_events
            << " address=0x"
            << JniProbeHex(address)
            << " width="
            << width
            << " old=0x"
            << std::hex
            << old_value
            << " new=0x"
            << new_value
            << std::dec
            << " pc="
            << V46DescribeGuestAddress(pc)
            << " lr="
            << V46DescribeGuestAddress(lr);

        Append(line.str());

        V56AppendRegistrySnapshot(
            "after-write");
    }

    bool V56GateAProofReady() const {
        if (v54_gate_a_result_hits < 1u ||
            v55_contribution_total != 0u) {
            return false;
        }

        for (const auto& stat :
             v55_group_stats) {
            // A Scout proof must still represent the exact v55 failure
            // class: every observed lookup for every startup group missed.
            // A single natural FOUND invalidates the bypass condition.
            if (stat.lookup_hits == 0u ||
                stat.lookup_misses !=
                    stat.lookup_hits) {
                return false;
            }
        }

        return true;
    }

    void V56RecordTrieResult(
        const V56TrieContext& context,
        bool found,
        std::uint32_t result_pointer) {

        if (!context.relevant) {
            return;
        }

        auto& stat =
            v56_target_lookups[
                context.key];

        ++stat.calls;
        if (found) {
            ++stat.found;
        } else {
            ++stat.misses;
        }
        stat.last_table =
            context.table;
        stat.last_caller =
            context.caller_lr;

        const char* table_kind =
            context.table ==
                v56_resource_manager +
                    0x28u
                ? "manager+0x28"
                : context.table ==
                      v56_resource_manager +
                          0x30u
                    ? "manager+0x30"
                    : "other";

        Append(
            "V56 TARGET LOOKUP key=\"" +
            context.key +
            "\" table=" +
            table_kind +
            "@0x" +
            JniProbeHex(
                context.table) +
            " result=" +
            (found
                ? "FOUND@0x" +
                      JniProbeHex(
                          result_pointer)
                : std::string{"MISS"}) +
            " caller=" +
            V46DescribeGuestAddress(
                context.caller_lr));

        if (context.trace_path) {
            Append(
                "V57 TRIE PATH END key=\"" +
                context.key +
                "\" table=" +
                V57TrieTableLabel(
                    context.table) +
                " result=" +
                (found
                    ? "FOUND"
                    : "MISS") +
                " steps=" +
                std::to_string(
                    context.trace_steps));
        }
    }

    std::string V56DiagnosticMatrixSummary() {
        V56RegistrySnapshot(
            "final");

        std::ostringstream out;
        out
            << "V56 DiagnosticMatrix"
            << " mode="
            << V56ModeName()
            << " pipeline{calls="
            << v56_registry_pipeline_calls
            << ",returns="
            << v56_registry_pipeline_returns
            << ",lastResult="
            << v56_pipeline_last_result
            << ",src28=0x"
            << JniProbeHex(
                   v56_source28_ptr)
            << ",src28Bytes="
            << v56_source28_bytes
            << ",src28Count="
            << (v56_source28_bytes /
                4u)
            << ",src30=0x"
            << JniProbeHex(
                   v56_source30_ptr)
            << ",src30Bytes="
            << v56_source30_bytes
            << ",src30Count="
            << (v56_source30_bytes /
                4u)
            << "}"
            << " registry{manager=0x"
            << JniProbeHex(
                   v56_resource_manager)
            << ",table28Root=0x"
            << JniProbeHex(
                   v56_table28_root)
            << ",table28Count="
            << v56_table28_count
            << ",table30Root=0x"
            << JniProbeHex(
                   v56_table30_root)
            << ",table30Count="
            << v56_table30_count
            << ",writes="
            << v56_registry_write_events
            << ",writes28="
            << v56_table28_write_events
            << ",writes30="
            << v56_table30_write_events
            << "}"
            << " scout{enabled="
            << (V56ScoutEnabled()
                    ? "YES"
                    : "NO")
            << ",activated="
            << (v56_gate_a_scout_activated
                    ? "YES"
                    : "NO")
            << ",forcedHits="
            << v56_gate_a_forced_hits
            << ",activationFrame="
            << v56_gate_a_activation_frame
            << "}"
            << " downstream{state="
            << V53CurrentGameState()
            << ",requests="
            << v53_state_request_calls
            << ",applies="
            << v53_state_apply_calls
            << "}";

        for (const auto& pair :
             v56_target_lookups) {
            out
                << " | "
                << pair.first
                << "{calls="
                << pair.second.calls
                << ",found="
                << pair.second.found
                << ",misses="
                << pair.second.misses
                << ",lastTable=0x"
                << JniProbeHex(
                       pair.second.last_table)
                << ",caller=0x"
                << JniProbeHex(
                       pair.second.last_caller)
                << "}";
        }

        out << " | diagnosis=";

        if (v56_registry_pipeline_calls == 0u) {
            out
                << "REGISTRY_PIPELINE_NEVER_EXECUTED";
        } else if (
            v56_source28_bytes == 0u &&
            v56_source30_bytes == 0u) {
            out
                << "PIPELINE_EXECUTED_WITH_EMPTY_SOURCE_TABLES";
        } else if (
            v56_table28_count == 0u &&
            v56_table30_count == 0u) {
            out
                << "SOURCE_NONEMPTY_BUT_MANAGER_TABLES_EMPTY";
        } else if (
            v55_contribution_total == 0u) {
            out
                << "MANAGER_TABLES_PRESENT_BUT_STARTUP_KEYS_MISS";
        } else {
            out
                << "STARTUP_GROUP_LOOKUP_PROGRESS_OBSERVED";
        }

        return out.str();
    }

    bool V57IsPathTraceKey(
        const std::string& key) const {

        return
            key == "AlwaysLoaded" ||
            key == "UIImages" ||
            key == "UI_MainMenu" ||
            key == "MainMenu_Background";
    }

    std::string V57TrieTableLabel(
        std::uint32_t table) const {

        if (v56_resource_manager != 0u &&
            table ==
                v56_resource_manager +
                    0x28u) {
            return "manager+0x28";
        }

        if (v56_resource_manager != 0u &&
            table ==
                v56_resource_manager +
                    0x30u) {
            return "manager+0x30";
        }

        return "other@0x" +
            JniProbeHex(table);
    }

    bool V57LogCtypeSelfCheck() {
        if (!V57CtypeEnabled()) {
            return false;
        }

        auto read_short =
            [&](std::uint32_t backing,
                unsigned char ch) {
                return
                    mem.Read16Guest(
                        backing +
                        static_cast<std::uint32_t>(
                            (static_cast<unsigned>(
                                 ch) +
                             1u) *
                            2u));
            };

        auto read_ctype =
            [&](unsigned char ch) {
                return
                    mem.Read8(
                        v57_ctype_backing +
                        static_cast<std::uint32_t>(
                            static_cast<unsigned>(
                                ch) +
                            1u));
            };

        const std::uint32_t toupper_got =
            mem.Read32Guest(
                kV57ToupperGotGuest);
        const std::uint32_t tolower_got =
            mem.Read32Guest(
                kV57TolowerGotGuest);
        const std::uint32_t ctype_got =
            mem.Read32Guest(
                kV57CtypeGotGuest);

        const std::uint32_t toupper_backing =
            toupper_got != 0u
                ? mem.Read32Guest(
                      toupper_got)
                : 0u;
        const std::uint32_t tolower_backing =
            tolower_got != 0u
                ? mem.Read32Guest(
                      tolower_got)
                : 0u;
        const std::uint32_t ctype_backing =
            ctype_got != 0u
                ? mem.Read32Guest(
                      ctype_got)
                : 0u;

        constexpr std::uint8_t kUpper = 0x01u;
        constexpr std::uint8_t kLower = 0x02u;
        constexpr std::uint8_t kNumber = 0x04u;
        constexpr std::uint8_t kSpace = 0x08u;
        constexpr std::uint8_t kPunct = 0x10u;
        constexpr std::uint8_t kControl = 0x20u;
        constexpr std::uint8_t kHex = 0x40u;
        constexpr std::uint8_t kBlank = 0x80u;

        const bool addresses_ok =
            toupper_got ==
                v57_toupper_variable &&
            tolower_got ==
                v57_tolower_variable &&
            ctype_got ==
                v57_ctype_variable &&
            toupper_backing ==
                v57_toupper_backing &&
            tolower_backing ==
                v57_tolower_backing &&
            ctype_backing ==
                v57_ctype_backing &&
            toupper_backing != 0u &&
            tolower_backing != 0u &&
            ctype_backing != 0u;

        const bool samples_ok =
            read_short(
                toupper_backing,
                'a') == 'A' &&
            read_short(
                toupper_backing,
                'A') == 'A' &&
            read_short(
                toupper_backing,
                'd') == 'D' &&
            read_short(
                toupper_backing,
                'i') == 'I' &&
            read_short(
                toupper_backing,
                'r') == 'R' &&
            read_short(
                toupper_backing,
                'u') == 'U' &&
            read_short(
                toupper_backing,
                '_') == '_' &&
            read_short(
                toupper_backing,
                '0') == '0' &&
            read_short(
                toupper_backing,
                '9') == '9' &&
            read_short(
                tolower_backing,
                'A') == 'a' &&
            read_short(
                tolower_backing,
                'a') == 'a' &&
            (read_ctype('A') &
                (kUpper | kHex)) ==
                (kUpper | kHex) &&
            (read_ctype('a') &
                (kLower | kHex)) ==
                (kLower | kHex) &&
            (read_ctype('0') &
                (kNumber | kHex)) ==
                (kNumber | kHex) &&
            (read_ctype(' ') &
                (kSpace | kBlank)) ==
                (kSpace | kBlank) &&
            (read_ctype('\t') &
                (kControl | kSpace | kBlank)) ==
                (kControl | kSpace) &&
            read_ctype(0x80u) ==
                kControl &&
            read_ctype(0xa0u) ==
                kPunct;

        v57_ctype_self_check_passed =
            addresses_ok &&
            samples_ok;

        if (!v57_ctype_self_check_logged) {
            v57_ctype_self_check_logged =
                true;

            std::ostringstream line;
            line
                << "V57 CTYPE ABI selfCheck="
                << (v57_ctype_self_check_passed
                        ? "PASS"
                        : "FAIL")
                << " toupper{GOT=0x"
                << JniProbeHex(
                       kV57ToupperGotGuest)
                << ",variable=0x"
                << JniProbeHex(
                       toupper_got)
                << ",backing=0x"
                << JniProbeHex(
                       toupper_backing)
                << ",a->"
                << static_cast<char>(
                       read_short(
                           toupper_backing,
                           'a'))
                << ",A->"
                << static_cast<char>(
                       read_short(
                           toupper_backing,
                           'A'))
                << ",_->"
                << static_cast<char>(
                       read_short(
                           toupper_backing,
                           '_'))
                << ",0->"
                << static_cast<char>(
                       read_short(
                           toupper_backing,
                           '0'))
                << "} tolower{GOT=0x"
                << JniProbeHex(
                       kV57TolowerGotGuest)
                << ",variable=0x"
                << JniProbeHex(
                       tolower_got)
                << ",backing=0x"
                << JniProbeHex(
                       tolower_backing)
                << ",A->"
                << static_cast<char>(
                       read_short(
                           tolower_backing,
                           'A'))
                << "} ctype{GOT=0x"
                << JniProbeHex(
                       kV57CtypeGotGuest)
                << ",variable=0x"
                << JniProbeHex(
                       ctype_got)
                << ",backing=0x"
                << JniProbeHex(
                       ctype_backing)
                << ",A=0x"
                << JniProbeHex(
                       read_ctype('A'))
                << ",a=0x"
                << JniProbeHex(
                       read_ctype('a'))
                << ",0=0x"
                << JniProbeHex(
                       read_ctype('0'))
                << ",space=0x"
                << JniProbeHex(
                       read_ctype(' '))
                << ",tab=0x"
                << JniProbeHex(
                       read_ctype('\t'))
                << ",80=0x"
                << JniProbeHex(
                       read_ctype(0x80u))
                << ",a0=0x"
                << JniProbeHex(
                       read_ctype(0xa0u))
                << "}";

            Append(line.str());
        }

        return v57_ctype_self_check_passed;
    }

    void V57ObserveGateCWrite(
        std::uint32_t address,
        std::uint32_t width,
        std::uint64_t old_value,
        std::uint64_t new_value) {

        if (v57_gate_c_last_object == 0u ||
            old_value == new_value) {
            return;
        }

        const std::uint32_t target =
            v57_gate_c_last_object +
            0x98u;

        const std::uint64_t write_start =
            address;
        const std::uint64_t write_end =
            write_start +
            width;

        if (write_end <= target ||
            write_start >=
                static_cast<std::uint64_t>(
                    target) +
                    4u) {
            return;
        }

        ++v57_gate_c_write_events;

        const std::uint32_t pc =
            jit != nullptr
                ? jit->Regs()[15]
                : 0u;
        const std::uint32_t lr =
            jit != nullptr
                ? jit->Regs()[14]
                : 0u;
        const std::uint32_t state_now =
            mem.Read32Guest(target);

        std::ostringstream line;
        line
            << "V57 GATEC WRITE #"
            << v57_gate_c_write_events
            << " object=0x"
            << JniProbeHex(
                   v57_gate_c_last_object)
            << " address=0x"
            << JniProbeHex(address)
            << " width="
            << width
            << " old=0x"
            << std::hex
            << old_value
            << " new=0x"
            << new_value
            << std::dec
            << " state98="
            << state_now
            << " pc="
            << V46DescribeGuestAddress(pc)
            << " lr="
            << V46DescribeGuestAddress(lr)
            << " frame="
            << current_frame_number
            << " tid="
            << current_probe_thread_id
            << " lifecycle=\""
            << current_lifecycle_name
            << "\" snapshot80_B0=[";

        for (std::uint32_t offset =
                 0x80u;
             offset <= 0xb0u;
             offset += 4u) {
            if (offset != 0x80u) {
                line << ",";
            }

            line
                << "+0x"
                << std::hex
                << offset
                << "=0x"
                << mem.Read32Guest(
                       v57_gate_c_last_object +
                       offset)
                << std::dec;
        }

        line << "]";
        Append(line.str());
    }

    void V57TraceTrieStep(
        V56TrieContext& context,
        std::uint32_t raw,
        std::uint32_t normalized,
        std::uint32_t node_word,
        std::uint32_t node_pointer) {

        if (!context.trace_path) {
            return;
        }

        const std::uint32_t node_byte =
            node_word &
            0xffu;
        const std::uint32_t position =
            jit != nullptr &&
                    jit->Regs()[1] >=
                        context.key_start
                ? jit->Regs()[1] -
                      context.key_start
                : 0xffffffffu;

        const char* relation =
            node_byte == normalized
                ? "EQUAL"
                : node_byte > normalized
                    ? "NODE_HIGHER"
                    : "NODE_LOWER";

        ++context.trace_steps;

        std::ostringstream line;
        line
            << "V57 TRIE PATH key=\""
            << context.key
            << "\" table="
            << V57TrieTableLabel(
                   context.table)
            << " step="
            << context.trace_steps
            << " pos="
            << position
            << " raw=0x"
            << JniProbeHex(raw)
            << " normalized=0x"
            << JniProbeHex(normalized)
            << " nodeByte=0x"
            << JniProbeHex(node_byte)
            << " nodeWord=0x"
            << JniProbeHex(node_word)
            << " nodePtr=0x"
            << JniProbeHex(node_pointer)
            << " nextIndex="
            << (node_word >> 8u)
            << " relation="
            << relation;

        Append(line.str());
    }

    std::string V57EffectiveDepth() const {
        if (v54_mainmenu_marker_hits != 0u) {
            return "MAINMENU_REQUEST_PATH";
        }
        if (v54_patch_marker_hits != 0u) {
            return "PATCH_REQUEST_PATH";
        }
        if (v54_gate_j_hits != 0u) {
            return "GATE_J";
        }
        if (v54_gate_i_hits != 0u) {
            return "GATE_I";
        }
        if (v54_gate_h_hits != 0u) {
            return "GATE_H";
        }
        if (v54_gate_g_hits != 0u) {
            return "GATE_G";
        }
        if (v54_gate_f_hits != 0u) {
            return "GATE_F";
        }
        if (v54_gate_e_hits != 0u) {
            return "GATE_E";
        }
        if (v54_after_d_hits != 0u) {
            return "AFTER_D";
        }
        if (v54_gate_d_hits != 0u) {
            return "GATE_D";
        }
        if (v54_gate_c_hits != 0u) {
            return "GATE_C";
        }
        if (v54_gate_a_result_hits != 0u) {
            return "GATE_A";
        }
        return "NONE";
    }

    std::string V57NaturalDepth() const {
        if (v57_gate_a_natural_pass_hits == 0u) {
            return
                v54_gate_a_result_hits != 0u
                    ? "GATE_A_BLOCK"
                    : "NONE";
        }

        if (v54_gate_c_hits != 0u &&
            v57_gate_c_native_pass_hits == 0u) {
            return "GATE_C_BLOCK";
        }

        if (!v56_gate_a_scout_activated &&
            !v57_gate_c_scout_activated) {
            return V57EffectiveDepth();
        }

        if (v57_gate_c_scout_activated) {
            return "GATE_C_BLOCK";
        }

        return "GATE_A_BLOCK";
    }

    std::string V57CtypeDeepScoutSummary() {
        float gate_a_ratio = 0.0f;
        std::memcpy(
            &gate_a_ratio,
            &v54_gate_a_result_bits,
            sizeof(gate_a_ratio));

        std::uint64_t selected_found = 0u;
        std::uint64_t selected_misses = 0u;

        for (const auto& pair :
             v56_target_lookups) {
            selected_found +=
                pair.second.found;
            selected_misses +=
                pair.second.misses;
        }

        std::ostringstream out;
        out
            << "V57 CtypeDeepScout"
            << " mode="
            << V56ModeName()
            << " ctype{enabled="
            << (V57CtypeEnabled()
                    ? "YES"
                    : "NO")
            << ",selfCheck="
            << (v57_ctype_self_check_passed
                    ? "PASS"
                    : V57CtypeEnabled()
                        ? "FAIL"
                        : "DISABLED")
            << ",toupperVar=0x"
            << JniProbeHex(
                   v57_toupper_variable)
            << ",toupperBacking=0x"
            << JniProbeHex(
                   v57_toupper_backing)
            << "}"
            << " lookups{found="
            << selected_found
            << ",misses="
            << selected_misses
            << "}"
            << " gateA{nativePassHits="
            << v57_gate_a_natural_pass_hits
            << ",lastRatio="
            << gate_a_ratio
            << ",scoutUsed="
            << (v56_gate_a_scout_activated
                    ? "YES"
                    : "NO")
            << "}"
            << " gateC{hits="
            << v57_gate_c_native_hits
            << ",object=0x"
            << JniProbeHex(
                   v57_gate_c_last_object)
            << ",nativeState="
            << v57_gate_c_last_native_state
            << ",nativePassHits="
            << v57_gate_c_native_pass_hits
            << ",writes="
            << v57_gate_c_write_events
            << ",scoutUsed="
            << (v57_gate_c_scout_activated
                    ? "YES"
                    : "NO")
            << ",forcedHits="
            << v57_gate_c_forced_hits
            << "}"
            << " deepestNatural="
            << V57NaturalDepth()
            << " deepestEffective="
            << V57EffectiveDepth()
            << " GameState="
            << V53CurrentGameState()
            << " requests="
            << v53_state_request_calls
            << " applies="
            << v53_state_apply_calls
            << " patchMarker="
            << v54_patch_marker_hits
            << " mainMenuMarker="
            << v54_mainmenu_marker_hits;

        return out.str();
    }

    void V52ObserveJniCallsite(
        const std::string& method_name) {

        if (V85PerformanceEnabled() ||
            current_frame_number < 75u ||
            jit == nullptr) {
            return;
        }

        const std::uint32_t lr =
            jit->Regs()[14];
        const std::uint32_t sp =
            jit->Regs()[13];

        const std::string key =
            method_name +
            "@0x" +
            JniProbeHex(lr);

        ++v52_post_ea_jni_callsites[key];

        const bool high_value =
            method_name == "GetNetworkStatus" ||
            method_name == "UI_ProcessEvents" ||
            method_name == "Graphics_GetGLViewSysFBO";

        if (!high_value ||
            !v52_stack_dumped_callsites
                 .insert(key)
                 .second) {
            return;
        }

        Append(
            "V52 POST-EA JNI CALLSITE frame=" +
            std::to_string(
                current_frame_number) +
            " method=" +
            method_name +
            " LR=" +
            V46DescribeGuestAddress(lr) +
            " SP=" +
            V46DescribeGuestAddress(sp));

        std::unordered_set<std::uint32_t>
            seen;
        std::uint32_t emitted = 0u;

        for (std::uint32_t offset = 0u;
             offset < 0x180u &&
             emitted < 16u;
             offset += 4u) {

            const std::uint32_t candidate =
                mem.Read32Guest(
                    sp + offset);
            const std::uint32_t plain =
                candidate & ~1u;

            if (plain < kGuestBase ||
                static_cast<std::uint64_t>(
                    plain) >=
                    static_cast<std::uint64_t>(
                        kGuestBase) +
                    mem.image.size() ||
                !seen.insert(plain).second) {
                continue;
            }

            Append(
                "V52 STACK CODE method=" +
                method_name +
                " sp+0x" +
                JniProbeHex(offset) +
                " -> " +
                V46DescribeGuestAddress(
                    candidate));

            ++emitted;
        }
    }

    void V52CaptureStateGraph(
        std::uint32_t frame) {

        // Native_onDrawFrame (APK offset 0x009f190c) resolves the
        // AndroidAppDriver* through this exact global for 1.5.252752.
        constexpr std::uint32_t
            kAndroidDriverGlobal =
                kGuestBase +
                0x00dc8fd4u;

        const std::uint32_t driver =
            mem.Read32Guest(
                kAndroidDriverGlobal);

        if (driver == 0u ||
            mem.Ptr(driver, 0x50u) ==
                nullptr) {
            Append(
                "V52 STATEGRAPH frame=" +
                std::to_string(frame) +
                " driverGlobal=" +
                V46DescribeGuestAddress(
                    kAndroidDriverGlobal) +
                " driver=invalid");
            return;
        }

        const std::uint32_t app =
            mem.Read32Guest(
                driver + 0x44u);

        if (app == 0u ||
            mem.Ptr(app, 4u) ==
                nullptr) {
            Append(
                "V52 STATEGRAPH frame=" +
                std::to_string(frame) +
                " driver=" +
                V46DescribeGuestAddress(
                    driver) +
                " app=invalid");
            return;
        }

        const std::uint32_t app_vtable =
            mem.Read32Guest(app);

        if (driver != v52_last_driver ||
            app != v52_last_app ||
            app_vtable !=
                v52_last_app_vtable) {

            v52_last_driver = driver;
            v52_last_app = app;
            v52_last_app_vtable =
                app_vtable;

            Append(
                "V52 OBJECT ROOT frame=" +
                std::to_string(frame) +
                " global=" +
                V46DescribeGuestAddress(
                    kAndroidDriverGlobal) +
                " driver=" +
                V46DescribeGuestAddress(
                    driver) +
                " app=" +
                V46DescribeGuestAddress(
                    app) +
                " appVtable=" +
                V46DescribeGuestAddress(
                    app_vtable));

            if (app_vtable >= kGuestBase &&
                static_cast<std::uint64_t>(
                    app_vtable) +
                        32u * 4u <=
                    static_cast<std::uint64_t>(
                        kGuestBase) +
                    mem.image.size()) {

                for (std::uint32_t i = 0u;
                     i < 32u;
                     ++i) {

                    const std::uint32_t target =
                        mem.Read32Guest(
                            app_vtable +
                            i * 4u);

                    if (target >= kGuestBase &&
                        static_cast<std::uint64_t>(
                            target & ~1u) <
                            static_cast<std::uint64_t>(
                                kGuestBase) +
                            mem.image.size()) {

                        Append(
                            "V52 APP VTABLE[" +
                            std::to_string(i) +
                            "]=" +
                            V46DescribeGuestAddress(
                                target));
                    }
                }
            }
        }

        struct Node {
            std::uint32_t address = 0u;
            std::uint32_t depth = 0u;
        };

        std::vector<Node> nodes;
        nodes.push_back(
            Node{app, 0u});

        std::unordered_set<std::uint32_t>
            visited;
        visited.insert(app);

        std::unordered_map<
            std::uint64_t,
            std::uint32_t>
            current_small_fields;

        for (std::size_t ni = 0u;
             ni < nodes.size() &&
             ni < 48u;
             ++ni) {

            const Node node =
                nodes[ni];

            const std::uint32_t bytes =
                node.depth == 0u
                    ? 0x800u
                    : 0x180u;

            if (mem.Ptr(
                    node.address,
                    bytes) == nullptr) {
                continue;
            }

            const std::uint32_t vtable =
                mem.Read32Guest(
                    node.address);

            for (std::uint32_t offset = 4u;
                 offset < bytes;
                 offset += 4u) {

                const std::uint32_t value =
                    mem.Read32Guest(
                        node.address +
                        offset);

                if (value <= 12u) {
                    const std::uint64_t key =
                        (static_cast<
                             std::uint64_t>(
                             node.address)
                         << 32u) |
                        offset;

                    current_small_fields[
                        key] =
                        value;
                }

                if (node.depth >= 2u ||
                    value <
                        kJniProbeHeapBase ||
                    static_cast<
                        std::uint64_t>(
                        value) >=
                        static_cast<
                            std::uint64_t>(
                            kJniProbeHeapBase) +
                        mem.HeapCapacity() ||
                    visited.size() >= 48u ||
                    mem.Ptr(value, 4u) ==
                        nullptr) {
                    continue;
                }

                const std::uint32_t child_vtable =
                    mem.Read32Guest(value);
                const std::uint32_t child_plain =
                    child_vtable & ~1u;

                if (child_plain <
                        kGuestBase ||
                    static_cast<
                        std::uint64_t>(
                        child_plain) >=
                        static_cast<
                            std::uint64_t>(
                            kGuestBase) +
                        mem.image.size() ||
                    !visited.insert(value)
                         .second) {
                    continue;
                }

                nodes.push_back(
                    Node{
                        value,
                        node.depth + 1u});
            }

            if (frame == 1u &&
                ni < 24u) {
                Append(
                    "V52 OBJECT node=" +
                    V46DescribeGuestAddress(
                        node.address) +
                    " depth=" +
                    std::to_string(
                        node.depth) +
                    " vtable=" +
                    V46DescribeGuestAddress(
                        vtable));
            }
        }

        std::uint32_t emitted = 0u;

        for (const auto& entry :
             current_small_fields) {

            const auto previous =
                v52_previous_small_fields
                    .find(entry.first);

            if (previous ==
                    v52_previous_small_fields
                        .end() ||
                previous->second ==
                    entry.second) {
                continue;
            }

            const std::uint32_t object =
                static_cast<std::uint32_t>(
                    entry.first >> 32u);
            const std::uint32_t offset =
                static_cast<std::uint32_t>(
                    entry.first);
            const std::uint32_t vtable =
                mem.Read32Guest(object);

            if (v52_state_field_events
                    .size() < 2048u) {
                v52_state_field_events.push_back(
                    V52StateFieldEvent{
                        frame,
                        object,
                        vtable,
                        offset,
                        previous->second,
                        entry.second});
            }

            if (frame >= 55u &&
                frame <= 90u &&
                emitted < 48u) {

                Append(
                    "V52 STATE-LIKE CHANGE frame=" +
                    std::to_string(frame) +
                    " object=" +
                    V46DescribeGuestAddress(
                        object) +
                    " vtable=" +
                    V46DescribeGuestAddress(
                        vtable) +
                    " +0x" +
                    JniProbeHex(offset) +
                    " " +
                    std::to_string(
                        previous->second) +
                    "->" +
                    std::to_string(
                        entry.second));

                ++emitted;
            }
        }

        v52_previous_small_fields =
            std::move(
                current_small_fields);

        Append(
            "V52 STATEGRAPH frame=" +
            std::to_string(frame) +
            " reachableObjects=" +
            std::to_string(
                visited.size()) +
            " smallFields=" +
            std::to_string(
                v52_previous_small_fields
                    .size()) +
            " totalChanges=" +
            std::to_string(
                v52_state_field_events
                    .size()));
    }

    void V52FinalizeDiagnostics() {
        std::ostringstream summary;

        summary
            << "V52 root driver=0x"
            << JniProbeHex(
                   v52_last_driver)
            << " app=0x"
            << JniProbeHex(
                   v52_last_app)
            << " vtable=0x"
            << JniProbeHex(
                   v52_last_app_vtable)
            << "; stateLikeChanges="
            << v52_state_field_events.size()
            << "; postEAJniCallsites="
            << v52_post_ea_jni_callsites
                   .size()
            << "; HTTP starts="
            << v52_http_starts
            << " deliveries="
            << v52_http_deliveries
            << "; JNI noisyCounters{IsSameObject="
            << v52_is_same_object_calls
            << ",UI_ProcessEvents="
            << v52_ui_process_events_calls
            << ",Graphics_GetGLViewSysFBO="
            << v52_graphics_fbo_calls
            << "}";

        result.diagnostic_summary =
            summary.str();

        Append(
            "V52 DIAGNOSTIC SUMMARY: " +
            result.diagnostic_summary);

        std::vector<
            std::pair<std::string,
                      std::uint64_t>>
            callsites(
                v52_post_ea_jni_callsites
                    .begin(),
                v52_post_ea_jni_callsites
                    .end());

        std::sort(
            callsites.begin(),
            callsites.end(),
            [](const auto& a,
               const auto& b) {
                return a.second >
                    b.second;
            });

        for (std::size_t i = 0u;
             i < callsites.size() &&
             i < 24u;
             ++i) {

            Append(
                "V52 POST-EA JNI TOP #" +
                std::to_string(i + 1u) +
                " calls=" +
                std::to_string(
                    callsites[i].second) +
                " " +
                callsites[i].first);
        }

        std::unordered_set<std::uint64_t>
            emitted_fields;
        std::uint32_t rank = 0u;

        for (const auto& event :
             v52_state_field_events) {

            if (event.frame < 55u ||
                event.frame > 90u ||
                event.before > 9u ||
                event.after > 9u) {
                continue;
            }

            const std::uint64_t key =
                (static_cast<
                     std::uint64_t>(
                     event.object)
                 << 32u) |
                event.offset;

            if (!emitted_fields
                    .insert(key)
                    .second ||
                rank >= 48u) {
                continue;
            }

            ++rank;

            Append(
                "V52 STATE CANDIDATE #" +
                std::to_string(rank) +
                " frame=" +
                std::to_string(
                    event.frame) +
                " object=" +
                V46DescribeGuestAddress(
                    event.object) +
                " vtable=" +
                V46DescribeGuestAddress(
                    event.vtable) +
                " +0x" +
                JniProbeHex(
                    event.offset) +
                " " +
                std::to_string(
                    event.before) +
                "->" +
                std::to_string(
                    event.after));
        }

        for (const auto& worker :
             deferred_threads) {

            Append(
                "V52 WORKER FINAL tid=" +
                std::to_string(
                    worker.id) +
                " created_in=" +
                worker.created_in +
                " start=" +
                V46DescribeGuestAddress(
                    worker.start_routine) +
                " PC=" +
                V46DescribeGuestAddress(
                    worker.regs[15]) +
                " ticks=" +
                std::to_string(
                    worker.runtime_ticks) +
                " started=" +
                (worker.runtime_started
                    ? std::string{"YES"}
                    : std::string{"NO"}) +
                " completed=" +
                (worker.runtime_completed
                    ? std::string{"YES"}
                    : std::string{"NO"}) +
                " failed=" +
                (worker.runtime_failed
                    ? std::string{"YES"}
                    : std::string{"NO"}));
        }
    }

    void RefreshSweepSummary() {
        result.sweep_issue_count =
            static_cast<std::uint32_t>(
                sweep_issues.size());
        result.sweep_recovery_count =
            sweep_recoveries;
        result.sweep_speculative =
            sweep_speculative;

        std::ostringstream summary;
        summary
            << "Bulk sweep: "
            << sweep_issues.size()
            << " unique issue(s), "
            << sweep_recoveries
            << " speculative recovery/recoveries";

        if (sweep_speculative) {
            summary
                << ". Issues observed after the first speculative recovery are candidates, not proof of real runtime failures.";
        }

        for (std::size_t i = 0;
             i < sweep_issues.size();
             ++i) {
            summary
                << "\n"
                << (i + 1u)
                << ". "
                << sweep_issues[i];
        }

        result.sweep_summary =
            summary.str();
    }

    void RecordSweepIssue(
        const std::string& kind,
        const std::string& key,
        const std::string& detail) {

        const std::string unique_key =
            kind + ":" + key;

        if (!sweep_issue_keys.insert(
                unique_key).second) {
            return;
        }

        const std::string line =
            std::string{
                sweep_speculative
                    ? "[speculative] "
                    : "[observed] "} +
            "[" + kind + "] " +
            detail;

        sweep_issues.push_back(line);

        Append(
            "V24 SWEEP ISSUE #" +
            std::to_string(
                sweep_issues.size()) +
            ": " +
            line);

        RefreshSweepSummary();
    }

    bool ConsumeSweepRecovery(
        const std::string& kind,
        const std::string& detail) {

        if (return_mode != ReturnMode::Lifecycle ||
            sweep_recoveries >=
                kSweepRecoveryLimit) {
            return false;
        }

        // Recovery quota is for distinct compatibility boundaries, not for
        // repeatedly returning from the same abort/null/import site. v24
        // burned all 48 recoveries on one abort loop; v25 only permits one
        // speculative bypass per unique site/detail.
        const std::string recovery_key =
            kind + ":" + detail;

        if (!sweep_recovery_keys.insert(
                recovery_key).second) {

            Append(
                "V25 SWEEP STOP: repeated speculative recovery site [" +
                kind +
                "] " +
                detail);

            return false;
        }

        ++sweep_recoveries;
        sweep_speculative = true;

        Append(
            "V25 SWEEP RECOVERY #" +
            std::to_string(
                sweep_recoveries) +
            " [" +
            kind +
            "]: " +
            detail);

        RefreshSweepSummary();
        return true;
    }

    bool V94WriteOverlapsWatch(
        std::uint32_t address,
        std::uint32_t width) const {

        if (!v94_watch_armed ||
            width == 0u) {
            return false;
        }

        const std::uint64_t begin = address;
        const std::uint64_t end =
            begin + width;
        const std::uint64_t slot_begin =
            v94_watch_slot;
        const std::uint64_t slot_end =
            slot_begin + 4u;

        return begin < slot_end &&
               end > slot_begin;
    }

    void V94ObserveGuestWrite(
        const char* kind,
        std::uint32_t address,
        std::uint32_t width,
        std::uint64_t raw_value,
        std::uint32_t watched_before,
        bool overlapped_before) {

        if (!overlapped_before ||
            !v94_watch_armed) {
            return;
        }

        const std::uint32_t watched_after =
            mem.Read32Guest(
                v94_watch_slot);

        if (watched_after ==
            watched_before) {
            return;
        }

        ++v94_watched_guest_writes;

        if (v94_first_change_seen) {
            return;
        }

        const std::uint32_t pc =
            jit ? jit->Regs()[15] : 0u;
        const std::uint32_t lr =
            jit ? jit->Regs()[14] : 0u;
        const std::uint32_t sp =
            jit ? jit->Regs()[13] : 0u;
        const std::uint32_t cpsr =
            jit ? jit->Cpsr() : 0u;

        v94_first_change_seen = true;
        v94_first_change_frame =
            current_frame_number;
        v94_first_change_slot =
            v94_watch_slot;
        v94_first_change_address =
            address;
        v94_first_change_width =
            width;
        v94_first_change_old =
            watched_before;
        v94_first_change_new =
            watched_after;
        v94_first_change_pc = pc;
        v94_first_change_lr = lr;
        v94_first_change_sp = sp;
        v94_first_change_cpsr = cpsr;
        v94_first_change_tid =
            current_probe_thread_id;
        v94_first_change_phase =
            V91PhaseName();

        AppendDiagnostic(
            std::string{RuntimeModeTag()} +
            " FIRST LR-SLOT CHANGE frame=" +
            std::to_string(
                current_frame_number) +
            " slot=0x" +
            JniProbeHex(
                v94_watch_slot) +
            " write=" +
            (kind != nullptr
                 ? std::string{kind}
                 : std::string{"?"}) +
            "@0x" +
            JniProbeHex(address) +
            " width=" +
            std::to_string(width) +
            " raw=0x" +
            JniProbeHex(
                static_cast<std::uint32_t>(
                    raw_value)) +
            " old=0x" +
            JniProbeHex(
                watched_before) +
            " new=0x" +
            JniProbeHex(
                watched_after) +
            " PC=0x" +
            JniProbeHex(pc) +
            " LR=0x" +
            JniProbeHex(lr) +
            " SP=0x" +
            JniProbeHex(sp) +
            " CPSR=0x" +
            JniProbeHex(cpsr) +
            " tid=" +
            std::to_string(
                current_probe_thread_id) +
            " phase=" +
            V91PhaseName());
    }

    void V94FinalizeSvcWatch(
        std::uint32_t swi,
        std::uint32_t slot,
        std::uint32_t watched_before) {

        if (!v94_watch_armed ||
            v94_watch_slot != slot) {
            return;
        }

        const std::uint32_t after =
            mem.Read32Guest(slot);
        if (after == watched_before) {
            return;
        }

        const std::string kind =
            "SVC-0x" + JniProbeHex(swi);
        V94ObserveGuestWrite(
            kind.c_str(),
            slot,
            4u,
            after,
            watched_before,
            true);
    }

    std::optional<std::uint32_t>
    MemoryReadCode(std::uint32_t address) override {
        const auto* p = mem.Ptr(address, 4);
        if (!p) {
            return std::nullopt;
        }
        return Read32(p);
    }

    std::uint8_t MemoryRead8(std::uint32_t address) override {
        return mem.Read8(address);
    }

    std::uint16_t MemoryRead16(std::uint32_t address) override {
        return mem.Read16Guest(address);
    }

    std::uint32_t MemoryRead32(std::uint32_t address) override {
        const std::uint32_t value =
            mem.Read32Guest(address);

        // v91: final safety net for the recurrent crash. The PLT loads free
        // directly from this GOT word. Guest stores and host bridges are
        // already RELRO-guarded, but an unforeseen host-side direct pointer
        // write could bypass those callbacks. Verify only the known free slot
        // here so ordinary guest memory reads do not pay a map lookup.
        if (V91Enabled() &&
            v91_relro_armed &&
            address == v91_free_got &&
            v91_free_got != 0u &&
            value != v91_free_expected) {

            ++v91_integrity_repairs;

            Append(
                "V91 RELRO READ REPAIR phase=" +
                V91PhaseName() +
                " tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " PC=0x" +
                JniProbeHex(
                    jit != nullptr
                        ? jit->Regs()[15]
                        : 0u) +
                " LR=0x" +
                JniProbeHex(
                    jit != nullptr
                        ? jit->Regs()[14]
                        : 0u) +
                " freeSlot=0x" +
                JniProbeHex(
                    v91_free_got) +
                " current=0x" +
                JniProbeHex(value) +
                " expected=0x" +
                JniProbeHex(
                    v91_free_expected));

            mem.Write32GuestUnchecked(
                v91_free_got,
                v91_free_expected);

            return v91_free_expected;
        }

        return value;
    }

    std::uint64_t MemoryRead64(std::uint32_t address) override {
        return mem.Read64Guest(address);
    }

    void MemoryWrite8(
        std::uint32_t address,
        std::uint8_t value) override {
        if (!V91AllowRelroWrite(
                address,
                1u,
                "STR8",
                value,
                true)) {
            return;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                1u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint8_t old =
            mem.Read8(address);
        mem.Write8Guest(address, value);
        V94ObserveGuestWrite(
            "STR8",
            address,
            1u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            1u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            1u,
            old,
            value);
    }

    void MemoryWrite16(
        std::uint32_t address,
        std::uint16_t value) override {
        if (!V91AllowRelroWrite(
                address,
                2u,
                "STR16",
                value,
                true)) {
            return;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                2u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint16_t old =
            mem.Read16Guest(address);
        mem.Write16Guest(address, value);
        V94ObserveGuestWrite(
            "STR16",
            address,
            2u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            2u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            2u,
            old,
            value);
    }

    void MemoryWrite32(
        std::uint32_t address,
        std::uint32_t value) override {
        if (!V91AllowRelroWrite(
                address,
                4u,
                "STR32",
                value,
                true)) {
            return;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                4u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint32_t old =
            mem.Read32Guest(address);
        mem.Write32Guest(address, value);
        V94ObserveGuestWrite(
            "STR32",
            address,
            4u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            4u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            4u,
            old,
            value);
    }

    void MemoryWrite64(
        std::uint32_t address,
        std::uint64_t value) override {
        if (!V91AllowRelroWrite(
                address,
                8u,
                "STR64",
                value,
                true)) {
            return;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                8u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint64_t old =
            mem.Read64Guest(address);
        mem.Write64Guest(address, value);
        V94ObserveGuestWrite(
            "STR64",
            address,
            8u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            8u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            8u,
            old,
            value);
    }

    // Dynarmic's callback-only exclusive-memory path calls these methods for
    // STREX/STREXB/STREXH/STREXD. UserCallbacks defaults to returning false,
    // which makes every guest STREX report failure and causes Android atomic
    // retry loops to spin forever. This probe is single-CPU/single-threaded;
    // Dynarmic's ExclusiveMonitor already validates the reservation, so once
    // we reach this callback the write can commit successfully.
    bool MemoryWriteExclusive8(
        std::uint32_t address,
        std::uint8_t value,
        [[maybe_unused]] std::uint8_t expected) override {
        if (!V91AllowRelroWrite(
                address,
                1u,
                "STREX8",
                value,
                true)) {
            return true;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                1u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint8_t old =
            mem.Read8(address);
        mem.Write8Guest(address, value);
        V94ObserveGuestWrite(
            "STREX8",
            address,
            1u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            1u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            1u,
            old,
            value);
        return true;
    }

    bool MemoryWriteExclusive16(
        std::uint32_t address,
        std::uint16_t value,
        [[maybe_unused]] std::uint16_t expected) override {
        if (!V91AllowRelroWrite(
                address,
                2u,
                "STREX16",
                value,
                true)) {
            return true;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                2u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint16_t old =
            mem.Read16Guest(address);
        mem.Write16Guest(address, value);
        V94ObserveGuestWrite(
            "STREX16",
            address,
            2u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            2u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            2u,
            old,
            value);
        return true;
    }

    bool MemoryWriteExclusive32(
        std::uint32_t address,
        std::uint32_t value,
        [[maybe_unused]] std::uint32_t expected) override {
        if (!V91AllowRelroWrite(
                address,
                4u,
                "STREX32",
                value,
                true)) {
            return true;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                4u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint32_t old =
            mem.Read32Guest(address);
        mem.Write32Guest(address, value);
        V94ObserveGuestWrite(
            "STREX32",
            address,
            4u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            4u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            4u,
            old,
            value);
        return true;
    }

    bool MemoryWriteExclusive64(
        std::uint32_t address,
        std::uint64_t value,
        [[maybe_unused]] std::uint64_t expected) override {
        if (!V91AllowRelroWrite(
                address,
                8u,
                "STREX64",
                value,
                true)) {
            return true;
        }

        const bool v94_overlap =
            V94WriteOverlapsWatch(
                address,
                8u);
        const std::uint32_t v94_before =
            v94_overlap
                ? mem.Read32Guest(
                      v94_watch_slot)
                : 0u;
        const std::uint64_t old =
            mem.Read64Guest(address);
        mem.Write64Guest(address, value);
        V94ObserveGuestWrite(
            "STREX64",
            address,
            8u,
            value,
            v94_before,
            v94_overlap);
        V56ObserveRegistryWrite(
            address,
            8u,
            old,
            value);
        V57ObserveGateCWrite(
            address,
            8u,
            old,
            value);
        return true;
    }

    void InterpreterFallback(
        std::uint32_t pc,
        std::size_t count) override {

        std::ostringstream out;
        out
            << "InterpreterFallback at PC=0x"
            << std::hex << pc
            << " count=" << std::dec << count;

        result.message = out.str();
        if (jit) {
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined3);
        }
    }

    std::string NormalizeVirtualAssetKey(
        std::string path) const {

        constexpr char kAssetPrefix[] =
            "ASSET:";

        if (path.rfind(kAssetPrefix, 0) == 0) {
            path.erase(
                0,
                sizeof(kAssetPrefix) - 1u);
        }

        while (path.rfind("./", 0) == 0) {
            path.erase(0, 2);
        }

        while (!path.empty() &&
               path.front() == '/') {
            path.erase(path.begin());
        }

        std::transform(
            path.begin(),
            path.end(),
            path.begin(),
            [](unsigned char ch) {
                if (ch == '\\') {
                    return '/';
                }

                return
                    static_cast<char>(
                        std::toupper(ch));
            });

        return path;
    }

    bool ReadObbU24(
        std::uint64_t offset,
        std::uint32_t& value) const {

        if (obb_data == nullptr ||
            offset + 3u > obb_size) {
            return false;
        }

        value =
            static_cast<std::uint32_t>(
                obb_data[offset]) |
            (static_cast<std::uint32_t>(
                 obb_data[offset + 1u])
             << 8u) |
            (static_cast<std::uint32_t>(
                 obb_data[offset + 2u])
             << 16u);

        return true;
    }

    bool ReadObbU32(
        std::uint64_t offset,
        std::uint32_t& value) const {

        if (obb_data == nullptr ||
            offset + 4u > obb_size) {
            return false;
        }

        value =
            static_cast<std::uint32_t>(
                obb_data[offset]) |
            (static_cast<std::uint32_t>(
                 obb_data[offset + 1u])
             << 8u) |
            (static_cast<std::uint32_t>(
                 obb_data[offset + 2u])
             << 16u) |
            (static_cast<std::uint32_t>(
                 obb_data[offset + 3u])
             << 24u);

        return true;
    }

    std::optional<std::uint32_t>
    FindOuterRsbGroup(
        const std::string& target) const {

        struct PrefixDefault {
            std::string name;
            std::uint32_t end_words =
                0xffffffffu;
        };

        std::uint32_t list_length = 0;
        std::uint32_t list_begin = 0;

        if (!ReadObbU32(
                0x10u,
                list_length) ||
            !ReadObbU32(
                0x14u,
                list_begin) ||
            static_cast<std::uint64_t>(
                list_begin) +
                list_length >
                obb_size) {
            return std::nullopt;
        }

        const std::uint64_t begin =
            list_begin;
        const std::uint64_t end =
            begin + list_length;
        std::uint64_t pos = begin;

        std::vector<PrefixDefault> defaults;
        defaults.push_back(PrefixDefault{});

        while (pos < end) {
            std::string head;

            for (std::size_t i = 0;
                 i < defaults.size();) {

                if (pos <
                    begin +
                        static_cast<std::uint64_t>(
                            defaults[i].end_words) *
                        4ull) {

                    head +=
                        defaults[i].name;
                    ++i;
                } else {
                    defaults.erase(
                        defaults.begin() +
                        static_cast<std::ptrdiff_t>(
                            i));
                }
            }

            if (defaults.empty()) {
                defaults.push_back(
                    PrefixDefault{});
            }

            std::string tail;
            std::size_t prefix_start = 0;
            std::uint32_t prefix_end =
                defaults.back().end_words;
            bool terminated = false;

            while (pos + 4u <= end) {
                const std::uint8_t ch =
                    obb_data[pos];

                std::uint32_t cover = 0;
                if (!ReadObbU24(
                        pos + 1u,
                        cover)) {
                    return std::nullopt;
                }

                pos += 4u;

                if (ch == 0u) {
                    if (cover != 0u &&
                        tail.size() != 1u &&
                        prefix_start <
                            tail.size()) {

                        defaults.push_back(
                            PrefixDefault{
                                tail.substr(
                                    prefix_start),
                                prefix_end});
                    }

                    terminated = true;
                    break;
                }

                tail.push_back(
                    static_cast<char>(ch));

                if (cover != 0u) {
                    if (tail.size() != 1u &&
                        prefix_start <
                            tail.size() - 1u) {

                        defaults.push_back(
                            PrefixDefault{
                                tail.substr(
                                    prefix_start,
                                    tail.size() -
                                        1u -
                                        prefix_start),
                                prefix_end});
                    }

                    prefix_start =
                        tail.size() - 1u;
                    prefix_end = cover;
                }
            }

            if (!terminated ||
                pos + 4u > end) {
                return std::nullopt;
            }

            std::uint32_t group_index = 0;
            if (!ReadObbU32(
                    pos,
                    group_index)) {
                return std::nullopt;
            }

            pos += 4u;

            std::string full =
                head + tail;

            std::transform(
                full.begin(),
                full.end(),
                full.begin(),
                [](unsigned char ch) {
                    return ch == '\\'
                        ? '/'
                        : static_cast<char>(
                              std::toupper(ch));
                });

            if (full == target) {
                return group_index;
            }
        }

        return std::nullopt;
    }

    std::string NormalizeResourceRegistryKey(
        std::string value) const {

        while (value.rfind("./", 0u) == 0u) {
            value.erase(0u, 2u);
        }

        while (!value.empty() &&
               value.front() == '/') {
            value.erase(value.begin());
        }

        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char ch) {
                if (ch == '\\') {
                    return '/';
                }

                return static_cast<char>(
                    std::toupper(ch));
            });

        return value;
    }

    std::string ReadGuestStdStringObject(
        std::uint32_t object) {

        if (object == 0u ||
            mem.Ptr(object, 4u) == nullptr) {
            return {};
        }

        const std::uint32_t data =
            mem.Read32Guest(object);

        if (data == 0u ||
            mem.Ptr(data, 1u) == nullptr) {
            return {};
        }

        return mem.ReadCStringGuest(
            data,
            4096u);
    }

    std::string ReadGuestResfileCString(
        std::uint32_t address) {

        if (address == 0u ||
            mem.Ptr(address, 1u) == nullptr) {
            return {};
        }

        const std::string normalized =
            NormalizeResourceRegistryKey(
                mem.ReadCStringGuest(
                    address,
                    256u));

        return
            normalized.rfind(
                "RESFILE_",
                0u) == 0u
                ? normalized
                : std::string{};
    }

    std::string RecoverGuestResfileWord(
        std::uint32_t word) {

        if (word == 0u) {
            return {};
        }

        const std::string as_object =
            NormalizeResourceRegistryKey(
                ReadGuestStdStringObject(
                    word));

        if (as_object.rfind(
                "RESFILE_",
                0u) == 0u) {
            return as_object;
        }

        if (const std::string direct =
                ReadGuestResfileCString(
                    word);
            !direct.empty()) {
            return direct;
        }

        if (mem.Ptr(
                word,
                4u) != nullptr) {
            return
                ReadGuestResfileCString(
                    mem.Read32Guest(
                        word));
        }

        return {};
    }

    void EnsureRsbResourceIdIndex() {
        if (rsb_resource_id_index_built) {
            return;
        }

        rsb_resource_id_index_built = true;
        rsb_resource_id_to_path.clear();

        if (obb_data == nullptr ||
            obb_size < 0x70u) {
            return;
        }

        struct PrefixDefault {
            std::string name;
            std::uint32_t end_words =
                0xffffffffu;
        };

        std::uint32_t list_length = 0u;
        std::uint32_t list_begin = 0u;

        if (!ReadObbU32(
                0x10u,
                list_length) ||
            !ReadObbU32(
                0x14u,
                list_begin) ||
            static_cast<std::uint64_t>(
                list_begin) +
                    list_length >
                obb_size) {
            return;
        }

        const std::uint64_t begin =
            list_begin;
        const std::uint64_t end =
            begin + list_length;
        std::uint64_t pos = begin;

        std::vector<PrefixDefault> defaults;
        defaults.push_back(PrefixDefault{});

        while (pos < end) {
            std::string head;

            for (std::size_t i = 0u;
                 i < defaults.size();) {

                if (pos <
                    begin +
                        static_cast<std::uint64_t>(
                            defaults[i].end_words) *
                        4ull) {

                    head += defaults[i].name;
                    ++i;
                } else {
                    defaults.erase(
                        defaults.begin() +
                        static_cast<std::ptrdiff_t>(
                            i));
                }
            }

            if (defaults.empty()) {
                defaults.push_back(
                    PrefixDefault{});
            }

            std::string tail;
            std::size_t prefix_start = 0u;
            std::uint32_t prefix_end =
                defaults.back().end_words;
            bool terminated = false;

            while (pos + 4u <= end) {
                const std::uint8_t ch =
                    obb_data[pos];

                std::uint32_t cover = 0u;
                if (!ReadObbU24(
                        pos + 1u,
                        cover)) {
                    return;
                }

                pos += 4u;

                if (ch == 0u) {
                    if (cover != 0u &&
                        tail.size() != 1u &&
                        prefix_start <
                            tail.size()) {

                        defaults.push_back(
                            PrefixDefault{
                                tail.substr(
                                    prefix_start),
                                prefix_end});
                    }

                    terminated = true;
                    break;
                }

                tail.push_back(
                    static_cast<char>(ch));

                if (cover != 0u) {
                    if (tail.size() != 1u &&
                        prefix_start <
                            tail.size() - 1u) {

                        defaults.push_back(
                            PrefixDefault{
                                tail.substr(
                                    prefix_start,
                                    tail.size() -
                                        1u -
                                        prefix_start),
                                prefix_end});
                    }

                    prefix_start =
                        tail.size() - 1u;
                    prefix_end = cover;
                }
            }

            if (!terminated ||
                pos + 4u > end) {
                return;
            }

            // Group index follows every outer-name record.
            pos += 4u;

            std::string full =
                NormalizeResourceRegistryKey(
                    head + tail);

            constexpr char kRton[] = ".RTON";

            if (full.size() <=
                    sizeof(kRton) - 1u ||
                full.compare(
                    full.size() -
                        (sizeof(kRton) - 1u),
                    sizeof(kRton) - 1u,
                    kRton) != 0) {
                continue;
            }

            std::string id =
                "RESFILE_" +
                full.substr(
                    0u,
                    full.size() -
                        (sizeof(kRton) - 1u));

            std::replace(
                id.begin(),
                id.end(),
                '/',
                '_');

            const auto existing =
                rsb_resource_id_to_path.find(id);

            if (existing ==
                rsb_resource_id_to_path.end()) {
                rsb_resource_id_to_path.emplace(
                    std::move(id),
                    std::move(full));
            } else if (
                existing->second != full) {
                // Do not guess if two physical members collapse onto one
                // RESFILE_* spelling.
                existing->second.clear();
            }
        }

        Append(
            "V35 RSB RESOURCE-ID INDEX: " +
            std::to_string(
                rsb_resource_id_to_path.size()) +
            " RTON identifier(s) indexed from the outer RSB table.");
    }

    std::optional<std::string>
    FindOuterRsbPathForResourceId(
        const std::string& resource_id) {

        EnsureRsbResourceIdIndex();

        const std::string key =
            NormalizeResourceRegistryKey(
                resource_id);

        const auto it =
            rsb_resource_id_to_path.find(
                key);

        if (it ==
                rsb_resource_id_to_path.end() ||
            it->second.empty()) {
            return std::nullopt;
        }

        return it->second;
    }

    void IndexResourceInfoTree(
        std::uint32_t tree,
        std::unordered_map<
            std::string,
            std::uint32_t>& output,
        std::size_t max_nodes = 65536u) {

        if (tree == 0u ||
            mem.Ptr(tree, 12u) == nullptr) {
            return;
        }

        // libstdc++ ARM32 _Rb_tree layout used by this exact binary:
        // tree+4 is the header/end node, tree+8 is header.parent/root.
        // Normal nodes store key std::string at +16 and ResourceInfo* at +20.
        const std::uint32_t header =
            tree + 4u;
        const std::uint32_t root =
            mem.Read32Guest(
                tree + 8u);

        if (root == 0u ||
            root == header) {
            return;
        }

        std::vector<std::uint32_t> stack;
        stack.push_back(root);

        std::unordered_set<std::uint32_t>
            visited;
        visited.reserve(1024u);

        while (!stack.empty() &&
               visited.size() < max_nodes) {

            const std::uint32_t node =
                stack.back();
            stack.pop_back();

            if (node == 0u ||
                node == header ||
                !visited.insert(node).second ||
                mem.Ptr(node, 24u) == nullptr) {
                continue;
            }

            const std::uint32_t key_data =
                mem.Read32Guest(
                    node + 16u);
            const std::uint32_t value =
                mem.Read32Guest(
                    node + 20u);

            if (key_data != 0u &&
                value != 0u &&
                mem.Ptr(
                    key_data,
                    1u) != nullptr) {

                std::string key =
                    mem.ReadCStringGuest(
                        key_data,
                        4096u);

                if (!key.empty()) {
                    key =
                        NormalizeResourceRegistryKey(
                            std::move(key));

                    output.emplace(
                        std::move(key),
                        value);
                }
            }

            const std::uint32_t left =
                mem.Read32Guest(
                    node + 8u);
            const std::uint32_t right =
                mem.Read32Guest(
                    node + 12u);

            if (left != 0u &&
                left != header) {
                stack.push_back(left);
            }

            if (right != 0u &&
                right != header) {
                stack.push_back(right);
            }
        }
    }

    std::uint32_t FindResourceInfoInTree(
        std::uint32_t tree,
        const std::string& wanted) {

        std::unordered_map<
            std::string,
            std::uint32_t> indexed;

        IndexResourceInfoTree(
            tree,
            indexed);

        const auto it =
            indexed.find(
                NormalizeResourceRegistryKey(
                    wanted));

        return
            it == indexed.end()
                ? 0u
                : it->second;
    }

    void EnsureManagerResourceIdIndex(
        std::uint32_t manager) {

        // v41: ResourceManager is populated incrementally during startup.
        // Re-snapshot the group ID trees on every native miss, just like the
        // v38 path map. Caching the first manager snapshot can permanently
        // preserve an empty/partial view.
        const bool manager_changed =
            resource_id_index_manager != manager;

        resource_id_index_manager =
            manager;
        resource_id_index.clear();

        if (manager == 0u ||
            mem.Ptr(
                manager,
                12u) == nullptr) {
            return;
        }

        const std::uint32_t begin =
            mem.Read32Guest(
                manager + 4u);
        const std::uint32_t end =
            mem.Read32Guest(
                manager + 8u);

        if (begin == 0u ||
            end < begin ||
            ((end - begin) & 3u) != 0u ||
            end - begin >
                4096u * 4u ||
            mem.Ptr(
                begin,
                static_cast<std::size_t>(
                    end - begin)) == nullptr) {
            return;
        }

        for (std::uint32_t cursor = begin;
             cursor < end;
             cursor += 4u) {

            const std::uint32_t group =
                mem.Read32Guest(
                    cursor);

            if (group == 0u ||
                mem.Ptr(
                    group,
                    68u) == nullptr) {
                continue;
            }

            IndexResourceInfoTree(
                group + 56u,
                resource_id_index);
        }

        if (manager_changed ||
            resource_id_index_last_logged_entries !=
                resource_id_index.size()) {

            resource_id_index_last_logged_entries =
                resource_id_index.size();

            Append(
                "V41 RESOURCE-ID MAP SNAPSHOT: manager=0x" +
                JniProbeHex(manager) +
                " keys=" +
                std::to_string(
                    resource_id_index.size()));
        }
    }

    void EnsureManagerResourcePathIndex(
        std::uint32_t manager) {

        // v38: this std::map is populated incrementally while resources load.
        // Re-snapshot it at each native miss instead of caching the first
        // (possibly empty) view forever, which is what v35 accidentally did.
        resource_path_index_manager =
            manager;
        resource_path_index.clear();

        if (manager == 0u ||
            mem.Ptr(
                manager + 40u,
                12u) == nullptr) {
            return;
        }

        IndexResourceInfoTree(
            manager + 40u,
            resource_path_index);

        result.resource_path_index_entries =
            static_cast<std::uint32_t>(
                resource_path_index.size());

        Append(
            "V35 RESOURCE-PATH MAP SNAPSHOT: manager=0x" +
            JniProbeHex(manager) +
            " keys=" +
            std::to_string(
                resource_path_index.size()));
    }

    std::uint32_t FindResourceInfoByPhysicalPath(
        std::uint32_t manager,
        const std::string& physical) {

        EnsureManagerResourcePathIndex(
            manager);

        const std::string wanted =
            NormalizeResourceRegistryKey(
                physical);

        if (const auto exact =
                resource_path_index.find(
                    wanted);
            exact !=
                resource_path_index.end()) {
            return exact->second;
        }

        // Some ResourceManager builds prefix paths with a root directory.
        // Accept a suffix only when it uniquely identifies one ResourceInfo.
        std::uint32_t unique = 0u;

        for (const auto& entry :
             resource_path_index) {

            if (entry.first.size() <
                wanted.size()) {
                continue;
            }

            const std::size_t offset =
                entry.first.size() -
                wanted.size();

            if (entry.first.compare(
                    offset,
                    wanted.size(),
                    wanted) != 0) {
                continue;
            }

            if (offset != 0u &&
                entry.first[offset - 1u] != '/') {
                continue;
            }

            if (unique != 0u &&
                unique != entry.second) {
                return 0u;
            }

            unique = entry.second;
        }

        if (unique != 0u) {
            return unique;
        }

        // v42: 0x1086f66c itself proves that ResourceManager's group vector
        // lives at +4/+8 and each group's ResourceInfo rb-tree lives at +56.
        // If the guessed global path map is empty, search those real native
        // group trees for the physical RSB member (exact/suffix/basename)
        // before giving up. This still returns only PvZ2-owned ResourceInfo*.
        EnsureManagerResourceIdIndex(
            manager);

        if (!resource_id_index.empty()) {
            const auto exact =
                resource_id_index.find(
                    wanted);

            if (exact !=
                resource_id_index.end()) {
                Append(
                    "V45 GROUP-TREE PHYSICAL HIT exact=\"" +
                    wanted +
                    "\" -> 0x" +
                    JniProbeHex(
                        exact->second));
                return exact->second;
            }

            const std::size_t slash =
                wanted.find_last_of('/');
            const std::string basename =
                slash == std::string::npos
                    ? wanted
                    : wanted.substr(
                          slash + 1u);

            std::uint32_t basename_unique = 0u;
            std::string basename_key;

            for (const auto& entry :
                 resource_id_index) {

                bool matches = false;

                if (entry.first.size() >=
                    wanted.size()) {
                    const std::size_t offset =
                        entry.first.size() -
                        wanted.size();

                    matches =
                        entry.first.compare(
                            offset,
                            wanted.size(),
                            wanted) == 0 &&
                        (offset == 0u ||
                         entry.first[offset - 1u] == '/');
                }

                if (!matches &&
                    !basename.empty() &&
                    entry.first.size() >=
                        basename.size()) {
                    const std::size_t offset =
                        entry.first.size() -
                        basename.size();

                    matches =
                        entry.first.compare(
                            offset,
                            basename.size(),
                            basename) == 0 &&
                        (offset == 0u ||
                         entry.first[offset - 1u] == '/' ||
                         entry.first[offset - 1u] == '_');
                }

                if (!matches) {
                    continue;
                }

                if (basename_unique != 0u &&
                    basename_unique !=
                        entry.second) {
                    basename_unique = 0u;
                    basename_key.clear();
                    break;
                }

                basename_unique =
                    entry.second;
                basename_key =
                    entry.first;
            }

            if (basename_unique != 0u) {
                Append(
                    "V45 GROUP-TREE PHYSICAL HIT key=\"" +
                    basename_key +
                    "\" wanted=\"" +
                    wanted +
                    "\" -> 0x" +
                    JniProbeHex(
                        basename_unique));
                return basename_unique;
            }

            if (resource_group_key_diagnostics < 6u) {
                ++resource_group_key_diagnostics;

                std::ostringstream diagnostic;
                diagnostic
                    << "V45 GROUP-TREE KEYS #"
                    << resource_group_key_diagnostics
                    << " wanted=\""
                    << wanted
                    << "\" total="
                    << resource_id_index.size()
                    << " sample={";

                std::size_t emitted = 0u;
                for (const auto& entry :
                     resource_id_index) {
                    if (emitted >= 16u) {
                        break;
                    }

                    if (emitted != 0u) {
                        diagnostic << " | ";
                    }

                    diagnostic
                        << entry.first
                        << "=>0x"
                        << JniProbeHex(
                               entry.second);
                    ++emitted;
                }

                diagnostic << "}";
                Append(
                    diagnostic.str());
            }
        }

        return 0u;
    }

    std::uint32_t ResolveResourceRegistryLookup(
        std::uint32_t manager,
        std::uint32_t group,
        std::uint32_t id_object) {

        const std::string id =
            ReadGuestStdStringObject(
                id_object);

        ++result.resource_registry_lookup_calls;

        if (id.empty()) {
            ++result.resource_registry_misses;
            return 0u;
        }

        std::uint32_t direct = 0u;

        if (group != 0u &&
            mem.Ptr(
                group,
                68u) != nullptr) {

            direct =
                FindResourceInfoInTree(
                    group + 56u,
                    id);
        } else {
            EnsureManagerResourceIdIndex(
                manager);

            const auto it =
                resource_id_index.find(
                    NormalizeResourceRegistryKey(
                        id));

            if (it !=
                resource_id_index.end()) {
                direct = it->second;
            }
        }

        if (direct != 0u) {
            ++result.resource_registry_direct_hits;

            if (result.resource_registry_direct_hits <=
                6u) {
                Append(
                    "V35 RESOURCE-ID DIRECT HIT \"" +
                    id +
                    "\" -> 0x" +
                    JniProbeHex(direct));
            }

            return direct;
        }

        const auto physical =
            FindOuterRsbPathForResourceId(
                id);

        if (physical.has_value()) {
            const std::uint32_t by_path =
                FindResourceInfoByPhysicalPath(
                    manager,
                    *physical);

            if (by_path != 0u) {
                ++result
                    .resource_registry_path_fallback_hits;

                if (resource_registry_logged_ids
                        .insert(id)
                        .second) {
                    Append(
                        "V35 RESOURCE REGISTRY FALLBACK \"" +
                        id +
                        "\" -> \"" +
                        *physical +
                        "\" -> ResourceInfo*=0x" +
                        JniProbeHex(by_path));
                }

                return by_path;
            }

            if (resource_registry_logged_ids
                    .insert(id)
                    .second) {
                Append(
                    "V35 RESOURCE REGISTRY PATH MISS \"" +
                    id +
                    "\" -> \"" +
                    *physical +
                    "\"; global path map contains " +
                    std::to_string(
                        resource_path_index.size()) +
                    " key(s).");
            }
        } else if (
            resource_registry_logged_ids
                .insert(id)
                .second) {

            Append(
                "V35 RESOURCE REGISTRY OUTER MISS \"" +
                id +
                "\"; no unique RTON member maps to this identifier.");
        }

        ++result.resource_registry_misses;
        return 0u;
    }

    std::uint32_t ResolveResourceRegistryNativeMiss(
        std::uint32_t manager,
        std::uint32_t group,
        std::uint32_t id_object,
        const char* site,
        const std::string& recovered_id = {}) {

        ++result.resource_registry_lookup_calls;

        const std::string object_id =
            ReadGuestStdStringObject(
                id_object);

        std::string id =
            object_id;

        if (id.rfind(
                "RESFILE_",
                0u) != 0u &&
            !recovered_id.empty()) {
            id = recovered_id;
        }

        const std::string normalized =
            NormalizeResourceRegistryKey(
                id);

        // This bridge is intentionally narrow. ImageRes and every successful
        // native lookup stay entirely inside PvZ2. Only RESFILE_* misses may
        // use the physical member already proven to exist in the selected RSB.
        if (normalized.rfind(
                "RESFILE_",
                0u) != 0u) {
            ++result.resource_registry_misses;
            return 0u;
        }

        if (resource_native_miss_diagnostics < 8u) {
            ++resource_native_miss_diagnostics;

            std::ostringstream diagnostic;
            diagnostic
                << "V45 RES MISS #"
                << resource_native_miss_diagnostics
                << " id=\""
                << normalized
                << "\" objectID=\""
                << object_id
                << "\" recoveredID=\""
                << recovered_id
                << "\" site="
                << (site != nullptr
                        ? site
                        : "n/a")
                << " manager=0x"
                << JniProbeHex(manager)
                << " group=0x"
                << JniProbeHex(group)
                << " managerWords={";

            if (manager != 0u &&
                mem.Ptr(manager, 72u) != nullptr) {
                for (std::uint32_t offset = 0u;
                     offset <= 68u;
                     offset += 4u) {

                    if (offset != 0u) {
                        diagnostic << ",";
                    }

                    diagnostic
                        << "+"
                        << offset
                        << ":0x"
                        << JniProbeHex(
                               mem.Read32Guest(
                                   manager + offset));
                }
            } else {
                diagnostic << "unreadable";
            }

            diagnostic << "}";
            Append(diagnostic.str());

            // Probe likely std::map offsets without mutating guest memory.
            // Limit traversal aggressively: this is layout discovery only.
            if (resource_native_miss_diagnostics <= 2u &&
                manager != 0u) {

                for (std::uint32_t offset = 0u;
                     offset <= 80u;
                     offset += 4u) {

                    if (mem.Ptr(
                            manager + offset,
                            12u) == nullptr) {
                        continue;
                    }

                    std::unordered_map<
                        std::string,
                        std::uint32_t> candidate;

                    IndexResourceInfoTree(
                        manager + offset,
                        candidate,
                        128u);

                    if (candidate.empty()) {
                        continue;
                    }

                    const auto wanted =
                        candidate.find(
                            normalized);

                    Append(
                        "V45 RES MAP CANDIDATE offset=+" +
                        std::to_string(offset) +
                        " keys=" +
                        std::to_string(
                            candidate.size()) +
                        " exact=" +
                        (wanted != candidate.end()
                            ? ("0x" +
                               JniProbeHex(
                                   wanted->second))
                            : std::string{"NO"}));
                }
            }
        }

        // v41: before translating an ID to a physical RSB path, retry the
        // exact ID against the already-populated runtime trees. This is safe:
        // the returned pointer comes from PvZ2's own ResourceInfo map.
        std::uint32_t direct = 0u;

        if (group != 0u &&
            mem.Ptr(
                group,
                68u) != nullptr) {
            direct =
                FindResourceInfoInTree(
                    group + 56u,
                    normalized);
        }

        if (direct == 0u) {
            EnsureManagerResourceIdIndex(
                manager);

            const auto exact =
                resource_id_index.find(
                    normalized);

            if (exact !=
                resource_id_index.end()) {
                direct = exact->second;
            }
        }

        if (direct != 0u) {
            ++result.resource_registry_direct_hits;

            if (resource_registry_logged_ids
                    .insert(
                        "V41EXACT:" + normalized)
                    .second) {
                Append(
                    "V45 RESFILE EXACT FALLBACK " +
                    normalized +
                    " -> ResourceInfo*=0x" +
                    JniProbeHex(direct) +
                    " site=" +
                    (site != nullptr
                        ? std::string{site}
                        : std::string{"n/a"}));
            }

            return direct;
        }

        const auto physical =
            FindOuterRsbPathForResourceId(
                normalized);

        if (!physical.has_value()) {
            ++result.resource_registry_misses;

            if (resource_registry_logged_ids
                    .insert(
                        "MISS:" + normalized)
                    .second) {
                Append(
                    "V38 RESFILE NATIVE MISS " +
                    normalized +
                    " site=" +
                    (site != nullptr
                        ? std::string{site}
                        : std::string{"n/a"}) +
                    " manager=0x" +
                    JniProbeHex(manager) +
                    " group=0x" +
                    JniProbeHex(group) +
                    " -> no unique outer-RSB member");
            }

            return 0u;
        }

        const std::uint32_t by_path =
            FindResourceInfoByPhysicalPath(
                manager,
                *physical);

        if (by_path != 0u) {
            ++result
                .resource_registry_path_fallback_hits;

            if (resource_registry_logged_ids
                    .insert(
                        "HIT:" + normalized)
                    .second) {
                Append(
                    "V38 RESFILE MISS FALLBACK " +
                    normalized +
                    " -> " +
                    *physical +
                    " -> ResourceInfo*=0x" +
                    JniProbeHex(by_path) +
                    " site=" +
                    (site != nullptr
                        ? std::string{site}
                        : std::string{"n/a"}));
            }

            return by_path;
        }

        ++result.resource_registry_misses;

        if (resource_registry_logged_ids
                .insert(
                    "PATHMISS:" + normalized)
                .second) {

            const std::uint32_t path_root =
                manager != 0u &&
                mem.Ptr(
                    manager + 48u,
                    4u) != nullptr
                    ? mem.Read32Guest(
                          manager + 48u)
                    : 0u;

            Append(
                "V38 RESFILE PATH MISS " +
                normalized +
                " -> " +
                *physical +
                " manager=0x" +
                JniProbeHex(manager) +
                " group=0x" +
                JniProbeHex(group) +
                " mapRoot=0x" +
                JniProbeHex(path_root) +
                " pathKeys=" +
                std::to_string(
                    resource_path_index.size()) +
                " site=" +
                (site != nullptr
                    ? std::string{site}
                    : std::string{"n/a"}));
        }

        return 0u;
    }

    const SyntheticAsset*
    GetOrBuildSyntheticTga(
        const std::string& requested) {

        const std::string asset_key =
            NormalizeVirtualAssetKey(
                requested);

        if (asset_key.size() < 4u ||
            asset_key.compare(
                asset_key.size() - 4u,
                4u,
                ".TGA") != 0) {
            return nullptr;
        }

        if (const auto cached =
                synthetic_assets.find(
                    asset_key);
            cached !=
                synthetic_assets.end()) {
            return &cached->second;
        }

        auto ptx_from_key =
            [](std::string key) {
                key.replace(
                    key.size() - 4u,
                    4u,
                    ".PTX");
                return key;
            };

        std::string resolved_key =
            asset_key;
        std::string ptx_path =
            ptx_from_key(
                resolved_key);

        auto group_index =
            FindOuterRsbGroup(
                ptx_path);

        // PvZ2 probes a few Android atlas filename variants after loading the
        // canonical atlas, notably "_Name.tga" and "Name_.tga". They refer to
        // the same PTX payload in this 1.5 RSB. Resolve those aliases at the
        // virtual-asset layer instead of pretending they are separate APK
        // assets.
        if (!group_index.has_value()) {
            const std::size_t slash =
                resolved_key.find_last_of('/');
            const std::size_t file_begin =
                slash == std::string::npos
                    ? 0u
                    : slash + 1u;
            const std::size_t extension =
                resolved_key.size() - 4u;

            std::vector<std::string>
                aliases;

            if (file_begin < extension &&
                resolved_key[file_begin] == '_') {
                std::string candidate =
                    resolved_key;
                candidate.erase(
                    file_begin,
                    1u);
                aliases.push_back(
                    std::move(candidate));
            }

            if (extension > file_begin &&
                resolved_key[extension - 1u] == '_') {
                std::string candidate =
                    resolved_key;
                candidate.erase(
                    extension - 1u,
                    1u);
                aliases.push_back(
                    std::move(candidate));
            }

            for (const auto& candidate :
                 aliases) {

                const std::string candidate_ptx =
                    ptx_from_key(
                        candidate);
                const auto candidate_group =
                    FindOuterRsbGroup(
                        candidate_ptx);

                if (!candidate_group.has_value()) {
                    continue;
                }

                resolved_key =
                    candidate;
                ptx_path =
                    candidate_ptx;
                group_index =
                    candidate_group;

                if (const auto cached =
                        synthetic_assets.find(
                            resolved_key);
                    cached !=
                        synthetic_assets.end()) {

                    SyntheticAsset alias =
                        cached->second;

                    auto inserted =
                        synthetic_assets.emplace(
                            asset_key,
                            std::move(alias));

                    Append(
                        "V32 PTX alias: \"" +
                        asset_key +
                        "\" -> \"" +
                        resolved_key +
                        "\"");

                    return
                        &inserted.first->second;
                }

                break;
            }
        }

        if (!group_index.has_value()) {
            return nullptr;
        }

        std::uint32_t group_count = 0;
        std::uint32_t group_info_begin = 0;
        std::uint32_t group_info_each = 0;

        if (!ReadObbU32(
                0x28u,
                group_count) ||
            !ReadObbU32(
                0x2cu,
                group_info_begin) ||
            !ReadObbU32(
                0x30u,
                group_info_each) ||
            group_info_each < 0xb0u ||
            *group_index >= group_count) {
            return nullptr;
        }

        const std::uint64_t info =
            static_cast<std::uint64_t>(
                group_info_begin) +
            static_cast<std::uint64_t>(
                *group_index) *
            group_info_each;

        std::uint32_t group_offset = 0;
        std::uint32_t group_size = 0;
        std::uint32_t part1_offset = 0;
        std::uint32_t part1_zsize = 0;
        std::uint32_t part1_size = 0;

        if (!ReadObbU32(
                info + 0x80u,
                group_offset) ||
            !ReadObbU32(
                info + 0x84u,
                group_size) ||
            !ReadObbU32(
                info + 0xa4u,
                part1_offset) ||
            !ReadObbU32(
                info + 0xa8u,
                part1_zsize) ||
            !ReadObbU32(
                info + 0xacu,
                part1_size) ||
            part1_size == 0u ||
            static_cast<std::uint64_t>(
                group_offset) +
                group_size >
                obb_size) {
            return nullptr;
        }

        std::uint32_t rsgp_magic = 0;
        std::uint32_t file_list_length = 0;
        std::uint32_t file_list_begin = 0;

        if (!ReadObbU32(
                group_offset,
                rsgp_magic) ||
            rsgp_magic != 0x72736770u ||
            !ReadObbU32(
                static_cast<std::uint64_t>(
                    group_offset) +
                    0x48u,
                file_list_length) ||
            !ReadObbU32(
                static_cast<std::uint64_t>(
                    group_offset) +
                    0x4cu,
                file_list_begin)) {
            return nullptr;
        }

        const std::uint64_t list_begin =
            static_cast<std::uint64_t>(
                group_offset) +
            file_list_begin;
        const std::uint64_t list_end =
            list_begin +
            file_list_length;

        if (list_end > obb_size) {
            return nullptr;
        }

        struct PrefixDefault {
            std::string name;
            std::uint32_t end_words =
                0xffffffffu;
        };

        std::vector<PrefixDefault> defaults;
        defaults.push_back(PrefixDefault{});

        std::uint64_t pos = list_begin;

        std::uint32_t file_offset = 0;
        std::uint32_t file_size = 0;
        std::uint32_t width = 0;
        std::uint32_t height = 0;
        bool found = false;

        while (pos < list_end) {
            std::string head;

            for (std::size_t i = 0;
                 i < defaults.size();) {

                if (pos <
                    list_begin +
                        static_cast<std::uint64_t>(
                            defaults[i].end_words) *
                        4ull) {

                    head +=
                        defaults[i].name;
                    ++i;
                } else {
                    defaults.erase(
                        defaults.begin() +
                        static_cast<std::ptrdiff_t>(
                            i));
                }
            }

            if (defaults.empty()) {
                defaults.push_back(
                    PrefixDefault{});
            }

            std::string tail;
            std::size_t prefix_start = 0;
            std::uint32_t prefix_end =
                defaults.back().end_words;
            bool terminated = false;

            while (pos + 4u <= list_end) {
                const std::uint8_t ch =
                    obb_data[pos];

                std::uint32_t cover = 0;
                if (!ReadObbU24(
                        pos + 1u,
                        cover)) {
                    return nullptr;
                }

                pos += 4u;

                if (ch == 0u) {
                    if (cover != 0u &&
                        tail.size() != 1u &&
                        prefix_start <
                            tail.size()) {

                        defaults.push_back(
                            PrefixDefault{
                                tail.substr(
                                    prefix_start),
                                prefix_end});
                    }

                    terminated = true;
                    break;
                }

                tail.push_back(
                    static_cast<char>(ch));

                if (cover != 0u) {
                    if (tail.size() != 1u &&
                        prefix_start <
                            tail.size() - 1u) {

                        defaults.push_back(
                            PrefixDefault{
                                tail.substr(
                                    prefix_start,
                                    tail.size() -
                                        1u -
                                        prefix_start),
                                prefix_end});
                    }

                    prefix_start =
                        tail.size() - 1u;
                    prefix_end = cover;
                }
            }

            if (!terminated ||
                pos + 12u > list_end) {
                return nullptr;
            }

            const std::uint64_t record =
                pos;

            std::uint32_t type = 0;
            std::uint32_t candidate_offset = 0;
            std::uint32_t candidate_size = 0;

            if (!ReadObbU32(
                    record,
                    type) ||
                !ReadObbU32(
                    record + 4u,
                    candidate_offset) ||
                !ReadObbU32(
                    record + 8u,
                    candidate_size)) {
                return nullptr;
            }

            const std::uint32_t record_size =
                type == 0u
                    ? 12u
                    : 32u;

            if (record +
                    record_size >
                list_end) {
                return nullptr;
            }

            std::string full =
                head + tail;

            std::transform(
                full.begin(),
                full.end(),
                full.begin(),
                [](unsigned char ch) {
                    return ch == '\\'
                        ? '/'
                        : static_cast<char>(
                              std::toupper(ch));
                });

            if (full == ptx_path &&
                type == 1u) {

                if (!ReadObbU32(
                        record + 24u,
                        width) ||
                    !ReadObbU32(
                        record + 28u,
                        height) ||
                    width == 0u ||
                    height == 0u) {
                    return nullptr;
                }

                file_offset =
                    candidate_offset;
                file_size =
                    candidate_size;
                found = true;
                break;
            }

            pos += record_size;
        }

        if (!found ||
            part1_zsize == 0u ||
