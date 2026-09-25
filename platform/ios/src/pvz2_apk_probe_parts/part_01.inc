        if (!sample_frame) {
            return;
        }

        if (final_blit) {
            if (v84_final_blit_draw_traces >= 160u) {
                return;
            }
            if (v84_final_trace_frame != current_frame_number) {
                v84_final_trace_frame = current_frame_number;
                v84_final_traces_this_frame = 0u;
            }
            if (v84_final_traces_this_frame >= 4u) {
                return;
            }
        } else {
            if (v80_transform_draw_traces >= 220u) {
                return;
            }
            if (v80_trace_frame != current_frame_number) {
                v80_trace_frame = current_frame_number;
                v80_traces_this_frame = 0u;
            }
            if (v80_traces_this_frame >= 10u) {
                return;
            }
        }

        std::optional<GLuint> position_index;
        for (GLuint index = 0u;
             index < gles_attrib_state.size();
             ++index) {

            const auto& state = gles_attrib_state[index];
            if (!state.enabled) {
                continue;
            }

            const std::uint64_t key =
                (static_cast<std::uint64_t>(
                     gles_current_program) << 32u) |
                index;
            const auto name_it = gles_attrib_names.find(key);
            if (name_it == gles_attrib_names.end()) {
                continue;
            }

            std::string lowered = name_it->second;
            std::transform(
                lowered.begin(),
                lowered.end(),
                lowered.begin(),
                [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });

            if (lowered.find("position") != std::string::npos) {
                position_index = index;
                break;
            }
        }

        if (!position_index.has_value()) {
            return;
        }

        const auto& position =
            gles_attrib_state[*position_index];

        if (position.type != GL_FLOAT ||
            position.size < 2 ||
            position.guest_pointer == 0u) {
            return;
        }

        const std::size_t packed_stride =
            static_cast<std::size_t>(position.size) *
            sizeof(GLfloat);
        const std::size_t stride =
            position.stride > 0
                ? static_cast<std::size_t>(position.stride)
                : packed_stride;
        const std::size_t sample_count =
            std::min<std::size_t>(
                static_cast<std::size_t>(count),
                256u);

        bool have_bounds = false;
        float min_x = 0.0f;
        float min_y = 0.0f;
        float max_x = 0.0f;
        float max_y = 0.0f;

        for (std::size_t i = 0u; i < sample_count; ++i) {
            const std::uint64_t vertex_index =
                static_cast<std::uint64_t>(first) + i;
            const std::uint64_t address64 =
                static_cast<std::uint64_t>(
                    position.guest_pointer) +
                vertex_index * stride;

            if (address64 >
                std::numeric_limits<std::uint32_t>::max()) {
                break;
            }

            const auto* bytes =
                mem.Ptr(
                    static_cast<std::uint32_t>(address64),
                    sizeof(GLfloat) * 2u);
            if (bytes == nullptr) {
                break;
            }

            GLfloat x = 0.0f;
            GLfloat y = 0.0f;
            std::memcpy(&x, bytes, sizeof(x));
            std::memcpy(
                &y,
                bytes + sizeof(GLfloat),
                sizeof(y));

            if (!std::isfinite(x) || !std::isfinite(y)) {
                continue;
            }

            if (!have_bounds) {
                min_x = max_x = x;
                min_y = max_y = y;
                have_bounds = true;
            } else {
                min_x = std::min(min_x, x);
                min_y = std::min(min_y, y);
                max_x = std::max(max_x, x);
                max_y = std::max(max_y, y);
            }
        }

        if (!have_bounds) {
            return;
        }

        bool have_matrix = false;
        std::array<GLfloat, 16> matrix{};
        std::string matrix_name = "(none)";

        for (const auto& entry : gles_uniform_names) {
            const GLuint program =
                static_cast<GLuint>(entry.first >> 32u);
            if (program != gles_current_program) {
                continue;
            }

            std::string lowered = entry.second;
            std::transform(
                lowered.begin(),
                lowered.end(),
                lowered.begin(),
                [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
            if (lowered.find("screenmatrix") ==
                std::string::npos) {
                continue;
            }

            const auto matrix_it =
                gles_uniform_matrix4_values.find(entry.first);
            if (matrix_it !=
                gles_uniform_matrix4_values.end()) {
                matrix = matrix_it->second;
                matrix_name = entry.second;
                have_matrix = true;
                break;
            }
        }

        double inferred_w = 0.0;
        double inferred_h = 0.0;
        if (have_matrix &&
            std::fabs(matrix[0]) > 1.0e-9f &&
            std::fabs(matrix[5]) > 1.0e-9f) {
            inferred_w =
                2.0 /
                std::fabs(
                    static_cast<double>(matrix[0]));
            inferred_h =
                2.0 /
                std::fabs(
                    static_cast<double>(matrix[5]));
        }

        auto texture_label =
            [&](GLuint texture) {
                std::ostringstream value;
                value << texture;
                const auto it =
                    gles_texture_info.find(texture);
                if (it != gles_texture_info.end()) {
                    value
                        << "("
                        << it->second.width
                        << "x"
                        << it->second.height
                        << ")";
                }
                return value.str();
            };

        std::uint64_t trace_number = 0u;
        const char* trace_label = nullptr;

        if (final_blit) {
            ++v84_final_traces_this_frame;
            ++v84_final_blit_draw_traces;
            trace_number = v84_final_blit_draw_traces;
            trace_label = "V84 FINAL BLIT DRAW #";

            if (have_matrix) {
                const bool canvas_1024 =
                    std::fabs(inferred_w - 1024.0) < 2.0 &&
                    std::fabs(inferred_h - 768.0) < 2.0;
                const bool canvas_2048 =
                    std::fabs(inferred_w - 2048.0) < 2.0 &&
                    std::fabs(inferred_h - 1536.0) < 2.0;
                if (canvas_1024) {
                    ++v84_final_blit_canvas_1024;
                } else if (canvas_2048) {
                    ++v84_final_blit_canvas_2048;
                } else {
                    ++v84_final_blit_canvas_other;
                }
            } else {
                ++v84_final_blit_canvas_other;
            }
        } else {
            ++v80_traces_this_frame;
            ++v80_transform_draw_traces;
            trace_number = v80_transform_draw_traces;
            trace_label = "V80 TRANSFORM DRAW #";
        }

        std::ostringstream diagnostic;
        diagnostic
            << trace_label
            << trace_number
            << " frame="
            << current_frame_number
            << " program="
            << gles_current_program
            << " guestFBO="
            << gles_bound_guest_framebuffer
            << " hostFBO="
            << gles_bound_host_framebuffer
            << " viewport=("
            << last_gles_viewport[0] << ","
            << last_gles_viewport[1] << ","
            << last_gles_viewport[2] << ","
            << last_gles_viewport[3]
            << ") first="
            << first
            << " count="
            << count
            << " posBBox=("
            << min_x << "," << min_y << ")-("
            << max_x << "," << max_y << ")"
            << " tex0="
            << texture_label(gles_bound_texture_2d[0u])
            << " tex1="
            << texture_label(gles_bound_texture_2d[1u])
            << " matrix="
            << matrix_name;

        if (have_matrix) {
            diagnostic
                << " m00=" << matrix[0]
                << " m11=" << matrix[5]
                << " tx=" << matrix[12]
                << " ty=" << matrix[13]
                << " inferredCanvas="
                << inferred_w << "x" << inferred_h;
        } else {
            diagnostic << " unavailable";
        }

        Append(diagnostic.str());
    }

    std::string V80TransformSummary() const {
        std::ostringstream out;
        out
            << "V80 TRANSFORM SUMMARY mode="
            << V56ModeName()
            << " screenMatrixUploads="
            << v80_screen_matrix_uploads
            << " screenMatrixChanges="
            << v80_screen_matrix_changes
            << " arrayDrawsSeen="
            << v80_array_draws_seen
            << " sampledTransformDraws="
            << v80_transform_draw_traces
            << " finalViewport=("
            << last_gles_viewport[0] << ","
            << last_gles_viewport[1] << ","
            << last_gles_viewport[2] << ","
            << last_gles_viewport[3]
            << ") hostSurface="
            << host_surface_width
            << "x"
            << host_surface_height
            << " touchDelivered="
            << v72_touch_events_delivered
            << " keyboard{show="
            << v73_keyboard_show_calls
            << ",hide="
            << v73_keyboard_hide_calls
            << ",status="
            << v73_keyboard_status_calls
            << ",requested="
            << (PvZ2HostKeyboardVisible() ? "YES" : "NO")
            << ",firstResponder="
            << (PvZ2HostKeyboardFirstResponder()
                    ? "YES"
                    : "NO")
            << "}";
        return out.str();
    }

    std::string V84RenderContractSummary() const {
        std::ostringstream out;
        float scale = 0.0f;
        std::uint32_t scale_bits =
            V84AndroidContractEnabled()
                ? v84_android_view_scale_factor_bits
                : 0x3f800000u;
        std::memcpy(&scale, &scale_bits, sizeof(scale));

        out
            << "V84 RENDER CONTRACT SUMMARY mode="
            << V56ModeName()
            << " points="
            << (V84PointsPixelsEnabled()
                    ? "2048x1536"
                    : "1024x768")
            << " pixels=2048x1536"
            << " pointSize=2.0"
            << " canSet="
            << (V84AndroidContractEnabled() ? "true" : "false")
            << " glViewScale="
            << scale
            << " calls{points="
            << v84_points_calls
            << ",pointSize="
            << v84_point_size_calls
            << ",canSet="
            << v84_can_scale_calls
            << ",getScale="
            << v84_get_scale_calls
            << ",setScale="
            << v84_set_scale_calls
            << "} finalBlits="
            << v84_final_blit_draw_traces
            << " finalCanvas{1024x768="
            << v84_final_blit_canvas_1024
            << ",2048x1536="
            << v84_final_blit_canvas_2048
            << ",other="
            << v84_final_blit_canvas_other
            << "}";
        return out.str();
    }

    bool V48TraceTransitionFrame() const {
        return
            current_frame_number >= 55u &&
            current_frame_number <= 90u;
    }

    void V48TraceDrawState(
        const char* draw_kind,
        GLenum mode,
        GLsizei count) {

        if (!V48TraceTransitionFrame() ||
            gles_transition_draw_traces >= 256u) {
            return;
        }

        ++gles_transition_draw_traces;

        std::ostringstream diagnostic;
        diagnostic
            << "V48 TRANSITION DRAW #"
            << gles_transition_draw_traces
            << " frame="
            << current_frame_number
            << " kind="
            << (draw_kind != nullptr
                    ? draw_kind
                    : "?")
            << " mode=0x"
            << JniProbeHex(
                   static_cast<std::uint32_t>(
                       mode))
            << " count="
            << count
            << " guestFBO="
            << gles_bound_guest_framebuffer
            << " hostFBO="
            << gles_bound_host_framebuffer
            << " program="
            << gles_current_program
            << " blend="
            << (gles_blend_enabled
                    ? "ON"
                    : "OFF")
            << "(0x"
            << JniProbeHex(
                   static_cast<std::uint32_t>(
                       gles_blend_src))
            << ",0x"
            << JniProbeHex(
                   static_cast<std::uint32_t>(
                       gles_blend_dst))
            << ") scissor="
            << (gles_scissor_enabled
                    ? "ON"
                    : "OFF")
            << " viewport=("
            << last_gles_viewport[0]
            << ","
            << last_gles_viewport[1]
            << ","
            << last_gles_viewport[2]
            << ","
            << last_gles_viewport[3]
            << ") colorMask=("
            << static_cast<unsigned>(
                   gles_color_mask[0])
            << ","
            << static_cast<unsigned>(
                   gles_color_mask[1])
            << ","
            << static_cast<unsigned>(
                   gles_color_mask[2])
            << ","
            << static_cast<unsigned>(
                   gles_color_mask[3])
            << ") clearRGBA=("
            << gles_clear_color[0]
            << ","
            << gles_clear_color[1]
            << ","
            << gles_clear_color[2]
            << ","
            << gles_clear_color[3]
            << ") tex2D=[";

        for (std::size_t unit = 0u;
             unit < gles_bound_texture_2d.size();
             ++unit) {
            if (unit != 0u) {
                diagnostic << ",";
            }

            const GLuint texture =
                gles_bound_texture_2d[unit];

            diagnostic
                << unit
                << ":"
                << texture;

            const auto info =
                gles_texture_info.find(
                    texture);

            if (texture != 0u &&
                info != gles_texture_info.end()) {
                diagnostic
                    << "("
                    << info->second.width
                    << "x"
                    << info->second.height
                    << ")";
            }
        }

        diagnostic << "] samplers={";
        bool first_uniform = true;

        for (const auto& entry :
             gles_uniform1i_values) {
            const GLuint program =
                static_cast<GLuint>(
                    entry.first >> 32u);

            if (program !=
                gles_current_program) {
                continue;
            }

            if (!first_uniform) {
                diagnostic << ",";
            }
            first_uniform = false;

            const GLint location =
                static_cast<GLint>(
                    static_cast<std::uint32_t>(
                        entry.first));

            const auto name =
                gles_uniform_names.find(
                    entry.first);

            diagnostic
                << (name !=
                            gles_uniform_names.end()
                        ? name->second
                        : std::string{"loc"} +
                              std::to_string(
                                  location))
                << "="
                << entry.second;
        }

        diagnostic << "} attribs={";
        bool first_attrib = true;

        for (GLuint index = 0u;
             index <
                 gles_attrib_state.size();
             ++index) {
            const auto& state =
                gles_attrib_state[index];

            if (!state.enabled) {
                continue;
            }

            if (!first_attrib) {
                diagnostic << ",";
            }
            first_attrib = false;

            const std::uint64_t key =
                (static_cast<std::uint64_t>(
                     gles_current_program)
                 << 32u) |
                index;

            const auto name =
                gles_attrib_names.find(
                    key);

            diagnostic
                << index
                << ":"
                << (name !=
                            gles_attrib_names.end()
                        ? name->second
                        : "?")
                << "[size="
                << state.size
                << ",type=0x"
                << JniProbeHex(
                       static_cast<std::uint32_t>(
                           state.type))
                << ",norm="
                << static_cast<unsigned>(
                       state.normalized)
                << ",stride="
                << state.stride
                << ",ptr=0x"
                << JniProbeHex(
                       state.guest_pointer)
                << "]";
        }

        diagnostic << "}";
        Append(diagnostic.str());
    }

    void V48TraceClearState(
        GLbitfield mask) {

        if (!V48TraceTransitionFrame() ||
            gles_transition_clear_traces >= 128u) {
            return;
        }

        ++gles_transition_clear_traces;

        std::ostringstream diagnostic;
        diagnostic
            << "V48 TRANSITION CLEAR #"
            << gles_transition_clear_traces
            << " frame="
            << current_frame_number
            << " guestFBO="
            << gles_bound_guest_framebuffer
            << " hostFBO="
            << gles_bound_host_framebuffer
            << " mask=0x"
            << JniProbeHex(
                   static_cast<std::uint32_t>(
                       mask))
            << " rgba=("
            << gles_clear_color[0]
            << ","
            << gles_clear_color[1]
            << ","
            << gles_clear_color[2]
            << ","
            << gles_clear_color[3]
            << ") colorMask=("
            << static_cast<unsigned>(
                   gles_color_mask[0])
            << ","
            << static_cast<unsigned>(
                   gles_color_mask[1])
            << ","
            << static_cast<unsigned>(
                   gles_color_mask[2])
            << ","
            << static_cast<unsigned>(
                   gles_color_mask[3])
            << ")";
        Append(diagnostic.str());
    }

    static constexpr std::uint32_t kSweepRecoveryLimit = 48u;
    std::uint32_t sweep_recoveries = 0;
    bool sweep_speculative = false;
    std::unordered_set<std::string> sweep_issue_keys;
    std::unordered_set<std::string> sweep_recovery_keys;
    std::vector<std::string> sweep_issues;

    std::unordered_map<std::string, SyntheticAsset> synthetic_assets;
    std::unordered_map<std::uint32_t, ProbeObbHandle> obb_fds;
    std::unordered_map<std::uint32_t, ProbeObbHandle> obb_files;
    std::unordered_set<std::string> fallback_logged;
    std::unordered_map<std::uint32_t, std::uint32_t> pthread_specific;
    std::unordered_map<std::uint32_t, std::string> jni_method_names;
    std::unordered_map<std::uint32_t, std::string> jni_method_signatures;
    std::unordered_map<std::uint32_t, std::string> jni_strings;
    // v34: AndroidHttpTransaction is asynchronous on Android. Track the
    // native peer passed to its Java constructor so Start() can be completed
    // deterministically through the real registered native error callback
    // instead of remaining pending forever.
    std::unordered_map<std::uint32_t, std::uint32_t>
        jni_native_http_peers;
    std::vector<std::pair<std::uint32_t, std::uint32_t>>
        pending_http_failures;
    std::unordered_set<std::uint32_t>
        queued_http_failure_peers;

    // v49: Android Cloud_attemptSilentSync is asynchronous. The Java Cloud
    // object normally calls Native_CloudStateLoaded later. Capture that
    // callback and complete the handshake once at a lifecycle-safe boundary.
    std::uint32_t native_cloud_state_loaded_address = 0u;
    bool pending_cloud_state_loaded = false;
    bool cloud_state_loaded_delivered = false;

    // v50: the APK's real AndroidHttpProxy.GetNetworkStatus implementation
    // returns 0=no active connection, 1=mobile/WiMAX, 2=Wi-Fi and 3=other
    // connected transport. v38 hard-coded 0; the binary also contains the
    // startup state GAME_WaitForNetworkLoad, so v50 deliberately exercises
    // the faithful connected/Wi-Fi branch while keeping HTTP requests
    // deterministic through the existing native error callbacks.
    std::uint64_t v50_network_status_calls = 0u;

    // v50 resource milestones derived from the extracted RSB metadata.
    // These do not force-load or remap anything; they only tell us exactly
    // whether startup ever asks for the UI package and the first real menu
    // atlases after the EA/Init splash.
    bool v50_ui_android_seen = false;
    bool v50_ui_ipad_seen = false;
    bool v50_mainmenu_background_seen = false;
    bool v50_ui_mainmenu_seen = false;
    bool v50_init_atlas_seen = false;
    std::uint32_t v50_mainmenu_background_first_frame = 0u;
    std::uint32_t v50_ui_mainmenu_first_frame = 0u;
    std::unordered_set<std::string> v50_resource_milestone_keys;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_array_lengths;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_array_data;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_array_element_sizes;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> jni_object_arrays;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_direct_buffer_address;
    std::unordered_map<std::uint32_t, std::uint64_t> jni_direct_buffer_capacity;

    // v51: Native_onSurfaceCreated creates first-run/player-profile state
    // under Android's private user-data directory. Earlier probes claimed
    // mkdir/config writes succeeded without keeping any backing data:
    // snapshot2.dat fopen failed, the Player profiles table could not be
    // saved, and Config_ConfigKeyExists stayed false forever. Keep one
    // process-local Android persistence surface so startup can advance
    // without coupling guest paths to the host iOS filesystem.
    std::unordered_map<
        std::string,
        std::shared_ptr<std::vector<std::uint8_t>>>
        v51_writable_files;
    std::unordered_set<std::string>
        v51_writable_directories;
    std::unordered_map<std::uint32_t, std::string>
        v51_file_token_paths;
    std::unordered_map<std::uint32_t, std::string>
        v51_fd_token_paths;
    std::unordered_set<std::uint32_t>
        v51_directory_handles;
    std::uint32_t v51_next_directory_handle = 0xf2000000u;
    std::uint64_t v51_userfs_write_calls = 0u;
    std::uint64_t v51_userfs_bytes_written = 0u;
    std::uint64_t v51_snapshot2_bytes = 0u;

    // v128 host-backed persistence accounting. v51 remains the active
    // guest-facing cache; dirty paths are flushed into the iOS sandbox.
    std::unordered_set<std::string> v128_userfs_dirty_paths;
    std::uint64_t v128_userfs_disk_loads = 0u;
    std::uint64_t v128_userfs_disk_load_bytes = 0u;
    std::uint64_t v128_userfs_disk_flushes = 0u;
    std::uint64_t v128_userfs_disk_flush_bytes = 0u;
    std::uint64_t v128_userfs_disk_failures = 0u;
    std::uint64_t v128_userfs_mkdirs = 0u;
    std::uint64_t v128_userfs_unlinks = 0u;
    bool v128_config_loaded = false;
    std::uint64_t v128_config_loads = 0u;
    std::uint64_t v128_config_flushes = 0u;
    std::uint64_t v128_config_failures = 0u;

    // v129: count exact replacements of Android's adaptive Board transform.
    std::uint64_t v129_board_scale_forces = 0u;
    std::uint64_t v129_board_scale_state_forces = 0u;
    std::uint64_t v129_board_scale_init_forces = 0u;
    std::uint64_t v129_board_scale_refresh_forces = 0u;

    std::unordered_set<std::string> v51_config_keys;
    std::unordered_map<std::string, std::string>
        v51_config_strings;
    std::unordered_map<std::string, std::int32_t>
        v51_config_integers;
    std::unordered_map<std::string, bool>
        v51_config_booleans;
    std::unordered_set<std::string>
        v51_config_logged_keys;

    // v52 diagnostic cockpit. Instead of guessing one startup gate per build,
    // capture the real AndroidAppDriver/GameApp object graph at a handful of
    // transition frames, record state-like small integer changes, and retain
    // post-EA JNI callsites/stack code candidates. This gives one iPad run
    // enough information to identify the state machine branch that remains
    // active after the EA splash.
    struct V52StateFieldEvent {
        std::uint32_t frame = 0u;
        std::uint32_t object = 0u;
        std::uint32_t vtable = 0u;
        std::uint32_t offset = 0u;
        std::uint32_t before = 0u;
        std::uint32_t after = 0u;
    };

    std::unordered_map<std::uint64_t, std::uint32_t>
        v52_previous_small_fields;
    std::vector<V52StateFieldEvent>
        v52_state_field_events;
    std::unordered_map<std::string, std::uint64_t>
        v52_post_ea_jni_callsites;
    std::unordered_set<std::string>
        v52_stack_dumped_callsites;
    std::uint32_t v52_last_driver = 0u;
    std::uint32_t v52_last_app = 0u;
    std::uint32_t v52_last_app_vtable = 0u;
    std::uint64_t v52_is_same_object_calls = 0u;
    std::uint64_t v52_ui_process_events_calls = 0u;
    std::uint64_t v52_graphics_fbo_calls = 0u;
    std::uint64_t v52_http_starts = 0u;
    std::uint64_t v52_http_deliveries = 0u;

    // v53: exact state-machine observation only. No transition is injected.
    std::uint32_t v53_game_state_manager = 0u;
    std::uint64_t v53_state_apply_calls = 0u;
    std::uint64_t v53_state_request_calls = 0u;

    // v54: StartupLogo.Update gate/depth diagnostics. These are observation
    // counters/last values only; guest control flow remains native.
    std::uint64_t v54_gate_a_resource_hits = 0u;
    std::uint64_t v54_gate_a_totals_hits = 0u;
    std::uint64_t v54_gate_a_result_hits = 0u;
    std::uint64_t v54_gate_c_hits = 0u;
    std::uint64_t v54_gate_d_hits = 0u;
    std::uint64_t v54_after_d_hits = 0u;
    std::uint64_t v54_gate_e_hits = 0u;
    std::uint64_t v54_gate_f_hits = 0u;
    std::uint64_t v54_gate_g_hits = 0u;
    std::uint64_t v54_gate_h_hits = 0u;
    std::uint64_t v54_gate_i_hits = 0u;
    std::uint64_t v54_gate_j_hits = 0u;
    std::uint64_t v54_patch_marker_hits = 0u;
    std::uint64_t v54_main_flow_hits = 0u;
    std::uint64_t v54_progress_result_hits = 0u;
    std::uint64_t v54_find_result_hits = 0u;
    std::uint64_t v54_late_result_hits = 0u;
    std::uint64_t v54_mainmenu_marker_hits = 0u;
    std::uint32_t v54_gate_a_resource = 0u;
    std::uint32_t v54_gate_a_completed = 0u;
    std::uint32_t v54_gate_a_total = 0u;
    std::uint32_t v54_gate_a_result_bits = 0u;
    std::uint32_t v54_gate_c_object = 0u;
    std::uint32_t v54_gate_c_state = 0xffffffffu;
    std::uint32_t v54_gate_d_counter = 0u;
    std::uint32_t v54_gate_e_value = 0u;
    std::uint32_t v54_gate_f_value = 0u;
    std::uint32_t v54_gate_g_value = 0u;
    std::uint32_t v54_gate_h_value = 0u;
    std::uint32_t v54_gate_i_value = 0u;
    std::uint32_t v54_gate_j_byte20 = 0u;
    std::uint32_t v54_gate_j_byte02 = 0u;
    std::uint32_t v54_progress_value = 0u;
    std::uint32_t v54_find_value = 0u;
    std::uint32_t v54_late_value = 0u;

    // v55: exact Gate-A resource-group observations.
    struct V55StartupGroupStat {
        std::uint64_t lookup_hits = 0u;
        std::uint64_t lookup_misses = 0u;
        std::uint64_t contribution_hits = 0u;
        std::uint32_t last_lookup = 0xffffffffu;
        std::uint32_t last_completed = 0u;
        std::uint32_t last_total = 0u;
    };

    std::array<V55StartupGroupStat, 4> v55_group_stats{};
    std::uint64_t v55_ctor_snapshot_hits = 0u;
    std::uint64_t v55_lookup_total = 0u;
    std::uint64_t v55_lookup_unknown = 0u;
    std::uint64_t v55_contribution_total = 0u;
    std::uint32_t v55_last_vector_count = 0xffffffffu;
    std::string v55_ctor_vector_snapshot;
    std::string v55_gate_vector_snapshot;

    // v56 Diagnostic Matrix state.
    PvZ2DiagnosticMode diagnostic_mode =
        PvZ2DiagnosticMode::PassiveRegistry;
    std::uint64_t diagnostic_capabilities = 0u;

    // v76 iOS GL-view-scale contract. The historical iOS driver stores the
    // scale on EAGLView.contentScaleFactor. Start at Android's old synthetic
    // 1.0 and let the guest choose the actual value through Set.
    std::uint32_t v76_gl_view_scale_factor_bits = 0x3f800000u;
    bool v76_gl_view_scale_set = false;
    std::uint32_t v76_scale_can_calls = 0u;
    std::uint32_t v76_scale_get_calls = 0u;
    std::uint32_t v76_scale_set_calls = 0u;

    // v79 is deliberately bounded: at most the first eight hits at each
    // instrumented site are emitted, enough to catch initial creation plus
    // a refresh/re-layout without turning widget hot paths into huge logs.
    std::unordered_map<std::uint32_t, std::uint64_t>
        v79_profile_hits;
    std::uint64_t v79_profile_total_events = 0u;

    // v82 Profile widget/action radar. The common-widget offsets are logged
    // as raw XYWH candidates; runtime correlation decides semantics.
    std::uint32_t v82_profile_object = 0u;
    std::uint32_t v82_candidate5 = 0u;
    std::uint32_t v82_candidate6 = 0u;
    std::uint32_t v82_candidate7 = 0u;
    std::uint64_t v82_candidate5_hits = 0u;
    std::uint64_t v82_candidate6_pre_hits = 0u;
    std::uint64_t v82_candidate6_post_hits = 0u;
    std::uint64_t v82_candidate7_hits = 0u;
    std::uint64_t v82_touch_serial = 0u;
    std::uint64_t v82_touch_radar_logs = 0u;
    std::uint64_t v82_keyboard_correlations = 0u;
    std::uint64_t v82_gamestate_correlations = 0u;
    std::uint64_t v82_profile_state_changes = 0u;
    std::int32_t v82_last_touch_x = 0;
    std::int32_t v82_last_touch_y = 0;
    std::int32_t v82_last_touch_previous_x = 0;
    std::int32_t v82_last_touch_previous_y = 0;
    std::uint32_t v82_last_touch_phase = 0xffffffffu;
    std::uint32_t v82_last_touch_frame = 0u;
    std::uint32_t v82_last_profile_c8 = 0xffffffffu;
    std::uint32_t v82_last_profile_a0 = 0u;
    std::uint32_t v82_last_profile_a4 = 0u;
    std::uint32_t v82_last_profile_a8 = 0u;
    bool v82_profile_state_initialized = false;

    // v83 verified Profile button dispatcher telemetry.
    std::uint64_t v83_button_dispatch_calls = 0u;
    std::uint64_t v83_button_id_hits[21] = {};
    std::uint32_t v83_last_button_id = 0xffffffffu;
    std::uint32_t v83_last_button_this = 0u;
    std::uint32_t v83_last_button_lr = 0u;
    std::uint32_t v83_last_button_frame = 0u;

    std::uint32_t v56_resource_manager = 0u;
    std::uint64_t v56_registry_pipeline_calls = 0u;
    std::uint64_t v56_registry_pipeline_returns = 0u;
    std::uint64_t v56_registry_write_events = 0u;
    std::uint64_t v56_table28_write_events = 0u;
    std::uint64_t v56_table30_write_events = 0u;
    std::uint32_t v56_source28_ptr = 0u;
    std::uint32_t v56_source28_bytes = 0u;
    std::uint32_t v56_source30_ptr = 0u;
    std::uint32_t v56_source30_bytes = 0u;
    std::uint32_t v56_table28_root = 0u;
    std::uint32_t v56_table28_count = 0u;
    std::uint32_t v56_table30_root = 0u;
    std::uint32_t v56_table30_count = 0u;
    std::uint32_t v56_pipeline_last_result = 0xffffffffu;
    bool v56_gate_a_scout_activated = false;
    std::uint64_t v56_gate_a_forced_hits = 0u;
    std::uint32_t v56_gate_a_activation_frame = 0u;
    std::string v56_last_registry_snapshot;

    struct V56TrieContext {
        std::uint32_t table = 0u;
        std::uint32_t caller_lr = 0u;
        std::uint32_t key_start = 0u;
        std::string key;
        bool relevant = false;
        bool trace_path = false;
        std::uint32_t trace_steps = 0u;
    };
    std::unordered_map<std::uint32_t, V56TrieContext>
        v56_trie_contexts;

    // v57 Bionic ctype compatibility / deep Scout state.
    std::uint32_t v57_toupper_variable = 0u;
    std::uint32_t v57_toupper_backing = 0u;
    std::uint32_t v57_tolower_variable = 0u;
    std::uint32_t v57_tolower_backing = 0u;
    std::uint32_t v57_ctype_variable = 0u;
    std::uint32_t v57_ctype_backing = 0u;
    bool v57_ctype_self_check_passed = false;
    bool v57_ctype_self_check_logged = false;

    std::unordered_set<std::string>
        v57_trie_traced_key_tables;

    std::uint64_t v57_gate_a_natural_pass_hits = 0u;
    std::uint64_t v57_gate_c_native_hits = 0u;
    std::uint64_t v57_gate_c_native_pass_hits = 0u;
    std::uint64_t v57_gate_c_write_events = 0u;
    std::uint64_t v57_gate_c_forced_hits = 0u;
    std::uint32_t v57_gate_c_first_frame = 0xffffffffu;
    std::uint32_t v57_gate_c_last_native_state = 0xffffffffu;
    std::uint32_t v57_gate_c_last_object = 0u;
    std::uint64_t v57_gate_c_window_write_base = 0u;
    bool v57_gate_c_scout_activated = false;
    std::uint32_t v57_gate_c_activation_frame = 0u;

    struct V56TargetLookupStat {
        std::uint64_t calls = 0u;
        std::uint64_t found = 0u;
        std::uint64_t misses = 0u;
        std::uint32_t last_table = 0u;
        std::uint32_t last_caller = 0u;
    };
    std::map<std::string, V56TargetLookupStat>
        v56_target_lookups;

    std::unordered_map<std::uint32_t, z_stream> zstreams;
    std::unordered_map<std::uint32_t, bool> zstream_deflate_mode;

    // v70: zlib keeps an internal state->strm backlink to the exact z_stream
    // address passed at init. An initialized host z_stream must not be copied.
    std::uint64_t v70_zlib_init_calls = 0u;
    std::uint64_t v70_zlib_calls = 0u;
    std::uint64_t v70_zlib_stream_errors = 0u;
    std::uint64_t v70_zlib_no_progress = 0u;
    std::uint64_t v70_zlib_input_bytes = 0u;
    std::uint64_t v70_zlib_output_bytes = 0u;

    std::uint64_t v71_etc1_transcodes = 0u;
    std::uint64_t v71_etc1_compressed_bytes = 0u;
    std::uint64_t v71_etc1_decoded_bytes = 0u;
    std::uint64_t v71_etc1_decode_failures = 0u;

    std::uint64_t v72_touch_batches = 0u;
    std::uint64_t v72_touch_events_delivered = 0u;
    std::uint64_t v72_invalid_event_buffers = 0u;

    std::uint64_t v73_text_batches = 0u;
    std::uint64_t v73_text_events_delivered = 0u;
    std::uint64_t v73_text_bytes_delivered = 0u;
    std::uint64_t v73_keyboard_show_calls = 0u;
    std::uint64_t v73_keyboard_hide_calls = 0u;
    std::uint64_t v73_keyboard_status_calls = 0u;

    std::string V46KnownCodeLabel(
        std::uint32_t offset) const {

        switch (offset) {
        case 0x002747d0u:
            return "GameStateMgrState.ApplyState";
        case 0x00274b44u:
            return "GameStateMgrState.RequestTransition";
        case 0x002767b4u:
            return "GameState.MainMenu.Enter(resources)";
        case 0x00276970u:
            return "GameState.StartupLogo.Update";
        case 0x002769d4u:
            return "StartupLogo.GateA.result-vmov";
        case 0x00276a30u:
            return "StartupLogo.GateD.counter-load";
        case 0x00276a3cu:
            return "StartupLogo.after-A-D";
        case 0x00276a60u:
            return "StartupLogo.GateE.b7a-load";
        case 0x00276adcu:
            return "StartupLogo.PatchScreen-request-marker";
        case 0x00276b20u:
            return "StartupLogo.main-flow-marker";
        case 0x00276d70u:
            return "StartupLogo.MainMenu-request-marker";
        case 0x000f66e4u:
            return "StartupGroups.global-constructor-final";
        case 0x002c84d0u:
            return "StartupLogo.GateA.resource-load";
        case 0x002c85ccu:
            return "StartupLogo.GateA.group-lookup-result";
        case 0x002c85f4u:
            return "StartupLogo.GateA.group-contribution";
        case 0x002c8620u:
            return "StartupLogo.GateA.completed-total";
        case 0x00867f54u:
            return "ResourceManager.group-name-to-index";
        case 0x0086b50cu:
            return "ResourceManager.group-completed-count";
        case 0x0086b630u:
            return "ResourceManager.group-total-count";
        case 0x00a83af8u:
            return "CompactTrie.node-byte-compare";
        case 0x002b9900u:
            return "StartupLogo.GateC.helper";
        case 0x005143a4u:
            return "StartupLogo.GateC.state-load";
        case 0x005149c4u:
            return "ImageRes.splash-null virtual-call site";
        case 0x005149c8u:
            return "ImageRes.splash-null virtual-call return";
        case 0x0086f66cu:
            return "ResourceRegistryLookup.function_start";
        case 0x0086f674u:
            return "ResourceRegistryLookup.entry MOV r4,r2";
        case 0x0086f8a0u:
            return "ResourceRegistryLookup.group return boundary";
        case 0x0086fa78u:
            return "ResourceRegistryLookup.global miss return";
        case 0x0086fa84u:
            return "ResourceRegistryLookup.global found-value load";
        case 0x0087a704u:
            return "GenericResFileRes.direct-group lookup call";
        case 0x0087a708u:
            return "GenericResFileRes.direct-group return branch";
        case 0x0087a758u:
            return "GenericResFileRes.group-loop lookup call";
        case 0x0087a76cu:
            return "GenericResFileRes.group-loop exhausted null";
        case 0x009ead80u:
            return "JNI_OnLoad";
        case 0x009ebf80u:
            return "Native_applicationWillFinishLaunching";
        case 0x009ec0a0u:
            return "Native_applicationDidFinishLaunching";
        case 0x009ec0bcu:
            return "Native_applicationWillBecomeForeground";
        case 0x009ec0c8u:
            return "Native_applicationDidBecomeActive";
        case 0x009f1840u:
            return "Native_onSurfaceCreated";
        case 0x009f18dcu:
            return "Native_onSurfaceChanged";
        case 0x009f190cu:
            return "Native_onDrawFrame";
        default:
            return {};
        }
    }

    std::string V46DescribeGuestAddress(
        std::uint32_t address) const {

        std::ostringstream out;
        out << "0x" << JniProbeHex(address);
        const std::uint32_t plain = address & ~1u;

        auto describe_region =
            [&](const char* name,
                std::uint32_t base) {
                out
                    << " ["
                    << name
                    << "+0x"
                    << JniProbeHex(plain - base)
                    << "]";
            };

        if (plain >= kGuestBase &&
            static_cast<std::uint64_t>(plain) <
                static_cast<std::uint64_t>(kGuestBase) +
                mem.image.size()) {

            const std::uint32_t offset =
                plain - kGuestBase;

            out
                << " [libPVZ2.so+0x"
                << JniProbeHex(offset)
                << ((address & 1u) != 0u
                    ? " Thumb"
                    : " ARM");

            const std::string known =
                V46KnownCodeLabel(offset);

            if (!known.empty()) {
                out
                    << " known=\""
                    << known
                    << "\"";
            }

            if (loaded_elf != nullptr &&
                !loaded_elf->function_starts.empty()) {

                const auto upper =
                    std::upper_bound(
                        loaded_elf->function_starts.begin(),
                        loaded_elf->function_starts.end(),
                        offset);

                if (upper !=
                    loaded_elf->function_starts.begin()) {

                    const auto current =
                        std::prev(upper);
                    const std::uint32_t start =
                        *current;

                    out
                        << " fn=+0x"
                        << JniProbeHex(start)
                        << "+0x"
                        << JniProbeHex(offset - start);

                    if (upper !=
                        loaded_elf->function_starts.end()) {
                        out
                            << "/0x"
                            << JniProbeHex(*upper - start);
                    }
                }
            }

            if (loaded_elf != nullptr) {
                std::uint32_t best_index =
                    std::numeric_limits<std::uint32_t>::max();
                std::uint32_t best_value = 0u;
                std::uint32_t best_distance =
                    std::numeric_limits<std::uint32_t>::max();
                bool best_contains = false;

                for (std::uint32_t i = 0u;
                     i < loaded_elf->dynsyms.size();
                     ++i) {

                    const auto& sym =
                        loaded_elf->dynsyms[i];

                    if (sym.shndx == 0u) {
                        continue;
                    }

                    const std::uint32_t value =
                        sym.value & ~1u;

                    if (value > offset) {
                        continue;
                    }

                    const std::uint32_t distance =
                        offset - value;

                    const bool contains =
                        sym.size != 0u &&
                        distance < sym.size;

                    if (best_index ==
                            std::numeric_limits<std::uint32_t>::max() ||
                        (contains && !best_contains) ||
                        (contains == best_contains &&
                         distance < best_distance)) {

                        best_index = i;
                        best_value = value;
                        best_distance = distance;
                        best_contains = contains;
                    }
                }

                if (best_index !=
                        std::numeric_limits<std::uint32_t>::max() &&
                    (best_contains ||
                     best_distance <= 0x00010000u)) {

                    const std::string symbol =
                        JniProbeSymbolName(
                            *loaded_elf,
                            best_index);

                    if (!symbol.empty()) {
                        out
                            << (best_contains
                                ? " symbol=\""
                                : " nearSymbol=\"")
                            << symbol
                            << "+0x"
                            << JniProbeHex(
                                offset - best_value)
                            << "\"";
                    }
                }
            }

            out << "]";
            return out.str();
        }

        if (plain >= kJniProbeStackBase &&
            plain < kJniProbeStackBase + kJniProbeStackSize) {
            describe_region("guest-stack", kJniProbeStackBase);
        } else if (
            plain >= kJniProbeHeapBase &&
            plain < kJniProbeHeapBase + mem.HeapCapacity()) {
            describe_region("guest-heap", kJniProbeHeapBase);
        } else if (
            plain >= kJniProbeTrampolineBase &&
            plain < kJniProbeTrampolineBase + kJniProbeTrampolineSize) {
            describe_region("host-trampoline", kJniProbeTrampolineBase);
        } else if (
            plain >= kJniProbeJniBase &&
            plain < kJniProbeJniBase + kJniProbeJniSize) {
            describe_region("synthetic-JNI", kJniProbeJniBase);
        } else if (
            plain >= kJniProbeObjectBase &&
            plain < kJniProbeObjectBase + kJniProbeObjectSize) {
            describe_region("synthetic-object", kJniProbeObjectBase);
        } else if (address == 0u) {
            out << " [null]";
        } else {
            out << " [other]";
        }

        return out.str();
    }

    void V46AppendControlFlowMap(
        const char* reason,
        std::uint32_t pc,
        std::uint32_t lr,
        std::uint32_t sp) {

        Append(
            std::string{"V46 ADDRMAP "} +
            reason +
            " PC=" +
            V46DescribeGuestAddress(pc) +
            " LR=" +
            V46DescribeGuestAddress(lr) +
            " returnPC=" +
            V46DescribeGuestAddress(lr & ~1u) +
            " SP=" +
            V46DescribeGuestAddress(sp));
    }

    std::uint32_t V63HeldMutexCount(
        std::uint32_t thread_id) const {

        const auto it =
            v63_thread_held_mutexes.find(thread_id);
        return
            it == v63_thread_held_mutexes.end()
                ? 0u
                : it->second;
    }

    std::string V63HeldMutexSummary(
        std::uint32_t thread_id) const {

        std::ostringstream out;
        bool first = true;

        for (const auto& item : v63_mutexes) {
            if (item.second.depth == 0u ||
                item.second.owner != thread_id) {
                continue;
            }

            if (!first) {
                out << ",";
            }
            first = false;
            out
                << "0x"
                << JniProbeHex(item.first)
                << "x"
                << item.second.depth;
        }

        return
            first
                ? std::string{"none"}
                : out.str();
    }

    std::vector<std::uint32_t> V63HeldMutexAddresses(
        std::uint32_t thread_id) const {

        std::vector<std::uint32_t> out;
        out.reserve(V63HeldMutexCount(thread_id));

        for (const auto& item : v63_mutexes) {
            if (item.second.depth != 0u &&
                item.second.owner == thread_id) {
                out.push_back(item.first);
            }
        }

        std::sort(out.begin(), out.end());
        return out;
    }

    std::string V63DescribeMutexAddresses(
        const std::vector<std::uint32_t>& mutexes) const {

        if (mutexes.empty()) {
            return "none";
        }

        std::ostringstream out;
        for (std::size_t i = 0; i < mutexes.size(); ++i) {
            if (i != 0u) out << ",";
            out << V46DescribeGuestAddress(mutexes[i]);
        }
        return out.str();
    }

    void V64ArmReleaseBoundary(
        std::uint32_t thread_id) {

        if (!V64Enabled() || V87Enabled()) {
            return;
        }

        if (v64_release_boundary_armed &&
            v64_release_boundary_thread == thread_id) {
            return;
        }

        v64_release_boundary_armed = true;
        v64_release_boundary_thread = thread_id;
        ++v64_release_boundary_arms;
    }

    void V64DisarmReleaseBoundary(
        std::uint32_t thread_id) {

        if (!V64Enabled() ||
            V87Enabled() ||
            !v64_release_boundary_armed ||
            v64_release_boundary_thread != thread_id) {
            return;
        }

        v64_release_boundary_armed = false;
        v64_release_boundary_thread = 0xffffffffu;
    }

    std::uint64_t V65RealtimeNowNs() const {
        const auto now =
            std::chrono::system_clock::now()
                .time_since_epoch();
        const auto nanos =
            std::chrono::duration_cast<
                std::chrono::nanoseconds>(now)
                .count();
        return
            nanos > 0
                ? static_cast<std::uint64_t>(nanos)
                : 0u;
    }

    bool V65BeginCondWait(
        std::uint32_t cond,
        std::uint32_t mutex,
        bool timed,
        std::uint32_t abstime) {

        if (!V65Enabled() ||
            (current_probe_thread_id == 0u &&
             !V96MainBlockingAllowed())) {
            return false;
        }

        const auto found =
            v63_mutexes.find(mutex);

        if (found == v63_mutexes.end() ||
            found->second.depth == 0u ||
            found->second.owner !=
                current_probe_thread_id) {

            Append(
                "V65 COND WAIT INVALID MUTEX tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " cond=" +
                V46DescribeGuestAddress(cond) +
                " mutex=" +
                V46DescribeGuestAddress(mutex));
            return false;
        }

        if (found->second.depth != 1u) {
            Append(
                "V65 COND WAIT RECURSIVE DEPTH UNSUPPORTED tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " mutex=" +
                V46DescribeGuestAddress(mutex) +
                " depth=" +
                std::to_string(found->second.depth));
            return false;
        }

        // In this cooperative guest scheduler this callback is atomic with
        // respect to all other guest threads. Releasing the tracked mutex and
        // registering the waiter before yielding therefore reproduces the
        // atomic unlock+sleep contract of pthread_cond_wait.
        if (!V63ReleaseMutex(mutex)) {
            return false;
        }

        V65CondWaitState wait;
        wait.cond = cond;
        wait.mutex = mutex;
        wait.timed = timed;

        if (timed && abstime != 0u) {
            const std::uint64_t sec =
                mem.Read32Guest(abstime + 0u);
            const std::uint64_t nsec =
                mem.Read32Guest(abstime + 4u);

            if (nsec < 1000000000ull) {
                wait.deadline_realtime_ns =
                    sec * 1000000000ull + nsec;
            } else {
                wait.deadline_realtime_ns =
                    V65RealtimeNowNs();
            }
        }

        v65_cond_waits[
            current_probe_thread_id] =
                wait;

        auto& waiters =
            v65_cond_waiters[cond];

        if (std::find(
                waiters.begin(),
                waiters.end(),
                current_probe_thread_id) ==
            waiters.end()) {
            waiters.push_back(
                current_probe_thread_id);
        }

        ++v65_cond_wait_calls;

        if (v65_cond_wait_calls <= 32u ||
            (v65_cond_wait_calls % 256u) == 0u) {
            Append(
                "V65 COND WAIT #" +
                std::to_string(
                    v65_cond_wait_calls) +
                " tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " cond=" +
                V46DescribeGuestAddress(cond) +
                " mutex=" +
                V46DescribeGuestAddress(mutex) +
                (timed
                    ? " timed=YES"
                    : " timed=NO") +
                " -> mutex released, worker sleeping");
        }

        return true;
    }

    std::uint32_t V65NotifyCond(
        std::uint32_t cond,
        bool broadcast) {

        if (!V65Enabled()) {
            return 0u;
        }

        auto found =
            v65_cond_waiters.find(cond);

        if (found ==
            v65_cond_waiters.end()) {
            return 0u;
        }

        std::uint32_t woke = 0u;

        for (const std::uint32_t tid :
             found->second) {

            auto wait =
                v65_cond_waits.find(tid);

            if (wait ==
                    v65_cond_waits.end() ||
                wait->second.cond != cond ||
                wait->second.notified) {
                continue;
            }

            wait->second.notified = true;
            wait->second.result_code = 0u;
            ++woke;

            if (!broadcast) {
                break;
            }
        }

        ++v65_cond_wake_calls;

        if (woke != 0u ||
            v65_cond_wake_calls <= 16u) {
            Append(
                std::string{
                    broadcast
                        ? "V65 COND BROADCAST"
                        : "V65 COND SIGNAL"} +
                " cond=" +
                V46DescribeGuestAddress(cond) +
                " woke=" +
                std::to_string(woke));
        }

        return woke;
    }

    bool V65PrepareCondResume(
        std::uint32_t thread_id,
        bool& did_resume,
        std::uint32_t& result_code) {

        did_resume = false;
        result_code = 0u;

        if (!V65Enabled()) {
            return true;
        }

        auto found =
            v65_cond_waits.find(
                thread_id);

        if (found ==
            v65_cond_waits.end()) {
            return true;
        }

        V65CondWaitState& wait =
            found->second;

        if (!wait.notified &&
            wait.timed &&
            wait.deadline_realtime_ns != 0u &&
            V65RealtimeNowNs() >=
                wait.deadline_realtime_ns) {

            wait.notified = true;
            wait.result_code = 110u; // ETIMEDOUT on Android/Bionic.
            ++v65_cond_timeouts;

            Append(
                "V65 COND TIMEOUT tid=" +
                std::to_string(thread_id) +
                " cond=" +
                V46DescribeGuestAddress(
                    wait.cond));
        }

        if (!wait.notified) {
            return false;
        }

        V63MutexState& mutex_state =
            v63_mutexes[wait.mutex];

        if (V87Enabled()) {
            auto mutex_wait =
                v87_mutex_waits.find(thread_id);

            if (mutex_wait !=
                v87_mutex_waits.end()) {

                if (!mutex_wait->second.cond_reacquire ||
                    mutex_wait->second.mutex !=
                        wait.mutex) {
                    v87_failure_message =
                        "v87 cond waiter has mismatched mutex wait state for tid=" +
                        std::to_string(thread_id) +
                        ".";
                    result.message =
                        v87_failure_message;
                    Append(
                        "V87 MUTEX ERROR " +
                        v87_failure_message);
                    return false;
                }

                if (!mutex_wait->second.granted) {
                    return false;
                }

                if (mutex_state.depth == 0u ||
                    mutex_state.owner !=
                        thread_id) {
                    v87_failure_message =
                        "v87 cond mutex handoff invariant failed for tid=" +
                        std::to_string(thread_id) +
                        ".";
                    result.message =
                        v87_failure_message;
                    Append(
                        "V87 MUTEX ERROR " +
                        v87_failure_message);
                    return false;
                }

                V87EraseMutexWait(thread_id);
            } else if (
                mutex_state.depth != 0u &&
                mutex_state.owner !=
                    thread_id) {

                if (!V87QueueMutexWait(
                        thread_id,
                        wait.mutex,
                        true)) {
                    return false;
                }

                return false;
            } else if (mutex_state.depth == 0u) {
                mutex_state.owner = thread_id;
                mutex_state.depth = 1u;
                ++v63_thread_held_mutexes[
                    thread_id];
                ++v63_mutex_acquires;
            }
        } else {
            if (mutex_state.depth != 0u &&
                mutex_state.owner !=
                    thread_id) {
                return false;
            }

            if (mutex_state.depth == 0u) {
                mutex_state.owner = thread_id;
                mutex_state.depth = 1u;
                ++v63_thread_held_mutexes[
                    thread_id];
                ++v63_mutex_acquires;
            }
        }

        const std::uint32_t cond =
            wait.cond;
        const std::uint32_t mutex =
            wait.mutex;
        result_code =
            wait.result_code;

        auto waiters =
            v65_cond_waiters.find(cond);
        if (waiters !=
            v65_cond_waiters.end()) {

            auto& ids =
                waiters->second;
            ids.erase(
                std::remove(
                    ids.begin(),
                    ids.end(),
                    thread_id),
                ids.end());

            if (ids.empty()) {
                v65_cond_waiters.erase(
                    waiters);
            }
        }

        v65_cond_waits.erase(found);
        did_resume = true;
        ++v65_cond_resumes;

        if (v65_cond_resumes <= 32u ||
            (v65_cond_resumes % 256u) == 0u) {
            Append(
                "V65 COND RESUME #" +
                std::to_string(
                    v65_cond_resumes) +
                " tid=" +
                std::to_string(thread_id) +
                " cond=" +
                V46DescribeGuestAddress(cond) +
                " mutex=" +
                V46DescribeGuestAddress(mutex) +
                " rc=" +
                std::to_string(result_code) +
                " -> mutex reacquired");
        }

        return true;
    }


    std::uint32_t V67HeapAllocationSize(
        std::uint32_t address) const {

        const auto it =
            mem.heap_allocations.find(address);
        return it != mem.heap_allocations.end()
            ? it->second
            : 0u;
    }

    bool V67IsCompletionToken(
        std::uint32_t token,
        std::uint32_t& vtable) const {

        vtable =
            token != 0u
                ? mem.Read32Guest(token)
                : 0u;

        if (vtable == 0u ||
            mem.Ptr(vtable, 0x18u) == nullptr) {
            return false;
        }

        return
            mem.Read32Guest(vtable + 0x0cu) ==
                kGuestBase + 0x00abedb8u &&
            mem.Read32Guest(vtable + 0x10u) ==
                kGuestBase + 0x00abedccu &&
            mem.Read32Guest(vtable + 0x14u) ==
                kGuestBase + 0x00abede0u;
    }

    std::string V67AllocationDescription(
        std::uint32_t address) const {

        const auto it =
            v67_small_allocations.find(address);
        if (it == v67_small_allocations.end()) {
            return "allocProvenance=untracked";
        }

        const auto& p = it->second;
        return
            "allocProvenance={size=" +
            std::to_string(p.size) +
            ",malloc#=" +
            std::to_string(p.malloc_index) +
            ",tid=" +
            std::to_string(p.tid) +
            ",viaNew=" +
            std::string{p.via_operator_new ? "YES" : "NO"} +
            ",importLR=" +
            V46DescribeGuestAddress(p.import_lr) +
            ",creatorLR=" +
            V46DescribeGuestAddress(p.creator_lr) +
            "}";
    }

    std::string V67TokenHistoryDescription(
        std::uint32_t token) const {

        const auto it =
            v67_token_history.find(token);
        if (it == v67_token_history.end()) {
            return "tokenHistory={inc=0,dec=0,last=NONE}";
        }

        const auto& h = it->second;
        return
            "tokenHistory={inc=" +
            std::to_string(h.increments) +
            ",dec=" +
            std::to_string(h.decrements) +
            ",lastTid=" +
            std::to_string(h.last_tid) +
            ",lastLR=" +
            V46DescribeGuestAddress(h.last_lr) +
            ",last=" +
            std::to_string(h.last_old) +
            "->" +
            std::to_string(h.last_new) +
            "}";
    }

    void V67TrackSmallAllocation(
        std::uint32_t address,
        std::uint32_t size,
        std::uint32_t import_lr,
        std::uint32_t sp) {

        if ((!V67Enabled() && !V69Enabled()) ||
            address == 0u ||
            (size != 16u && size != 24u)) {
            return;
        }

        V67AllocationProvenance p;
        p.size = size;
        p.tid = current_probe_thread_id;
        p.import_lr = import_lr;
        p.creator_lr = import_lr;
        p.malloc_index = malloc_calls;

        const std::uint32_t plain_lr =
            import_lr & ~1u;

        const std::uint32_t operator_new_begin =
            kGuestBase + 0x00b363a4u;
        const std::uint32_t operator_new_end =
            kGuestBase + 0x00b36448u;

        if (plain_lr >= operator_new_begin &&
            plain_lr < operator_new_end &&
            mem.Ptr(sp + 12u, 4u) != nullptr) {

            const std::uint32_t saved_lr =
                mem.Read32Guest(sp + 12u);

            if (saved_lr >= kGuestBase &&
                static_cast<std::uint64_t>(
                    saved_lr & ~1u) <
                    static_cast<std::uint64_t>(
                        kGuestBase) +
                    mem.image.size()) {
                p.creator_lr = saved_lr;
                p.via_operator_new = true;
            }
        }

        v67_small_allocations[address] = p;
    }

    void V67RecordTokenStore(
        const char* kind,
        std::uint32_t token,
        std::uint32_t new_value,
        std::uint32_t caller_lr) {

        const std::uint32_t old_value =
            token != 0u
                ? mem.Read32Guest(token + 4u)
                : 0u;

        std::uint32_t vtable = 0u;
        const bool token_family =
            V67IsCompletionToken(
                token,
                vtable);

        if (token_family) {
            ++v67_token_events;

            auto& history =
                v67_token_history[token];

            const bool increment =
                kind != nullptr &&
                std::string{kind} == "INC";

            if (increment) {
                ++history.increments;
            } else {
                ++history.decrements;
            }

            history.last_tid =
                current_probe_thread_id;
            history.last_lr =
                caller_lr;
            history.last_old =
                old_value;
            history.last_new =
                new_value;

            const std::uint64_t token_events =
                history.increments +
                history.decrements;

            const bool sample =
                token_events <= 8u ||
                (token_events &
                 (token_events - 1u)) == 0u ||
                (v67_token_events % 4096u) == 0u;

            if (sample && V67Enabled()) {
                Append(
                    "V67 TOKEN " +
                    std::string{
                        kind != nullptr
                            ? kind
                            : "STORE"} +
                    " event=" +
                    std::to_string(v67_token_events) +
                    " token=" +
                    V46DescribeGuestAddress(token) +
                    " vtable=" +
                    V46DescribeGuestAddress(vtable) +
                    " counter=" +
                    std::to_string(old_value) +
                    "->" +
                    std::to_string(new_value) +
                    " tid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " callerLR=" +
                    V46DescribeGuestAddress(caller_lr) +
                    " " +
                    V67AllocationDescription(token) +
                    " " +
                    V67TokenHistoryDescription(token));
            }
        }

        // Exact emulation of the replaced ARM instruction:
        // STR r1,[r0,#4].
        if (token != 0u) {
            mem.Write32Guest(
                token + 4u,
                new_value);
        }
    }

    void V66RecordTaskSubstate(
        const char* kind,
        std::uint32_t task,
        std::uint32_t child,
        std::uint32_t result_value) {

        if (!V66Enabled()) {
            return;
        }

        ++v66_task_substate_events;
        if (result_value == 0u) {
            ++v66_task_substate_zeroes;
        }

        const std::uint32_t child_vtable =
            child != 0u
                ? mem.Read32Guest(child)
                : 0u;
        const std::uint32_t child_vfn_c =
            child_vtable != 0u
                ? mem.Read32Guest(child_vtable + 0x0cu)
                : 0u;

        const std::uint64_t key =
            (static_cast<std::uint64_t>(task) << 32) ^
            (static_cast<std::uint64_t>(child) << 1) ^
            static_cast<std::uint64_t>(
                result_value == 0u ? 1u : 0u);

        std::uint64_t& hits =
            v66_task_substate_hits[key];
        ++hits;

        const bool sample =
            hits <= (V69Enabled() ? 2u : 8u) ||
            (hits & (hits - 1u)) == 0u ||
            (!V69Enabled() &&
             (hits % 65536u) == 0u);

        constexpr std::uint64_t kTaskStagnationLimit =
            65536u;

        std::uint32_t completion_token_vtable = 0u;
        const bool v68_completion_token_zero =
            V68Enabled() &&
            result_value == 0u &&
            V67IsCompletionToken(
                child,
                completion_token_vtable);

        // v67 proved that this shared vfnC is not a readiness predicate:
        // it is exactly (token->counter > 0). A zero result therefore means
        // idle/available and is intentionally used by Task B to enter its
        // resource-vector scan. Treating repeated zeroes as stagnation kills
        // a live worker loop. Keep the legacy guard for every other child
        // class, but never infer a stall from this completion-token family.
        const bool stagnant =
            result_value == 0u &&
            !v68_completion_token_zero &&
            hits >= kTaskStagnationLimit;

        if (!sample && !stagnant) {
            return;
        }

        std::ostringstream out;
        out
            << "V66 TASK SUBSTATE "
            << (kind != nullptr ? kind : "unknown")
            << " hit=" << hits
            << " tid=" << current_probe_thread_id
            << " task=" << V46DescribeGuestAddress(task)
            << " taskVtable="
            << V46DescribeGuestAddress(
                   task != 0u ? mem.Read32Guest(task) : 0u)
            << " child=" << V46DescribeGuestAddress(child)
            << " childClass="
            << (child != 0u
                    ? V62HeapPointerClass(child)
                    : std::string{"null"})
            << " childVtable="
            << V46DescribeGuestAddress(child_vtable)
            << " childVfnC="
            << V46DescribeGuestAddress(child_vfn_c)
            << " vfnCResult=" << result_value;

        if (v68_completion_token_zero) {
            out
                << " v68TokenState=IDLE_NOT_STALL";
        }

        if (V67Enabled()) {
            std::uint32_t token_vtable = 0u;
            if (V67IsCompletionToken(child, token_vtable)) {
                out
                    << " "
                    << V67AllocationDescription(child)
                    << " "
                    << V67TokenHistoryDescription(child);
            }
        }

        out
            << " taskState={+18:0x"
            << JniProbeHex(
                   task != 0u
                       ? mem.Read32Guest(task + 0x18u)
                       : 0u)
            << ",+1c:0x"
            << JniProbeHex(
                   task != 0u
                       ? mem.Read32Guest(task + 0x1cu)
                       : 0u)
            << ",+20:"
            << V46DescribeGuestAddress(
                   task != 0u
                       ? mem.Read32Guest(task + 0x20u)
                       : 0u)
            << ",+24:"
            << V46DescribeGuestAddress(
                   task != 0u
                       ? mem.Read32Guest(task + 0x24u)
                       : 0u)
            << ",+28:"
            << V46DescribeGuestAddress(
                   task != 0u
                       ? mem.Read32Guest(task + 0x28u)
                       : 0u)
            << "}";

        const std::uint32_t tracked_child_size =
            V67HeapAllocationSize(child);
        const std::uint32_t child_snapshot_size =
            tracked_child_size != 0u
                ? std::min<std::uint32_t>(
                      tracked_child_size,
                      0x40u)
                : 0x40u;

        if ((hits <= 2u || stagnant) &&
            child != 0u &&
            child_snapshot_size >= 4u &&
            mem.Ptr(child, child_snapshot_size) != nullptr) {

            out
                << " childSnapshotBytes="
                << child_snapshot_size
                << " childWords={";
            for (std::uint32_t off = 0u;
                 off + 4u <= child_snapshot_size;
                 off += 4u) {
                if (off != 0u) {
                    out << ",";
                }
                out
                    << "+0x" << JniProbeHex(off)
                    << ":0x"
                    << JniProbeHex(
                           mem.Read32Guest(child + off));
            }
            out << "}";

            if (child_vtable != 0u &&
                mem.Ptr(child_vtable, 0x28u) != nullptr) {
                out << " childVtableWords={";
                for (std::uint32_t off = 0u;
                     off < 0x28u;
                     off += 4u) {
                    if (off != 0u) {
                        out << ",";
                    }
                    out
                        << "+0x" << JniProbeHex(off)
                        << ":"
                        << V46DescribeGuestAddress(
                               mem.Read32Guest(
                                   child_vtable + off));
                }
                out << "}";
            }
        }

        Append(out.str());

        if (stagnant) {
            ++v66_task_stagnation_failures;

            v66_failure_message =
                "v66 TaskResource stagnation: tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " kind=" +
                std::string{
                    kind != nullptr
                        ? kind
                        : "unknown"} +
                " task=" +
                V46DescribeGuestAddress(task) +
                " child=" +
                V46DescribeGuestAddress(child) +
                " childVtable=" +
                V46DescribeGuestAddress(child_vtable) +
                " childVfnC=" +
                V46DescribeGuestAddress(child_vfn_c) +
                " repeatedZeroHits=" +
                std::to_string(hits) +
                (V67Enabled()
                    ? " " +
                      V67AllocationDescription(child) +
                      " " +
                      V67TokenHistoryDescription(child)
                    : std::string{}) +
                ".";

            Append(
                "V66 TASK STAGNATION STOP #" +
                std::to_string(
                    v66_task_stagnation_failures) +
                " " +
                v66_failure_message +
                " fail-fast without modifying guest state");

            if (jit) {
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined3);
            }
        }
    }


    bool V69ShouldSample(
        std::uint64_t count) const {

        return
            count <= 8u ||
            (count != 0u &&
             (count & (count - 1u)) == 0u);
    }

    std::uint32_t V69VectorCount(
        std::uint32_t begin,
        std::uint32_t end) const {

        if (begin == 0u ||
            end < begin ||
            ((end - begin) & 3u) != 0u ||
            end - begin > 0x00100000u) {
            return 0xffffffffu;
        }

        return
            (end - begin) /
            4u;
    }

    void V69ObserveTaskA(
        std::uint32_t task,
        const char* stage) {

        constexpr std::uint32_t kTaskAVtable =
            kGuestBase + 0x00cd0bd8u;

        if (!V69Enabled() ||
            task == 0u ||
            mem.Ptr(task, 0x2cu) == nullptr ||
            mem.Read32Guest(task) != kTaskAVtable) {
            return;
        }

        V69TaskASnapshot now;
        now.valid = true;
        now.state18 =
            mem.Read32Guest(task + 0x18u);
        now.owner =
            mem.Read32Guest(task + 0x0cu);
        now.owner8 =
            now.owner != 0u &&
                    mem.Ptr(now.owner + 8u, 4u) != nullptr
                ? mem.Read32Guest(now.owner + 8u)
                : 0xffffffffu;
        now.dep20 =
            mem.Read32Guest(task + 0x20u);
        now.child28 =
            mem.Read32Guest(task + 0x28u);

        auto& previous =
            v69_task_a_snapshots[task];

        const bool changed =
            !previous.valid ||
            previous.state18 != now.state18 ||
            previous.owner != now.owner ||
            previous.owner8 != now.owner8 ||
            previous.dep20 != now.dep20 ||
            previous.child28 != now.child28;

        if (!changed) {
            return;
        }

        previous = now;
        ++v69_task_a_change_events;

        if (v69_task_a_change_events <= 32u ||
            V69ShouldSample(
                v69_task_a_change_events)) {

            Append(
                "V69 TASK-A CHANGE #" +
                std::to_string(
                    v69_task_a_change_events) +
                " stage=" +
                std::string{
                    stage != nullptr
                        ? stage
                        : "unknown"} +
                " tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " task=" +
                V46DescribeGuestAddress(task) +
                " state18=0x" +
                JniProbeHex(now.state18) +
                " owner=" +
                V46DescribeGuestAddress(
                    now.owner) +
                " owner8=0x" +
                JniProbeHex(now.owner8) +
                " dep20=" +
                V46DescribeGuestAddress(
                    now.dep20) +
                " child28=" +
                V46DescribeGuestAddress(
                    now.child28));
        }
    }

    void V69RecordWorkerPreWait(
        std::uint32_t wait_object) {

        if (!V69Enabled()) {
            return;
        }

        ++v69_worker_wait_calls;

        const std::uint32_t flag =
            wait_object != 0u &&
                    mem.Ptr(wait_object + 8u, 4u) != nullptr
                ? mem.Read32Guest(
                      wait_object + 8u)
                : 0xffffffffu;

        if (flag == 0u) {
            ++v69_worker_wait_zero;
        } else if (flag != 0xffffffffu) {
            ++v69_worker_wait_nonzero;
        }

        const bool changed =
            flag !=
            v69_last_worker_wait_flag;

        if (changed ||
            V69ShouldSample(
                v69_worker_wait_calls)) {

            Append(
                "V69 RES-WORKER PREWAIT #" +
                std::to_string(
                    v69_worker_wait_calls) +
                " tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " waitObj=" +
                V46DescribeGuestAddress(
                    wait_object) +
                " pendingFlag=" +
                (flag == 0xffffffffu
                    ? std::string{"UNREADABLE"}
                    : std::to_string(flag)) +
                " zero/nonzero=" +
                std::to_string(
                    v69_worker_wait_zero) +
                "/" +
                std::to_string(
                    v69_worker_wait_nonzero));
        }

        v69_last_worker_wait_flag =
            flag;
    }

    void V69RecordLifecycle(
        const char* stage,
        std::uint32_t task,
        std::uint32_t result_value,
        bool has_result,
        std::uint64_t& event_counter,
        std::uint64_t* true_counter = nullptr) {

        if (!V69Enabled()) {
            return;
        }

        ++event_counter;

        if (has_result &&
            result_value == 1u &&
            true_counter != nullptr) {
            ++(*true_counter);
        }

        std::uint32_t active_count =
            0xffffffffu;
        std::uint32_t completed_count =
            0xffffffffu;

        if (jit) {
            const auto& regs =
                jit->Regs();
            const std::uint32_t manager =
                regs[4];

            if (manager != 0u &&
                mem.Ptr(manager + 0x64u, 4u) != nullptr) {

                active_count =
                    V69VectorCount(
                        mem.Read32Guest(
                            manager + 0x50u),
                        mem.Read32Guest(
                            manager + 0x54u));

                completed_count =
                    V69VectorCount(
                        mem.Read32Guest(
                            manager + 0x5cu),
                        mem.Read32Guest(
                            manager + 0x60u));

                if (active_count !=
                    0xffffffffu) {
                    v69_max_active_count =
                        std::max(
                            v69_max_active_count,
                            active_count);
                }

                if (completed_count !=
                    0xffffffffu) {
                    v69_max_completed_count =
                        std::max(
                            v69_max_completed_count,
                            completed_count);
                }
            }
        }

        if (V69ShouldSample(
                event_counter)) {

            std::ostringstream out;
            out
                << "V69 LIFECYCLE "
                << (stage != nullptr
                        ? stage
                        : "unknown")
                << " #" << event_counter
                << " tid="
                << current_probe_thread_id
                << " task="
                << V46DescribeGuestAddress(task)
                << " vtable="
                << V46DescribeGuestAddress(
                       task != 0u &&
                               mem.Ptr(task, 4u) != nullptr
                           ? mem.Read32Guest(task)
                           : 0u);

            if (has_result) {
                out
                    << " result="
                    << result_value;
            }

            out
                << " activeCount="
                << (active_count == 0xffffffffu
                        ? std::string{"?"}
                        : std::to_string(
                              active_count))
                << " completedCount="
                << (completed_count == 0xffffffffu
                        ? std::string{"?"}
                        : std::to_string(
                              completed_count));

            Append(out.str());
        }

        V69ObserveTaskA(
            task,
            stage);
    }

    void V69AppendSummary(
        const char* reason) {

        if (!V69Enabled() ||
            v69_summary_emitted) {
            return;
        }

        v69_summary_emitted = true;

        std::uint64_t token_increments = 0u;
        std::uint64_t token_decrements = 0u;

        for (const auto& entry :
             v67_token_history) {
            token_increments +=
                entry.second.increments;
            token_decrements +=
                entry.second.decrements;
        }

        Append(
            "V69 LIFECYCLE SUMMARY reason=" +
            std::string{
                reason != nullptr
                    ? reason
                    : "n/a"} +
            " activeReady=" +
            std::to_string(
                v69_active_ready_calls) +
            "/" +
            std::to_string(
                v69_active_ready_true) +
            " phase=" +
            std::to_string(
                v69_active_phase_calls) +
            "/" +
            std::to_string(
                v69_active_phase_true) +
            " startReturns=" +
            std::to_string(
                v69_start_work_returns) +
            " movedToCompleted=" +
            std::to_string(
                v69_completed_moves) +
            " completedPoll=" +
            std::to_string(
                v69_completed_poll_returns) +
            " completedReady=" +
            std::to_string(
                v69_completed_ready_calls) +
            "/" +
            std::to_string(
                v69_completed_ready_true) +
            " terminal=" +
            std::to_string(
                v69_completed_terminal_calls) +
            "/" +
            std::to_string(
                v69_completed_terminal_true) +
            " finalizerReturns=" +
            std::to_string(
                v69_finalizer_returns) +
            " waitFlagZero/nonzero=" +
            std::to_string(
                v69_worker_wait_zero) +
            "/" +
            std::to_string(
                v69_worker_wait_nonzero) +
            " maxVectors(active/completed)=" +
            std::to_string(
                v69_max_active_count) +
            "/" +
            std::to_string(
                v69_max_completed_count) +
            " taskAChanges=" +
            std::to_string(
                v69_task_a_change_events) +
            " tokenEvents=" +
            std::to_string(
                v67_token_events) +
            " tokenInc/dec=" +
            std::to_string(
                token_increments) +
            "/" +
            std::to_string(
                token_decrements) +
            " trackedTokens=" +
            std::to_string(
                v67_token_history.size()));
    }

    void V69EmulateCmp(
        std::uint32_t lhs,
        std::uint32_t rhs) {

        if (!jit) {
            return;
        }

        const std::uint32_t value =
            lhs - rhs;

        std::uint32_t cpsr =
            jit->Cpsr();

        cpsr &= ~0xf0000000u;

        if ((value & 0x80000000u) != 0u) {
            cpsr |= 0x80000000u; // N
        }
        if (value == 0u) {
            cpsr |= 0x40000000u; // Z
        }
        if (lhs >= rhs) {
            cpsr |= 0x20000000u; // C = no borrow
        }
        if (((lhs ^ rhs) &
             (lhs ^ value) &
             0x80000000u) != 0u) {
            cpsr |= 0x10000000u; // V
        }

        jit->SetCpsr(cpsr);
    }

    void V69MaybeBoundedStop() {

        constexpr std::uint64_t
            kLifecycleSampleLimit =
                1048576u;

        if (diagnostic_mode !=
                PvZ2DiagnosticMode::V69TaskResourceLifecycle ||
            current_probe_thread_id != 7u ||
            v69_summary_emitted ||
            v69_active_ready_calls <
                kLifecycleSampleLimit) {
            return;
        }

        V69AppendSummary(
            "bounded-1M-active-ready-sample");

        v66_failure_message =
            "v69 bounded TaskResource lifecycle diagnostic completed after " +
            std::to_string(
                v69_active_ready_calls) +
            " active-ready observations on resource worker tid=7; guest state was not forced.";

        Append(
            "V69 DIAGNOSTIC STOP: " +
            v66_failure_message);

        if (jit) {
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined3);
        }
    }

    void V66EmulateCmpR0Zero() {
        if (!jit) {
            return;
        }

        const std::uint32_t value =
            jit->Regs()[0];

        std::uint32_t cpsr =
            jit->Cpsr();

        // CMP r0,#0 == SUBS without storing the result.
        // Preserve the non-NZCV CPSR bits.
        cpsr &= ~0xf0000000u;
        if ((value & 0x80000000u) != 0u) {
            cpsr |= 0x80000000u; // N
        }
        if (value == 0u) {
            cpsr |= 0x40000000u; // Z
        }
        cpsr |= 0x20000000u;     // C: subtracting zero never borrows.
        // V remains clear.
        jit->SetCpsr(cpsr);
    }

    std::uint64_t V66SteadyNowNs() const {
        const auto now =
            std::chrono::steady_clock::now()
                .time_since_epoch();
        const auto nanos =
            std::chrono::duration_cast<
                std::chrono::nanoseconds>(now)
                .count();
        return
            nanos > 0
                ? static_cast<std::uint64_t>(nanos)
                : 0u;
    }

    bool V66ThreadBlocked(
        std::uint32_t thread_id) const {

        if (!V66Enabled()) {
            return false;
        }

        return
            v66_sem_waits.find(thread_id) !=
                v66_sem_waits.end() ||
            v66_sleeps.find(thread_id) !=
                v66_sleeps.end();
    }

    bool V66HasTimedSleeper() const {
        if (!V66Enabled()) {
            return false;
        }

        if (!v66_sleeps.empty()) {
            return true;
        }

        for (const auto& entry : v66_sem_waits) {
            if (entry.second.timed &&
                entry.second.deadline_realtime_ns != 0u) {
                return true;
            }
        }

        return false;
    }

    bool V66BeginSemaphoreWait(
        std::uint32_t sem,
        bool timed,
        std::uint32_t abstime) {

        if (!V66Enabled() ||
            (current_probe_thread_id == 0u &&
             !V96MainBlockingAllowed())) {
            return false;
        }

        if (V107Enabled()) {
            // Reaching a fresh sem_wait means this executing thread cannot
            // still legitimately be sleeping on an earlier semaphore.
            const auto stale_sem =
                v66_sem_waits.find(
                    current_probe_thread_id);
            if (stale_sem !=
                v66_sem_waits.end()) {
                const std::uint32_t old_sem =
                    stale_sem->second.sem;
                V66EraseSemaphoreWait(
                    current_probe_thread_id,
                    old_sem);
                ++v107_stale_sem_wait_repairs;
                AppendDiagnostic(
                    "V107 STALE SEM WAIT REPAIR #" +
                    std::to_string(
                        v107_stale_sem_wait_repairs) +
                    " tid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " oldSem=" +
                    V46DescribeGuestAddress(
                        old_sem) +
                    " newSem=" +
                    V46DescribeGuestAddress(
                        sem));
            }

            // Likewise, a worker that has actually executed up to sem_wait
            // cannot still be an unconsumed pthread_mutex_lock waiter. A stale
            // mutex record would otherwise be checked before semaphore resume
            // and can permanently mask a legitimate sem_post.
            if (V87MutexWaitPending(
                    current_probe_thread_id)) {
                const auto stale_mutex =
                    v87_mutex_waits.find(
                        current_probe_thread_id);
                const std::uint32_t mutex =
                    stale_mutex !=
                            v87_mutex_waits.end()
                        ? stale_mutex->second.mutex
                        : 0u;
                const bool cond_reacquire =
                    stale_mutex !=
                            v87_mutex_waits.end() &&
                        stale_mutex->second
                            .cond_reacquire;

                if (!cond_reacquire) {
                    V87EraseMutexWait(
                        current_probe_thread_id);
                    ++v107_stale_mutex_wait_repairs;
                    AppendDiagnostic(
                        "V107 STALE MUTEX WAIT REPAIR #" +
                        std::to_string(
                            v107_stale_mutex_wait_repairs) +
                        " tid=" +
                        std::to_string(
                            current_probe_thread_id) +
                        " mutex=" +
                        V46DescribeGuestAddress(
                            mutex) +
                        " enteringSem=" +
                        V46DescribeGuestAddress(
                            sem));
                }
            }
        }

        V66SemaphoreWaitState wait;
        wait.sem = sem;
        wait.timed = timed;

        if (timed && abstime != 0u) {
            const std::uint64_t sec =
                mem.Read32Guest(abstime + 0u);
            const std::uint64_t nsec =
                mem.Read32Guest(abstime + 4u);

            wait.deadline_realtime_ns =
                nsec < 1000000000ull
                    ? sec * 1000000000ull + nsec
                    : V65RealtimeNowNs();
        }

        v66_sem_waits[current_probe_thread_id] =
            wait;

        auto& waiters =
            v66_sem_waiters[sem];

        if (std::find(
                waiters.begin(),
                waiters.end(),
                current_probe_thread_id) ==
            waiters.end()) {
            waiters.push_back(
                current_probe_thread_id);
        }

        ++v66_sem_wait_calls;

        if (v66_sem_wait_calls <= 32u ||
            (v66_sem_wait_calls % 256u) == 0u) {
            Append(
                "V66 SEM WAIT #" +
                std::to_string(v66_sem_wait_calls) +
                " tid=" +
                std::to_string(current_probe_thread_id) +
                " sem=" +
                V46DescribeGuestAddress(sem) +
                (timed
                    ? " timed=YES"
                    : " timed=NO") +
                " -> worker sleeping");
        }

        return true;
    }

    std::uint32_t V66NotifySemaphore(
        std::uint32_t sem) {

        if (!V66Enabled()) {
            return 0u;
        }

        auto found =
            v66_sem_waiters.find(sem);

        if (found !=
            v66_sem_waiters.end()) {
            for (const std::uint32_t tid :
                 found->second) {
                auto wait =
                    v66_sem_waits.find(tid);

                if (wait ==
                        v66_sem_waits.end() ||
                    wait->second.sem != sem ||
                    wait->second.notified) {
                    continue;
                }

                wait->second.notified = true;
                return 1u;
            }
        }

        if (!V107Enabled()) {
            return 0u;
        }

        // v107: v66_sem_waits is authoritative. v66_sem_waiters is only a
        // FIFO acceleration index; if that secondary index diverged, a real
        // sem_post token must not be lost. Wake exactly one matching waiter
        // and repair its FIFO membership for subsequent posts.
        for (auto& entry :
             v66_sem_waits) {
            const std::uint32_t tid =
                entry.first;
            V66SemaphoreWaitState& wait =
                entry.second;

            if (wait.sem != sem ||
                wait.notified) {
                continue;
            }

            wait.notified = true;

            auto& waiters =
                v66_sem_waiters[sem];
            if (std::find(
                    waiters.begin(),
                    waiters.end(),
                    tid) ==
                waiters.end()) {
                waiters.push_back(tid);
            }

            ++v107_sem_index_repairs;
            AppendDiagnostic(
                "V107 SEM INDEX REPAIR #" +
                std::to_string(
                    v107_sem_index_repairs) +
                " sem=" +
                V46DescribeGuestAddress(sem) +
                " tid=" +
                std::to_string(tid) +
                " count=" +
                std::to_string(
                    mem.Read32Guest(sem)));

            return 2u;
        }

        return 0u;
    }

    bool V66BeginSleep(
        std::uint64_t duration_ns,
        const char* kind) {

        if (!V66Enabled() ||
            (current_probe_thread_id == 0u &&
             !V96MainBlockingAllowed())) {
            return false;
        }

        if (duration_ns == 0u) {
            return false;
        }

        V66SleepState sleep;
        const std::uint64_t now =
            V66SteadyNowNs();

        sleep.deadline_steady_ns =
            std::numeric_limits<std::uint64_t>::max() -
                    now < duration_ns
                ? std::numeric_limits<std::uint64_t>::max()
                : now + duration_ns;

        v66_sleeps[current_probe_thread_id] =
            sleep;
        ++v66_sleep_calls;

        if (v66_sleep_calls <= 32u ||
            (v66_sleep_calls % 256u) == 0u) {
            Append(
                "V66 SLEEP #" +
                std::to_string(v66_sleep_calls) +
                " tid=" +
                std::to_string(current_probe_thread_id) +
                " kind=" +
                std::string{kind != nullptr ? kind : "sleep"} +
                " durationNs=" +
                std::to_string(duration_ns));
        }

        return true;
    }

    void V66EraseSemaphoreWait(
        std::uint32_t thread_id,
        std::uint32_t sem) {

        auto waiters =
            v66_sem_waiters.find(sem);

        if (waiters != v66_sem_waiters.end()) {
            auto& ids =
                waiters->second;
            ids.erase(
                std::remove(
                    ids.begin(),
                    ids.end(),
                    thread_id),
                ids.end());

            if (ids.empty()) {
                v66_sem_waiters.erase(waiters);
            }
        }

        v66_sem_waits.erase(thread_id);
    }

    bool V66PrepareBlockingResume(
        std::uint32_t thread_id,
        bool& did_resume,
        std::uint32_t& result_code) {

        did_resume = false;
        result_code = 0u;

        if (!V66Enabled()) {
            return true;
        }

        auto sleep =
            v66_sleeps.find(thread_id);

        if (sleep != v66_sleeps.end()) {
            if (V66SteadyNowNs() <
                sleep->second.deadline_steady_ns) {
                return false;
            }

            v66_sleeps.erase(sleep);
            did_resume = true;
            result_code = 0u;
            ++v66_sleep_resumes;

            if (v66_sleep_resumes <= 32u ||
                (v66_sleep_resumes % 256u) == 0u) {
                Append(
                    "V66 SLEEP RESUME #" +
                    std::to_string(v66_sleep_resumes) +
                    " tid=" +
                    std::to_string(thread_id));
            }

            return true;
        }

        auto found =
            v66_sem_waits.find(thread_id);

        if (found == v66_sem_waits.end()) {
            return true;
        }

        V66SemaphoreWaitState& wait =
            found->second;

        if (!wait.notified &&
            wait.timed &&
            wait.deadline_realtime_ns != 0u &&
            V65RealtimeNowNs() >=
                wait.deadline_realtime_ns) {

            const std::uint32_t sem =
                wait.sem;
            V66EraseSemaphoreWait(
                thread_id,
                sem);

            if (guest_errno_address == 0u) {
                guest_errno_address =
                    mem.AllocateObject(4u, 4u);
            }
            if (guest_errno_address != 0u) {
                mem.Write32Guest(
                    guest_errno_address,
                    110u); // ETIMEDOUT
            }

            did_resume = true;
            result_code = 0xffffffffu;
            ++v66_sem_timeouts;

            Append(
                "V66 SEM TIMEOUT tid=" +
                std::to_string(thread_id) +
                " sem=" +
                V46DescribeGuestAddress(sem));
            return true;
        }

        if (!wait.notified) {
            return false;
        }

        const std::uint32_t count =
            mem.Read32Guest(wait.sem);

        if (count == 0u) {
            // Another successful waiter/trywait consumed the posted token
            // before this cooperative worker was scheduled. Return to sleep
            // and wait for the next post.
            wait.notified = false;
            return false;
        }

        mem.Write32Guest(
            wait.sem,
            count - 1u);

        const std::uint32_t sem =
            wait.sem;

        V66EraseSemaphoreWait(
            thread_id,
            sem);

        did_resume = true;
        result_code = 0u;
        ++v66_sem_resumes;

        if (v66_sem_resumes <= 32u ||
            (v66_sem_resumes % 256u) == 0u) {
            Append(
                "V66 SEM RESUME #" +
                std::to_string(v66_sem_resumes) +
                " tid=" +
                std::to_string(thread_id) +
                " sem=" +
                V46DescribeGuestAddress(sem) +
                " -> token consumed");
        }

        return true;
    }

    bool V65ThreadBlocked(
        std::uint32_t thread_id) const {

        return
            V65Enabled() &&
            v65_cond_waits.find(thread_id) !=
                v65_cond_waits.end();
    }

    bool V87MutexWaitPending(
        std::uint32_t thread_id) const {

        return
            V87Enabled() &&
            v87_mutex_waits.find(thread_id) !=
                v87_mutex_waits.end();
    }

    bool V87MutexWaitGranted(
        std::uint32_t thread_id) const {

        if (!V87Enabled()) {
            return false;
        }

        const auto wait =
            v87_mutex_waits.find(thread_id);

        return
            wait != v87_mutex_waits.end() &&
            wait->second.granted;
    }

    std::uint32_t V87PreferredMutexOwner(
        std::uint32_t waiter_tid) const {

        if (!V87Enabled()) {
            return 0xffffffffu;
        }

        std::unordered_set<std::uint32_t> seen;
        std::uint32_t cursor = waiter_tid;

        for (std::uint32_t depth = 0u;
             depth < 64u;
             ++depth) {

            const auto wait =
                v87_mutex_waits.find(cursor);

            if (wait == v87_mutex_waits.end()) {
                return 0xffffffffu;
            }

            // v97: handoff sets owner/depth and leaves the wait record alive
            // only until V87PrepareMutexResume consumes it. Once granted, that
            // record is not an edge in the wait-for graph.
            if (V97Enabled() &&
                wait->second.granted) {
                return 0xffffffffu;
            }

            const auto mutex =
                v63_mutexes.find(
                    wait->second.mutex);

            if (mutex == v63_mutexes.end() ||
                mutex->second.depth == 0u ||
                mutex->second.owner == 0xffffffffu) {
                return 0xffffffffu;
            }

            const std::uint32_t owner =
                mutex->second.owner;

            if (owner == waiter_tid) {
                return owner;
            }

            const auto owner_wait =
                v87_mutex_waits.find(owner);

            if (owner_wait ==
                    v87_mutex_waits.end() ||
                (V97Enabled() &&
                 owner_wait->second.granted)) {
                // No live dependency beyond this owner. A granted record
                // means the owner must be scheduled to finish its lock call,
                // not followed as though it were still waiting.
                return owner;
            }

            if (!seen.insert(owner).second) {
                return owner;
            }

            cursor = owner;
        }

        return 0xffffffffu;
    }

    void V87EraseMutexWait(
        std::uint32_t thread_id) {

        const auto wait =
            v87_mutex_waits.find(thread_id);

        if (wait == v87_mutex_waits.end()) {
            return;
        }

        const std::uint32_t mutex =
            wait->second.mutex;

        auto queue =
            v87_mutex_waiters.find(mutex);

        if (queue != v87_mutex_waiters.end()) {
            auto& ids = queue->second;

            ids.erase(
                std::remove(
                    ids.begin(),
                    ids.end(),
                    thread_id),
                ids.end());

            if (ids.empty()) {
                v87_mutex_waiters.erase(queue);
            }
        }

        v87_mutex_waits.erase(wait);
    }

    bool V87QueueMutexWait(
        std::uint32_t thread_id,
        std::uint32_t mutex,
        bool cond_reacquire) {

        if (!V87Enabled()) {
            return false;
        }

        const auto existing =
            v87_mutex_waits.find(thread_id);

        if (existing != v87_mutex_waits.end()) {
            return
                existing->second.mutex == mutex &&
                existing->second.cond_reacquire ==
                    cond_reacquire;
        }

        const auto state =
            v63_mutexes.find(mutex);

        if (state == v63_mutexes.end() ||
            state->second.depth == 0u ||
            state->second.owner == 0xffffffffu) {
            return false;
        }

        const std::uint32_t owner =
            state->second.owner;

        std::unordered_set<std::uint32_t> seen;
        seen.insert(thread_id);
        std::uint32_t cursor = owner;

        while (cursor != 0xffffffffu) {
            // The requester is not inserted in v87_mutex_waits until this
            // validation succeeds, so preserve direct self-deadlock detection.
            if (cursor == thread_id) {
                ++v87_deadlock_cycles;

                v87_failure_message =
                    "v87 detected a mutex wait-for cycle: waiterTid=" +
                    std::to_string(thread_id) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex) +
                    " ownerTid=" +
                    std::to_string(owner) +
                    ".";

                result.message =
                    v87_failure_message;

                Append(
                    "V87 MUTEX DEADLOCK #" +
                    std::to_string(v87_deadlock_cycles) +
                    " " +
                    v87_failure_message);

                return false;
            }

            const auto owner_wait =
                v87_mutex_waits.find(cursor);

            // A thread without a wait record owns/runs normally. In v97 a
            // granted record is equivalent for graph purposes: handoff has
            // already assigned ownership, and the record survives only until
            // the thread consumes the pthread_mutex_lock return.
            if (owner_wait ==
                    v87_mutex_waits.end() ||
                (V97Enabled() &&
                 owner_wait->second.granted)) {

                if (owner_wait != v87_mutex_waits.end() &&
                    owner_wait->second.granted) {
                    ++v97_granted_graph_terminals;

                    if (v97_granted_graph_terminals <= 16u ||
                        (v97_granted_graph_terminals &
                         (v97_granted_graph_terminals - 1u)) == 0u) {
                        AppendDiagnostic(
                            "V97 MUTEX GRAPH GRANTED TERMINAL #" +
                            std::to_string(
                                v97_granted_graph_terminals) +
                            " requesterTid=" +
                            std::to_string(thread_id) +
                            " ownerTid=" +
                            std::to_string(cursor) +
                            " mutex=" +
                            V46DescribeGuestAddress(mutex) +
                            " ownerWaitMutex=" +
                            V46DescribeGuestAddress(
                                owner_wait->second.mutex));
                    }
                }

                break;
            }

            // Only an ungranted waiter contributes a live dependency edge.
            if (!seen.insert(cursor).second) {
                ++v87_deadlock_cycles;

                v87_failure_message =
                    "v87 detected a mutex wait-for cycle: waiterTid=" +
                    std::to_string(thread_id) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex) +
                    " ownerTid=" +
                    std::to_string(owner) +
                    ".";

                result.message =
                    v87_failure_message;

                Append(
                    "V87 MUTEX DEADLOCK #" +
                    std::to_string(v87_deadlock_cycles) +
                    " " +
                    v87_failure_message);

                return false;
            }

            const auto owner_mutex =
                v63_mutexes.find(
                    owner_wait->second.mutex);

            if (owner_mutex ==
                    v63_mutexes.end() ||
                owner_mutex->second.depth == 0u) {
                break;
            }

            cursor =
                owner_mutex->second.owner;
        }

        V87MutexWaitState wait;
        wait.mutex = mutex;
        wait.observed_owner = owner;
        wait.cond_reacquire = cond_reacquire;

        v87_mutex_waits[thread_id] =
            wait;

        auto& queue =
            v87_mutex_waiters[mutex];

        if (std::find(
                queue.begin(),
                queue.end(),
                thread_id) == queue.end()) {
            queue.push_back(thread_id);
        }

        ++v87_mutex_wait_calls;

        if (v87_mutex_wait_calls <= 32u ||
            (v87_mutex_wait_calls &
             (v87_mutex_wait_calls - 1u)) == 0u) {
            Append(
                "V87 MUTEX WAIT #" +
                std::to_string(v87_mutex_wait_calls) +
                " tid=" +
                std::to_string(thread_id) +
                " ownerTid=" +
                std::to_string(owner) +
                " mutex=" +
                V46DescribeGuestAddress(mutex) +
                " kind=" +
                std::string{
                    cond_reacquire
                        ? "cond-reacquire"
                        : "lock"});
        }

        return true;
    }

    std::uint32_t V87HandoffMutex(
        std::uint32_t mutex,
        V63MutexState& state) {

        if (!V87Enabled() ||
            state.depth != 0u) {
            return 0xffffffffu;
        }

        auto queue =
            v87_mutex_waiters.find(mutex);

        if (queue ==
            v87_mutex_waiters.end()) {
            return 0xffffffffu;
        }

        while (!queue->second.empty()) {
            const std::uint32_t tid =
                queue->second.front();

            queue->second.pop_front();

            auto wait =
                v87_mutex_waits.find(tid);

            if (wait ==
                    v87_mutex_waits.end() ||
                wait->second.mutex != mutex ||
                wait->second.granted) {
                continue;
            }

            state.owner = tid;
            state.depth = 1u;

            ++v63_thread_held_mutexes[tid];
            ++v63_mutex_acquires;

            wait->second.granted = true;
            ++v87_mutex_handoffs;

            if (v87_mutex_handoffs <= 32u ||
                (v87_mutex_handoffs &
                 (v87_mutex_handoffs - 1u)) == 0u) {
                Append(
                    "V87 MUTEX HANDOFF #" +
                    std::to_string(v87_mutex_handoffs) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex) +
                    " -> tid=" +
                    std::to_string(tid));
            }

            if (queue->second.empty()) {
                v87_mutex_waiters.erase(queue);
            }

            return tid;
        }

        v87_mutex_waiters.erase(queue);
        return 0xffffffffu;
    }

    bool V87PrepareMutexResume(
        std::uint32_t thread_id,
        bool& did_resume,
        std::uint32_t& result_code) {

        did_resume = false;
        result_code = 0u;

        if (!V87Enabled()) {
            return true;
        }

        auto wait =
            v87_mutex_waits.find(thread_id);

        if (wait == v87_mutex_waits.end()) {
            return true;
        }

        // pthread_cond_wait has its own resume path because the condition result
        // code must survive until the mutex is reacquired.
        if (wait->second.cond_reacquire) {
            return true;
        }

        if (!wait->second.granted) {
            return false;
        }

        const auto mutex =
            v63_mutexes.find(
                wait->second.mutex);

        if (mutex == v63_mutexes.end() ||
            mutex->second.depth == 0u ||
            mutex->second.owner != thread_id) {

            v87_failure_message =
                "v87 mutex handoff invariant failed for tid=" +
                std::to_string(thread_id) +
                " mutex=" +
                V46DescribeGuestAddress(
                    wait->second.mutex) +
                ".";

            result.message =
                v87_failure_message;

            Append(
                "V87 MUTEX ERROR " +
                v87_failure_message);

            return false;
        }

        const std::uint32_t mutex_address =
            wait->second.mutex;

        V87EraseMutexWait(thread_id);

        did_resume = true;
        result_code = 0u;
        ++v87_mutex_resumes;

        if (v87_mutex_resumes <= 32u ||
            (v87_mutex_resumes &
             (v87_mutex_resumes - 1u)) == 0u) {
            Append(
                "V87 MUTEX RESUME #" +
                std::to_string(v87_mutex_resumes) +
                " tid=" +
                std::to_string(thread_id) +
                " mutex=" +
                V46DescribeGuestAddress(
                    mutex_address));
        }

        return true;
    }

    bool V96MainBlockingAllowed() const {
        return
            V96Enabled() &&
            return_mode == ReturnMode::Lifecycle &&
            current_probe_thread_id == 0u;
    }

    bool V65HasTimedWaiter() const {
        if (!V65Enabled()) {
            return false;
        }

        for (const auto& entry : v65_cond_waits) {
            if (entry.second.timed &&
                entry.second.deadline_realtime_ns != 0u) {
                return true;
            }
        }

        return false;
    }

    bool HasTimedBlockingWait() const {
        return
            V65HasTimedWaiter() ||
            V66HasTimedSleeper();
    }

    bool V96MainBlockingPending() const {
        return
            V96Enabled() &&
            (V65ThreadBlocked(0u) ||
             V66ThreadBlocked(0u) ||
             V87MutexWaitPending(0u));
    }

    const char* V96MainBlockingKind() const {
        if (!V96Enabled()) {
            return "none";
        }

        if (V65ThreadBlocked(0u)) {
            return
                V87MutexWaitPending(0u)
                    ? "cond-reacquire"
                    : "cond-wait";
        }

        if (v66_sleeps.find(0u) !=
            v66_sleeps.end()) {
            return "sleep";
        }

        if (v66_sem_waits.find(0u) !=
            v66_sem_waits.end()) {
            return "sem-wait";
        }

        if (V87MutexWaitPending(0u)) {
            return "mutex-wait";
        }

        return "none";
    }

    bool V96PrepareMainBlockingResume(
        bool& did_resume,
        std::uint32_t& result_code) {

        did_resume = false;
        result_code = 0u;

        if (!V96Enabled()) {
            return true;
        }

        // Condition waits own the mutex-reacquire state machine. They must
        // run before the generic mutex resume path so ETIMEDOUT/signal result
        // codes survive until the same mutex has actually been reacquired.
        if (V65ThreadBlocked(0u)) {
            bool cond_resumed = false;
            std::uint32_t cond_result = 0u;

            if (!V65PrepareCondResume(
                    0u,
                    cond_resumed,
                    cond_result)) {
                return v87_failure_message.empty();
            }

            if (cond_resumed) {
                did_resume = true;
                result_code = cond_result;
            }

            return true;
        }

        if (V66ThreadBlocked(0u)) {
            bool blocking_resumed = false;
            std::uint32_t blocking_result = 0u;

            if (!V66PrepareBlockingResume(
                    0u,
                    blocking_resumed,
                    blocking_result)) {
                return true;
            }

            if (blocking_resumed) {
                did_resume = true;
                result_code = blocking_result;
            }

            return true;
        }

        if (V87MutexWaitPending(0u)) {
            bool mutex_resumed = false;
            std::uint32_t mutex_result = 0u;

            if (!V87PrepareMutexResume(
                    0u,
                    mutex_resumed,
                    mutex_result)) {
                return v87_failure_message.empty();
            }

            if (mutex_resumed) {
                did_resume = true;
                result_code = mutex_result;
            }

            return true;
        }

        // A pending main wait is never removed by notify/post alone; reaching
        // this path means the blocking state was already consumed.
        did_resume = true;
        result_code = 0u;
        return true;
    }

    void V87RecordOwnerPreemption(
        std::uint32_t thread_id) {

        if (!V87Enabled()) {
            return;
        }

        ++v87_owner_preemptions;

        if (v87_owner_preemptions <= 16u ||
            (v87_owner_preemptions &
             (v87_owner_preemptions - 1u)) == 0u) {
            Append(
                "V87 MUTEX PREEMPT #" +
                std::to_string(v87_owner_preemptions) +
                " tid=" +
                std::to_string(thread_id) +
                " held={" +
                V63HeldMutexSummary(thread_id) +
                "}");
        }
    }

    std::string V87MutexSummary() const {

        std::ostringstream out;

        out
            << "V87 MUTEX SUMMARY waits="
            << v87_mutex_wait_calls
            << " handoffs="
            << v87_mutex_handoffs
            << " resumes="
            << v87_mutex_resumes
            << " ownerPreemptions="
            << v87_owner_preemptions
            << " priorityContinuations="
            << v87_priority_continuations
            << " v88BurstContinuations="
            << v88_burst_continuations
            << " deadlockCycles="
            << v87_deadlock_cycles
            << " v97GrantedGraphTerminals="
            << v97_granted_graph_terminals
            << " pendingWaiters="
            << v87_mutex_waits.size();

        return out.str();
    }

    bool V63AcquireMutex(
        std::uint32_t mutex,
        bool is_trylock) {

        if (!V63Enabled()) {
            return true;
        }

        V63MutexState& state =
            v63_mutexes[mutex];

        if (state.depth == 0u) {
            state.owner =
                current_probe_thread_id;
            state.depth = 1u;
            ++v63_thread_held_mutexes[
                current_probe_thread_id];
            ++v63_mutex_acquires;

            const std::uint64_t acquire_interval =
                V66Enabled()
                    ? 65536u
                    : 512u;

            if (current_probe_thread_id != 0u &&
                (v63_mutex_acquires <= 32u ||
                 (v63_mutex_acquires %
                  acquire_interval) == 0u)) {
                Append(
                    "V63 MUTEX ACQUIRE #" +
                    std::to_string(v63_mutex_acquires) +
                    " tid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex) +
                    " held=" +
                    std::to_string(
                        V63HeldMutexCount(
                            current_probe_thread_id)));
            }

            return true;
        }

        if (state.owner ==
            current_probe_thread_id) {

            if (V87Enabled() &&
                state.type_known &&
                state.type != 1u) {

                if (is_trylock) {
                    ++v63_mutex_busy;
                    return false;
                }

                if (state.type == 2u) {
                    v87_last_mutex_error = 35u; // EDEADLK
                    Append(
                        "V87 MUTEX ERRORCHECK RELOCK tid=" +
                        std::to_string(
                            current_probe_thread_id) +
                        " mutex=" +
                        V46DescribeGuestAddress(mutex) +
                        " -> EDEADLK");
                    return false;
                }

                V87QueueMutexWait(
                    current_probe_thread_id,
                    mutex,
                    false);
                return false;
            }

            ++state.depth;
            ++v63_mutex_acquires;

            if (current_probe_thread_id != 0u &&
                state.depth <= 4u) {
                Append(
                    "V63 MUTEX REENTER tid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex) +
                    " depth=" +
                    std::to_string(state.depth));
            }

            return true;
        }

        ++v63_mutex_busy;

        if (is_trylock) {
            if (v63_mutex_busy <= 16u ||
                (v63_mutex_busy % 256u) == 0u) {
                Append(
                    "V63 MUTEX BUSY #" +
                    std::to_string(v63_mutex_busy) +
                    " requesterTid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " ownerTid=" +
                    std::to_string(state.owner) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex));
            }
            return false;
        }

        if (V87Enabled()) {
            V87QueueMutexWait(
                current_probe_thread_id,
                mutex,
                false);
            return false;
        }

        ++v63_mutex_conflicts;
        Append(
            "V63 MUTEX OWNERSHIP CONFLICT #" +
            std::to_string(v63_mutex_conflicts) +
            " blockingLock requesterTid=" +
            std::to_string(
                current_probe_thread_id) +
            " ownerTid=" +
            std::to_string(state.owner) +
            " mutex=" +
            V46DescribeGuestAddress(mutex) +
            " ownerHeld={" +
            V63HeldMutexSummary(state.owner) +
            "} requesterHeld={" +
            V63HeldMutexSummary(
                current_probe_thread_id) +
            "}");
        return false;
    }

    bool V63ReleaseMutex(
        std::uint32_t mutex) {

        if (!V63Enabled()) {
            return true;
        }

        const auto found =
            v63_mutexes.find(mutex);

        if (found ==
                v63_mutexes.end() ||
            found->second.depth == 0u) {

            if (v63_mutex_releases < 16u) {
                Append(
                    "V63 MUTEX UNTRACKED UNLOCK tid=" +
                    std::to_string(
                        current_probe_thread_id) +
                    " mutex=" +
                    V46DescribeGuestAddress(mutex));
            }

            ++v63_mutex_releases;
            return true;
        }

        V63MutexState& state =
            found->second;

        if (state.owner !=
            current_probe_thread_id) {
            ++v63_mutex_conflicts;
            Append(
                "V63 MUTEX OWNERSHIP CONFLICT #" +
                std::to_string(v63_mutex_conflicts) +
                " unlockerTid=" +
                std::to_string(
                    current_probe_thread_id) +
                " ownerTid=" +
                std::to_string(state.owner) +
                " mutex=" +
                V46DescribeGuestAddress(mutex));
            return false;
        }

        --state.depth;
        ++v63_mutex_releases;

        if (state.depth == 0u) {
            auto held =
                v63_thread_held_mutexes.find(
                    current_probe_thread_id);
            if (held !=
                v63_thread_held_mutexes.end()) {
                if (held->second > 1u) {
                    --held->second;
                } else {
                    v63_thread_held_mutexes.erase(held);
                }
            }

            state.owner = 0xffffffffu;

            const std::uint32_t handoff_tid =
                V87HandoffMutex(
                    mutex,
                    state);

            if (handoff_tid == 0u &&
                current_probe_thread_id != 0u &&
                jit) {
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined4);
            }
        }

        const std::uint32_t held_after =
            V63HeldMutexCount(
                current_probe_thread_id);

        // v63 accidentally logged every hot-loop transition to held=0, which
        // generated >50 MiB before first draw. Keep ownership diagnostics but
        // sample ordinary releases aggressively; the meaningful v64 safe
        // boundary has its own bounded log below.
        const std::uint64_t release_interval =
            V66Enabled()
                ? 65536u
                : 4096u;

        if (current_probe_thread_id != 0u &&
            (v63_mutex_releases <= 32u ||
             (v63_mutex_releases %
              release_interval) == 0u)) {
            Append(
                "V63 MUTEX RELEASE #" +
                std::to_string(v63_mutex_releases) +
                " tid=" +
                std::to_string(
                    current_probe_thread_id) +
                " mutex=" +
                V46DescribeGuestAddress(mutex) +
                " depth=" +
                std::to_string(state.depth) +
                " held=" +
                std::to_string(held_after));
        }

        const bool v64_safe_release =
            V64Enabled() &&
            !V87Enabled() &&
