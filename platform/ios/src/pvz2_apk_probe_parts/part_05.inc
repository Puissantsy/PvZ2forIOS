                const std::uint32_t function_ptr =
                    mem.Read32Guest(entry + 8);

                const std::string native_name =
                    mem.ReadCStringGuest(name_ptr, 192);
                const std::string native_signature =
                    mem.ReadCStringGuest(signature_ptr, 512);

                if (native_name == "Native_GameAppInitialize") {
                    result.game_app_initialize_address =
                        function_ptr;
                    result.game_app_initialize_signature =
                        native_signature;
                } else if (
                    native_name ==
                    "Native_CloudStateLoaded") {
                    native_cloud_state_loaded_address =
                        function_ptr;
                    Append(
                        "V49 CLOUD CALLBACK captured Native_CloudStateLoaded at 0x" +
                        JniProbeHex(function_ptr) +
                        " signature=" +
                        native_signature);
                }

                Append(
                    "  native[" +
                    std::to_string(i) +
                    "] " +
                    native_name +
                    " " +
                    native_signature +
                    " -> 0x" +
                    JniProbeHex(function_ptr));
            }

            regs[0] = 0;
            return;
        }

        if (swi == kJniProbeSvcReturn) {
            control_returned = true;

            if (return_mode == ReturnMode::Constructor) {
                Append(
                    "constructor[" +
                    std::to_string(current_constructor_index) +
                    "] returned from 0x" +
                    JniProbeHex(current_constructor_address));
            } else if (return_mode == ReturnMode::GameAppInitialize) {
                result.returned_game_app_initialize = true;
                result.game_app_initialize_return = regs[0];

                Append(
                    "Native_GameAppInitialize returned 0x" +
                    JniProbeHex(regs[0]));
            } else if (return_mode == ReturnMode::Lifecycle) {
                Append(
                    current_lifecycle_name +
                    " returned.");
            } else if (return_mode == ReturnMode::AudioCallback) {
                // v102 inline OpenSL completion: deliberately quiet. The
                // bounded V102 AUDIO PACER/INLINE markers carry the useful
                // telemetry without one log line per 1024 audio frames.
            } else {
                result.returned_from_jni_onload = true;
                result.return_value = regs[0];

                Append(
                    "JNI_OnLoad returned 0x" +
                    JniProbeHex(regs[0]));
            }

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined1);
            return;
        }

        if (swi >= kJniProbeSvcUnsupportedJniBase &&
            swi < kJniProbeSvcUnsupportedJniBase +
                    kJniProbeJniSlotCount) {

            const std::uint32_t slot =
                swi - kJniProbeSvcUnsupportedJniBase;

            auto new_object =
                [&]() {
                    return
                        0x55000000u +
                        (next_synthetic_object++ * 0x100u);
                };

            auto new_string =
                [&](const std::string& value) {
                    const std::uint32_t handle =
                        new_object();
                    jni_strings[handle] = value;
                    return handle;
                };

            auto log_jni_fallback =
                [&](const std::string& label) {
                    const std::string key =
                        "jni:" + std::to_string(slot);

                    if (fallback_logged.insert(key).second) {
                        Append(
                            "JNI COMPAT FALLBACK: slot=" +
                            std::to_string(slot) +
                            " " +
                            label);
                    }
                };

            // Reference management. Slot 24 is the exact blocker reached by
            // v13 (IsSameObject).
            switch (slot) {
            case 4: // GetVersion
                regs[0] = kJniVersion14;
                return;

            case 5: // DefineClass
                regs[0] =
                    0x53000000u +
                    (next_synthetic_class++ * 0x100u);
                log_jni_fallback("DefineClass");
                return;

            case 7: // FromReflectedMethod
            case 8: // FromReflectedField
                regs[0] =
                    slot == 7
                        ? 0x54000000u +
                            (next_synthetic_method++ * 0x100u)
                        : 0x54100000u +
                            (next_synthetic_field++ * 0x100u);
                log_jni_fallback(
                    slot == 7
                        ? "FromReflectedMethod"
                        : "FromReflectedField");
                return;

            case 9:  // ToReflectedMethod
            case 12: // ToReflectedField
                regs[0] = new_object();
                log_jni_fallback("reflected member object");
                return;

            case 10: // GetSuperclass
                regs[0] = regs[1];
                return;

            case 11: // IsAssignableFrom
                regs[0] = 1;
                return;

            case 13: // Throw
            case 14: // ThrowNew
                // Probe mode keeps Java exceptions non-fatal and reports the
                // call once. Real exception state comes with the Java bridge.
                regs[0] = 0;
                log_jni_fallback(
                    slot == 13 ? "Throw" : "ThrowNew");
                return;

            case 15: // ExceptionOccurred
                regs[0] = 0;
                return;

            case 16: // ExceptionDescribe
            case 17: // ExceptionClear
                regs[0] = 0;
                return;

            case 18: { // FatalError
                const std::string detail =
                    "JNI FatalError reached at LR=0x" +
                    JniProbeHex(
                        jit ? jit->Regs()[14] : 0u);

                RecordSweepIssue(
                    "jni-fatal",
                    JniProbeHex(
                        jit ? jit->Regs()[14] : 0u),
                    detail);

                if (ConsumeSweepRecovery(
                        "jni-fatal",
                        detail)) {
                    regs[0] = 0u;
                    return;
                }

                result.message =
                    detail;
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            case 19: // PushLocalFrame
                regs[0] = 0;
                return;

            case 20: // PopLocalFrame
                regs[0] = regs[1];
                return;

            case 22: // DeleteGlobalRef
            case 23: // DeleteLocalRef
                regs[0] = 0;
                return;

            case 24: // IsSameObject
                regs[0] =
                    regs[1] == regs[2]
                        ? 1u
                        : 0u;

                ++v52_is_same_object_calls;

                // v52: this is one of the noisiest harmless JNI calls. Keep
                // enough samples to diagnose semantics without paying for a
                // persistent log write on every invocation.
                if (v52_is_same_object_calls <= 8u ||
                    (v52_is_same_object_calls % 1000u) == 0u) {
                    Append(
                        "V52 JNI IsSameObject call#" +
                        std::to_string(
                            v52_is_same_object_calls) +
                        "(0x" +
                        JniProbeHex(regs[1]) +
                        ",0x" +
                        JniProbeHex(regs[2]) +
                        ") -> " +
                        std::to_string(
                            regs[0]));
                }
                return;

            case 25: // NewLocalRef
                regs[0] = regs[1];
                return;

            case 26: // EnsureLocalCapacity
                regs[0] = 0;
                return;

            case 27: // AllocObject
            case 28: // NewObject
            case 29: // NewObjectV
            case 30: { // NewObjectA
                const std::uint32_t handle =
                    new_object();

                if (slot >= 28u) {
                    const std::uint32_t method_id =
                        regs[2];

                    const auto name_it =
                        jni_method_names.find(
                            method_id);
                    const auto sig_it =
                        jni_method_signatures.find(
                            method_id);

                    const std::string method_name =
                        name_it !=
                                jni_method_names.end()
                            ? name_it->second
                            : std::string{};

                    const std::string signature =
                        sig_it !=
                                jni_method_signatures.end()
                            ? sig_it->second
                            : std::string{};

                    // AndroidHttpTransaction.<init>(
                    //   long nativePeer, String method, String url)
                    // is reached through NewObjectV in this APK. Preserve
                    // the low 32-bit ARM guest pointer carried by the jlong.
                    if (method_name == "<init>" &&
                        signature ==
                            "(JLjava/lang/String;Ljava/lang/String;)V") {

                        std::uint64_t peer64 = 0u;

                        if (slot == 29u) {
                            const std::uint32_t aligned =
                                (regs[3] + 7u) &
                                ~7u;
                            peer64 =
                                mem.Read64Guest(
                                    aligned);
                        } else if (slot == 30u) {
                            // jvalue[] entries are 8 bytes.
                            peer64 =
                                mem.Read64Guest(
                                    regs[3]);
                        } else if (slot == 28u) {
                            // Direct varargs follow r0-r3. The first jlong is
                            // double-word aligned on the ARM32 stack.
                            const std::uint32_t aligned =
                                (regs[13] + 7u) &
                                ~7u;
                            peer64 =
                                mem.Read64Guest(
                                    aligned);
                        }

                        const std::uint32_t peer =
                            static_cast<std::uint32_t>(
                                peer64);

                        if (peer != 0u &&
                            mem.Ptr(
                                peer,
                                4u) != nullptr) {

                            jni_native_http_peers[
                                handle] =
                                peer;

                            Append(
                                "V34 HTTP object: java=0x" +
                                JniProbeHex(handle) +
                                " nativePeer=0x" +
                                JniProbeHex(peer) +
                                " constructorSlot=" +
                                std::to_string(slot));
                        } else {
                            Append(
                                "V34 HTTP object: unable to recover native peer for java=0x" +
                                JniProbeHex(handle) +
                                " rawLow=0x" +
                                JniProbeHex(peer));
                        }
                    }
                }

                regs[0] = handle;
                log_jni_fallback("object construction");
                return;
            }

            case 32: // IsInstanceOf
                regs[0] = 1;
                return;

            default:
                break;
            }

            // Instance, nonvirtual and static Java method calls. The probe
            // records method IDs from GetMethodID/GetStaticMethodID and uses
            // the JNI return family to provide deterministic values.
            auto handle_call_family =
                [&](std::uint32_t family_base,
                    bool nonvirtual) -> bool {

                    if (slot < family_base ||
                        slot >= family_base + 30u) {
                        return false;
                    }

                    const std::uint32_t family =
                        (slot - family_base) / 3u;

                    const std::uint32_t method_id =
                        nonvirtual
                            ? regs[3]
                            : regs[2];

                    const auto name_it =
                        jni_method_names.find(method_id);
                    const auto sig_it =
                        jni_method_signatures.find(method_id);

                    const std::string method_name =
                        name_it == jni_method_names.end()
                            ? std::string{"<unknown>"}
                            : name_it->second;

                    const std::string signature =
                        sig_it == jni_method_signatures.end()
                            ? std::string{}
                            : sig_it->second;

                    const std::uint32_t call_variant =
                        (slot - family_base) % 3u;

                    V52ObserveJniCallsite(
                        method_name);

                    auto java_arg_word =
                        [&](std::uint32_t index)
                            -> std::uint32_t {

                            if (nonvirtual) {
                                if (call_variant == 0u) {
                                    return
                                        mem.Read32Guest(
                                            regs[13] +
                                            index * 4u);
                                }

                                const std::uint32_t argument_block =
                                    mem.Read32Guest(
                                        regs[13]);

                                if (call_variant == 1u) {
                                    return
                                        mem.Read32Guest(
                                            argument_block +
                                            index * 4u);
                                }

                                return
                                    mem.Read32Guest(
                                        argument_block +
                                        index * 8u);
                            }

                            if (call_variant == 0u) {
                                if (index == 0u) {
                                    return regs[3];
                                }

                                return
                                    mem.Read32Guest(
                                        regs[13] +
                                        (index - 1u) * 4u);
                            }

                            const std::uint32_t argument_block =
                                regs[3];

                            if (call_variant == 1u) {
                                return
                                    mem.Read32Guest(
                                        argument_block +
                                        index * 4u);
                            }

                            return
                                mem.Read32Guest(
                                    argument_block +
                                    index * 8u);
                        };

                    auto java_string_value =
                        [&](std::uint32_t handle)
                            -> std::string {

                            const auto it =
                                jni_strings.find(handle);

                            return
                                it == jni_strings.end()
                                    ? std::string{}
                                    : it->second;
                        };

                    if (fallback_logged.insert(
                            "jni-call:" + method_name + ":" +
                            std::to_string(family)).second) {

                        Append(
                            "JNI method fallback: " +
                            method_name +
                            " sig=" +
                            signature +
                            " slot=" +
                            std::to_string(slot));
                    }

                    // Method-specific Android surface needed by the real
                    // PvZ2 1.5 resource loader. The original Java returns an
                    // absolute .obb path; the in-memory VFS below recognizes
                    // that guest path and serves the selected expansion bytes.
                    if (family == 0 &&
                        method_name ==
                            "FrameworkInfo_SysGetMainExpansionFilePath") {

                        regs[0] =
                            new_string(
                                "/storage/emulated/0/Android/obb/com.ea.game.pvz2_row/main.7.com.ea.game.pvz2_row.obb");

                        Append(
                            "JNI bridge: FrameworkInfo_SysGetMainExpansionFilePath -> /storage/emulated/0/Android/obb/com.ea.game.pvz2_row/main.7.com.ea.game.pvz2_row.obb");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Resources_GetExternalStorageDirectory") {

                        regs[0] =
                            new_string(
                                "/storage/emulated/0");
                        Append(
                            "JNI bridge: Resources_GetExternalStorageDirectory -> /storage/emulated/0");
                        return true;
                    }

                    if (family == 0 &&
                        (method_name == "Resources_GetResourceFolder" ||
                         method_name == "Resources_GetUserDataFolder" ||
                         method_name == "Resources_GetAppSupportDataFolder")) {

                        regs[0] =
                            new_string(
                                "/data/data/com.ea.game.pvz2_row/files");
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> /data/data/com.ea.game.pvz2_row/files");
                        return true;
                    }

                    if (family == 0 &&
                        (method_name == "Device_GetCachesDir" ||
                         method_name == "Resources_GetCacheDataFolder")) {

                        regs[0] =
                            new_string(
                                "/data/data/com.ea.game.pvz2_row/cache");
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> /data/data/com.ea.game.pvz2_row/cache");
                        return true;
                    }

                    // v25 semantic Android/JNI bridge batch. These are
                    // high-confidence methods observed by the v24 sweep
                    // before any speculative recovery.
                    if (family == 0 &&
                        method_name ==
                            "Info_SysGetPackageName") {

                        regs[0] =
                            new_string(
                                "com.ea.game.pvz2_row");
                        Append(
                            "JNI bridge: Info_SysGetPackageName -> com.ea.game.pvz2_row");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Info_SysGetProductVersionString") {

                        regs[0] =
                            new_string(
                                "1.5.252752");
                        Append(
                            "JNI bridge: Info_SysGetProductVersionString -> 1.5.252752");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Info_SysGetUserLocale") {

                        // Keep resource discovery deterministic for the
                        // original 2013 data set. A later presentation layer
                        // can expose the real iOS locale.
                        regs[0] =
                            new_string(
                                "en_US");
                        Append(
                            "JNI bridge: Info_SysGetUserLocale -> en_US");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Device_GetDeviceName") {

                        regs[0] =
                            new_string(
                                "iPad13,18");
                        Append(
                            "JNI bridge: Device_GetDeviceName -> iPad13,18");
                        return true;
                    }

                    if (family == 5 &&
                        method_name ==
                            "GetNetworkStatus") {

                        ++v50_network_status_calls;

                        // Verified directly from this APK's Java
                        // AndroidHttpProxy.GetNetworkStatus bytecode:
                        //   0 = no active network
                        //   1 = mobile/WiMAX
                        //   2 = Wi-Fi
                        //   3 = another connected transport
                        //
                        // v38 returned 0. v50 exercises the real connected
                        // Wi-Fi path because libPVZ2 contains
                        // GAME_WaitForNetworkLoad and v49 proved the cloud
                        // completion itself is not the post-EA blocker.
                        regs[0] = 2u;

                        if (v50_network_status_calls <=
                                12u ||
                            (v50_network_status_calls %
                             500u) == 0u) {
                            Append(
                                "V50 JNI bridge: GetNetworkStatus -> 2 (Wi-Fi) call#" +
                                std::to_string(
                                    v50_network_status_calls) +
                                " frame=" +
                                std::to_string(
                                    current_frame_number));
                        }
                        return true;
                    }

                    if (family == 5 &&
                        method_name ==
                            "Device_GetCurrentUIOrientation") {

                        // Android Configuration.ORIENTATION_LANDSCAPE.
                        regs[0] = 2u;
                        Append(
                            "JNI bridge: Device_GetCurrentUIOrientation -> 2 (landscape)");
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Graphics_IsOpenGLES20") {

                        regs[0] = 1u;
                        Append(
                            "JNI bridge: Graphics_IsOpenGLES20 -> true");
                        return true;
                    }

                    if (family == 9 &&
                        method_name ==
                            "Graphics_GetScreenSizeInPixels") {

                        const std::uint32_t array =
                            java_arg_word(0u);

                        const auto data_it =
                            jni_array_data.find(array);
                        const auto length_it =
                            jni_array_lengths.find(array);

                        const std::uint32_t pixels_w =
                            V77Enabled()
                                ? 2048u
                                : (V76Enabled() &&
                                   v76_gl_view_scale_set
                                       ? host_surface_width
                                       : 2360u);
                        const std::uint32_t pixels_h =
                            V77Enabled()
                                ? 1536u
                                : (V76Enabled() &&
                                   v76_gl_view_scale_set
                                       ? host_surface_height
                                       : 1640u);

                        if (data_it !=
                                jni_array_data.end() &&
                            length_it !=
                                jni_array_lengths.end() &&
                            length_it->second >= 2u &&
                            data_it->second != 0u) {

                            mem.Write32Guest(
                                data_it->second + 0u,
                                pixels_w);
                            mem.Write32Guest(
                                data_it->second + 4u,
                                pixels_h);
                        }

                        regs[0] = 0u;
                        Append(
                            std::string{
                                V77Enabled()
                                    ? "V77 JNI bridge: "
                                    : "JNI bridge: "} +
                            "Graphics_GetScreenSizeInPixels -> " +
                            std::to_string(pixels_w) +
                            "x" +
                            std::to_string(pixels_h));
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Config_ConfigKeyExists") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const bool exists =
                            v51_config_keys.count(key) != 0u;

                        regs[0] =
                            exists
                                ? 1u
                                : 0u;

                        if (v51_config_logged_keys
                                .insert(
                                    "exists:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG exists key=\"" +
                                key +
                                "\" -> " +
                                (exists
                                    ? std::string{"true"}
                                    : std::string{"false"}));
                        }
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Config_ConfigWriteString") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const std::string value =
                            java_string_value(
                                java_arg_word(1u));

                        v51_config_keys.insert(key);
                        v51_config_strings[key] = value;
                        regs[0] = 1u;

                        if (v51_config_logged_keys
                                .insert(
                                    "write-string:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG write-string key=\"" +
                                key +
                                "\" bytes=" +
                                std::to_string(
                                    value.size()));
                        }
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Config_ConfigWriteInteger") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const std::int32_t value =
                            static_cast<std::int32_t>(
                                java_arg_word(1u));

                        v51_config_keys.insert(key);
                        v51_config_integers[key] = value;
                        regs[0] = 1u;

                        if (v51_config_logged_keys
                                .insert(
                                    "write-int:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG write-int key=\"" +
                                key +
                                "\" value=" +
                                std::to_string(value));
                        }
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Config_ConfigWriteBoolean") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const bool value =
                            java_arg_word(1u) != 0u;

                        v51_config_keys.insert(key);
                        v51_config_booleans[key] = value;
                        regs[0] = 1u;

                        if (v51_config_logged_keys
                                .insert(
                                    "write-bool:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG write-bool key=\"" +
                                key +
                                "\" value=" +
                                (value
                                    ? std::string{"true"}
                                    : std::string{"false"}));
                        }
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Config_ConfigReadString") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const auto it =
                            v51_config_strings.find(key);
                        const std::string value =
                            it != v51_config_strings.end()
                                ? it->second
                                : std::string{};

                        regs[0] =
                            new_string(value);

                        if (v51_config_logged_keys
                                .insert(
                                    "read-string:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG read-string key=\"" +
                                key +
                                "\" -> " +
                                (it != v51_config_strings.end()
                                    ? std::string{"stored"}
                                    : std::string{"empty"}));
                        }
                        return true;
                    }

                    if (family == 5 &&
                        method_name ==
                            "Config_ConfigReadInteger") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const auto it =
                            v51_config_integers.find(key);
                        regs[0] =
                            it != v51_config_integers.end()
                                ? static_cast<std::uint32_t>(
                                      it->second)
                                : 0u;

                        if (v51_config_logged_keys
                                .insert(
                                    "read-int:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG read-int key=\"" +
                                key +
                                "\" -> " +
                                (it != v51_config_integers.end()
                                    ? std::to_string(
                                          it->second)
                                    : std::string{"0"}));
                        }
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Config_ConfigReadBoolean") {

                        const std::string key =
                            java_string_value(
                                java_arg_word(0u));
                        const auto it =
                            v51_config_booleans.find(key);
                        const bool value =
                            it != v51_config_booleans.end() &&
                            it->second;
                        regs[0] =
                            value
                                ? 1u
                                : 0u;

                        if (v51_config_logged_keys
                                .insert(
                                    "read-bool:" + key)
                                .second) {
                            Append(
                                "V51 CONFIG read-bool key=\"" +
                                key +
                                "\" -> " +
                                (value
                                    ? std::string{"true"}
                                    : std::string{"false"}));
                        }
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Util_GetUUIDString") {

                        // The Android helper is used as a persistent device
                        // identifier/config key. A stable non-empty UUID is
                        // more faithful than the old empty-string fallback and
                        // keeps probe runs deterministic.
                        regs[0] =
                            new_string(
                                "8f76d9e4-6a52-4b6a-9f0e-152527520001");

                        Append(
                            "JNI bridge: Util_GetUUIDString -> stable probe UUID");
                        return true;
                    }

                    // v29 established the safe empty-pump fallback.
                    // v72 now implements the exact AndroidUIEventManager
                    // DirectByteBuffer ABI recovered from classes.dex:
                    //   header[0] = event count, records begin at +16;
                    //   touch record = 48 bytes, little-endian.
                    if (family == 1 &&
                        method_name ==
                            "UI_ProcessEvents") {

                        const std::uint32_t buffer_handle =
                            java_arg_word(0u);

                        const auto address_it =
                            jni_direct_buffer_address.find(
                                buffer_handle);
                        const auto capacity_it =
                            jni_direct_buffer_capacity.find(
                                buffer_handle);

                        std::size_t cleared = 0u;
                        std::uint8_t* buffer = nullptr;

                        if (address_it !=
                                jni_direct_buffer_address.end() &&
                            capacity_it !=
                                jni_direct_buffer_capacity.end() &&
                            address_it->second != 0u &&
                            capacity_it->second != 0u) {

                            const std::uint64_t bounded64 =
                                std::min<std::uint64_t>(
                                    capacity_it->second,
                                    1u << 20);

                            const std::size_t bytes =
                                static_cast<std::size_t>(
                                    bounded64);

                            if (auto* p =
                                    mem.Ptr(
                                        address_it->second,
                                        bytes)) {
                                std::memset(
                                    p,
                                    0,
                                    bytes);
                                cleared = bytes;
                                buffer = p;
                            }
                        }

                        ++v52_ui_process_events_calls;

                        if (V72Enabled()) {
                            if (buffer == nullptr ||
                                cleared <
                                    kV72EventHeaderBytes) {

                                regs[0] = 0u;
                                ++v72_invalid_event_buffers;

                                if (v72_invalid_event_buffers <=
                                    8u) {
                                    Append(
                                        "V72 UI EVENT BUFFER invalid#" +
                                        std::to_string(
                                            v72_invalid_event_buffers) +
                                        " handle=0x" +
                                        JniProbeHex(
                                            buffer_handle) +
                                        " bytes=" +
                                        std::to_string(
                                            cleared) +
                                        " pendingTouch=" +
                                        std::to_string(
                                            V72PendingTouchCount()) +
                                        " pendingPinch=" +
                                        std::to_string(
                                            V110PendingPinchCount()) +
                                        " pendingText=" +
                                        std::to_string(
                                            V73PendingTextCount()));
                                }

                                return true;
                            }

                            std::size_t write_offset =
                                kV72EventHeaderBytes;
                            std::uint32_t event_count = 0u;

                            const std::size_t max_touch_events =
                                (cleared - write_offset) /
                                kV72TouchRecordBytes;

                            bool more_touch = false;
                            const std::vector<V72TouchEvent> events =
                                V72TakeTouchEvents(
                                    max_touch_events,
                                    more_touch);

                            for (const V72TouchEvent& event :
                                 events) {

                                if (V85PerformanceEnabled()) V85RecordTouchProcess(event);

                                if (V82Enabled()) {
                                    ++v82_touch_serial;
                                    v82_last_touch_x = event.x;
                                    v82_last_touch_y = event.y;
                                    v82_last_touch_previous_x = event.previous_x;
                                    v82_last_touch_previous_y = event.previous_y;
                                    v82_last_touch_phase = event.phase;
                                    v82_last_touch_frame = current_frame_number;

                                    if ((event.phase == 0u ||
                                         event.phase == 3u ||
                                         event.phase == 4u) &&
                                        v82_touch_radar_logs < 256u) {
                                        ++v82_touch_radar_logs;
                                        Append(
                                            "V82 TOUCH RADAR #" +
                                            std::to_string(v82_touch_radar_logs) +
                                            " " + V82TouchContext() + " " +
                                            V82RadarSnapshot(event.x, event.y));
                                    }
                                }

                                std::uint8_t* record =
                                    buffer +
                                    write_offset;

                                // Android UITouchEvent.Serialize order:
                                // type, ident, XY, previousXY, tapCount,
                                // timestamp(double), phase, two sentinels.
                                Write32(record + 0x00u, 0u);
                                Write32(
                                    record + 0x04u,
                                    event.pointer_id + 1u);
                                Write32(
                                    record + 0x08u,
                                    static_cast<std::uint32_t>(
                                        event.x));
                                Write32(
                                    record + 0x0cu,
                                    static_cast<std::uint32_t>(
                                        event.y));
                                Write32(
                                    record + 0x10u,
                                    static_cast<std::uint32_t>(
                                        event.previous_x));
                                Write32(
                                    record + 0x14u,
                                    static_cast<std::uint32_t>(
                                        event.previous_y));
                                Write32(record + 0x18u, 1u);

                                std::uint64_t timestamp_bits = 0u;
                                static_assert(
                                    sizeof(timestamp_bits) ==
                                    sizeof(event.timestamp_ms));
                                std::memcpy(
                                    &timestamp_bits,
                                    &event.timestamp_ms,
                                    sizeof(timestamp_bits));

                                for (std::size_t byte = 0u;
                                     byte < 8u;
                                     ++byte) {
                                    record[
                                        0x1cu + byte] =
                                        static_cast<std::uint8_t>(
                                            timestamp_bits >>
                                            (byte * 8u));
                                }

                                Write32(
                                    record + 0x24u,
                                    event.phase);
                                Write32(
                                    record + 0x28u,
                                    0xdeadbeefu);
                                Write32(
                                    record + 0x2cu,
                                    0xdeadbeefu);

                                write_offset +=
                                    kV72TouchRecordBytes;
                                ++event_count;
                            }

                            if (!events.empty()) {
                                ++v72_touch_batches;
                                v72_touch_events_delivered +=
                                    events.size();

                                const V72TouchEvent& first =
                                    events.front();

                                Append(
                                    "V72 UI EVENTS batch#" +
                                    std::to_string(
                                        v72_touch_batches) +
                                    " count=" +
                                    std::to_string(
                                        events.size()) +
                                    " more=" +
                                    (more_touch
                                        ? std::string{"YES"}
                                        : std::string{"NO"}) +
                                    " first{ident=" +
                                    std::to_string(
                                        first.pointer_id + 1u) +
                                    ",phase=" +
                                    std::to_string(
                                        first.phase) +
                                    ",xy=" +
                                    std::to_string(
                                        first.x) +
                                    "," +
                                    std::to_string(
                                        first.y) +
                                    ",prev=" +
                                    std::to_string(
                                        first.previous_x) +
                                    "," +
                                    std::to_string(
                                        first.previous_y) +
                                    "}");

                                if (V80Enabled()) {
                                    for (std::size_t i = 0u;
                                         i < events.size() &&
                                         v81_touch_events_logged < 192u;
                                         ++i) {
                                        const V72TouchEvent& event =
                                            events[i];
                                        ++v81_touch_events_logged;
                                        Append(
                                            "V81 TOUCH DELIVER #" +
                                            std::to_string(v81_touch_events_logged) +
                                            " mode=" +
                                            (V81Enabled()
                                                ? std::string{"LOGICAL_POINTS"}
                                                : std::string{"PIXEL_CONTROL"}) +
                                            " batch=" +
                                            std::to_string(v72_touch_batches) +
                                            " index=" +
                                            std::to_string(i) +
                                            " ident=" +
                                            std::to_string(event.pointer_id + 1u) +
                                            " phase=" +
                                            std::to_string(event.phase) +
                                            " xy=" +
                                            std::to_string(event.x) +
                                            "," +
                                            std::to_string(event.y) +
                                            " prev=" +
                                            std::to_string(event.previous_x) +
                                            "," +
                                            std::to_string(event.previous_y));
                                    }
                                }
                            }

                            bool more_pinch = false;
                            std::uint32_t pinch_delivered = 0u;

                            if (V110Enabled()) {
                                const std::size_t max_pinch_events =
                                    (cleared - write_offset) /
                                    kV110PinchRecordBytes;
                                const std::vector<V110PinchEvent> pinch_events =
                                    V110TakePinchEvents(
                                        max_pinch_events,
                                        more_pinch);

                                for (const V110PinchEvent& event : pinch_events) {
                                    std::uint8_t* record = buffer + write_offset;
                                    Write32(record + 0x00u, 3u);
                                    Write32(record + 0x04u,
                                        static_cast<std::uint32_t>(event.x));
                                    Write32(record + 0x08u,
                                        static_cast<std::uint32_t>(event.y));

                                    std::uint32_t dist_bits = 0u;
                                    std::uint32_t delta_bits = 0u;
                                    static_assert(sizeof(dist_bits) ==
                                                  sizeof(event.scale_dist_sq));
                                    static_assert(sizeof(delta_bits) ==
                                                  sizeof(event.scale_delta));
                                    std::memcpy(&dist_bits,
                                                &event.scale_dist_sq,
                                                sizeof(dist_bits));
                                    std::memcpy(&delta_bits,
                                                &event.scale_delta,
                                                sizeof(delta_bits));
                                    Write32(record + 0x0cu, dist_bits);
                                    Write32(record + 0x10u, delta_bits);
                                    Write32(record + 0x14u, 0xdeadbeefu);
                                    Write32(record + 0x18u, 0xdeadbeefu);
                                    Write32(record + 0x1cu, 0xdeadbeefu);
                                    write_offset += kV110PinchRecordBytes;
                                    ++pinch_delivered;
                                    ++event_count;
                                }

                                if (pinch_delivered != 0u) {
                                    ++v110_pinch_batches;
                                    v110_pinch_events_delivered += pinch_delivered;
                                    if (v110_pinch_batches <= 16u ||
                                        (v110_pinch_batches &
                                         (v110_pinch_batches - 1u)) == 0u) {
                                        const V110PinchEvent& first =
                                            pinch_events.front();
                                        Append(
                                            "V110 PINCH EVENTS batch#" +
                                            std::to_string(v110_pinch_batches) +
                                            " count=" +
                                            std::to_string(pinch_delivered) +
                                            " more=" +
                                            (more_pinch ? "YES" : "NO") +
                                            " midpoint=" +
                                            std::to_string(first.x) + "," +
                                            std::to_string(first.y) +
                                            " distSq=" +
                                            std::to_string(first.scale_dist_sq) +
                                            " delta=" +
                                            std::to_string(first.scale_delta));
                                    }
                                }
                            }

                            bool more_text = false;
                            std::uint32_t text_delivered = 0u;
                            std::uint64_t text_bytes = 0u;
                            std::uint32_t first_text_action = 0u;
                            std::size_t first_text_bytes = 0u;
                            bool first_text_seen = false;

                            if (V73Enabled()) {
                                std::lock_guard<std::mutex> lock(
                                    gV73TextMutex);

                                while (!gV73TextQueue.empty()) {
                                    const V73TextInputEvent& event =
                                        gV73TextQueue.front();

                                    const std::size_t padded =
                                        (event.utf8.size() + 3u) &
                                        ~std::size_t{3u};
                                    const std::size_t record_size =
                                        12u + padded;

                                    if (record_size >
                                        cleared - write_offset) {
                                        break;
                                    }

                                    std::uint8_t* record =
                                        buffer +
                                        write_offset;

                                    Write32(record + 0u, 6u);
                                    Write32(
                                        record + 4u,
                                        event.action);
                                    Write32(
                                        record + 8u,
                                        static_cast<std::uint32_t>(
                                            event.utf8.size()));

                                    if (!event.utf8.empty()) {
                                        std::memcpy(
                                            record + 12u,
                                            event.utf8.data(),
                                            event.utf8.size());
                                    }

                                    if (padded >
                                        event.utf8.size()) {
                                        std::memset(
                                            record +
                                                12u +
                                                event.utf8.size(),
                                            0,
                                            padded -
                                                event.utf8.size());
                                    }

                                    if (!first_text_seen) {
                                        first_text_seen = true;
                                        first_text_action =
                                            event.action;
                                        first_text_bytes =
                                            event.utf8.size();
                                    }

                                    text_bytes +=
                                        event.utf8.size();
                                    ++text_delivered;
                                    ++event_count;
                                    write_offset +=
                                        record_size;

                                    gV73TextQueue.pop_front();
                                }

                                more_text =
                                    !gV73TextQueue.empty();
                            }

                            if (text_delivered != 0u) {
                                ++v73_text_batches;
                                v73_text_events_delivered +=
                                    text_delivered;
                                v73_text_bytes_delivered +=
                                    text_bytes;

                                Append(
                                    "V73 TEXT EVENTS batch#" +
                                    std::to_string(
                                        v73_text_batches) +
                                    " count=" +
                                    std::to_string(
                                        text_delivered) +
                                    " bytes=" +
                                    std::to_string(
                                        text_bytes) +
                                    " more=" +
                                    (more_text
                                        ? std::string{"YES"}
                                        : std::string{"NO"}) +
                                    " first{action=" +
                                    std::to_string(
                                        first_text_action) +
                                    ",bytes=" +
                                    std::to_string(
                                        first_text_bytes) +
                                    "}");
                            }

                            Write32(
                                buffer,
                                event_count);

                            regs[0] =
                                (more_touch ||
                                 more_pinch ||
                                 more_text)
                                    ? 1u
                                    : 0u;

                            if (event_count == 0u &&
                                (v52_ui_process_events_calls <= 8u ||
                                 (v52_ui_process_events_calls %
                                      250u) == 0u)) {

                                Append(
                                    std::string{
                                        V73Enabled()
                                            ? "V73"
                                            : "V72"} +
                                    " UI_ProcessEvents call#" +
                                    std::to_string(
                                        v52_ui_process_events_calls) +
                                    " empty queue; bufferBytes=" +
                                    std::to_string(
                                        cleared));
                            }

                            return true;
                        }

                        // Legacy modes remain exactly passive: zeroed block,
                        // zero events, Java boolean false.
                        regs[0] = 0u;

                        if (v52_ui_process_events_calls <= 8u ||
                            (v52_ui_process_events_calls % 250u) == 0u) {
                            Append(
                                "V52 JNI UI_ProcessEvents call#" +
                                std::to_string(
                                    v52_ui_process_events_calls) +
                                " -> false; zeroed direct buffer bytes=" +
                                std::to_string(cleared));
                        }
                        return true;
                    }

                    if (family == 9 &&
                        method_name ==
                            "Graphics_GetScreenSizeInPoints") {

                        const std::uint32_t array =
                            java_arg_word(0u);

                        const auto data_it =
                            jni_array_data.find(array);
                        const auto length_it =
                            jni_array_lengths.find(array);

                        if (V84FinalBlitEnabled()) {
                            ++v84_points_calls;
                        }

                        const std::uint32_t points_w =
                            V84PointsPixelsEnabled()
                                ? 2048u
                                : (V77Enabled()
                                       ? 1024u
                                       : 1180u);
                        const std::uint32_t points_h =
                            V84PointsPixelsEnabled()
                                ? 1536u
                                : (V77Enabled()
                                       ? 768u
                                       : 820u);

                        if (data_it !=
                                jni_array_data.end() &&
                            length_it !=
                                jni_array_lengths.end() &&
                            length_it->second >= 2u &&
                            data_it->second != 0u) {

                            mem.Write32Guest(
                                data_it->second + 0u,
                                points_w);
                            mem.Write32Guest(
                                data_it->second + 4u,
                                points_h);
                        }

                        regs[0] = 0u;
                        Append(
                            std::string{
                                V84FinalBlitEnabled()
                                    ? "V84 JNI bridge: "
                                    : (V77Enabled()
                                           ? "V77 JNI bridge: "
                                           : "JNI bridge: ")} +
                            "Graphics_GetScreenSizeInPoints -> " +
                            std::to_string(points_w) +
                            "x" +
                            std::to_string(points_h));
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Graphics_CanSetGLViewScaleFactor") {

                        ++v76_scale_can_calls;
                        if (V84FinalBlitEnabled()) {
                            ++v84_can_scale_calls;
                        }

                        if (V84AndroidContractEnabled()) {
                            regs[0] = 1u;
                            Append(
                                "V84 ANDROID CONTRACT Graphics_CanSetGLViewScaleFactor -> true (matches APK AndroidSurfaceView)");
                        } else if (V76Enabled()) {
                            // Exact historical iOS semantic at ~0x00590010:
                            // [EAGLView respondsToSelector:@selector(contentScaleFactor)].
                            // EAGLView is a UIView and supports the property.
                            regs[0] = 1u;
                            Append(
                                "V76 JNI Graphics_CanSetGLViewScaleFactor call#" +
                                std::to_string(
                                    v76_scale_can_calls) +
                                " -> true (iOS EAGLView contentScaleFactor supported)");
                        } else if (V77Enabled()) {
                            // v76 proved the Android guest does not use the same
                            // caller-side scale policy as the historical iOS
                            // executable: it requested 2.000666 and expanded a
                            // native 2360x1640 surface to 2361x1641. Keep the
                            // stable Android-side contract disabled in v77 and
                            // test historical iPad geometry independently.
                            regs[0] = 0u;
                            Append(
                                "V77 JNI Graphics_CanSetGLViewScaleFactor -> false (Android scale path disabled for geometry A/B)");
                        } else {
                            regs[0] = 0u;
                            Append(
                                "JNI bridge: Graphics_CanSetGLViewScaleFactor -> false");
                        }
                        return true;
                    }

                    if (family == 5 &&
                        method_name ==
                            "Graphics_GetGLViewSysFBO") {

                        // OpenGL ES default framebuffer.
                        regs[0] = 0u;

                        ++v52_graphics_fbo_calls;

                        if (v52_graphics_fbo_calls <= 8u ||
                            (v52_graphics_fbo_calls % 250u) == 0u) {
                            Append(
                                "V52 JNI Graphics_GetGLViewSysFBO call#" +
                                std::to_string(
                                    v52_graphics_fbo_calls) +
                                " -> 0");
                        }
                        return true;
                    }

                    if (family == 7 &&
                        method_name ==
                            "Graphics_GetPointSizeInPixels") {

                        regs[0] = 0x40000000u; // 2.0f
                        if (V84FinalBlitEnabled()) {
                            ++v84_point_size_calls;
                        }
                        Append(
                            std::string{
                                V84FinalBlitEnabled()
                                    ? "V84 JNI bridge: "
                                    : "JNI bridge: "} +
                            "Graphics_GetPointSizeInPixels -> 2.0");
                        return true;
                    }

                    if (family == 7 &&
                        method_name ==
                            "Graphics_GetGLViewScaleFactor") {

                        ++v76_scale_get_calls;
                        if (V84FinalBlitEnabled()) {
                            ++v84_get_scale_calls;
                        }

                        regs[0] =
                            V84AndroidContractEnabled()
                                ? v84_android_view_scale_factor_bits
                                : (V76Enabled()
                                       ? v76_gl_view_scale_factor_bits
                                       : 0x3f800000u);

                        float value = 1.0f;
                        std::uint32_t value_bits = regs[0];
                        std::memcpy(
                            &value,
                            &value_bits,
                            sizeof(value));

                        Append(
                            std::string{
                                V84AndroidContractEnabled()
                                    ? "V84 ANDROID CONTRACT"
                                    : (V76Enabled()
                                           ? "V76"
                                           : "JNI bridge:")} +
                            " Graphics_GetGLViewScaleFactor call#" +
                            std::to_string(
                                v76_scale_get_calls) +
                            " -> " +
                            std::to_string(value) +
                            " bits=0x" +
                            JniProbeHex(value_bits));
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Diag_GetHardwareModel") {

                        regs[0] =
                            new_string(
                                "iPad13,18");
                        Append(
                            "JNI bridge: Diag_GetHardwareModel -> iPad13,18");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Diag_GetDeviceID") {

                        regs[0] =
                            new_string(
                                "8f76d9e4-6a52-4b6a-9f0e-152527520001");
                        Append(
                            "JNI bridge: Diag_GetDeviceID -> stable probe UUID");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Diag_GetOSVersion") {

                        regs[0] =
                            new_string(
                                "iPadOS 26.6.1");
                        Append(
                            "JNI bridge: Diag_GetOSVersion -> iPadOS 26.6.1");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Info_SysGetIntentExtraDataString") {

                        regs[0] = new_string("");
                        Append(
                            "JNI bridge: Info_SysGetIntentExtraDataString -> empty");
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "OpenSessionForRead") {

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: OpenSessionForRead -> false");
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Device_IsKeyboardShowing" &&
                        V73Enabled()) {

                        const bool visible =
                            PvZ2HostKeyboardVisible();

                        regs[0] =
                            visible
                                ? 1u
                                : 0u;

                        ++v73_keyboard_status_calls;

                        if (v73_keyboard_status_calls <= 12u ||
                            (v73_keyboard_status_calls % 100u) == 0u) {
                            Append(
                                "V73 KEYBOARD status call#" +
                                std::to_string(
                                    v73_keyboard_status_calls) +
                                " -> " +
                                (visible
                                    ? std::string{"true"}
                                    : std::string{"false"}));
                        }

                        if (V80Enabled() &&
                            (v73_keyboard_status_calls <= 24u ||
                             (v73_keyboard_status_calls % 25u) == 0u)) {
                            Append(
                                "V80 KEYBOARD status frame=" +
                                std::to_string(current_frame_number) +
                                " call#" +
                                std::to_string(v73_keyboard_status_calls) +
                                " requested=" +
                                (visible
                                    ? std::string{"YES"}
                                    : std::string{"NO"}) +
                                " firstResponder=" +
                                (PvZ2HostKeyboardFirstResponder()
                                    ? std::string{"YES"}
                                    : std::string{"NO"}));
                        }
                        return true;
                    }

                    if (family == 1 &&
                        (method_name == "IsSessionOpen" ||
                         method_name == "IsSessionOpening" ||
                         method_name == "Play_IsConnected" ||
                         method_name == "Device_IsKeyboardShowing" ||
                         method_name == "Web_SysOpenURL")) {

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> false");
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Device_IsSupportedUIOrientation") {

                        regs[0] = 1u;
                        Append(
                            "JNI bridge: Device_IsSupportedUIOrientation -> true");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Device_GetCachesDir") {

                        regs[0] =
                            new_string(
                                "/data/data/com.ea.game.pvz2_row/cache");
                        Append(
                            "JNI bridge: Device_GetCachesDir -> synthetic Android cache path");
                        return true;
                    }

                    if (family == 0 &&
                        (method_name == "GetHumanReadableUrl" ||
                         method_name == "GetStatusLine" ||
                         method_name == "GetResponseHeader" ||
                         method_name == "GetAccessToken" ||
                         method_name == "GetFriendPictureURL" ||
                         method_name == "GetFriendName" ||
                         method_name == "Cloud_GetPcpId")) {

                        regs[0] = new_string("");
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> empty string");
                        return true;
                    }

                    if (family == 0 &&
                        (method_name == "getAppFriends" ||
                         method_name == "getNonAppFriends" ||
                         method_name ==
                             "getScheduledLocalNotificationsData")) {

                        regs[0] = new_string("[]");
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> []");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "getTimezone") {

                        regs[0] = new_string("UTC");
                        Append(
                            "JNI bridge: getTimezone -> UTC");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "GetRequestBody") {

                        const std::uint32_t handle =
                            new_object();

                        jni_array_lengths[handle] = 0u;
                        jni_array_data[handle] =
                            mem.AllocateHeap(
                                1u,
                                1u);
                        jni_array_element_sizes[handle] =
                            1u;

                        regs[0] = handle;
                        Append(
                            "JNI bridge: GetRequestBody -> empty byte[]");
                        return true;
                    }

                    if (family == 5 &&
                        (method_name == "GetStatusCode" ||
                         method_name == "GetResponseLength")) {

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> 0");
                        return true;
                    }

                    if (family == 6 &&
                        (method_name == "GetExpirationDate" ||
                         method_name == "GetSessionState")) {

                        regs[0] = 0u;
                        regs[1] = 0u;
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> 0");
                        return true;
                    }

                    if (family == 9 &&
                        method_name == "Start") {

                        const std::uint32_t java_object =
                            regs[1];

                        const auto peer_it =
                            jni_native_http_peers.find(
                                java_object);

                        if (peer_it !=
                                jni_native_http_peers.end()) {

                            const std::uint32_t peer =
                                peer_it->second;

                            if (queued_http_failure_peers
                                    .insert(peer)
                                    .second) {

                                pending_http_failures
                                    .emplace_back(
                                        java_object,
                                        peer);

                                ++v52_http_starts;

                                Append(
                                    "V34 HTTP Start: queued deterministic offline error callback java=0x" +
                                    JniProbeHex(
                                        java_object) +
                                    " nativePeer=0x" +
                                    JniProbeHex(peer));
                            } else {
                                Append(
                                    "V34 HTTP Start: nativePeer=0x" +
                                    JniProbeHex(peer) +
                                    " already queued/delivered");
                            }
                        } else {
                            Append(
                                "V34 HTTP Start: no native peer mapped for java=0x" +
                                JniProbeHex(
                                    java_object) +
                                "; retaining no-op semantics");
                        }

                        regs[0] = 0u;
                        return true;
                    }

                    if (family == 9 &&
                        method_name ==
                            "Cloud_attemptSilentSync") {

                        if (!cloud_state_loaded_delivered) {
                            pending_cloud_state_loaded =
                                true;
                        }

                        regs[0] = 0u;
                        Append(
                            "V49 CLOUD HANDSHAKE: Cloud_attemptSilentSync -> Java no-op; queued Native_CloudStateLoaded completion=" +
                            std::string{
                                pending_cloud_state_loaded
                                    ? "YES"
                                    : "NO"});
                        return true;
                    }

                    if (family == 9 &&
                        V73Enabled() &&
                        (method_name ==
                             "Device_ShowKeyboard" ||
                         method_name ==
                             "Device_HideKeyboard")) {

                        const bool show =
                            method_name ==
                                "Device_ShowKeyboard";

                        PvZ2HostSetKeyboardVisible(
                            show);

                        if (V85PerformanceEnabled()) {
                            V85RecordGuestAction(show ? "Device_ShowKeyboard" : "Device_HideKeyboard");
                        }

                        if (show) {
                            ++v73_keyboard_show_calls;
                        } else {
                            ++v73_keyboard_hide_calls;
                        }

                        regs[0] = 0u;

                        Append(
                            "V73 KEYBOARD " +
                            std::string{
                                show
                                    ? "show"
                                    : "hide"} +
                            " request#" +
                            std::to_string(
                                show
                                    ? v73_keyboard_show_calls
                                    : v73_keyboard_hide_calls) +
                            " -> UIKit UITextField");

                        if (V82Enabled()) {
                            ++v82_keyboard_correlations;
                            Append(
                                "V82 ACTION KEYBOARD #" +
                                std::to_string(v82_keyboard_correlations) +
                                " frame=" + std::to_string(current_frame_number) +
                                " action=" +
                                (show ? std::string{"SHOW"} : std::string{"HIDE"}) +
                                " " + V82TouchContext() + " " +
                                V82RadarSnapshot(
                                    v82_last_touch_x, v82_last_touch_y));
                        }

                        if (V80Enabled()) {
                            Append(
                                "V80 KEYBOARD guestRequest frame=" +
                                std::to_string(current_frame_number) +
                                " action=" +
                                (show
                                    ? std::string{"show"}
                                    : std::string{"hide"}) +
                                " requestedNow=" +
                                (PvZ2HostKeyboardVisible()
                                    ? std::string{"YES"}
                                    : std::string{"NO"}) +
                                " firstResponderNow=" +
                                (PvZ2HostKeyboardFirstResponder()
                                    ? std::string{"YES"}
                                    : std::string{"NO"}));
                        }
                        return true;
                    }

                    static const std::unordered_set<std::string>
                        kV29VoidNoOpMethods = {
                            // AndroidHttpTransaction.
                            "SetTimeout",
                            "SetRequestHeader",
                            "SetRequestBody",
                            "SetBasicAuth",
                            "Start",
                            "Release",

                            // Cloud / Play / social integration. These are
                            // optional boot-time services; the probe keeps
                            // them offline and deterministic.
                            "Cloud_Connect",
                            "Cloud_initiateSync",
                            "Cloud_SetPcpId",
                            "Play_Connect",
                            "Play_Connect_Silent",
                            "Play_Disconnect",
                            "Play_ResetAchievements",
                            "Play_QueueAchievement",
                            "Play_QueueAchievement_Percentage",
                            "Play_ShowAchievementView",
                            "Play_SubmitScoreToLeaderboard",
                            "Play_ShowLeaderboardView",
                            "Play_ShowLeaderboardViewAll",
                            "InitWithAppId",
                            "CloseAndClearSession",
                            "Dialog",
                            "RefreshFriendsLists",

                            // Analytics / telemetry bridges observed during
                            // the v28 first-draw sweep.
                            "Init",
                            "sessionStart",
                            "sessionEnd",
                            "sendQueuedEvents",
                            "flushToDisk",
                            "currencyGiven",
                            "purchase",
                            "buyIn",
                            "onResume",
                            "onPause",
                            "onDestroy",
                            "GetUserResources",
                            "UserUpdate",
                            "Event",

                            // iOS-hosted UI/notification operations currently
                            // have no Android Java peer.
                            "Device_ShowKeyboard",
                            "Device_HideKeyboard",
                            "Device_ExitToHome",
                            "Graphics_SetGLViewScaleFactor",
                            "RegisterForRemoteNotifications",
                            "UnregisterForRemoteNotifications",
                            "removeScheduledNotification",
                            "removeAllScheduledNotifications",
                            "scheduleBasicNotification",
                            "removeScheduledNotificationsBySource",
                            "UI_DidRecieveFocus"
                        };

                    if (family == 9 &&
                        method_name ==
                            "Graphics_SetGLViewScaleFactor" &&
                        V84AndroidContractEnabled()) {

                        const std::uint32_t bits =
                            java_arg_word(0u);
                        float scale = 0.0f;
                        std::memcpy(
                            &scale,
                            &bits,
                            sizeof(scale));

                        v84_android_view_scale_factor_bits =
                            bits;
                        ++v84_set_scale_calls;
                        regs[0] = 0u;

                        Append(
                            "V84 ANDROID CONTRACT Graphics_SetGLViewScaleFactor call#" +
                            std::to_string(v84_set_scale_calls) +
                            " requested=" +
                            std::to_string(scale) +
                            " bits=0x" +
                            JniProbeHex(bits) +
                            " -> stored only; hostResize=NO (matches APK iput)");
                        return true;
                    }

                    if (family == 9 &&
                        method_name ==
                            "Graphics_SetGLViewScaleFactor" &&
                        V76Enabled()) {

                        ++v76_scale_set_calls;

                        const std::uint32_t bits =
                            java_arg_word(0u);
                        float scale = 0.0f;
                        std::memcpy(
                            &scale,
                            &bits,
                            sizeof(scale));

                        const bool valid =
                            std::isfinite(scale) &&
                            scale >= 0.5f &&
                            scale <= 4.0f;

                        bool resized = false;
                        std::uint32_t target_w =
                            host_surface_width;
                        std::uint32_t target_h =
                            host_surface_height;

                        if (valid) {
                            v76_gl_view_scale_factor_bits =
                                bits;
                            v76_gl_view_scale_set = true;

                            target_w =
                                static_cast<std::uint32_t>(
                                    std::lround(
                                        1180.0 * scale));
                            target_h =
                                static_cast<std::uint32_t>(
                                    std::lround(
                                        820.0 * scale));

                            if (target_w != 0u &&
                                target_h != 0u &&
                                host_gles_ready) {

                                resized =
                                    PvZ2HostGLESResize(
                                        target_w,
                                        target_h);

                                if (resized) {
                                    host_surface_width =
                                        target_w;
                                    host_surface_height =
                                        target_h;
                                }
                            }
                        }

                        regs[0] = 0u;

                        Append(
                            "V76 JNI Graphics_SetGLViewScaleFactor call#" +
                            std::to_string(
                                v76_scale_set_calls) +
                            " requested=" +
                            std::to_string(scale) +
                            " bits=0x" +
                            JniProbeHex(bits) +
                            " valid=" +
                            (valid ? "YES" : "NO") +
                            " target=" +
                            std::to_string(target_w) +
                            "x" +
                            std::to_string(target_h) +
                            " hostResize=" +
                            (resized ? "YES" : "NO"));
                        return true;
                    }

                    if (family == 9 &&
                        kV29VoidNoOpMethods.count(
                            method_name) != 0u) {

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> no-op");
                        return true;
                    }

                    if (family == 6 &&
                        method_name ==
                            "Resources_GetAssetFileSize") {

                        const std::string requested =
                            java_string_value(
                                java_arg_word(0u));

                        if (const SyntheticAsset* synthetic =
                                GetOrBuildSyntheticTga(
                                    requested)) {

                            const std::uint64_t size =
                                synthetic->bytes
                                    ? synthetic->bytes->size()
                                    : 0u;

                            regs[0] =
                                static_cast<std::uint32_t>(
                                    size);
                            regs[1] =
                                static_cast<std::uint32_t>(
                                    size >> 32u);

                            Append(
                                "JNI bridge: Resources_GetAssetFileSize(\"" +
                                requested +
                                "\") -> " +
                                std::to_string(size) +
                                " via v31 PTX->TGA virtual asset");
                            return true;
                        }

                        // AndroidGameApp implements this with
                        // AssetManager.openFd(). The supported APK contains
                        // no ordinary assets/ files; IOException returns -1L.
                        regs[0] = 0xffffffffu;
                        regs[1] = 0xffffffffu;

                        Append(
                            "JNI bridge: Resources_GetAssetFileSize(\"" +
                            requested +
                            "\") -> -1 (not an APK AssetManager asset)");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Resources_GetAssetFileInfo") {

                        const std::string requested =
                            java_string_value(
                                java_arg_word(0u));

                        const std::uint32_t info_array =
                            java_arg_word(1u);

                        const auto data_it =
                            jni_array_data.find(
                                info_array);
                        const auto length_it =
                            jni_array_lengths.find(
                                info_array);

                        const SyntheticAsset* synthetic =
                            GetOrBuildSyntheticTga(
                                requested);

                        if (data_it !=
                                jni_array_data.end() &&
                            length_it !=
                                jni_array_lengths.end() &&
                            data_it->second != 0u) {

                            const std::uint64_t bytes64 =
                                static_cast<std::uint64_t>(
                                    length_it->second) *
                                8ull;

                            const std::size_t bytes =
                                static_cast<std::size_t>(
                                    std::min<std::uint64_t>(
                                        bytes64,
                                        0xffffffffull));

                            if (auto* p =
                                    mem.Ptr(
                                        data_it->second,
                                        bytes)) {
                                std::memset(
                                    p,
                                    0,
                                    bytes);
                            }

                            if (synthetic != nullptr &&
                                synthetic->bytes != nullptr &&
                                length_it->second >= 2u) {

                                mem.Write64Guest(
                                    data_it->second + 0u,
                                    0u);
                                mem.Write64Guest(
                                    data_it->second + 8u,
                                    synthetic->bytes->size());
                            }
                        }

                        if (synthetic != nullptr &&
                            synthetic->bytes != nullptr) {

                            // Original Android Java returns the APK resource
                            // path plus start/length. For the cross-platform
                            // bridge, return the same requested virtual path;
                            // POSIX VFS below serves the generated TGA bytes
                            // with start offset zero.
                            regs[0] =
                                new_string(
                                    requested);

                            Append(
                                "JNI bridge: Resources_GetAssetFileInfo(\"" +
                                requested +
                                "\") -> virtual path start=0 length=" +
                                std::to_string(
                                    synthetic->bytes->size()));
                            return true;
                        }

                        // AndroidGameApp returns null when AssetManager.openFd
                        // throws. OBB resources are not APK assets.
                        regs[0] = 0u;

                        Append(
                            "JNI bridge: Resources_GetAssetFileInfo(\"" +
                            requested +
                            "\") -> null (not an APK AssetManager asset)");
                        return true;
                    }

                    if (family == 1) {
                        if (method_name == "expansionFileDelivered" ||
                            method_name == "isGooglePlayExpansionEnabled" ||
                            method_name == "fetchExpansionFile") {
                            regs[0] = 1;
                            Append(
                                "JNI bridge: " +
                                method_name +
                                " -> true");
                            return true;
                        }

                        if (method_name == "needsToUpdateDB" ||
                            method_name == "needToDownloadExpansionFile") {
                            regs[0] = 0;
                            Append(
                                "JNI bridge: " +
                                method_name +
                                " -> false");
                            return true;
                        }
                    }

                    RecordSweepIssue(
                        "jni-method-fallback",
                        method_name + ":" +
                            std::to_string(family),
                        method_name +
                            " sig=" +
                            signature +
                            " family=" +
                            std::to_string(family));

                    // 0 Object, 1 boolean, 2 byte, 3 char, 4 short,
                    // 5 int, 6 long, 7 float, 8 double, 9 void.
                    if (family == 0) {
                        if (signature.find(
                                "Ljava/lang/String;") !=
                            std::string::npos) {
                            regs[0] = new_string("");
                        } else {
                            regs[0] = new_object();
                        }
                    } else {
                        regs[0] = 0;
                        if (family == 6 ||
                            family == 8) {
                            regs[1] = 0;
                        }
                    }

                    return true;
                };

            if (handle_call_family(34u, false) ||
                handle_call_family(64u, true) ||
                handle_call_family(114u, false)) {
                return;
            }

            if (slot == 94u ||
                slot == 144u) { // GetFieldID / GetStaticFieldID

                const std::string field_name =
                    mem.ReadCStringGuest(regs[2], 256);
                const std::string signature =
                    mem.ReadCStringGuest(regs[3], 256);

                regs[0] =
                    0x54100000u +
                    (next_synthetic_field++ * 0x100u);

                Append(
                    std::string{
                        slot == 94u
                            ? "JNIEnv.GetFieldID "
                            : "JNIEnv.GetStaticFieldID "} +
                    field_name +
                    " sig=" +
                    signature +
                    " -> 0x" +
                    JniProbeHex(regs[0]));
                return;
            }

            if (slot == 113u) { // GetStaticMethodID
                const std::string method_name =
                    mem.ReadCStringGuest(regs[2], 256);
                const std::string signature =
                    mem.ReadCStringGuest(regs[3], 512);

                const std::uint32_t method_id =
                    0x54000000u +
                    (next_synthetic_method++ * 0x100u);

                jni_method_names[method_id] =
                    method_name;
                jni_method_signatures[method_id] =
                    signature;

                regs[0] = method_id;

                Append(
                    "JNIEnv.GetStaticMethodID " +
                    method_name +
                    " sig=" +
                    signature +
                    " -> 0x" +
                    JniProbeHex(method_id));
                return;
            }

            if (slot >= 95u &&
                slot <= 103u) { // Get<Field>

                regs[0] =
                    slot == 95u
                        ? new_object()
                        : 0u;

                if (slot == 101u ||
                    slot == 103u) {
                    regs[1] = 0;
                }

                log_jni_fallback("instance field read");
                return;
            }

            if (slot >= 104u &&
                slot <= 112u) { // Set<Field>
                regs[0] = 0;
                log_jni_fallback("instance field write");
                return;
            }

            if (slot >= 145u &&
                slot <= 153u) { // GetStatic<Field>

                regs[0] =
                    slot == 145u
                        ? new_object()
                        : 0u;

                if (slot == 151u ||
                    slot == 153u) {
                    regs[1] = 0;
                }

                log_jni_fallback("static field read");
                return;
            }

            if (slot >= 154u &&
                slot <= 162u) { // SetStatic<Field>
                regs[0] = 0;
                log_jni_fallback("static field write");
                return;
            }

            // Strings.
            if (slot == 163u) { // NewString UTF-16
                const std::uint32_t chars = regs[1];
                const std::uint32_t length = regs[2];

                std::string value;
                value.reserve(length);

                for (std::uint32_t i = 0;
                     i < length;
                     ++i) {
                    const std::uint16_t ch =
                        mem.Read16Guest(
                            chars + i * 2u);

                    value.push_back(
                        ch <= 0x7fu
                            ? static_cast<char>(ch)
                            : '?');
                }

                regs[0] = new_string(value);
                return;
            }

            if (slot == 164u ||
                slot == 168u) { // GetStringLength / UTFLength

                const auto it =
                    jni_strings.find(regs[1]);

                regs[0] =
                    it == jni_strings.end()
                        ? 0u
                        : static_cast<std::uint32_t>(
                            it->second.size());
                return;
            }

            if (slot == 165u) { // GetStringChars
                const auto it =
                    jni_strings.find(regs[1]);

                if (regs[2]) {
                    mem.Write8Guest(regs[2], 1);
                }

                if (it == jni_strings.end()) {
                    regs[0] = 0;
                    return;
                }

                const std::uint32_t buffer =
                    mem.AllocateObject(
                        static_cast<std::uint32_t>(
                            (it->second.size() + 1u) * 2u),
                        2);

                for (std::size_t i = 0;
                     i < it->second.size();
                     ++i) {
                    mem.Write16Guest(
                        buffer +
                            static_cast<std::uint32_t>(i * 2u),
                        static_cast<std::uint8_t>(
                            it->second[i]));
                }

                mem.Write16Guest(
                    buffer +
                        static_cast<std::uint32_t>(
                            it->second.size() * 2u),
                    0);

                regs[0] = buffer;
                return;
            }

            if (slot == 166u ||
                slot == 170u) { // ReleaseString*
                regs[0] = 0;
                return;
            }

            if (slot == 167u) { // NewStringUTF
                regs[0] =
                    new_string(
                        mem.ReadCStringGuest(
                            regs[1],
                            1u << 20));
                return;
            }

            if (slot == 169u) { // GetStringUTFChars
                const auto it =
                    jni_strings.find(regs[1]);

                if (regs[2]) {
                    mem.Write8Guest(regs[2], 1);
                }

                if (it == jni_strings.end()) {
                    regs[0] = 0;
                    return;
                }

                const std::uint32_t buffer =
                    mem.AllocateObject(
                        static_cast<std::uint32_t>(
                            it->second.size() + 1u),
                        1);

                for (std::size_t i = 0;
                     i < it->second.size();
                     ++i) {
                    mem.Write8Guest(
                        buffer +
                            static_cast<std::uint32_t>(i),
                        static_cast<std::uint8_t>(
                            it->second[i]));
                }

                mem.Write8Guest(
                    buffer +
                        static_cast<std::uint32_t>(
                            it->second.size()),
                    0);

                regs[0] = buffer;
                return;
            }

            // Arrays.
            if (slot == 171u) { // GetArrayLength
                const auto it =
                    jni_array_lengths.find(regs[1]);

                regs[0] =
                    it == jni_array_lengths.end()
                        ? 0u
                        : it->second;
                return;
            }

            if (slot == 172u) { // NewObjectArray
                const std::uint32_t handle =
                    new_object();

                jni_array_lengths[handle] =
                    regs[1];

                jni_object_arrays[handle] =
                    std::vector<std::uint32_t>(
                        regs[1],
                        regs[3]);

                regs[0] = handle;
                return;
            }

            if (slot == 173u) { // GetObjectArrayElement
                const auto it =
                    jni_object_arrays.find(regs[1]);

                regs[0] =
                    it != jni_object_arrays.end() &&
                    regs[2] < it->second.size()
                        ? it->second[regs[2]]
                        : 0u;
                return;
            }

            if (slot == 174u) { // SetObjectArrayElement
                auto it =
                    jni_object_arrays.find(regs[1]);

                if (it != jni_object_arrays.end() &&
                    regs[2] < it->second.size()) {
                    it->second[regs[2]] =
                        regs[3];
                }

                regs[0] = 0;
                return;
            }

            if (slot >= 175u &&
                slot <= 182u) { // New primitive arrays

                static constexpr std::uint32_t sizes[] = {
                    1u, 1u, 2u, 2u,
                    4u, 8u, 4u, 8u
                };

                const std::uint32_t length =
                    regs[1];

                const std::uint32_t element_size =
                    sizes[slot - 175u];

                const std::uint32_t bytes =
                    length * element_size;

                const std::uint32_t handle =
                    new_object();

                const std::uint32_t data =
                    mem.AllocateHeap(
                        std::max<std::uint32_t>(
                            bytes,
                            1u),
                        std::max<std::uint32_t>(
                            element_size,
                            1u));

                if (data && bytes) {
                    if (auto* p =
                            mem.Ptr(data, bytes)) {
                        std::memset(
                            p,
                            0,
                            bytes);
                    }
                }

                jni_array_lengths[handle] =
                    length;
                jni_array_data[handle] =
                    data;
                jni_array_element_sizes[handle] =
                    element_size;

                regs[0] = handle;
                return;
            }

            if (slot >= 183u &&
                slot <= 190u) { // Get primitive array elements
                if (regs[2]) {
                    mem.Write8Guest(regs[2], 0);
                }

                const auto it =
                    jni_array_data.find(regs[1]);

                regs[0] =
                    it == jni_array_data.end()
                        ? 0u
                        : it->second;
                return;
            }

            if (slot >= 191u &&
                slot <= 198u) { // Release primitive array elements
                regs[0] = 0;
                return;
            }

            if ((slot >= 199u &&
                 slot <= 206u) ||
                (slot >= 207u &&
                 slot <= 214u)) {

                const bool set_region =
                    slot >= 207u;

                const std::uint32_t array =
                    regs[1];
                const std::uint32_t start =
                    regs[2];
                const std::uint32_t length =
                    regs[3];

                const auto data_it =
                    jni_array_data.find(array);
                const auto size_it =
                    jni_array_element_sizes.find(array);

                const std::uint32_t buffer =
                    mem.Read32Guest(regs[13]);

                if (data_it != jni_array_data.end() &&
                    size_it != jni_array_element_sizes.end()) {

                    const std::uint32_t bytes =
                        length * size_it->second;

                    auto* array_ptr =
                        mem.Ptr(
                            data_it->second +
                                start * size_it->second,
                            bytes);

                    auto* buffer_ptr =
                        mem.Ptr(
                            buffer,
                            bytes);

                    if (array_ptr &&
                        buffer_ptr) {

                        const std::uint32_t
                            array_address =
                                data_it->second +
                                start *
                                    size_it->second;
                        const std::uint32_t
                            write_destination =
                                set_region
                                    ? array_address
                                    : buffer;

                        if (V91AllowRelroWrite(
                                write_destination,
                                bytes,
                                set_region
                                    ? "JNI.SetPrimitiveArrayRegion"
                                    : "JNI.GetPrimitiveArrayRegion")) {

                            if (set_region) {
                                std::memmove(
                                    array_ptr,
                                    buffer_ptr,
                                    bytes);
                            } else {
                                std::memmove(
                                    buffer_ptr,
                                    array_ptr,
                                    bytes);
                            }
                        }
                    }
                }

                regs[0] = 0;
                return;
            }

            switch (slot) {
            case 216: // UnregisterNatives
            case 217: // MonitorEnter
            case 218: // MonitorExit
                regs[0] = 0;
                return;

            case 219: // GetJavaVM
                if (regs[1]) {
                    mem.Write32Guest(
                        regs[1],
                        vm_object);
                }
                regs[0] = 0;
                return;

            case 220: // GetStringRegion
            case 221: { // GetStringUTFRegion
                const auto it =
                    jni_strings.find(regs[1]);

                const std::uint32_t output =
                    mem.Read32Guest(regs[13]);

                if (it != jni_strings.end() &&
                    output) {
                    const std::size_t start =
                        std::min<std::size_t>(
                            regs[2],
                            it->second.size());

                    const std::size_t length =
                        std::min<std::size_t>(
                            regs[3],
                            it->second.size() - start);

                    if (slot == 221u) {
                        for (std::size_t i = 0;
                             i < length;
                             ++i) {
                            mem.Write8Guest(
                                output +
                                    static_cast<std::uint32_t>(i),
                                static_cast<std::uint8_t>(
                                    it->second[start + i]));
                        }
                    } else {
                        for (std::size_t i = 0;
                             i < length;
                             ++i) {
                            mem.Write16Guest(
                                output +
                                    static_cast<std::uint32_t>(i * 2u),
                                static_cast<std::uint8_t>(
                                    it->second[start + i]));
                        }
                    }
                }

                regs[0] = 0;
                return;
            }

            case 222: { // GetPrimitiveArrayCritical
                if (regs[2]) {
                    mem.Write8Guest(regs[2], 0);
                }

                const auto it =
                    jni_array_data.find(regs[1]);

                regs[0] =
                    it == jni_array_data.end()
                        ? 0u
                        : it->second;
                return;
            }

            case 223: // ReleasePrimitiveArrayCritical
            case 225: // ReleaseStringCritical
                regs[0] = 0;
                return;

            case 224: { // GetStringCritical
                const auto it =
                    jni_strings.find(regs[1]);

                if (regs[2]) {
                    mem.Write8Guest(regs[2], 1);
                }

                if (it == jni_strings.end()) {
                    regs[0] = 0;
                    return;
                }

                const std::uint32_t buffer =
                    mem.AllocateObject(
                        static_cast<std::uint32_t>(
                            (it->second.size() + 1u) * 2u),
                        2);

                for (std::size_t i = 0;
                     i < it->second.size();
                     ++i) {
                    mem.Write16Guest(
                        buffer +
                            static_cast<std::uint32_t>(i * 2u),
                        static_cast<std::uint8_t>(
                            it->second[i]));
                }

                mem.Write16Guest(
                    buffer +
                        static_cast<std::uint32_t>(
                            it->second.size() * 2u),
                    0);

                regs[0] = buffer;
                return;
            }

            case 226: // NewWeakGlobalRef
                regs[0] = regs[1];
                return;

            case 227: // DeleteWeakGlobalRef
                regs[0] = 0;
                return;

            case 228: // ExceptionCheck
                regs[0] = 0;
                return;

            case 229: { // NewDirectByteBuffer
                const std::uint32_t handle =
                    new_object();

                const std::uint64_t capacity =
                    static_cast<std::uint64_t>(regs[2]) |
                    (static_cast<std::uint64_t>(
                        regs[3]) << 32);

                jni_direct_buffer_address[handle] =
                    regs[1];
                jni_direct_buffer_capacity[handle] =
                    capacity;

                regs[0] = handle;
                return;
            }

            case 230: { // GetDirectBufferAddress
                const auto it =
                    jni_direct_buffer_address.find(regs[1]);

                regs[0] =
                    it == jni_direct_buffer_address.end()
                        ? 0u
                        : it->second;
                return;
            }

            case 231: { // GetDirectBufferCapacity
                const auto it =
                    jni_direct_buffer_capacity.find(regs[1]);

                const std::uint64_t capacity =
                    it == jni_direct_buffer_capacity.end()
                        ? 0xffffffffffffffffull
                        : it->second;

                regs[0] =
                    static_cast<std::uint32_t>(
                        capacity);
                regs[1] =
                    static_cast<std::uint32_t>(
                        capacity >> 32);
                return;
            }

            case 232: // GetObjectRefType
                regs[0] =
                    regs[1] == 0
                        ? 0u
                        : 1u; // JNILocalRefType
                return;

            default:
                break;
            }

            result.unsupported_jni_slot = slot;

            const std::string unsupported_jni =
                "JNIEnv slot outside compatibility baseline: " +
                std::to_string(slot) +
                " (table offset 0x" +
                JniProbeHex(slot * 4u) +
                ", LR=0x" +
                JniProbeHex(
                    jit ? jit->Regs()[14] : 0u) +
                ").";

            RecordSweepIssue(
                "unsupported-jni",
                std::to_string(slot),
                unsupported_jni);

            if (ConsumeSweepRecovery(
                    "unsupported-jni",
                    unsupported_jni)) {
                regs[0] = 0u;
                regs[1] = 0u;
                ++supported_calls;
                return;
            }

            result.message =
                unsupported_jni;

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined2);
            return;
        }

        const auto binding =
            imports_by_svc.find(swi);

        if (binding == imports_by_svc.end()) {
            result.message =
                "Unknown guest SVC 0x" +
                JniProbeHex(swi);

            RecordSweepIssue(
                "hard-svc",
                JniProbeHex(swi),
                result.message);

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined4);
            return;
        }

        const std::string& name = binding->second.name;

        if (V99Enabled() &&
            name.rfind("__v99_sl_", 0u) == 0u) {
            if (V99HandleOpenSLSvc(
                    name,
                    regs)) {
                ++supported_calls;
                return;
            }
        }

        if (name == "__errno") {
            if (guest_errno_address == 0) {
                guest_errno_address =
                    mem.AllocateObject(4, 4);

                if (guest_errno_address) {
                    mem.Write32Guest(
                        guest_errno_address,
                        0);
                }
            }

            regs[0] =
                guest_errno_address;
            ++supported_calls;
            return;
        }

        if (name == "__gnu_Unwind_Find_exidx") {
            if (regs[1]) {
                mem.Write32Guest(
                    regs[1],
                    0);
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "__android_log_assert") {
            const std::string condition =
                mem.ReadCStringGuest(
                    regs[0],
                    256);
            const std::string tag =
                mem.ReadCStringGuest(
                    regs[1],
                    128);
            const std::string format =
                mem.ReadCStringGuest(
                    regs[2],
                    512);

            const std::string assertion =
                "__android_log_assert condition=\"" +
                condition +
                "\" tag=\"" +
                tag +
                "\" format=\"" +
                format +
                "\"";

            Append(
                "import " +
                assertion +
                " (suppressed during probe)");

            RecordSweepIssue(
                "android-assert",
                condition + ":" + format,
                assertion);

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "strerror") {
            const char* host =
                std::strerror(
                    static_cast<int>(regs[0]));

            const std::string message =
                host ? host : "Unknown error";

            const std::uint32_t guest =
                mem.AllocateObject(
                    static_cast<std::uint32_t>(
                        message.size() + 1),
                    1);

            if (guest) {
                for (std::size_t i = 0;
                     i < message.size();
                     ++i) {
                    mem.Write8Guest(
                        guest +
                            static_cast<std::uint32_t>(i),
                        static_cast<std::uint8_t>(
                            message[i]));
                }

                mem.Write8Guest(
                    guest +
                        static_cast<std::uint32_t>(
                            message.size()),
                    0);
            }

            regs[0] = guest;
            ++supported_calls;
            return;
        }

        if (name == "malloc" ||
            name == "memalign") {

            const std::uint32_t alignment =
                name == "memalign"
                    ? std::max<std::uint32_t>(regs[0], 4u)
                    : 16u;

            const std::uint32_t requested =
                name == "memalign"
                    ? regs[1]
                    : regs[0];

            const std::uint32_t address =
                mem.AllocateHeap(
                    requested,
                    alignment);

            regs[0] = address;
            ++supported_calls;
            ++malloc_calls;

            if (!V85PerformanceEnabled()) {
                V67TrackSmallAllocation(
                    address,
                    requested,
                    regs[14],
                    regs[13]);
            }

            result.malloc_calls =
                malloc_calls;
            result.heap_high_water =
                mem.HeapHighWater();
            result.heap_live_bytes =
                mem.HeapLiveBytes();
            result.heap_live_allocations =
                mem.HeapLiveAllocations();

            if (malloc_calls <= 8u ||
                (malloc_calls % 4096u) == 0u ||
                address == 0u) {

                Append(
                    "V27 HEAP " +
                    name +
                    " #" +
                    std::to_string(
                        malloc_calls) +
                    " requested=" +
                    std::to_string(
                        requested) +
                    " -> 0x" +
                    JniProbeHex(address) +
                    " highWater=" +
                    std::to_string(
                        mem.HeapHighWater()) +
                    " liveBytes=" +
                    std::to_string(
                        mem.HeapLiveBytes()) +
                    " liveAllocs=" +
                    std::to_string(
                        mem.HeapLiveAllocations()));
            }
            return;
        }

        if (name == "free") {
            if (!V85PerformanceEnabled() &&
                (V67Enabled() || V69Enabled())) {
                v67_small_allocations.erase(
                    regs[0]);
                v67_token_history.erase(
                    regs[0]);
            }

            constexpr std::uint32_t
                kV93DeleteReturnGuest =
                    kGuestBase + 0x00868b54u;
            const bool v93_target_free =
                V93Enabled() &&
                regs[14] ==
                    kV93DeleteReturnGuest;
            std::uint32_t
                v93_saved_pc_before = 0u;

            if (v93_target_free) {
                ++v93_target_free_calls;
                v93_last_sample_valid = true;
                v93_last_frame =
                    current_frame_number;
                v93_last_free_ptr =
                    regs[0];
                v93_last_sp =
                    regs[13];
                v93_last_lr =
                    regs[14];
                v93_last_cpsr =
                    jit ? jit->Cpsr() : 0u;

                // Function 0x108689c8 pushed six registers (24 bytes) and
                // reserved 16 local bytes. Its epilogue adds SP,#16 then
                // pops {r4,r5,r6,r7,r8,pc}; therefore the saved PC that the
                // POP will consume is still at the current SP+36 here.
                v93_saved_pc_before =
                    mem.Read32Guest(
                        regs[13] + 36u);
                v93_last_saved_pc_before =
                    v93_saved_pc_before;

                if (V94Enabled()) {
                    v94_last_outer_at_free =
                        mem.Read32Guest(
                            regs[13] + 52u);

                    if (v94_last_outer_at_free !=
                        kGuestBase + 0x0086f1fcu) {
                        AppendDiagnostic(
                            std::string{RuntimeModeTag()} +
                            " OUTER-LR AT FREE frame=" +
                            std::to_string(
                                current_frame_number) +
                            " slot=0x" +
                            JniProbeHex(
                                regs[13] + 52u) +
                            " value=0x" +
                            JniProbeHex(
                                v94_last_outer_at_free) +
                            " expected=0x" +
                            JniProbeHex(
                                kGuestBase +
                                0x0086f1fcu) +
                            " bit0=" +
                            std::to_string(
                                v94_last_outer_at_free &
                                1u));
                    }
                }

                if ((v93_saved_pc_before &
                     1u) != 0u) {
                    ++v93_odd_saved_pc_calls;
                }
                if (!V93GuestImageTarget(
                        v93_saved_pc_before)) {
                    ++v93_invalid_saved_pc_calls;
                }

                v93_last_stack_base =
                    regs[13] >= 16u
                        ? regs[13] - 16u
                        : regs[13];
                for (std::size_t i = 0u;
                     i <
                         v93_last_stack_words
                             .size();
                     ++i) {
                    v93_last_stack_words[i] =
                        mem.Read32Guest(
                            v93_last_stack_base +
                            static_cast<std::uint32_t>(
                                i * 4u));
                }
            }

            mem.FreeHeap(regs[0]);

            if (v93_target_free) {
                const std::uint32_t
                    saved_pc_after =
                        mem.Read32Guest(
                            v93_last_sp +
                            36u);
                v93_last_saved_pc_after =
                    saved_pc_after;

                const bool changed =
                    saved_pc_after !=
                    v93_saved_pc_before;
                if (changed) {
                    ++v93_saved_pc_changed_by_free;
                }

                const bool notable =
                    v93_target_free_calls <= 4u ||
                    changed ||
                    ((v93_saved_pc_before &
                      1u) != 0u) ||
                    !V93GuestImageTarget(
                        v93_saved_pc_before);

                if (notable) {
                    AppendDiagnostic(
                        "V93 FREE-RETURN #" +
                        std::to_string(
                            v93_target_free_calls) +
                        " frame=" +
                        std::to_string(
                            current_frame_number) +
                        " freePtr=0x" +
                        JniProbeHex(
                            v93_last_free_ptr) +
                        " SP=0x" +
                        JniProbeHex(
                            v93_last_sp) +
                        " LR=0x" +
                        JniProbeHex(
                            v93_last_lr) +
                        " savedBefore=0x" +
                        JniProbeHex(
                            v93_saved_pc_before) +
                        " bit0=" +
                        std::to_string(
                            v93_saved_pc_before &
                            1u) +
                        " inImage=" +
                        (V93GuestImageTarget(
                             v93_saved_pc_before)
                             ? std::string{"YES"}
                             : std::string{"NO"}) +
                        " savedAfter=0x" +
                        JniProbeHex(
                            saved_pc_after) +
                        " changedByFree=" +
                        (changed
                             ? std::string{"YES"}
                             : std::string{"NO"}));
                }
            }

            regs[0] = 0;
            ++supported_calls;
            ++free_calls;

            result.free_calls =
                free_calls;
            result.heap_high_water =
                mem.HeapHighWater();
            result.heap_live_bytes =
                mem.HeapLiveBytes();
            result.heap_live_allocations =
                mem.HeapLiveAllocations();
            return;
        }

        if (name == "realloc") {
            const std::uint32_t old_address =
                regs[0];
            const std::uint32_t new_size =
                regs[1];

            const std::uint32_t address =
                mem.ReallocateHeap(
                    old_address,
                    new_size);

            if (!V85PerformanceEnabled() &&
                (V67Enabled() || V69Enabled())) {
                v67_small_allocations.erase(
                    old_address);
                v67_token_history.erase(
                    old_address);

                if (address != 0u &&
                    (new_size == 16u ||
                     new_size == 24u)) {
                    V67TrackSmallAllocation(
                        address,
                        new_size,
                        regs[14],
                        regs[13]);
                }
            }

            regs[0] = address;
            ++supported_calls;
            ++realloc_calls;

            result.realloc_calls =
                realloc_calls;
            result.heap_high_water =
                mem.HeapHighWater();
            result.heap_live_bytes =
                mem.HeapLiveBytes();
            result.heap_live_allocations =
                mem.HeapLiveAllocations();
            return;
        }

        if (name == "__cxa_atexit") {
            const std::uint32_t function = regs[0];
            ++result.cxa_atexit_calls;
            ++supported_calls;
            regs[0] = 0;

            if (result.cxa_atexit_calls <= 8 ||
                (result.cxa_atexit_calls % 100u) == 0u) {
                Append(
                    "import __cxa_atexit(func=0x" +
                    JniProbeHex(function) +
                    ") -> 0");
            }
            return;
        }

        if (name == "__cxa_finalize") {
            ++supported_calls;
            regs[0] = 0;
            return;
        }

        if (name == "__aeabi_memcpy" ||
            name == "memcpy" ||
            name == "__aeabi_memmove" ||
            name == "memmove") {

            const std::uint32_t destination = regs[0];
            const std::uint32_t source = regs[1];
            const std::uint32_t size = regs[2];

            // C library copy helpers are allowed to receive arbitrary pointers
            // when the requested size is zero; no guest memory is touched.
            if (size == 0) {
                regs[0] = destination;
                ++supported_calls;
                return;
            }

            auto* dst = mem.Ptr(destination, size);
            const auto* src = mem.Ptr(source, size);

            if (!dst || !src) {
                const std::uint32_t pc = regs[15];
                const std::uint32_t lr = regs[14];
                const std::uint32_t sp = regs[13];
                const std::uint32_t caller =
                    lr >= 4u ? lr - 4u : lr;

                auto phase_name = [&]() -> std::string {
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
                    case ReturnMode::JniOnLoad:
                    default:
                        return "JNI_OnLoad";
                    }
                };

                auto region_name =
                    [&](std::uint32_t address) -> const char* {
                        const std::uint64_t a = address;

                        if (a >= kGuestBase &&
                            a < static_cast<std::uint64_t>(
                                    kGuestBase) +
                                    mem.image.size()) {
                            return "image";
                        }

                        if (a >= kJniProbeStackBase &&
                            a < static_cast<std::uint64_t>(
                                    kJniProbeStackBase) +
                                    kJniProbeStackSize) {
                            return "stack";
                        }

                        if (a >= kJniProbeHeapBase &&
                            a < static_cast<std::uint64_t>(
                                    kJniProbeHeapBase) +
                                    mem.HeapCapacity()) {
                            return "heap";
                        }

                        if (a >= kJniProbeTrampolineBase &&
                            a < static_cast<std::uint64_t>(
                                    kJniProbeTrampolineBase) +
                                    kJniProbeTrampolineSize) {
                            return "trampoline";
                        }

                        if (a >= kJniProbeJniBase &&
                            a < static_cast<std::uint64_t>(
                                    kJniProbeJniBase) +
                                    kJniProbeJniSize) {
                            return "jni";
                        }

                        if (a >= kJniProbeObjectBase &&
                            a < static_cast<std::uint64_t>(
                                    kJniProbeObjectBase) +
                                    kJniProbeObjectSize) {
                            return "object";
                        }

                        if ((address >= 0x52000000u &&
                             address < 0x53000000u) ||
                            (address >= 0x54000000u &&
                             address < 0x56000000u)) {
                            return "synthetic-java-handle";
                        }

                        return "unmapped";
                    };

                std::ostringstream fault;
                fault
                    << name
                    << " guest-memory fault in "
                    << phase_name()
                    << ": dst=0x"
                    << JniProbeHex(destination)
                    << " (" << region_name(destination)
                    << ", full=" << (dst ? "yes" : "no") << ")"
                    << ", src=0x"
                    << JniProbeHex(source)
                    << " (" << region_name(source)
                    << ", full=" << (src ? "yes" : "no") << ")"
                    << ", size=" << std::dec << size
                    << " (0x" << JniProbeHex(size) << ")"
                    << ", PC=0x" << JniProbeHex(pc)
                    << ", LR=0x" << JniProbeHex(lr)
                    << ", caller=0x" << JniProbeHex(caller)
                    << ", SP=0x" << JniProbeHex(sp)
                    << ", regs{r4=0x"
                    << JniProbeHex(regs[4])
                    << ",r5=0x"
                    << JniProbeHex(regs[5])
                    << ",r6=0x"
                    << JniProbeHex(regs[6])
                    << ",r7=0x"
                    << JniProbeHex(regs[7])
                    << ",r8=0x"
                    << JniProbeHex(regs[8])
                    << ",r9=0x"
                    << JniProbeHex(regs[9])
                    << ",r10=0x"
                    << JniProbeHex(regs[10])
                    << ",r11=0x"
                    << JniProbeHex(regs[11])
                    << ",r12=0x"
                    << JniProbeHex(regs[12])
                    << "}"
                    << ", stack[0..7]={0x"
                    << JniProbeHex(mem.Read32Guest(sp + 0u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 4u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 8u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 12u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 16u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 20u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 24u))
                    << ",0x"
                    << JniProbeHex(mem.Read32Guest(sp + 28u))
                    << "}";

                if (lr == kGuestBase + 0x007a24f0u) {
                    fault
                        << ", vectorRangeInsert{newBegin=0x"
                        << JniProbeHex(regs[5])
                        << ",oldBegin=0x"
                        << JniProbeHex(regs[9])
                        << ",insertPos=0x"
                        << JniProbeHex(regs[10])
                        << ",prefixBytes=0x"
                        << JniProbeHex(regs[8])
                        << ",insertBytes=0x"
                        << JniProbeHex(regs[6])
                        << ",oldEnd=0x"
                        << JniProbeHex(regs[7])
                        << ",vectorThis=0x"
                        << JniProbeHex(regs[11])
                        << "}";
                }

                fault << ".";

                result.message = fault.str();
                Append("MEMORY FAULT: " + result.message);

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            if (!V91AllowRelroWrite(
                    destination,
                    size,
                    name.c_str())) {
                regs[0] = destination;
                ++supported_calls;
                return;
            }

            std::memmove(dst, src, size);
            regs[0] = destination;
            ++supported_calls;
            return;
        }

        if (name == "memcmp") {
            const std::uint32_t a = regs[0];
            const std::uint32_t b = regs[1];
            const std::uint32_t size = regs[2];

            const auto* pa = mem.Ptr(a, size);
            const auto* pb = mem.Ptr(b, size);

            if (!pa || !pb) {
                result.message =
                    "memcmp attempted to access outside guest memory.";

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    std::memcmp(pa, pb, size));

            ++supported_calls;
            return;
        }

        if (name == "strlen") {
            const std::string value =
                mem.ReadCStringGuest(
                    regs[0],
                    1u << 20);

            regs[0] =
                static_cast<std::uint32_t>(
                    value.size());

            ++supported_calls;
            return;
        }

        if (name == "strcmp" ||
            name == "strncmp") {

            const std::string a =
                mem.ReadCStringGuest(
                    regs[0],
                    name == "strncmp"
                        ? regs[2]
                        : 1u << 20);

            const std::string b =
                mem.ReadCStringGuest(
                    regs[1],
                    name == "strncmp"
                        ? regs[2]
                        : 1u << 20);

            int comparison = 0;

            if (name == "strncmp") {
                comparison =
                    std::strncmp(
                        a.c_str(),
                        b.c_str(),
                        regs[2]);
            } else {
                comparison =
                    std::strcmp(
                        a.c_str(),
                        b.c_str());
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    comparison);

            ++supported_calls;
            return;
        }

        // Common POSIX/time/environment calls used during native startup.
        // Filesystem and full threading semantics remain separate bridges.
        if (name == "getenv") {
            const std::string key =
                mem.ReadCStringGuest(
                    regs[0],
                    256);

            std::string value;

            if (key == "LANG" ||
                key == "LC_ALL" ||
                key == "LC_CTYPE") {
                value = "C";
            } else if (key == "TMPDIR") {
                value = "/tmp";
            }

            if (value.empty()) {
                regs[0] = 0;
            } else {
                const std::uint32_t guest =
                    mem.AllocateObject(
                        static_cast<std::uint32_t>(
                            value.size() + 1),
                        1);

                if (guest) {
                    for (std::size_t i = 0;
                         i < value.size();
                         ++i) {
                        mem.Write8Guest(
                            guest +
                                static_cast<std::uint32_t>(i),
                            static_cast<std::uint8_t>(
                                value[i]));
                    }
                    mem.Write8Guest(
                        guest +
                            static_cast<std::uint32_t>(
                                value.size()),
                        0);
                }

                regs[0] = guest;
            }

            ++supported_calls;
            return;
        }

        if (name == "getcwd") {
            const std::uint32_t destination = regs[0];
            const std::uint32_t capacity = regs[1];

            if (destination == 0 ||
                capacity < 2 ||
                !mem.Ptr(
                    destination,
                    capacity)) {
                regs[0] = 0;
            } else {
                mem.Write8Guest(destination, '/');
                mem.Write8Guest(destination + 1, 0);
                regs[0] = destination;
            }

            ++supported_calls;
            return;
        }

        if (name == "time") {
            const std::uint32_t now =
                static_cast<std::uint32_t>(
                    std::time(nullptr));

            if (regs[0]) {
                mem.Write32Guest(
                    regs[0],
                    now);
            }

            regs[0] = now;
            ++supported_calls;
            return;
        }

        if (name == "clock") {
            regs[0] =
                static_cast<std::uint32_t>(
                    std::clock());
            ++supported_calls;
            return;
        }

        if (name == "gettimeofday") {
            if (regs[0]) {
                const auto now =
                    std::chrono::system_clock::now();
                const auto micros =
                    std::chrono::duration_cast<
                        std::chrono::microseconds>(
                        now.time_since_epoch())
                        .count();

                mem.Write32Guest(
                    regs[0] + 0,
                    static_cast<std::uint32_t>(
                        micros / 1000000));
                mem.Write32Guest(
                    regs[0] + 4,
                    static_cast<std::uint32_t>(
                        micros % 1000000));
            }

            if (regs[1]) {
                mem.Write32Guest(
                    regs[1] + 0,
                    0);
                mem.Write32Guest(
                    regs[1] + 4,
                    0);
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "clock_gettime") {
            if (regs[1]) {
                const auto now =
                    regs[0] == 0
                        ? std::chrono::system_clock::now()
                              .time_since_epoch()
                        : std::chrono::steady_clock::now()
                              .time_since_epoch();

                const auto nanos =
                    std::chrono::duration_cast<
                        std::chrono::nanoseconds>(
                        now)
                        .count();

                mem.Write32Guest(
                    regs[1] + 0,
                    static_cast<std::uint32_t>(
                        nanos / 1000000000ll));
                mem.Write32Guest(
                    regs[1] + 4,
                    static_cast<std::uint32_t>(
                        nanos % 1000000000ll));
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "nanosleep" ||
            name == "usleep") {

            if (V66Enabled() &&
                (current_probe_thread_id != 0u ||
                 V96MainBlockingAllowed())) {

                std::uint64_t duration_ns = 0u;

                if (name == "usleep") {
                    duration_ns =
                        static_cast<std::uint64_t>(
                            regs[0]) *
                        1000ull;
                } else if (regs[0] != 0u) {
                    const std::uint64_t sec =
                        mem.Read32Guest(regs[0] + 0u);
                    const std::uint64_t nsec =
                        mem.Read32Guest(regs[0] + 4u);

                    if (nsec < 1000000000ull) {
                        duration_ns =
                            sec * 1000000000ull +
                            nsec;
                    }
                }

                if (duration_ns != 0u &&
                    V66BeginSleep(
                        duration_ns,
                        name.c_str())) {

                    regs[0] = 0u;
                    ++supported_calls;

                    if (jit) {
                        jit->HaltExecution(
                            Dynarmic::HaltReason::UserDefined4);
                    }
                    return;
                }
            }

            // Constructor/main-thread compatibility path: never stall the
            // host while there is no cooperative worker context to resume.
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sysconf") {
            // Conservative Android-like values for the startup queries most
            // native libraries make. Unknown names report -1.
            switch (static_cast<int>(regs[0])) {
            case 30: // _SC_PAGESIZE on common Android/Bionic revisions
                regs[0] = 4096;
                break;
            default:
                regs[0] = 1;
                break;
            }

            ++supported_calls;
            return;
        }

        if (name == "prctl" ||
            name == "ptrace") {
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        // Soft-float AAPCS math bridge used by Android armeabi-v7a.
        // Float values travel in one core register; doubles use rN/rN+1.
        auto read_float_reg =
            [&](std::size_t index) {
                float value = 0.0f;
                const std::uint32_t bits = regs[index];
                std::memcpy(
                    &value,
                    &bits,
                    sizeof(value));
                return value;
            };

        auto write_float_reg =
            [&](float value) {
                std::uint32_t bits = 0;
                std::memcpy(
                    &bits,
                    &value,
                    sizeof(bits));
                regs[0] = bits;
            };

        auto read_double_regs =
            [&](std::size_t index) {
                const std::uint64_t bits =
                    static_cast<std::uint64_t>(regs[index]) |
                    (static_cast<std::uint64_t>(
                        regs[index + 1]) << 32);
                double value = 0.0;
