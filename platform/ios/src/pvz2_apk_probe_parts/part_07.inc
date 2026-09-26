                        address,
                        kStatSize) == nullptr) {
                    return false;
                }

                for (std::uint32_t i = 0u;
                     i < kStatSize;
                     i += 4u) {
                    mem.Write32Guest(
                        address + i,
                        0u);
                }

                mem.Write32Guest(
                    address + 0x10u,
                    0040755u);
                return true;
            };

        auto v51_write_handle =
            [&](ProbeObbHandle& handle,
                std::uint32_t source,
                std::uint64_t bytes)
                -> bool {

                if (!handle.writable) {
                    set_guest_errno(9u);
                    return false;
                }

                if (handle.dev_null) {
                    handle.offset += bytes;
                    ++v51_userfs_write_calls;
                    v51_userfs_bytes_written += bytes;
                    return true;
                }

                if (!handle.owned) {
                    set_guest_errno(9u);
                    return false;
                }

                if (bytes != 0u &&
                    mem.Ptr(
                        source,
                        static_cast<std::size_t>(
                            bytes)) == nullptr) {
                    set_guest_errno(14u);
                    return false;
                }

                const std::uint64_t end =
                    handle.offset + bytes;

                if (end >
                    static_cast<std::uint64_t>(
                        std::numeric_limits<
                            std::size_t>::max())) {
                    set_guest_errno(27u);
                    return false;
                }

                if (end > handle.owned->size()) {
                    handle.owned->resize(
                        static_cast<std::size_t>(
                            end),
                        0u);
                }

                if (bytes != 0u) {
                    std::memcpy(
                        handle.owned->data() +
                            static_cast<std::size_t>(
                                handle.offset),
                        mem.Ptr(
                            source,
                            static_cast<std::size_t>(
                                bytes)),
                        static_cast<std::size_t>(
                            bytes));
                }

                handle.offset = end;
                handle.length =
                    static_cast<std::uint64_t>(
                        handle.owned->size());
                handle.eof = false;

                ++v51_userfs_write_calls;
                v51_userfs_bytes_written += bytes;

                if (handle.virtual_path.find(
                        "snapshot2.dat") !=
                    std::string::npos) {
                    v51_snapshot2_bytes =
                        std::max<std::uint64_t>(
                            v51_snapshot2_bytes,
                            handle.length);
                }

                if (V128Enabled() && !handle.virtual_path.empty()) {
                    v128_userfs_dirty_paths.insert(
                        normalize_v51_user_path(handle.virtual_path));
                }

                return true;
            };

        static const std::unordered_set<std::string> kStdio = {
            "fclose","fdopen","feof","ferror","fflush","fgetc","fgets",
            "fopen","fprintf","fputc","fputs","fread","fscanf","fseek",
            "fsetpos","ftell","fwrite","getc","printf","putc","puts",
            "setvbuf","snprintf","sprintf","sscanf","ungetc","vsnprintf",
            "vsprintf","qsort","lrand48","srand48","strtok"
        };

        if (kStdio.count(name) != 0) {
            if (name == "snprintf" ||
                name == "sprintf" ||
                name == "vsnprintf" ||
                name == "vsprintf" ||
                name == "printf" ||
                name == "fprintf") {

                std::string format;
                std::string formatted;
                std::uint32_t destination = 0u;
                std::size_t capacity = 0u;
                bool writes_buffer = false;

                if (name == "snprintf") {
                    destination = regs[0];
                    capacity =
                        static_cast<std::size_t>(
                            regs[1]);
                    format =
                        mem.ReadCStringGuest(
                            regs[2],
                            1u << 16);
                    formatted =
                        format_direct(
                            format,
                            3u);
                    writes_buffer = true;
                } else if (name == "sprintf") {
                    destination = regs[0];
                    format =
                        mem.ReadCStringGuest(
                            regs[1],
                            1u << 16);
                    formatted =
                        format_direct(
                            format,
                            2u);
                    capacity =
                        formatted.size() + 1u;
                    writes_buffer = true;
                } else if (name == "vsnprintf") {
                    destination = regs[0];
                    capacity =
                        static_cast<std::size_t>(
                            regs[1]);
                    format =
                        mem.ReadCStringGuest(
                            regs[2],
                            1u << 16);
                    formatted =
                        format_va_list(
                            format,
                            regs[3]);
                    writes_buffer = true;
                } else if (name == "vsprintf") {
                    destination = regs[0];
                    format =
                        mem.ReadCStringGuest(
                            regs[1],
                            1u << 16);
                    formatted =
                        format_va_list(
                            format,
                            regs[2]);
                    capacity =
                        formatted.size() + 1u;
                    writes_buffer = true;
                } else if (name == "printf") {
                    format =
                        mem.ReadCStringGuest(
                            regs[0],
                            1u << 16);
                    formatted =
                        format_direct(
                            format,
                            1u);
                } else {
                    format =
                        mem.ReadCStringGuest(
                            regs[1],
                            1u << 16);
                    formatted =
                        format_direct(
                            format,
                            2u);
                }

                if (writes_buffer &&
                    destination != 0u &&
                    capacity != 0u) {

                    const std::size_t copy =
                        std::min<std::size_t>(
                            formatted.size(),
                            capacity - 1u);

                    if (auto* output =
                            mem.Ptr(
                                destination,
                                capacity)) {

                        if (V91AllowRelroWrite(
                                destination,
                                capacity,
                                "format-output")) {
                            if (copy != 0u) {
                                std::memcpy(
                                    output,
                                    formatted.data(),
                                    copy);
                            }

                            output[copy] = 0u;
                        }
                    }
                }

                if (fallback_logged.insert(
                        "v31-format:" +
                        name).second) {
                    Append(
                        "V31 FORMAT bridge active: " +
                        name);
                }

                if (!writes_buffer &&
                    !formatted.empty()) {
                    Append(
                        "V31 GUEST " +
                        name +
                        ": \"" +
                        formatted +
                        "\"");
                }

                regs[0] =
                    static_cast<std::uint32_t>(
                        std::min<std::size_t>(
                            formatted.size(),
                            0x7fffffffu));

                ++supported_calls;
                return;
            }

            if (name == "fopen") {
                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);
                const std::string mode =
                    mem.ReadCStringGuest(
                        regs[1],
                        32);

                const bool user_path =
                    v51_is_user_data_path(
                        guest_path) ||
                    normalize_v51_user_path(
                        guest_path) ==
                        "/dev/null";

                if (user_path) {
                    const bool create =
                        mode.find('w') !=
                            std::string::npos ||
                        mode.find('a') !=
                            std::string::npos;
                    const bool truncate =
                        mode.find('w') !=
                        std::string::npos;
                    const bool append =
                        mode.find('a') !=
                        std::string::npos;
                    const bool writable =
                        create ||
                        mode.find('+') !=
                            std::string::npos;

                    const auto opened =
                        v51_open_memory_file(
                            guest_path,
                            create,
                            truncate,
                            append,
                            writable);

                    if (opened.has_value()) {
                        const std::uint32_t token =
                            next_probe_file++;
                        obb_files[token] = *opened;
                        v51_file_token_paths[token] =
                            opened->virtual_path;
                        regs[0] = token;
                        ++supported_calls;

                        Append(
                            "V51 USERFS fopen(\"" +
                            guest_path +
                            "\", \"" +
                            mode +
                            "\") -> token=0x" +
                            JniProbeHex(token) +
                            " size=" +
                            std::to_string(
                                opened->length));
                        return;
                    }

                    set_guest_errno(2u);
                    regs[0] = 0u;
                    ++supported_calls;
                    Append(
                        "V51 USERFS fopen(\"" +
                        guest_path +
                        "\", \"" +
                        mode +
                        "\") -> null ENOENT");
                    return;
                }

                const auto resolved =
                    resolve_obb_virtual_file(
                        guest_path);

                if (resolved.has_value()) {

                    const std::uint32_t token =
                        next_probe_file++;

                    obb_files[token] =
                        *resolved;

                    regs[0] = token;
                    ++supported_calls;

                    Append(
                        "V26 VFS fopen(\"" +
                        guest_path +
                        "\") -> " +
                        resolved->label +
                        " token=0x" +
                        JniProbeHex(token) +
                        " base=0x" +
                        JniProbeHex(
                            static_cast<std::uint32_t>(
                                resolved->base)) +
                        " size=" +
                        std::to_string(
                            resolved->length));
                    return;
                }

                set_guest_errno(2u);
                regs[0] = 0;
                ++supported_calls;

                Append(
                    "V19 VFS fopen(\"" +
                    guest_path +
                    "\") -> null");
                return;
            }

            if (name == "fflush") {
                const std::uint32_t token = regs[0];
                const auto path_it = v51_file_token_paths.find(token);
                if (path_it != v51_file_token_paths.end() && V128Enabled()) {
                    const bool ok =
                        v128_userfs_dirty_paths.count(path_it->second) == 0u ||
                        v128_flush_file(path_it->second);
                    regs[0] = ok ? 0u : 0xffffffffu;
                    ++supported_calls;
                    return;
                }
            }

            if (name == "fclose") {
                const std::uint32_t token =
                    regs[0];
                const auto path_it =
                    v51_file_token_paths.find(
                        token);

                if (path_it != v51_file_token_paths.end() &&
                    V128Enabled() &&
                    v128_userfs_dirty_paths.count(path_it->second) != 0u) {
                    v128_flush_file(path_it->second);
                }

                if (path_it !=
                        v51_file_token_paths.end() &&
                    path_it->second.find(
                        "snapshot2.dat") !=
                        std::string::npos) {

                    const auto file_it =
                        v51_writable_files.find(
                            path_it->second);
                    Append(
                        "V51 PROFILE SNAPSHOT close path=\"" +
                        path_it->second +
                        "\" bytes=" +
                        std::to_string(
                            file_it !=
                                    v51_writable_files.end()
                                ? file_it->second->size()
                                : 0u));
                }

                v51_file_token_paths.erase(token);

                const auto erased =
                    obb_files.erase(token);

                regs[0] =
                    erased != 0u
                        ? 0u
                        : 0xffffffffu;

                ++supported_calls;
                return;
            }

            if (name == "fread") {
                const std::uint32_t dst =
                    regs[0];
                const std::uint32_t element_size =
                    regs[1];
                const std::uint32_t element_count =
                    regs[2];
                const std::uint32_t token =
                    regs[3];

                const auto it =
                    obb_files.find(token);

                if (it == obb_files.end() ||
                    element_size == 0u) {
                    regs[0] = 0;
                    ++supported_calls;
                    return;
                }

                const std::uint64_t requested =
                    static_cast<std::uint64_t>(
                        element_size) *
                    element_count;

                const std::uint64_t read_start =
                    it->second.base +
                    it->second.offset;

                const std::uint64_t available =
                    it->second.offset <
                            it->second.length
                        ? it->second.length -
                            it->second.offset
                        : 0u;

                const std::uint64_t bytes =
                    std::min(
                        requested,
                        available);

                if (bytes != 0u &&
                    !mem.Ptr(
                        dst,
                        static_cast<std::size_t>(
                            bytes))) {

                    set_guest_errno(14u);
                    regs[0] = 0;
                    ++supported_calls;
                    return;
                }

                if (bytes != 0u) {
                    const std::uint8_t* source =
                        it->second.owned
                            ? it->second.owned->data() +
                                static_cast<std::size_t>(
                                    it->second.offset)
                            : obb_data +
                                static_cast<std::size_t>(
                                    it->second.base +
                                    it->second.offset);

                    if (V91AllowRelroWrite(
                            dst,
                            static_cast<std::size_t>(
                                bytes),
                            "VFS.fread")) {
                        std::memcpy(
                            mem.Ptr(
                                dst,
                                static_cast<std::size_t>(
                                    bytes)),
                            source,
                            static_cast<std::size_t>(
                                bytes));
                    }
                }

                it->second.offset += bytes;
                it->second.eof =
                    bytes < requested;

                ++obb_read_calls;
                if (bytes != 0u) {
                    ++obb_nonzero_read_calls;
                }
                obb_bytes_returned += bytes;
                obb_max_read_end =
                    std::max<std::uint64_t>(
                        obb_max_read_end,
                        read_start + bytes);
                last_obb_read_offset =
                    read_start;
                last_obb_read_requested =
                    static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(
                            requested,
                            0xffffffffull));
                last_obb_read_returned =
                    static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(
                            bytes,
                            0xffffffffull));

                regs[0] =
                    element_size == 0u
                        ? 0u
                        : static_cast<std::uint32_t>(
                            bytes /
                            element_size);

                ++supported_calls;
                return;
            }

            if (name == "fseek") {
                const std::uint32_t token =
                    regs[0];
                const std::int32_t offset =
                    static_cast<std::int32_t>(
                        regs[1]);
                const std::uint32_t whence =
                    regs[2];

                const auto it =
                    obb_files.find(token);

                if (it == obb_files.end()) {
                    set_guest_errno(9u);
                    regs[0] = 0xffffffffu;
                    ++supported_calls;
                    return;
                }

                std::int64_t base = 0;
                if (whence == 1u) {
                    base =
                        static_cast<std::int64_t>(
                            it->second.offset);
                } else if (whence == 2u) {
                    base =
                        static_cast<std::int64_t>(
                            it->second.length);
                }

                const std::int64_t next =
                    base + offset;

                if (next < 0 ||
                    (!it->second.writable &&
                     static_cast<std::uint64_t>(
                         next) >
                         it->second.length)) {

                    set_guest_errno(22u);
                    regs[0] = 0xffffffffu;
                } else {
                    it->second.offset =
                        static_cast<std::uint64_t>(
                            next);
                    it->second.eof = false;
                    ++obb_seek_calls;
                    last_obb_seek_target =
                        static_cast<std::uint64_t>(
                            next);
                    regs[0] = 0;
                }

                ++supported_calls;
                return;
            }

            if (name == "ftell") {
                const auto it =
                    obb_files.find(regs[0]);

                regs[0] =
                    it == obb_files.end()
                        ? 0xffffffffu
                        : static_cast<std::uint32_t>(
                            it->second.offset);

                ++supported_calls;
                return;
            }

            if (name == "feof") {
                const auto it =
                    obb_files.find(regs[0]);

                regs[0] =
                    it != obb_files.end() &&
                    it->second.eof
                        ? 1u
                        : 0u;

                ++supported_calls;
                return;
            }

            if (name == "ferror") {
                regs[0] = 0;
                ++supported_calls;
                return;
            }

            if (name == "fwrite") {
                const std::uint32_t source =
                    regs[0];
                const std::uint32_t element_size =
                    regs[1];
                const std::uint32_t element_count =
                    regs[2];
                const std::uint32_t token =
                    regs[3];

                const auto it =
                    obb_files.find(token);

                if (it != obb_files.end()) {
                    const std::uint64_t bytes =
                        static_cast<std::uint64_t>(
                            element_size) *
                        element_count;

                    regs[0] =
                        v51_write_handle(
                            it->second,
                            source,
                            bytes)
                            ? element_count
                            : 0u;
                    ++supported_calls;
                    return;
                }
            }

            log_fallback_once("stdio");

            if (name == "fwrite") {
                regs[0] = regs[2];
            } else if (name == "fdopen" ||
                       name == "fgets") {
                regs[0] = 0;
            } else if (name == "fgetc" ||
                       name == "getc" ||
                       name == "ungetc") {
                regs[0] = 0xffffffffu;
            } else if (name == "fputc" ||
                       name == "putc") {
                regs[0] =
                    regs[0] & 0xffu;
            } else if (name == "fputs" ||
                       name == "puts") {
                const std::string printed =
                    mem.ReadCStringGuest(
                        regs[0],
                        1024);

                Append(
                    "V24 GUEST " +
                    name +
                    ": \"" +
                    printed +
                    "\"");

                if (!printed.empty()) {
                    RecordSweepIssue(
                        "guest-diagnostic",
                        printed,
                        printed);
                }

                regs[0] = 0;
            } else if (name == "qsort") {
                regs[0] = 0;
            } else if (name == "srand48") {
                // POSIX/Bionic srand48: X0 = (seed << 16) | 0x330e.
                // Android armeabi-v7a uses a 32-bit long.
                const std::uint64_t seed =
                    static_cast<std::uint64_t>(regs[0]);
                v131_rand48_state =
                    ((seed << 16u) | 0x330eull) &
                    0x0000ffffffffffffull;
                ++v131_srand48_calls;
                if (V131Enabled() && v131_srand48_calls <= 4u) {
                    AppendDiagnostic(
                        "V131 srand48 #" +
                        std::to_string(v131_srand48_calls) +
                        " seed=" + std::to_string(regs[0]) +
                        " state=" +
                        std::to_string(v131_rand48_state));
                }
                regs[0] = 0u;
            } else if (name == "lrand48") {
                // POSIX 48-bit LCG:
                // X(n+1)=(0x5deece66d*X(n)+0xb) mod 2^48,
                // lrand48 returns the high 31 bits.
                v131_rand48_state =
                    (0x5deece66dull * v131_rand48_state +
                     0xbull) &
                    0x0000ffffffffffffull;
                regs[0] = static_cast<std::uint32_t>(
                    v131_rand48_state >> 17u);
                ++v131_lrand48_calls;
                if (V131Enabled() && v131_lrand48_calls <= 8u) {
                    AppendDiagnostic(
                        "V131 lrand48 #" +
                        std::to_string(v131_lrand48_calls) +
                        " value=" + std::to_string(regs[0]));
                }
            } else {
                regs[0] = 0;
            }

            ++supported_calls;
            return;
        }

        static const std::unordered_set<std::string> kPosixFiles = {
            "access","close","closedir","fnmatch","fstat","fsync",
            "ftruncate","ioctl","lseek","mkdir","mktemp","open","opendir",
            "poll","read","readdir","readdir_r","stat","syscall","unlink",
            "write","writev"
        };

        if (kPosixFiles.count(name) != 0) {
            if (name == "opendir") {
                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);

                if (v51_is_user_data_path(
                        guest_path)) {
                    const std::string path =
                        normalize_v51_user_path(
                            guest_path);
                    v51_writable_directories.insert(
                        path);

                    const std::uint32_t token =
                        v51_next_directory_handle++;
                    v51_directory_handles.insert(
                        token);
                    regs[0] = token;
                    ++supported_calls;

                    if (fallback_logged.insert(
                            "v51-opendir:" +
                            path).second) {
                        Append(
                            "V51 USERFS opendir(\"" +
                            guest_path +
                            "\") -> empty dir token=0x" +
                            JniProbeHex(token));
                    }
                    return;
                }

                set_guest_errno(2u);
                regs[0] = 0u;
                ++supported_calls;

                if (fallback_logged.insert(
                        "v28-opendir:" +
                        guest_path).second) {
                    Append(
                        "V28 DIR opendir(\"" +
                        guest_path +
                        "\") -> NULL ENOENT");
                }
                return;
            }

            if (name == "readdir") {
                // EOF is represented by a null dirent pointer. Returning
                // 0xffffffff (the old generic fallback) is a valid non-null
                // pointer to guest code and caused an unbounded
                // readdir/fnmatch loop.
                regs[0] = 0u;
                ++supported_calls;
                return;
            }

            if (name == "readdir_r") {
                // int readdir_r(DIR*, struct dirent*, struct dirent** result)
                // Successful end-of-directory: return 0 and *result = NULL.
                if (regs[2] != 0u) {
                    mem.Write32Guest(
                        regs[2],
                        0u);
                }

                regs[0] = 0u;
                ++supported_calls;
                return;
            }

            if (name == "fnmatch") {
                const std::string pattern =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);
                const std::string candidate =
                    mem.ReadCStringGuest(
                        regs[1],
                        2048);

                regs[0] =
                    static_cast<std::uint32_t>(
                        ::fnmatch(
                            pattern.c_str(),
                            candidate.c_str(),
                            static_cast<int>(
                                regs[2])));

                ++supported_calls;
                return;
            }

            if (name == "closedir") {
                const auto erased =
                    v51_directory_handles.erase(
                        regs[0]);
                if (erased != 0u) {
                    regs[0] = 0u;
                } else {
                    set_guest_errno(9u);
                    regs[0] = 0xffffffffu;
                }
                ++supported_calls;
                return;
            }

            if (name == "open") {
                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);
                const std::uint32_t flags =
                    regs[1];

                const bool user_path =
                    v51_is_user_data_path(
                        guest_path) ||
                    normalize_v51_user_path(
                        guest_path) ==
                        "/dev/null";

                if (user_path) {
                    constexpr std::uint32_t kOCreat =
                        0x40u;
                    constexpr std::uint32_t kOTrunc =
                        0x200u;
                    constexpr std::uint32_t kOAppend =
                        0x400u;
                    constexpr std::uint32_t kAccMode =
                        0x3u;

                    const bool create =
                        (flags & kOCreat) != 0u;
                    const bool truncate =
                        (flags & kOTrunc) != 0u;
                    const bool append =
                        (flags & kOAppend) != 0u;
                    const bool writable =
                        (flags & kAccMode) != 0u ||
                        create ||
                        truncate ||
                        append;

                    const auto opened =
                        v51_open_memory_file(
                            guest_path,
                            create,
                            truncate,
                            append,
                            writable);

                    if (opened.has_value()) {
                        const std::uint32_t token =
                            next_probe_fd++;
                        obb_fds[token] = *opened;
                        v51_fd_token_paths[token] =
                            opened->virtual_path;
                        regs[0] = token;
                        ++supported_calls;

                        Append(
                            "V51 USERFS open(\"" +
                            guest_path +
                            "\", flags=0x" +
                            JniProbeHex(flags) +
                            ") -> fd=0x" +
                            JniProbeHex(token) +
                            " size=" +
                            std::to_string(
                                opened->length));
                        return;
                    }

                    set_guest_errno(2u);
                    regs[0] = 0xffffffffu;
                    ++supported_calls;
                    Append(
                        "V51 USERFS open(\"" +
                        guest_path +
                        "\", flags=0x" +
                        JniProbeHex(flags) +
                        ") -> -1 ENOENT");
                    return;
                }

                const auto resolved =
                    resolve_obb_virtual_file(
                        guest_path);

                if (resolved.has_value()) {

                    const std::uint32_t token =
                        next_probe_fd++;

                    obb_fds[token] =
                        *resolved;

                    regs[0] = token;
                    ++supported_calls;

                    Append(
                        "V26 VFS open(\"" +
                        guest_path +
                        "\") -> " +
                        resolved->label +
                        " fd=0x" +
                        JniProbeHex(token) +
                        " base=0x" +
                        JniProbeHex(
                            static_cast<std::uint32_t>(
                                resolved->base)) +
                        " size=" +
                        std::to_string(
                            resolved->length));
                    return;
                }

                set_guest_errno(2u);
                regs[0] = 0xffffffffu;
                ++supported_calls;

                Append(
                    "V19 VFS open(\"" +
                    guest_path +
                    "\") -> -1 ENOENT");
                return;
            }

            if (name == "close") {
                const std::uint32_t token =
                    regs[0];
                const auto path_it = v51_fd_token_paths.find(token);
                if (path_it != v51_fd_token_paths.end() &&
                    V128Enabled() &&
                    v128_userfs_dirty_paths.count(path_it->second) != 0u) {
                    v128_flush_file(path_it->second);
                }
                v51_fd_token_paths.erase(token);

                const auto erased =
                    obb_fds.erase(token);

                regs[0] =
                    erased != 0u
                        ? 0u
                        : 0xffffffffu;

                ++supported_calls;
                return;
            }

            if (name == "read") {
                const std::uint32_t token =
                    regs[0];
                const std::uint32_t dst =
                    regs[1];
                const std::uint32_t requested =
                    regs[2];

                const auto it =
                    obb_fds.find(token);

                if (it == obb_fds.end()) {
                    set_guest_errno(9u);
                    regs[0] = 0xffffffffu;
                    ++supported_calls;
                    return;
                }

                const std::uint64_t read_start =
                    it->second.base +
                    it->second.offset;

                const std::uint64_t available =
                    it->second.offset <
                            it->second.length
                        ? it->second.length -
                            it->second.offset
                        : 0u;

                const std::uint64_t bytes =
                    std::min<std::uint64_t>(
                        requested,
                        available);

                if (bytes != 0u &&
                    !mem.Ptr(
                        dst,
                        static_cast<std::size_t>(
                            bytes))) {

                    set_guest_errno(14u);
                    regs[0] = 0xffffffffu;
                    ++supported_calls;
                    return;
                }

                const std::uint64_t v89_vfs_begin_ns=V89HostCostEnabled()&&bytes!=0u?V85SteadyNowNs():0u;
                if (bytes != 0u) {
                    const std::uint8_t* source =
                        it->second.owned
                            ? it->second.owned->data() +
                                static_cast<std::size_t>(
                                    it->second.offset)
                            : obb_data +
                                static_cast<std::size_t>(
                                    it->second.base +
                                    it->second.offset);

                    if (V91AllowRelroWrite(
                            dst,
                            static_cast<std::size_t>(
                                bytes),
                            "VFS.read")) {
                        std::memcpy(
                            mem.Ptr(
                                dst,
                                static_cast<std::size_t>(
                                    bytes)),
                            source,
                            static_cast<std::size_t>(
                                bytes));
                    }
                    if(V89HostCostEnabled())V89RecordHostCost("vfs.read.memcpy",v89_vfs_begin_ns,bytes);
                }

                it->second.offset += bytes;
                it->second.eof =
                    bytes < requested;

                ++obb_read_calls;
                if (bytes != 0u) {
                    ++obb_nonzero_read_calls;
                }
                obb_bytes_returned += bytes;
                obb_max_read_end =
                    std::max<std::uint64_t>(
                        obb_max_read_end,
                        read_start + bytes);
                last_obb_read_offset =
                    read_start;
                last_obb_read_requested =
                    requested;
                last_obb_read_returned =
                    static_cast<std::uint32_t>(bytes);

                regs[0] =
                    static_cast<std::uint32_t>(
                        bytes);

                ++supported_calls;

                if (fallback_logged.insert(
                        "v19-obb-read").second) {
                    Append(
                        "V26 VFS first read: fd=0x" +
                        JniProbeHex(token) +
                        " label=" +
                        it->second.label +
                        " absolute=0x" +
                        JniProbeHex(
                            static_cast<std::uint32_t>(
                                read_start)) +
                        " bytes=" +
                        std::to_string(bytes));
                }

                return;
            }

            if (name == "lseek") {
                const std::uint32_t token =
                    regs[0];
                const std::int32_t offset =
                    static_cast<std::int32_t>(
                        regs[1]);
                const std::uint32_t whence =
                    regs[2];

                const auto it =
                    obb_fds.find(token);

                if (it == obb_fds.end()) {
                    set_guest_errno(9u);
                    regs[0] = 0xffffffffu;
                    ++supported_calls;
                    return;
                }

                std::int64_t base = 0;

                if (whence == 1u) {
                    base =
                        static_cast<std::int64_t>(
                            it->second.offset);
                } else if (whence == 2u) {
                    base =
                        static_cast<std::int64_t>(
                            it->second.length);
                }

                const std::int64_t next =
                    base + offset;

                if (next < 0 ||
                    (!it->second.writable &&
                     static_cast<std::uint64_t>(
                         next) >
                         it->second.length)) {

                    set_guest_errno(22u);
                    regs[0] = 0xffffffffu;
                } else {
                    it->second.offset =
                        static_cast<std::uint64_t>(
                            next);
                    it->second.eof = false;
                    ++obb_seek_calls;
                    last_obb_seek_target =
                        static_cast<std::uint64_t>(
                            next);

                    regs[0] =
                        static_cast<std::uint32_t>(
                            next);
                }

                ++supported_calls;
                return;
            }

            if (name == "fstat") {
                const auto it =
                    obb_fds.find(regs[0]);

                if (it != obb_fds.end() &&
                    write_armeabi_stat(
                        regs[1],
                        it->second.length)) {
                    regs[0] = 0;
                } else {
                    set_guest_errno(9u);
                    regs[0] = 0xffffffffu;
                }

                ++supported_calls;
                return;
            }

            if (name == "stat" ||
                name == "access") {

                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);

                std::uint64_t user_size = 0u;
                bool user_directory = false;
                const bool user_exists =
                    v51_path_exists(
                        guest_path,
                        &user_size,
                        &user_directory);

                const auto resolved =
                    user_exists
                        ? std::optional<ProbeObbHandle>{}
                        : resolve_obb_virtual_file(
                              guest_path);

                const bool exists =
                    user_exists ||
                    resolved.has_value();

                if (name == "access") {
                    regs[0] =
                        exists
                            ? 0u
                            : 0xffffffffu;
                } else if (user_exists) {
                    regs[0] =
                        (user_directory
                             ? write_armeabi_dir_stat(
                                   regs[1])
                             : write_armeabi_stat(
                                   regs[1],
                                   user_size))
                            ? 0u
                            : 0xffffffffu;
                } else if (resolved.has_value() &&
                           write_armeabi_stat(
                               regs[1],
                               resolved->length)) {
                    regs[0] = 0u;
                } else {
                    regs[0] = 0xffffffffu;
                }

                if (!exists) {
                    set_guest_errno(2u);
                }

                ++supported_calls;
                return;
            }

            if (name == "write") {
                const auto it =
                    obb_fds.find(regs[0]);
                if (it != obb_fds.end()) {
                    const std::uint32_t requested =
                        regs[2];
                    regs[0] =
                        v51_write_handle(
                            it->second,
                            regs[1],
                            requested)
                            ? requested
                            : 0xffffffffu;
                    ++supported_calls;
                    return;
                }
            }

            if (name == "fsync") {
                const auto path_it = v51_fd_token_paths.find(regs[0]);
                if (path_it != v51_fd_token_paths.end() && V128Enabled()) {
                    const bool ok =
                        v128_userfs_dirty_paths.count(path_it->second) == 0u ||
                        v128_flush_file(path_it->second);
                    regs[0] = ok ? 0u : 0xffffffffu;
                    ++supported_calls;
                    return;
                }
            }

            if (name == "ftruncate") {
                const auto it =
                    obb_fds.find(regs[0]);
                const std::uint32_t requested =
                    regs[1];

                if (it != obb_fds.end() &&
                    it->second.writable &&
                    it->second.owned &&
                    !it->second.dev_null) {
                    it->second.owned->resize(
                        requested,
                        0u);
                    it->second.length = requested;
                    if (V128Enabled() && !it->second.virtual_path.empty()) {
                        v128_userfs_dirty_paths.insert(
                            normalize_v51_user_path(it->second.virtual_path));
                    }
                    if (it->second.offset >
                        requested) {
                        it->second.offset =
                            requested;
                    }
                    regs[0] = 0u;
                } else {
                    set_guest_errno(9u);
                    regs[0] = 0xffffffffu;
                }

                ++supported_calls;
                return;
            }

            if (name == "mkdir") {
                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);

                if (v51_is_user_data_path(
                        guest_path)) {
                    const std::string path =
                        normalize_v51_user_path(
                            guest_path);
                    v51_writable_directories.insert(
                        path);
                    if (V128Enabled()) {
                        const std::string host = v128_host_path_for_guest(path);
                        if (!host.empty() &&
                            v128_mkdirs_for_file(host + "/.pvz2dir")) {
                            ++v128_userfs_mkdirs;
                        }
                    }
                    regs[0] = 0u;

                    if (fallback_logged.insert(
                            "v51-mkdir:" + path)
                            .second) {
                        Append(
                            "V51 USERFS mkdir(\"" +
                            guest_path +
                            "\") -> 0");
                    }
                } else {
                    regs[0] = 0u;
                }

                ++supported_calls;
                return;
            }

            if (name == "unlink") {
                const std::string guest_path =
                    normalize_v51_user_path(
                        mem.ReadCStringGuest(
                            regs[0],
                            2048));

                if (v51_is_user_data_path(
                        guest_path)) {
                    const auto erased =
                        v51_writable_files.erase(guest_path);
                    bool disk_erased = false;
                    if (V128Enabled()) {
                        const std::string host =
                            v128_host_path_for_guest(guest_path);
                        if (!host.empty() && ::unlink(host.c_str()) == 0) {
                            disk_erased = true;
                            ++v128_userfs_unlinks;
                        }
                        v128_userfs_dirty_paths.erase(guest_path);
                    }
                    regs[0] =
                        (erased != 0u || disk_erased)
                            ? 0u
                            : 0xffffffffu;
                    if (erased == 0u && !disk_erased) {
                        set_guest_errno(2u);
                    }
                    ++supported_calls;
                    return;
                }
            }

            log_fallback_once("posix-fs");

            if (name == "write") {
                regs[0] = regs[2];
            } else if (name == "writev") {
                regs[0] = 0;
            } else if (name == "fsync") {
                regs[0] = 0;
            } else if (name == "poll") {
                regs[0] = 0;
            } else {
                regs[0] = 0xffffffffu;
            }

            ++supported_calls;
            return;
        }

        static const std::unordered_set<std::string> kTimeLocale = {
            "asctime","gmtime","localtime","localtime_r","mktime",
            "strftime","strptime"
        };

        if (kTimeLocale.count(name) != 0) {
            log_fallback_once("time-locale");
            // Constructors/GameAppInitialize only need these calls not to
            // escape the guest. Full struct tm conversion comes with VFS/time.
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name.rfind("gl", 0) == 0) {
            auto allocate_guest_string =
                [&](const char* value) {
                    if (value == nullptr) {
                        value = "";
                    }

                    const std::size_t length =
                        std::strlen(value);
                    const std::uint32_t guest =
                        mem.AllocateObject(
                            static_cast<std::uint32_t>(
                                length + 1u),
                            1u);

                    if (guest) {
                        for (std::size_t i = 0;
                             i < length;
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
                                    length),
                            0u);
                    }

                    return guest;
                };

            auto guest_arg =
                [&](std::uint32_t index)
                    -> std::uint32_t {
                    if (index < 4u) {
                        return regs[index];
                    }

                    return
                        mem.Read32Guest(
                            regs[13] +
                            (index - 4u) * 4u);
                };

            auto guest_f32 =
                [&](std::uint32_t index) {
                    const std::uint32_t bits =
                        guest_arg(index);
                    float value = 0.0f;
                    std::memcpy(
                        &value,
                        &bits,
                        sizeof(value));
                    return value;
                };

            auto pixel_bytes =
                [&](GLsizei width,
                    GLsizei height,
                    GLenum format,
                    GLenum type)
                    -> std::size_t {

                    if (width <= 0 ||
                        height <= 0) {
                        return 0u;
                    }

                    std::size_t bytes_per_pixel = 0u;

                    if (type == GL_UNSIGNED_BYTE) {
                        switch (format) {
                        case GL_RGBA:
                            bytes_per_pixel = 4u;
                            break;
                        case GL_RGB:
                            bytes_per_pixel = 3u;
                            break;
                        case GL_LUMINANCE_ALPHA:
                            bytes_per_pixel = 2u;
                            break;
                        case GL_ALPHA:
                        case GL_LUMINANCE:
                            bytes_per_pixel = 1u;
                            break;
                        default:
                            break;
                        }
                    } else if (
                        type == GL_UNSIGNED_SHORT_5_6_5 ||
                        type == GL_UNSIGNED_SHORT_4_4_4_4 ||
                        type == GL_UNSIGNED_SHORT_5_5_5_1) {
                        bytes_per_pixel = 2u;
                    }

                    if (bytes_per_pixel == 0u) {
                        return 0u;
                    }

                    return
                        static_cast<std::size_t>(width) *
                        static_cast<std::size_t>(height) *
                        bytes_per_pixel;
                };

            if (host_gles_ready) {
                if (fallback_logged.insert(
                        "v31-host-gles:" +
                        name).second) {
                    Append(
                        "V31 HOST GLES dispatch: " +
                        name);
                }

                if (name == "glGetError") {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            glGetError());
                } else if (
                    name == "glCheckFramebufferStatus" ||
                    name == "glCheckFramebufferStatusOES") {

                    regs[0] =
                        static_cast<std::uint32_t>(
                            glCheckFramebufferStatus(
                                static_cast<GLenum>(
                                    guest_arg(0u))));
                } else if (name == "glCreateProgram") {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            glCreateProgram());
                } else if (name == "glCreateShader") {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            glCreateShader(
                                static_cast<GLenum>(
                                    guest_arg(0u))));
                } else if (
                    name == "glGenTextures" ||
                    name == "glGenFramebuffers" ||
                    name == "glGenFramebuffersOES") {

                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(0u));
                    const std::uint32_t output =
                        guest_arg(1u);

                    std::vector<GLuint> objects(
                        count > 0
                            ? static_cast<std::size_t>(
                                  count)
                            : 0u);

                    if (name == "glGenTextures") {
                        glGenTextures(
                            count,
                            objects.data());
                    } else {
                        glGenFramebuffers(
                            count,
                            objects.data());
                    }

                    for (GLsizei i = 0;
                         i < count;
                         ++i) {
                        const GLuint object =
                            objects[
                                static_cast<std::size_t>(
                                    i)];

                        mem.Write32Guest(
                            output +
                                static_cast<std::uint32_t>(
                                    i) *
                                    4u,
                            static_cast<std::uint32_t>(
                                object));

                        if (name != "glGenTextures") {
                            gles_generated_framebuffers.insert(
                                object);

                            Append(
                                "V47 GLES GEN FBO guest/host=" +
                                std::to_string(
                                    object));
                        }
                    }

                    regs[0] = 0u;
                } else if (
                    name == "glDeleteTextures" ||
                    name == "glDeleteFramebuffers" ||
                    name == "glDeleteFramebuffersOES") {

                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(0u));
                    const std::uint32_t input =
                        guest_arg(1u);

                    std::vector<GLuint> objects(
                        count > 0
                            ? static_cast<std::size_t>(
                                  count)
                            : 0u);

                    for (GLsizei i = 0;
                         i < count;
                         ++i) {
                        objects[
                            static_cast<std::size_t>(i)] =
                                static_cast<GLuint>(
                                    mem.Read32Guest(
                                        input +
                                        static_cast<std::uint32_t>(
                                            i) *
                                        4u));
                    }

                    if (name == "glDeleteTextures") {
                        glDeleteTextures(
                            count,
                            objects.data());
                    } else {
                        glDeleteFramebuffers(
                            count,
                            objects.data());

                        for (const GLuint object :
                             objects) {
                            gles_generated_framebuffers.erase(
                                object);
                            gles_framebuffer_color_texture.erase(
                                object);
                            gles_draws_by_framebuffer.erase(
                                object);
                        }
                    }

                    regs[0] = 0u;
                } else if (name == "glShaderSource") {
                    const GLuint shader =
                        static_cast<GLuint>(
                            guest_arg(0u));
                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(1u));
                    const std::uint32_t strings_address =
                        guest_arg(2u);
                    const std::uint32_t lengths_address =
                        guest_arg(3u);

                    std::vector<std::string> sources;
                    std::vector<const GLchar*> source_ptrs;
                    std::vector<GLint> lengths;

                    if (count > 0) {
                        sources.reserve(
                            static_cast<std::size_t>(
                                count));
                        source_ptrs.reserve(
                            static_cast<std::size_t>(
                                count));
                        lengths.reserve(
                            static_cast<std::size_t>(
                                count));
                    }

                    for (GLsizei i = 0;
                         i < count;
                         ++i) {
                        const std::uint32_t guest_string =
                            mem.Read32Guest(
                                strings_address +
                                static_cast<std::uint32_t>(
                                    i) *
                                4u);

                        sources.push_back(
                            mem.ReadCStringGuest(
                                guest_string,
                                1u << 20));

                        lengths.push_back(
                            lengths_address != 0u
                                ? static_cast<GLint>(
                                      mem.Read32Guest(
                                          lengths_address +
                                          static_cast<std::uint32_t>(
                                              i) *
                                          4u))
                                : -1);
                    }

                    for (const auto& source :
                         sources) {
                        source_ptrs.push_back(
                            source.c_str());
                    }

                    glShaderSource(
                        shader,
                        count,
                        source_ptrs.data(),
                        lengths_address != 0u
                            ? lengths.data()
                            : nullptr);

                    ++gles_shader_source_calls;

                    if (gles_shader_source_calls <= 8u) {
                        std::ostringstream diagnostic;
                        diagnostic
                            << "V41 GLES SHADER #"
                            << gles_shader_source_calls
                            << " object="
                            << shader
                            << " parts="
                            << count
                            << " source=\"";

                        std::size_t emitted = 0u;

                        for (const auto& source :
                             sources) {
                            for (const char ch : source) {
                                if (emitted >= 4096u) {
                                    break;
                                }

                                if (ch == '\n' ||
                                    ch == '\r' ||
                                    ch == '\t') {
                                    diagnostic << ' ';
                                } else if (ch == '\"') {
                                    diagnostic << '\'';
                                } else {
                                    diagnostic << ch;
                                }

                                ++emitted;
                            }

                            if (emitted >= 4096u) {
                                break;
                            }
                        }

                        if (emitted >= 4096u) {
                            diagnostic << "...";
                        }

                        diagnostic << "\"";
                        Append(diagnostic.str());
                    }

                    regs[0] = 0u;
                } else if (name == "glCompileShader") {
                    glCompileShader(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glAttachShader") {
                    glAttachShader(
                        static_cast<GLuint>(
                            guest_arg(0u)),
                        static_cast<GLuint>(
                            guest_arg(1u)));
                    regs[0] = 0u;
                } else if (name == "glBindAttribLocation") {
                    const std::string attribute =
                        mem.ReadCStringGuest(
                            guest_arg(2u),
                            4096u);

                    const GLuint program =
                        static_cast<GLuint>(
                            guest_arg(0u));
                    const GLuint index =
                        static_cast<GLuint>(
                            guest_arg(1u));

                    glBindAttribLocation(
                        program,
                        index,
                        attribute.c_str());

                    if (index <
                        gles_attrib_state.size()) {
                        const std::uint64_t key =
                            (static_cast<std::uint64_t>(
                                 program) << 32u) |
                            index;

                        gles_attrib_names[key] =
                            attribute;

                        Append(
                            "V42 GLES ATTRIB LOCATION program=" +
                            std::to_string(program) +
                            " index=" +
                            std::to_string(index) +
                            " name=\"" +
                            attribute +
                            "\"");
                    }

                    regs[0] = 0u;
                } else if (name == "glLinkProgram") {
                    glLinkProgram(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (
                    name == "glGetShaderiv" ||
                    name == "glGetProgramiv") {

                    GLint value = 0;

                    if (name == "glGetShaderiv") {
                        glGetShaderiv(
                            static_cast<GLuint>(
                                guest_arg(0u)),
                            static_cast<GLenum>(
                                guest_arg(1u)),
                            &value);
                    } else {
                        glGetProgramiv(
                            static_cast<GLuint>(
                                guest_arg(0u)),
                            static_cast<GLenum>(
                                guest_arg(1u)),
                            &value);
                    }

                    if (guest_arg(2u) != 0u) {
                        mem.Write32Guest(
                            guest_arg(2u),
                            static_cast<std::uint32_t>(
                                value));
                    }

                    regs[0] = 0u;
                } else if (
                    name == "glGetShaderInfoLog" ||
                    name == "glGetProgramInfoLog") {

                    const GLsizei capacity =
                        static_cast<GLsizei>(
                            guest_arg(1u));
                    std::vector<GLchar> buffer(
                        capacity > 0
                            ? static_cast<std::size_t>(
                                  capacity)
                            : 1u);
                    GLsizei length = 0;

                    if (name == "glGetShaderInfoLog") {
                        glGetShaderInfoLog(
                            static_cast<GLuint>(
                                guest_arg(0u)),
                            capacity,
                            &length,
                            buffer.data());
                    } else {
                        glGetProgramInfoLog(
                            static_cast<GLuint>(
                                guest_arg(0u)),
                            capacity,
                            &length,
                            buffer.data());
                    }

                    if (guest_arg(2u) != 0u) {
                        mem.Write32Guest(
                            guest_arg(2u),
                            static_cast<std::uint32_t>(
                                length));
                    }

                    if (guest_arg(3u) != 0u &&
                        capacity > 0) {
                        const std::size_t copy =
                            std::min<std::size_t>(
                                static_cast<std::size_t>(
                                    std::max<GLsizei>(
                                        length,
                                        0)),
                                static_cast<std::size_t>(
                                    capacity - 1));

                        if (auto* out =
                                mem.Ptr(
                                    guest_arg(3u),
                                    static_cast<std::size_t>(
                                        capacity))) {

                            if (V91AllowRelroWrite(
                                    guest_arg(3u),
                                    static_cast<std::size_t>(
                                        capacity),
                                    "GLES.info-log")) {
                                std::memcpy(
                                    out,
                                    buffer.data(),
                                    copy);
                                out[copy] = 0u;
                            }
                        }
                    }

                    regs[0] = 0u;
                } else if (name == "glGetString") {
                    const GLubyte* host =
                        glGetString(
                            static_cast<GLenum>(
                                guest_arg(0u)));

                    regs[0] =
                        allocate_guest_string(
                            reinterpret_cast<const char*>(
                                host));
                } else if (name == "glGetUniformLocation") {
                    const std::string uniform =
                        mem.ReadCStringGuest(
                            guest_arg(1u),
                            4096u);

                    const GLuint program =
                        static_cast<GLuint>(
                            guest_arg(0u));

                    const GLint location =
                        glGetUniformLocation(
                            program,
                            uniform.c_str());

                    regs[0] =
                        static_cast<std::uint32_t>(
                            location);

                    if (location >= 0) {
                        const std::uint64_t key =
                            (static_cast<std::uint64_t>(
                                 program) << 32u) |
                            static_cast<std::uint32_t>(
                                location);

                        gles_uniform_names[key] =
                            uniform;

                        Append(
                            "V41 GLES UNIFORM LOCATION program=" +
                            std::to_string(program) +
                            " loc=" +
                            std::to_string(location) +
                            " name=\"" +
                            uniform +
                            "\"");
                    }
                } else if (name == "glUseProgram") {
                    gles_current_program =
                        static_cast<GLuint>(
                            guest_arg(0u));

                    glUseProgram(
                        gles_current_program);
                    regs[0] = 0u;
                } else if (name == "glUniform1i") {
                    const GLint location =
                        static_cast<GLint>(
                            guest_arg(0u));
                    const GLint value =
                        static_cast<GLint>(
                            guest_arg(1u));

                    glUniform1i(
                        location,
                        value);

                    const std::uint64_t key =
                        (static_cast<std::uint64_t>(
                             gles_current_program)
                         << 32u) |
                        static_cast<std::uint32_t>(
                            location);
                    gles_uniform1i_values[key] =
                        value;

                    regs[0] = 0u;
                } else if (name == "glUniform4fv") {
                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(1u));
                    const std::size_t bytes =
                        count > 0
                            ? static_cast<std::size_t>(
                                  count) *
                                  4u *
                                  sizeof(GLfloat)
                            : 0u;

                    const GLfloat* values =
                        reinterpret_cast<const GLfloat*>(
                            bytes != 0u
                                ? mem.Ptr(
                                      guest_arg(2u),
                                      bytes)
                                : nullptr);

                    const GLint location =
                        static_cast<GLint>(
                            guest_arg(0u));

                    glUniform4fv(
                        location,
                        count,
                        values);

                    ++gles_uniform4_calls;

                    if (gles_uniform4_calls <= 128u &&
                        count > 0 &&
                        values != nullptr) {

                        const std::uint64_t key =
                            (static_cast<std::uint64_t>(
                                 gles_current_program) << 32u) |
                            static_cast<std::uint32_t>(
                                location);

                        const auto found =
                            gles_uniform_names.find(
                                key);

                        std::ostringstream diagnostic;
                        diagnostic
                            << "V41 GLES UNIFORM4 #"
                            << gles_uniform4_calls
                            << " program="
                            << gles_current_program
                            << " loc="
                            << location
                            << " name=\""
                            << (found !=
                                    gles_uniform_names.end()
                                    ? found->second
                                    : std::string{"?"})
                            << "\" value=("
                            << values[0]
                            << ","
                            << values[1]
                            << ","
                            << values[2]
                            << ","
                            << values[3]
                            << ")";
                        Append(diagnostic.str());
                    }

                    regs[0] = 0u;
                } else if (
                    name == "glUniformMatrix4fv") {
                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(1u));
                    const std::size_t bytes =
                        count > 0
                            ? static_cast<std::size_t>(
                                  count) *
                                  16u *
                                  sizeof(GLfloat)
                            : 0u;

                    const GLfloat* values =
                        reinterpret_cast<const GLfloat*>(
                            bytes != 0u
                                ? mem.Ptr(
                                      guest_arg(3u),
                                      bytes)
                                : nullptr);

                    if (values != nullptr && count > 0) {
                        const GLint location =
                            static_cast<GLint>(guest_arg(0u));
                        const std::uint64_t key =
                            (static_cast<std::uint64_t>(
                                 gles_current_program) << 32u) |
                            static_cast<std::uint32_t>(location);

                        std::array<GLfloat, 16> matrix{};
                        std::copy_n(values, 16u, matrix.begin());

                        const auto previous =
                            gles_uniform_matrix4_values.find(key);
                        const bool changed =
                            previous ==
                                gles_uniform_matrix4_values.end() ||
                            previous->second != matrix;
                        gles_uniform_matrix4_values[key] = matrix;

                        const auto name_it =
                            gles_uniform_names.find(key);
                        const std::string uniform_name =
                            name_it != gles_uniform_names.end()
                                ? name_it->second
                                : std::string{"loc"} +
                                      std::to_string(location);

                        std::string lowered = uniform_name;
                        std::transform(
                            lowered.begin(),
                            lowered.end(),
                            lowered.begin(),
                            [](unsigned char c) {
                                return static_cast<char>(
                                    std::tolower(c));
                            });

                        if (V80Enabled() &&
                            lowered.find("screenmatrix") !=
                                std::string::npos) {

                            ++v80_screen_matrix_uploads;

                            if (changed) {
                                ++v80_screen_matrix_changes;

                                if (v80_screen_matrix_changes <= 96u) {
                                    const double inferred_w =
                                        std::fabs(matrix[0]) > 1.0e-9f
                                            ? 2.0 /
                                                  std::fabs(
                                                      static_cast<double>(
                                                          matrix[0]))
                                            : 0.0;
                                    const double inferred_h =
                                        std::fabs(matrix[5]) > 1.0e-9f
                                            ? 2.0 /
                                                  std::fabs(
                                                      static_cast<double>(
                                                          matrix[5]))
                                            : 0.0;

                                    std::ostringstream diagnostic;
                                    diagnostic
                                        << "V80 SCREENMATRIX change#"
                                        << v80_screen_matrix_changes
                                        << " upload#"
                                        << v80_screen_matrix_uploads
                                        << " frame="
                                        << current_frame_number
                                        << " program="
                                        << gles_current_program
                                        << " loc="
                                        << location
                                        << " name="
                                        << uniform_name
                                        << " viewport=("
                                        << last_gles_viewport[0] << ","
                                        << last_gles_viewport[1] << ","
                                        << last_gles_viewport[2] << ","
                                        << last_gles_viewport[3]
                                        << ") inferredCanvas="
                                        << inferred_w << "x" << inferred_h
                                        << " m=[";
                                    for (std::size_t i = 0u;
                                         i < matrix.size();
                                         ++i) {
                                        if (i != 0u) diagnostic << ",";
                                        diagnostic << matrix[i];
                                    }
                                    diagnostic << "]";
                                    Append(diagnostic.str());
                                }
                            }
                        }
                    }

                    glUniformMatrix4fv(
                        static_cast<GLint>(
                            guest_arg(0u)),
                        count,
                        static_cast<GLboolean>(
                            guest_arg(2u)),
                        values);
                    regs[0] = 0u;
                } else if (name == "glBindTexture") {
                    const GLenum target =
                        static_cast<GLenum>(
                            guest_arg(0u));
                    const GLuint texture =
                        static_cast<GLuint>(
                            guest_arg(1u));

                    if (target == GL_TEXTURE_2D &&
                        gles_active_texture_unit >=
                            GL_TEXTURE0) {
                        const std::uint32_t unit =
                            static_cast<std::uint32_t>(
                                gles_active_texture_unit -
                                GL_TEXTURE0);

                        if (unit <
                            gles_bound_texture_2d.size()) {
                            gles_bound_texture_2d[unit] =
                                texture;
                        }
                    }

                    glBindTexture(
                        target,
                        texture);
                    regs[0] = 0u;
                } else if (name == "glTexParameteri") {
                    glTexParameteri(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLenum>(
                            guest_arg(1u)),
                        static_cast<GLint>(
                            guest_arg(2u)));
                    regs[0] = 0u;
                } else if (name == "glPixelStorei") {
                    glPixelStorei(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)));
                    regs[0] = 0u;
                } else if (name == "glTexImage2D") {
                    ++gles_texture_uploads;
                    const GLsizei width =
                        static_cast<GLsizei>(
                            guest_arg(3u));
                    const GLsizei height =
                        static_cast<GLsizei>(
                            guest_arg(4u));
                    const GLenum format =
                        static_cast<GLenum>(
                            guest_arg(6u));
                    const GLenum type =
                        static_cast<GLenum>(
                            guest_arg(7u));
                    const std::uint32_t pixels_address =
                        guest_arg(8u);
                    const std::size_t bytes =
                        pixel_bytes(
                            width,
                            height,
                            format,
                            type);

                    const void* pixels =
                        pixels_address != 0u
                            ? mem.Ptr(
                                  pixels_address,
                                  bytes != 0u
                                      ? bytes
                                      : 1u)
                            : nullptr;

                    if (gles_texture_uploads <= 12u) {
                        std::ostringstream diagnostic;
                        diagnostic
                            << "V41 GLES TEXUPLOAD #"
                            << gles_texture_uploads
                            << " size="
                            << width
                            << "x"
                            << height
                            << " format=0x"
                            << std::hex
                            << format
                            << " type=0x"
                            << type
                            << std::dec
                            << " bytes="
                            << bytes;

                        if (pixels != nullptr &&
                            bytes >= 4u &&
                            type == GL_UNSIGNED_BYTE &&
                            (format == GL_RGBA ||
                             format == GL_BGRA)) {

                            const auto* p =
                                static_cast<
                                    const std::uint8_t*>(
                                        pixels);

                            const std::size_t pixel_count =
                                std::min<std::size_t>(
                                    bytes / 4u,
                                    static_cast<std::size_t>(
                                        std::max<GLsizei>(
                                            width,
                                            0)) *
                                    static_cast<std::size_t>(
                                        std::max<GLsizei>(
                                            height,
                                            0)));

                            std::uint64_t sum_r = 0u;
                            std::uint64_t sum_g = 0u;
                            std::uint64_t sum_b = 0u;
                            std::uint64_t sum_a = 0u;
                            std::uint64_t partial_a = 0u;
                            std::uint64_t opaque_a = 0u;
                            std::uint64_t zero_a = 0u;

                            for (std::size_t i = 0u;
                                 i < pixel_count;
                                 ++i) {
                                const std::uint8_t c0 =
                                    p[i * 4u + 0u];
                                const std::uint8_t c1 =
                                    p[i * 4u + 1u];
                                const std::uint8_t c2 =
                                    p[i * 4u + 2u];
                                const std::uint8_t a =
                                    p[i * 4u + 3u];

                                const std::uint8_t r =
                                    format == GL_BGRA
                                        ? c2
                                        : c0;
                                const std::uint8_t g =
                                    c1;
                                const std::uint8_t b =
                                    format == GL_BGRA
                                        ? c0
                                        : c2;

                                sum_r += r;
                                sum_g += g;
                                sum_b += b;
                                sum_a += a;

                                if (a == 0u) {
                                    ++zero_a;
                                } else if (a == 255u) {
                                    ++opaque_a;
                                } else {
                                    ++partial_a;
                                }
                            }

                            if (pixel_count != 0u) {
                                diagnostic
                                    << " avgRGBA=("
                                    << sum_r / pixel_count
                                    << ","
                                    << sum_g / pixel_count
                                    << ","
                                    << sum_b / pixel_count
                                    << ","
                                    << sum_a / pixel_count
                                    << ") alpha{0="
                                    << zero_a
                                    << ",partial="
                                    << partial_a
                                    << ",255="
                                    << opaque_a
                                    << "}";
                            }
                        }

                        Append(diagnostic.str());
                    }

                    GLuint bound_texture = 0u;

                    if (gles_active_texture_unit >=
                        GL_TEXTURE0) {
                        const std::uint32_t unit =
                            static_cast<std::uint32_t>(
                                gles_active_texture_unit -
                                GL_TEXTURE0);

                        if (unit <
                            gles_bound_texture_2d.size()) {
                            bound_texture =
                                gles_bound_texture_2d[unit];
                        }
                    }

                    if (bound_texture != 0u) {
                        gles_texture_info[
                            bound_texture] =
                            V42TextureInfo{
                                width,
                                height,
                                format,
                                type,
                                pixels != nullptr};

                        if (width == 1024 &&
                            height == 1024 &&
                            format == GL_RGBA &&
                            type ==
                                GL_UNSIGNED_SHORT_4_4_4_4 &&
                            pixels != nullptr) {

                            gles_splash_texture_candidate =
                                bound_texture;

                            const auto* packed =
                                static_cast<
                                    const std::uint16_t*>(
                                        pixels);

                            const std::size_t pixel_count =
                                static_cast<std::size_t>(
                                    width) *
                                static_cast<std::size_t>(
                                    height);

                            std::uint64_t sum_r = 0u;
                            std::uint64_t sum_g = 0u;
                            std::uint64_t sum_b = 0u;
                            std::uint64_t sum_a = 0u;
                            std::uint64_t zero_a = 0u;
                            std::uint64_t partial_a = 0u;
                            std::uint64_t full_a = 0u;

                            for (std::size_t i = 0u;
                                 i < pixel_count;
                                 ++i) {
                                const std::uint16_t px =
                                    packed[i];
                                const std::uint8_t r =
                                    static_cast<std::uint8_t>(
                                        ((px >> 12u) &
                                         0x0fu) *
                                        17u);
                                const std::uint8_t g =
                                    static_cast<std::uint8_t>(
                                        ((px >> 8u) &
                                         0x0fu) *
                                        17u);
                                const std::uint8_t b =
                                    static_cast<std::uint8_t>(
                                        ((px >> 4u) &
                                         0x0fu) *
                                        17u);
                                const std::uint8_t a =
                                    static_cast<std::uint8_t>(
                                        (px & 0x0fu) *
                                        17u);

                                sum_r += r;
                                sum_g += g;
                                sum_b += b;
                                sum_a += a;

                                if (a == 0u) {
                                    ++zero_a;
                                } else if (a == 255u) {
                                    ++full_a;
                                } else {
                                    ++partial_a;
                                }
                            }

                            Append(
                                "V43 SPLASH TEXTURE CANDIDATE tex=" +
                                std::to_string(
                                    bound_texture) +
                                " avgRGBA=(" +
                                std::to_string(
                                    sum_r /
                                    pixel_count) +
                                "," +
                                std::to_string(
                                    sum_g /
                                    pixel_count) +
                                "," +
                                std::to_string(
                                    sum_b /
                                    pixel_count) +
                                "," +
                                std::to_string(
                                    sum_a /
                                    pixel_count) +
                                ") alpha{0=" +
                                std::to_string(
                                    zero_a) +
                                ",partial=" +
                                std::to_string(
                                    partial_a) +
                                ",255=" +
                                std::to_string(
                                    full_a) +
                                "}");
                        }
                    }

                    const std::uint64_t v89_tex_begin_ns=V89HostCostEnabled()?V85SteadyNowNs():0u;
                    glTexImage2D(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLint>(
                            guest_arg(2u)),
                        width,
                        height,
                        static_cast<GLint>(
                            guest_arg(5u)),
                        format,
                        type,
                        pixels);
                    if(V89HostCostEnabled())V89RecordHostCost("gles.glTexImage2D",v89_tex_begin_ns,bytes);
                    regs[0] = 0u;
                } else if (name == "glTexSubImage2D") {
                    ++gles_texture_uploads;
                    const GLsizei width =
                        static_cast<GLsizei>(
                            guest_arg(4u));
                    const GLsizei height =
                        static_cast<GLsizei>(
                            guest_arg(5u));
                    const GLenum format =
                        static_cast<GLenum>(
                            guest_arg(6u));
                    const GLenum type =
                        static_cast<GLenum>(
                            guest_arg(7u));
                    const std::uint32_t pixels_address =
                        guest_arg(8u);
                    const std::size_t bytes =
                        pixel_bytes(
                            width,
                            height,
                            format,
                            type);

                    const void* pixels =
                        pixels_address != 0u
                            ? mem.Ptr(
                                  pixels_address,
                                  bytes != 0u
                                      ? bytes
                                      : 1u)
                            : nullptr;

                    const std::uint64_t v89_subtex_begin_ns=V89HostCostEnabled()?V85SteadyNowNs():0u;
                    glTexSubImage2D(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLint>(
                            guest_arg(2u)),
                        static_cast<GLint>(
                            guest_arg(3u)),
                        width,
                        height,
                        format,
                        type,
                        pixels);
                    if(V89HostCostEnabled())V89RecordHostCost("gles.glTexSubImage2D",v89_subtex_begin_ns,bytes);
                    regs[0] = 0u;
                } else if (
                    name == "glCompressedTexImage2D") {

                    ++gles_texture_uploads;

                    const GLenum target =
                        static_cast<GLenum>(
                            guest_arg(0u));
                    const GLint level =
                        static_cast<GLint>(
                            guest_arg(1u));
                    const GLenum internal_format =
                        static_cast<GLenum>(
                            guest_arg(2u));
                    const GLsizei width =
                        static_cast<GLsizei>(
                            guest_arg(3u));
                    const GLsizei height =
                        static_cast<GLsizei>(
                            guest_arg(4u));
                    const GLint border =
                        static_cast<GLint>(
                            guest_arg(5u));
                    const GLsizei image_size =
                        static_cast<GLsizei>(
                            guest_arg(6u));
                    const std::uint32_t data_address =
                        guest_arg(7u);

                    const void* data =
                        data_address != 0u
                            ? mem.Ptr(
                                  data_address,
                                  image_size > 0
                                      ? static_cast<std::size_t>(
                                            image_size)
                                      : 1u)
                            : nullptr;

                    GLuint bound_texture = 0u;

                    if (gles_active_texture_unit >=
                        GL_TEXTURE0) {
                        const std::uint32_t unit =
                            static_cast<std::uint32_t>(
                                gles_active_texture_unit -
                                GL_TEXTURE0);

                        if (unit <
                            gles_bound_texture_2d.size()) {
                            bound_texture =
                                gles_bound_texture_2d[unit];
                        }
                    }

                    if (V71Enabled() &&
                        internal_format ==
                            kPvZ2Etc1Rgb8Oes) {

                        std::vector<std::uint8_t>
                            decoded_rgb;

                        const std::uint64_t v89_etc_begin_ns=V89HostCostEnabled()&&data!=nullptr?V85SteadyNowNs():0u;
                        const bool decoded =
                            data == nullptr
                                ? false
                                : DecodeEtc1Rgb(
                                      data,
                                      image_size > 0
                                          ? static_cast<std::size_t>(
                                                image_size)
                                          : 0u,
                                      width,
                                      height,
                                      decoded_rgb);
                        if(V89HostCostEnabled()&&data!=nullptr)V89RecordHostCost("etc1.decode",v89_etc_begin_ns,image_size>0?static_cast<std::uint64_t>(image_size):0u);

                        if (data == nullptr) {
                            glTexImage2D(
                                target,
                                level,
                                GL_RGB,
                                width,
                                height,
                                border,
                                GL_RGB,
                                GL_UNSIGNED_BYTE,
                                nullptr);
                        } else if (decoded) {
                            const std::uint64_t v89_etc_upload_begin_ns=V89HostCostEnabled()?V85SteadyNowNs():0u;
                            glTexImage2D(
                                target,
                                level,
                                GL_RGB,
                                width,
                                height,
                                border,
                                GL_RGB,
                                GL_UNSIGNED_BYTE,
                                decoded_rgb.data());
                            if(V89HostCostEnabled())V89RecordHostCost("gles.etc1Upload",v89_etc_upload_begin_ns,decoded_rgb.size());

                            ++v71_etc1_transcodes;
                            v71_etc1_compressed_bytes +=
                                static_cast<std::uint64_t>(
                                    std::max<GLsizei>(
                                        image_size,
                                        0));
                            v71_etc1_decoded_bytes +=
                                static_cast<std::uint64_t>(
                                    decoded_rgb.size());

                            Append(
                                "V71 ETC1 TRANSCODE #" +
                                std::to_string(
                                    v71_etc1_transcodes) +
                                " tex=" +
                                std::to_string(
                                    bound_texture) +
                                " size=" +
                                std::to_string(width) +
                                "x" +
                                std::to_string(height) +
                                " compressed=" +
                                std::to_string(
                                    image_size) +
                                " decodedRGB=" +
                                std::to_string(
                                    decoded_rgb.size()) +
                                " format=0x8d64 -> GL_RGB8");
                        } else {
                            ++v71_etc1_decode_failures;

                            Append(
                                "V71 ETC1 DECODE FAILURE #" +
                                std::to_string(
                                    v71_etc1_decode_failures) +
                                " tex=" +
                                std::to_string(
                                    bound_texture) +
                                " size=" +
                                std::to_string(width) +
                                "x" +
                                std::to_string(height) +
                                " compressed=" +
                                std::to_string(
                                    image_size));

                            // Keep a valid host texture object without
                            // fabricating guest pixels. The failure remains
                            // visible in the v71 diagnostics.
                            glTexImage2D(
                                target,
                                level,
                                GL_RGB,
                                width,
                                height,
                                border,
                                GL_RGB,
                                GL_UNSIGNED_BYTE,
                                nullptr);
                        }

                        if (bound_texture != 0u) {
                            gles_texture_info[
                                bound_texture] =
                                V42TextureInfo{
                                    width,
                                    height,
                                    GL_RGB,
                                    GL_UNSIGNED_BYTE,
                                    data == nullptr ||
                                    decoded};
                        }
                    } else {
                        glCompressedTexImage2D(
                            target,
                            level,
                            internal_format,
                            width,
                            height,
                            border,
                            image_size,
                            data);
                    }

                    regs[0] = 0u;
                } else if (
                    name == "glBindFramebuffer" ||
                    name == "glBindFramebufferOES") {

                    const GLuint guest_framebuffer =
                        static_cast<GLuint>(
                            guest_arg(1u));

                    GLuint framebuffer =
                        guest_framebuffer;

                    if (framebuffer == 0u) {
                        framebuffer =
                            static_cast<GLuint>(
                                host_default_framebuffer);
                    }

                    if (guest_framebuffer !=
                            gles_bound_guest_framebuffer ||
                        framebuffer !=
                            gles_bound_host_framebuffer) {

                        ++gles_framebuffer_bind_changes;

                        if (gles_framebuffer_bind_changes <=
                                96u ||
                            current_frame_number == 15u ||
                            current_frame_number == 60u ||
                            current_frame_number == 75u ||
                            current_frame_number == 90u ||
                            current_frame_number == 120u ||
                            current_frame_number == 600u) {

                            Append(
                                "V47 GLES BIND FBO change#" +
                                std::to_string(
                                    gles_framebuffer_bind_changes) +
                                " frame=" +
                                std::to_string(
                                    current_frame_number) +
                                " guest=" +
                                std::to_string(
                                    guest_framebuffer) +
                                " host=" +
                                std::to_string(
                                    framebuffer));
                        }
                    }

                    gles_bound_guest_framebuffer =
                        guest_framebuffer;
                    gles_bound_host_framebuffer =
                        framebuffer;

                    glBindFramebuffer(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        framebuffer);
                    regs[0] = 0u;
                } else if (
                    name == "glFramebufferTexture2D" ||
                    name == "glFramebufferTexture2DOES") {

                    const GLenum target =
                        static_cast<GLenum>(
                            guest_arg(0u));
                    const GLenum attachment =
                        static_cast<GLenum>(
                            guest_arg(1u));
                    const GLenum textarget =
                        static_cast<GLenum>(
                            guest_arg(2u));
                    const GLuint texture =
                        static_cast<GLuint>(
                            guest_arg(3u));
                    const GLint level =
                        static_cast<GLint>(
                            guest_arg(4u));

                    glFramebufferTexture2D(
                        target,
                        attachment,
                        textarget,
                        texture,
                        level);

                    if (attachment ==
                            GL_COLOR_ATTACHMENT0 &&
                        gles_bound_host_framebuffer !=
                            0u) {

                        if (texture != 0u) {
                            gles_framebuffer_color_texture[
                                gles_bound_host_framebuffer] =
                                texture;
                        } else {
                            gles_framebuffer_color_texture.erase(
                                gles_bound_host_framebuffer);
                        }

                        std::string dimensions =
                            "unknown";

                        if (const auto info =
                                gles_texture_info.find(
                                    texture);
                            info !=
                                gles_texture_info.end()) {

                            dimensions =
                                std::to_string(
                                    info->second.width) +
                                "x" +
                                std::to_string(
                                    info->second.height);
                        }

                        Append(
                            "V47 GLES FBO ATTACH frame=" +
                            std::to_string(
                                current_frame_number) +
                            " guestFBO=" +
                            std::to_string(
                                gles_bound_guest_framebuffer) +
                            " hostFBO=" +
                            std::to_string(
                                gles_bound_host_framebuffer) +
                            " colorTex=" +
                            std::to_string(
                                texture) +
                            " size=" +
                            dimensions);
                    }

                    regs[0] = 0u;
                } else if (name == "glViewport") {
                    const std::array<std::int32_t, 4> viewport{
                        static_cast<std::int32_t>(
                            guest_arg(0u)),
                        static_cast<std::int32_t>(
                            guest_arg(1u)),
                        static_cast<std::int32_t>(
                            guest_arg(2u)),
                        static_cast<std::int32_t>(
                            guest_arg(3u))};

                    ++gles_viewport_calls;

                    if (!gles_viewport_seen ||
                        viewport !=
                            last_gles_viewport) {
                        Append(
                            "V39 GLES VIEWPORT #" +
                            std::to_string(
                                gles_viewport_calls) +
                            " guest=(" +
                            std::to_string(viewport[0]) +
                            "," +
                            std::to_string(viewport[1]) +
                            "," +
                            std::to_string(viewport[2]) +
                            "," +
                            std::to_string(viewport[3]) +
                            ") hostFBO=" +
                            std::to_string(host_surface_width) +
                            "x" +
                            std::to_string(host_surface_height) +
                            " phase=" +
                            (current_lifecycle_name.empty()
                                ? std::string{"n/a"}
                                : current_lifecycle_name));

                        last_gles_viewport =
                            viewport;
                        gles_viewport_seen = true;
                    }

                    glViewport(
                        static_cast<GLint>(
                            viewport[0]),
                        static_cast<GLint>(
                            viewport[1]),
                        static_cast<GLsizei>(
                            viewport[2]),
                        static_cast<GLsizei>(
                            viewport[3]));
                    regs[0] = 0u;
                } else if (name == "glScissor") {
                    const std::array<std::int32_t, 4> scissor{
                        static_cast<std::int32_t>(
                            guest_arg(0u)),
                        static_cast<std::int32_t>(
                            guest_arg(1u)),
                        static_cast<std::int32_t>(
                            guest_arg(2u)),
                        static_cast<std::int32_t>(
                            guest_arg(3u))};

                    ++gles_scissor_calls;

                    if (!gles_scissor_seen ||
                        scissor !=
                            last_gles_scissor) {
                        Append(
                            "V39 GLES SCISSOR #" +
                            std::to_string(
                                gles_scissor_calls) +
                            " guest=(" +
                            std::to_string(scissor[0]) +
                            "," +
                            std::to_string(scissor[1]) +
                            "," +
                            std::to_string(scissor[2]) +
                            "," +
                            std::to_string(scissor[3]) +
                            ") hostFBO=" +
                            std::to_string(host_surface_width) +
                            "x" +
                            std::to_string(host_surface_height) +
                            " phase=" +
                            (current_lifecycle_name.empty()
                                ? std::string{"n/a"}
                                : current_lifecycle_name));

                        last_gles_scissor =
                            scissor;
                        gles_scissor_seen = true;
                    }

                    glScissor(
                        static_cast<GLint>(
                            scissor[0]),
                        static_cast<GLint>(
                            scissor[1]),
                        static_cast<GLsizei>(
                            scissor[2]),
                        static_cast<GLsizei>(
                            scissor[3]));
                    regs[0] = 0u;
                } else if (name == "glClearColor") {
                    gles_clear_color = {
                        guest_f32(0u),
                        guest_f32(1u),
                        guest_f32(2u),
                        guest_f32(3u)};

                    glClearColor(
                        gles_clear_color[0],
                        gles_clear_color[1],
                        gles_clear_color[2],
                        gles_clear_color[3]);
                    regs[0] = 0u;
                } else if (name == "glClear") {
                    ++gles_clear_calls;

                    const GLbitfield mask =
                        static_cast<GLbitfield>(
                            guest_arg(0u));

                    V48TraceClearState(mask);
                    glClear(mask);
                    regs[0] = 0u;
                } else if (name == "glClearDepthf") {
                    glClearDepthf(
                        guest_f32(0u));
                    regs[0] = 0u;
                } else if (name == "glDepthRangef") {
                    glDepthRangef(
                        guest_f32(0u),
                        guest_f32(1u));
                    regs[0] = 0u;
                } else if (name == "glDepthMask") {
                    glDepthMask(
                        static_cast<GLboolean>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glDepthFunc") {
                    glDepthFunc(
                        static_cast<GLenum>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glEnable") {
                    const GLenum capability =
                        static_cast<GLenum>(
                            guest_arg(0u));

                    glEnable(
                        capability);

                    if (capability == GL_BLEND &&
                        !gles_blend_enabled) {
                        gles_blend_enabled = true;
                        ++gles_blend_state_changes;
                        Append(
                            "V41 GLES BLEND enabled change#" +
                            std::to_string(
                                gles_blend_state_changes));
                    }

                    if (capability ==
                        GL_SCISSOR_TEST) {
                        gles_scissor_enabled =
                            true;
                    }

                    regs[0] = 0u;
                } else if (name == "glDisable") {
                    const GLenum capability =
                        static_cast<GLenum>(
                            guest_arg(0u));

                    glDisable(
                        capability);

                    if (capability == GL_BLEND &&
                        gles_blend_enabled) {
                        gles_blend_enabled = false;
                        ++gles_blend_state_changes;
                        Append(
                            "V41 GLES BLEND disabled change#" +
                            std::to_string(
                                gles_blend_state_changes));
                    }

                    if (capability ==
                        GL_SCISSOR_TEST) {
                        gles_scissor_enabled =
                            false;
                    }

                    regs[0] = 0u;
                } else if (name == "glBlendFunc") {
                    const GLenum src =
                        static_cast<GLenum>(
                            guest_arg(0u));
                    const GLenum dst =
                        static_cast<GLenum>(
                            guest_arg(1u));

                    glBlendFunc(
                        src,
                        dst);

                    if (src != gles_blend_src ||
                        dst != gles_blend_dst) {
                        gles_blend_src = src;
                        gles_blend_dst = dst;
                        ++gles_blend_state_changes;

                        Append(
                            "V41 GLES BLENDFUNC change#" +
                            std::to_string(
                                gles_blend_state_changes) +
                            " src=0x" +
                            JniProbeHex(
                                static_cast<std::uint32_t>(
                                    src)) +
                            " dst=0x" +
                            JniProbeHex(
                                static_cast<std::uint32_t>(
                                    dst)));
                    }

                    regs[0] = 0u;
                } else if (name == "glFrontFace") {
                    glFrontFace(
                        static_cast<GLenum>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glCullFace") {
                    glCullFace(
                        static_cast<GLenum>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glLineWidth") {
                    glLineWidth(
                        guest_f32(0u));
                    regs[0] = 0u;
                } else if (name == "glColorMask") {
                    gles_color_mask = {
                        static_cast<GLboolean>(
                            guest_arg(0u)),
                        static_cast<GLboolean>(
                            guest_arg(1u)),
                        static_cast<GLboolean>(
                            guest_arg(2u)),
                        static_cast<GLboolean>(
                            guest_arg(3u))};

                    glColorMask(
                        gles_color_mask[0],
                        gles_color_mask[1],
                        gles_color_mask[2],
                        gles_color_mask[3]);
                    regs[0] = 0u;
                } else if (name == "glActiveTexture") {
                    gles_active_texture_unit =
                        static_cast<GLenum>(
                            guest_arg(0u));

                    glActiveTexture(
                        gles_active_texture_unit);
                    regs[0] = 0u;
                } else if (
                    name == "glEnableVertexAttribArray") {
                    const GLuint index =
                        static_cast<GLuint>(
                            guest_arg(0u));

                    if (index <
                        gles_attrib_state.size()) {
                        gles_attrib_state[index]
                            .enabled = true;
                    }

                    glEnableVertexAttribArray(
                        index);
                    regs[0] = 0u;
                } else if (
                    name == "glDisableVertexAttribArray") {
                    const GLuint index =
                        static_cast<GLuint>(
                            guest_arg(0u));

                    if (index <
                        gles_attrib_state.size()) {
                        gles_attrib_state[index]
                            .enabled = false;
                    }

                    glDisableVertexAttribArray(
                        index);
                    regs[0] = 0u;
                } else if (
                    name == "glVertexAttribPointer") {
                    const GLuint index =
                        static_cast<GLuint>(
                            guest_arg(0u));
                    const GLint size =
                        static_cast<GLint>(
                            guest_arg(1u));
                    const GLenum type =
                        static_cast<GLenum>(
                            guest_arg(2u));
                    const GLboolean normalized =
                        static_cast<GLboolean>(
                            guest_arg(3u));
                    const GLsizei stride =
                        static_cast<GLsizei>(
                            guest_arg(4u));
                    const std::uint32_t pointer_address =
                        guest_arg(5u);
                    const void* pointer =
                        pointer_address != 0u
                            ? mem.Ptr(
                                  pointer_address,
                                  1u)
                            : nullptr;

                    if (index <
                        gles_attrib_state.size()) {
                        auto& state =
                            gles_attrib_state[index];

                        state.size = size;
                        state.type = type;
                        state.normalized =
                            normalized;
                        state.stride = stride;
                        state.guest_pointer =
                            pointer_address;
                    }

                    glVertexAttribPointer(
                        index,
                        size,
                        type,
                        normalized,
                        stride,
                        pointer);
                    regs[0] = 0u;
                } else if (name == "glDrawArrays") {
                    ++gles_draw_calls;
                    ++gles_draws_by_framebuffer[
                        gles_bound_host_framebuffer];

                    auto splash_texture_bound =
                        [&]() {
                            if (gles_splash_texture_candidate ==
                                0u) {
                                return false;
                            }

                            for (const GLuint texture :
                                 gles_bound_texture_2d) {
                                if (texture ==
                                    gles_splash_texture_candidate) {
                                    return true;
                                }
                            }

                            return false;
                        };

                    auto color_attrib_index =
                        [&]() -> std::optional<GLuint> {
                            for (GLuint index = 0u;
                                 index <
                                     gles_attrib_state.size();
                                 ++index) {
                                const std::uint64_t key =
                                    (static_cast<std::uint64_t>(
                                         gles_current_program)
                                     << 32u) |
                                    index;

                                const auto found =
                                    gles_attrib_names.find(
                                        key);

                                if (found !=
                                        gles_attrib_names.end() &&
                                    found->second ==
                                        "color") {
                                    return index;
                                }
                            }

                            return std::nullopt;
                        };

                    const GLint first =
                        static_cast<GLint>(
                            guest_arg(1u));
                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(2u));

                    std::vector<std::uint8_t>
                        corrected_colors;
                    std::optional<GLuint>
                        corrected_index;

                    if (splash_texture_bound() &&
                        count > 0) {
                        const auto color_index =
                            color_attrib_index();

                        if (color_index.has_value()) {
                            const auto& state =
                                gles_attrib_state[
                                    *color_index];

                            if (state.enabled &&
                                state.size == 4 &&
                                state.type ==
                                    GL_UNSIGNED_BYTE &&
                                state.normalized ==
                                    GL_TRUE &&
                                state.guest_pointer != 0u) {

                                const std::size_t stride =
                                    state.stride > 0
                                        ? static_cast<std::size_t>(
                                              state.stride)
                                        : 4u;
                                const std::size_t vertex_count =
                                    static_cast<std::size_t>(
                                        std::max<GLint>(
                                            0,
                                            first)) +
                                    static_cast<std::size_t>(
                                        count);
                                const std::size_t bytes =
                                    vertex_count == 0u
                                        ? 0u
                                        : (vertex_count - 1u) *
                                              stride +
                                          4u;

                                const auto* base =
                                    static_cast<
                                        const std::uint8_t*>(
                                            mem.Ptr(
                                                state.guest_pointer,
                                                bytes));

                                if (base != nullptr) {
                                    std::uint32_t peak = 0u;
                                    const std::size_t sample =
                                        std::min<std::size_t>(
                                            vertex_count,
                                            64u);

                                    for (std::size_t i = 0u;
                                         i < sample;
                                         ++i) {
                                        const auto* color =
                                            base +
                                            i * stride;
                                        for (std::size_t c = 0u;
                                             c < 4u;
                                             ++c) {
                                            peak =
                                                std::max<
                                                    std::uint32_t>(
                                                    peak,
                                                    color[c]);
                                        }
                                    }

                                    if (gles_vertex_color_traces <
                                        48u) {
                                        ++gles_vertex_color_traces;

                                        std::ostringstream diagnostic;
                                        diagnostic
                                            << "V43 SPLASH COLOR DRAW #"
                                            << gles_vertex_color_traces
                                            << " glDrawArrays program="
                                            << gles_current_program
                                            << " attrib="
                                            << *color_index
                                            << " first="
                                            << first
                                            << " count="
                                            << count
                                            << " stride="
                                            << stride
                                            << " peak="
                                            << peak
                                            << " firstRGBA=("
                                            << static_cast<unsigned>(
                                                   base[0])
                                            << ","
                                            << static_cast<unsigned>(
                                                   base[1])
                                            << ","
                                            << static_cast<unsigned>(
                                                   base[2])
                                            << ","
                                            << static_cast<unsigned>(
                                                   base[3])
                                            << ")";
                                        Append(
                                            diagnostic.str());
                                    }

                                    if (false &&
                                        gles_splash_color_baseline ==
                                            0u &&
                                        peak >= 176u &&
                                        peak <= 208u) {
                                        gles_splash_color_baseline =
                                            peak;

                                        Append(
                                            "V42 SPLASH COLOR BASELINE=" +
                                            std::to_string(
                                                peak) +
                                            " -> normalize client color only while startup atlas texture is bound");
                                    }

                                    if (false &&
                                        gles_splash_color_baseline !=
                                            0u &&
                                        peak <=
                                            gles_splash_color_baseline) {

                                        corrected_colors.resize(
                                            vertex_count *
                                            4u);

                                        for (std::size_t i = 0u;
                                             i < vertex_count;
                                             ++i) {
                                            const auto* source =
                                                base +
                                                i * stride;
                                            auto* target =
                                                corrected_colors.data() +
                                                i * 4u;

                                            for (std::size_t c = 0u;
                                                 c < 4u;
                                                 ++c) {
                                                const std::uint32_t scaled =
                                                    (static_cast<std::uint32_t>(
                                                         source[c]) *
                                                         255u +
                                                     gles_splash_color_baseline /
                                                         2u) /
                                                    gles_splash_color_baseline;

                                                target[c] =
                                                    static_cast<std::uint8_t>(
                                                        std::min<
                                                            std::uint32_t>(
                                                            255u,
                                                            scaled));
                                            }
                                        }

                                        glVertexAttribPointer(
                                            *color_index,
                                            4,
                                            GL_UNSIGNED_BYTE,
                                            GL_TRUE,
                                            0,
                                            corrected_colors.data());

                                        corrected_index =
                                            color_index;
                                        ++gles_splash_color_corrections;
                                    }
                                }
                            }
                        }
                    }

                    const GLenum draw_mode =
                        static_cast<GLenum>(
                            guest_arg(0u));

                    V48TraceDrawState(
                        "arrays",
                        draw_mode,
                        count);

                    V80TraceArrayTransform(
                        first,
                        count);

                    glDrawArrays(
                        draw_mode,
                        first,
                        count);

                    if (corrected_index.has_value()) {
                        const auto& state =
                            gles_attrib_state[
                                *corrected_index];

                        glVertexAttribPointer(
                            *corrected_index,
                            state.size,
                            state.type,
                            state.normalized,
                            state.stride,
                            mem.Ptr(
                                state.guest_pointer,
                                1u));
                    }

                    regs[0] = 0u;
                } else if (name == "glDrawElements") {
                    ++gles_draw_calls;
                    ++gles_draws_by_framebuffer[
                        gles_bound_host_framebuffer];
                    const GLsizei count =
                        static_cast<GLsizei>(
                            guest_arg(1u));
                    const GLenum type =
                        static_cast<GLenum>(
                            guest_arg(2u));
                    std::size_t index_bytes = 1u;

                    if (type == GL_UNSIGNED_SHORT) {
                        index_bytes = 2u;
                    } else if (type == GL_UNSIGNED_INT) {
                        index_bytes = 4u;
                    }

                    const std::uint32_t indices_address =
                        guest_arg(3u);
                    const void* indices =
                        indices_address != 0u
                            ? mem.Ptr(
                                  indices_address,
                                  count > 0
                                      ? static_cast<std::size_t>(
                                            count) *
                                            index_bytes
                                      : 1u)
                            : nullptr;

                    std::vector<std::uint8_t>
                        corrected_colors;
                    std::optional<GLuint>
                        corrected_index;

                    bool splash_bound = false;
                    if (gles_splash_texture_candidate != 0u) {
                        for (const GLuint texture :
                             gles_bound_texture_2d) {
                            if (texture ==
                                gles_splash_texture_candidate) {
                                splash_bound = true;
                                break;
                            }
                        }
                    }

                    if (splash_bound &&
                        count > 0 &&
                        indices != nullptr) {

                        std::optional<GLuint>
                            color_index;

                        for (GLuint index = 0u;
                             index <
                                 gles_attrib_state.size();
                             ++index) {
                            const std::uint64_t key =
                                (static_cast<std::uint64_t>(
                                     gles_current_program)
                                 << 32u) |
                                index;

                            const auto found =
                                gles_attrib_names.find(
                                    key);

                            if (found !=
                                    gles_attrib_names.end() &&
                                found->second ==
                                    "color") {
                                color_index = index;
                                break;
                            }
                        }

                        if (color_index.has_value()) {
                            const auto& state =
                                gles_attrib_state[
                                    *color_index];

                            if (state.enabled &&
                                state.size == 4 &&
                                state.type ==
                                    GL_UNSIGNED_BYTE &&
                                state.normalized ==
                                    GL_TRUE &&
                                state.guest_pointer != 0u) {

                                std::uint32_t max_index = 0u;

                                for (GLsizei i = 0;
                                     i < count;
                                     ++i) {
                                    std::uint32_t value = 0u;

                                    if (type ==
                                        GL_UNSIGNED_BYTE) {
                                        value =
                                            static_cast<
                                                const std::uint8_t*>(
                                                    indices)[i];
                                    } else if (
                                        type ==
                                        GL_UNSIGNED_SHORT) {
                                        value =
                                            static_cast<
                                                const std::uint16_t*>(
                                                    indices)[i];
                                    } else if (
                                        type ==
                                        GL_UNSIGNED_INT) {
                                        value =
                                            static_cast<
                                                const std::uint32_t*>(
                                                    indices)[i];
                                    }

                                    max_index =
                                        std::max(
                                            max_index,
                                            value);
                                }

                                const std::size_t stride =
                                    state.stride > 0
                                        ? static_cast<std::size_t>(
                                              state.stride)
                                        : 4u;
                                const std::size_t vertex_count =
                                    static_cast<std::size_t>(
                                        max_index) +
                                    1u;
                                const std::size_t bytes =
                                    (vertex_count - 1u) *
                                        stride +
                                    4u;

                                const auto* base =
                                    static_cast<
                                        const std::uint8_t*>(
                                            mem.Ptr(
                                                state.guest_pointer,
                                                bytes));

                                if (base != nullptr) {
                                    std::uint32_t peak = 0u;
                                    const std::size_t sample =
                                        std::min<std::size_t>(
                                            vertex_count,
                                            64u);

                                    for (std::size_t i = 0u;
                                         i < sample;
                                         ++i) {
                                        const auto* color =
                                            base +
                                            i * stride;

                                        for (std::size_t c = 0u;
                                             c < 4u;
                                             ++c) {
                                            peak =
                                                std::max<
                                                    std::uint32_t>(
                                                    peak,
                                                    color[c]);
                                        }
                                    }

                                    if (gles_vertex_color_traces <
                                        48u) {
                                        ++gles_vertex_color_traces;

                                        std::ostringstream diagnostic;
                                        diagnostic
                                            << "V43 SPLASH COLOR DRAW #"
                                            << gles_vertex_color_traces
                                            << " glDrawElements program="
                                            << gles_current_program
                                            << " attrib="
                                            << *color_index
                                            << " count="
                                            << count
                                            << " maxIndex="
                                            << max_index
                                            << " stride="
                                            << stride
                                            << " peak="
                                            << peak
                                            << " firstRGBA=("
                                            << static_cast<unsigned>(
                                                   base[0])
                                            << ","
                                            << static_cast<unsigned>(
                                                   base[1])
                                            << ","
                                            << static_cast<unsigned>(
                                                   base[2])
                                            << ","
                                            << static_cast<unsigned>(
                                                   base[3])
                                            << ")";
                                        Append(
                                            diagnostic.str());
                                    }

                                    if (false &&
                                        gles_splash_color_baseline ==
                                            0u &&
                                        peak >= 176u &&
                                        peak <= 208u) {
                                        gles_splash_color_baseline =
                                            peak;

                                        Append(
                                            "V42 SPLASH COLOR BASELINE=" +
                                            std::to_string(
                                                peak) +
                                            " -> normalize client color only while startup atlas texture is bound");
                                    }

                                    if (false &&
                                        gles_splash_color_baseline !=
                                            0u &&
                                        peak <=
                                            gles_splash_color_baseline) {

                                        corrected_colors.resize(
                                            vertex_count *
                                            4u);

                                        for (std::size_t i = 0u;
                                             i < vertex_count;
                                             ++i) {
                                            const auto* source =
                                                base +
                                                i * stride;
                                            auto* target =
                                                corrected_colors.data() +
                                                i * 4u;

                                            for (std::size_t c = 0u;
                                                 c < 4u;
                                                 ++c) {
                                                const std::uint32_t scaled =
                                                    (static_cast<std::uint32_t>(
                                                         source[c]) *
                                                         255u +
                                                     gles_splash_color_baseline /
                                                         2u) /
                                                    gles_splash_color_baseline;

                                                target[c] =
                                                    static_cast<std::uint8_t>(
                                                        std::min<
                                                            std::uint32_t>(
                                                            255u,
                                                            scaled));
                                            }
                                        }

                                        glVertexAttribPointer(
                                            *color_index,
                                            4,
                                            GL_UNSIGNED_BYTE,
                                            GL_TRUE,
                                            0,
                                            corrected_colors.data());

                                        corrected_index =
                                            color_index;
                                        ++gles_splash_color_corrections;
                                    }
                                }
                            }
                        }
                    }

                    const GLenum draw_mode =
                        static_cast<GLenum>(
                            guest_arg(0u));

                    V48TraceDrawState(
                        "elements",
                        draw_mode,
                        count);

                    glDrawElements(
                        draw_mode,
                        count,
                        type,
                        indices);

                    if (corrected_index.has_value()) {
                        const auto& state =
                            gles_attrib_state[
                                *corrected_index];

                        glVertexAttribPointer(
                            *corrected_index,
                            state.size,
                            state.type,
                            state.normalized,
                            state.stride,
                            mem.Ptr(
                                state.guest_pointer,
                                1u));
                    }

                    regs[0] = 0u;
                } else if (name == "glGetIntegerv") {
                    GLint value = 0;
                    glGetIntegerv(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        &value);

                    if (static_cast<GLenum>(
                            guest_arg(0u)) ==
                            GL_FRAMEBUFFER_BINDING &&
                        static_cast<GLuint>(
                            value) ==
                            static_cast<GLuint>(
                                host_default_framebuffer)) {
                        value = 0;
                    }

                    if (guest_arg(1u) != 0u) {
                        mem.Write32Guest(
                            guest_arg(1u),
                            static_cast<std::uint32_t>(
                                value));
                    }

                    regs[0] = 0u;
                } else if (name == "glIsProgram") {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            glIsProgram(
                                static_cast<GLuint>(
                                    guest_arg(0u))));
                } else if (name == "glIsShader") {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            glIsShader(
                                static_cast<GLuint>(
                                    guest_arg(0u))));
                } else if (name == "glIsTexture") {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            glIsTexture(
                                static_cast<GLuint>(
                                    guest_arg(0u))));
                } else if (name == "glDeleteProgram") {
                    glDeleteProgram(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glDeleteShader") {
                    glDeleteShader(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else {
                    // Fixed-function GLES1 calls are not part of the real
                    // ES2 path observed by the v30 first frame. Keep them
                    // harmless while recording exactly which one becomes
                    // relevant in later frames.
                    if (fallback_logged.insert(
                            "v31-host-gles-unforwarded:" +
                            name).second) {
                        Append(
                            "V31 HOST GLES unforwarded compatibility call: " +
                            name);
                    }

                    regs[0] = 0u;
                }

                ++supported_calls;
                return;
            }

            log_fallback_once("gles-probe");

            if (name == "glGetError") {
                regs[0] = 0;
            } else if (name == "glCheckFramebufferStatus" ||
                       name == "glCheckFramebufferStatusOES") {
                regs[0] = 0x8CD5u; // GL_FRAMEBUFFER_COMPLETE
            } else if (name == "glCreateProgram" ||
                       name == "glCreateShader") {
                regs[0] = next_gl_object++;
            } else if (name == "glGenTextures" ||
                       name == "glGenFramebuffers" ||
                       name == "glGenFramebuffersOES") {
                const std::uint32_t count = regs[0];
                const std::uint32_t output = regs[1];

                for (std::uint32_t i = 0;
                     i < count;
                     ++i) {
                    mem.Write32Guest(
                        output + i * 4u,
                        next_gl_object++);
                }

                regs[0] = 0;
            } else if (name == "glGetShaderiv" ||
                       name == "glGetProgramiv") {
                if (regs[2]) {
                    mem.Write32Guest(regs[2], 1);
                }
                regs[0] = 0;
            } else if (name == "glGetShaderInfoLog" ||
                       name == "glGetProgramInfoLog") {
                if (regs[2]) {
                    mem.Write32Guest(regs[2], 0);
                }
                if (regs[3]) {
                    mem.Write8Guest(regs[3], 0);
                }
                regs[0] = 0;
            } else if (name == "glGetString") {
                regs[0] =
                    allocate_guest_string(
                        "PvZ2forIOS GLES compatibility probe");
            } else if (name == "glGetUniformLocation") {
                regs[0] = 0;
            } else if (name == "glIsProgram" ||
                       name == "glIsShader" ||
                       name == "glIsTexture") {
                regs[0] = regs[0] ? 1u : 0u;
            } else if (name == "glGetIntegerv") {
                if (regs[1]) {
                    mem.Write32Guest(regs[1], 0);
                }
                regs[0] = 0;
            } else {
                regs[0] = 0;
            }

            ++supported_calls;
            return;
        }

        if (name == "slCreateEngine") {
            if (V99Enabled() &&
                V99HandleSlCreateEngine(
                    regs)) {
                ++supported_calls;
                return;
            }

            log_fallback_once("opensl-probe");
            // Historical control modes deliberately report audio unavailable.
            regs[0] = 1; // non-success SLresult
            ++supported_calls;
            return;
        }

        static const std::unordered_set<std::string> kMiscSafe = {
            "abort","exit","raise","setjmp","longjmp"
        };

        if (kMiscSafe.count(name) != 0) {
            log_fallback_once("control-flow");

            if (name == "abort" ||
                name == "exit" ||
                name == "raise") {

                const std::uint32_t lr =
                    jit ? jit->Regs()[14] : 0u;

                const std::string detail =
                    "Guest requested " +
                    name +
                    " at caller LR=0x" +
                    JniProbeHex(lr) +
                    (last_android_log.empty()
                        ? std::string{}
                        : " after log=\"" +
                            last_android_log +
                            "\"");

                RecordSweepIssue(
                    "control-flow",
                    name + ":" +
                        JniProbeHex(lr),
                    detail);

                if (ConsumeSweepRecovery(
                        "control-flow",
                        detail)) {

                    // The import trampoline returns through BX LR after this
                    // callback. Returning zero lets the diagnostic sweep
                    // explore subsequent compatibility gaps. Because
                    // abort/exit/raise are semantically non-returning, every
                    // later issue is explicitly marked speculative.
                    regs[0] = 0u;
                    ++supported_calls;
                    return;
                }

                result.message =
                    detail;

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            if (name == "longjmp") {
                const std::string detail =
                    "Guest requested longjmp; generic recovery would corrupt control-flow state.";

                RecordSweepIssue(
                    "hard-control-flow",
                    "longjmp",
                    detail);

                result.message =
                    detail;

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            regs[0] = 0;
            ++supported_calls;
