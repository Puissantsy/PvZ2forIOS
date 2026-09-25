                std::memcpy(
                    &value,
                    &bits,
                    sizeof(value));
                return value;
            };

        auto write_double_regs =
            [&](double value) {
                std::uint64_t bits = 0;
                std::memcpy(
                    &bits,
                    &value,
                    sizeof(bits));
                regs[0] =
                    static_cast<std::uint32_t>(bits);
                regs[1] =
                    static_cast<std::uint32_t>(
                        bits >> 32);
            };

        if (name == "acosf" ||
            name == "asinf" ||
            name == "ceilf" ||
            name == "cosf" ||
            name == "floorf" ||
            name == "sinf" ||
            name == "sqrtf" ||
            name == "tanf") {

            const float x =
                read_float_reg(0);
            float answer = 0.0f;

            if (name == "acosf") answer = std::acos(x);
            else if (name == "asinf") answer = std::asin(x);
            else if (name == "ceilf") answer = std::ceil(x);
            else if (name == "cosf") answer = std::cos(x);
            else if (name == "floorf") answer = std::floor(x);
            else if (name == "sinf") answer = std::sin(x);
            else if (name == "sqrtf") answer = std::sqrt(x);
            else if (name == "tanf") answer = std::tan(x);

            write_float_reg(answer);
            ++supported_calls;
            return;
        }

        if (name == "atan2f" ||
            name == "fmodf" ||
            name == "powf") {

            const float a =
                read_float_reg(0);
            const float b =
                read_float_reg(1);
            float answer = 0.0f;

            if (name == "atan2f") answer = std::atan2(a, b);
            else if (name == "fmodf") answer = std::fmod(a, b);
            else if (name == "powf") answer = std::pow(a, b);

            write_float_reg(answer);
            ++supported_calls;
            return;
        }

        if (name == "acos" ||
            name == "ceil" ||
            name == "cos" ||
            name == "exp" ||
            name == "fabs" ||
            name == "floor" ||
            name == "log10" ||
            name == "sin" ||
            name == "sqrt" ||
            name == "tan") {

            const double x =
                read_double_regs(0);
            double answer = 0.0;

            if (name == "acos") answer = std::acos(x);
            else if (name == "ceil") answer = std::ceil(x);
            else if (name == "cos") answer = std::cos(x);
            else if (name == "exp") answer = std::exp(x);
            else if (name == "fabs") answer = std::fabs(x);
            else if (name == "floor") answer = std::floor(x);
            else if (name == "log10") answer = std::log10(x);
            else if (name == "sin") answer = std::sin(x);
            else if (name == "sqrt") answer = std::sqrt(x);
            else if (name == "tan") answer = std::tan(x);

            write_double_regs(answer);
            ++supported_calls;
            return;
        }

        if (name == "atan2" ||
            name == "fmod" ||
            name == "pow") {

            const double a =
                read_double_regs(0);
            const double b =
                read_double_regs(2);
            double answer = 0.0;

            if (name == "atan2") answer = std::atan2(a, b);
            else if (name == "fmod") answer = std::fmod(a, b);
            else if (name == "pow") answer = std::pow(a, b);

            write_double_regs(answer);
            ++supported_calls;
            return;
        }

        if (name == "modf") {
            const double x =
                read_double_regs(0);
            double integer_part = 0.0;
            const double fraction =
                std::modf(
                    x,
                    &integer_part);

            if (regs[2] != 0) {
                std::uint64_t bits = 0;
                std::memcpy(
                    &bits,
                    &integer_part,
                    sizeof(bits));
                mem.Write64Guest(
                    regs[2],
                    bits);
            }

            write_double_regs(fraction);
            ++supported_calls;
            return;
        }

        // Bulk zlib bridge. Guest z_stream is the 32-bit Android layout;
        // host zlib state remains private and only buffer pointers/counters
        // are mirrored across the ABI boundary.
        if (name == "adler32" ||
            name == "crc32") {

            const std::uint32_t initial = regs[0];
            const std::uint32_t buffer = regs[1];
            const std::uint32_t length = regs[2];
            const auto* p =
                length == 0
                    ? nullptr
                    : mem.Ptr(buffer, length);

            if (length != 0 && !p) {
                result.message =
                    name +
                    " attempted to read outside guest memory.";
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    name == "adler32"
                        ? ::adler32(
                            initial,
                            reinterpret_cast<const Bytef*>(p),
                            length)
                        : ::crc32(
                            initial,
                            reinterpret_cast<const Bytef*>(p),
                            length));

            ++supported_calls;
            return;
        }

        if (name == "compress" ||
            name == "uncompress") {

            const std::uint32_t destination = regs[0];
            const std::uint32_t destination_length_ptr = regs[1];
            const std::uint32_t source = regs[2];
            const std::uint32_t source_length = regs[3];

            const std::uint32_t guest_capacity =
                mem.Read32Guest(
                    destination_length_ptr);

            auto* dst =
                mem.Ptr(
                    destination,
                    guest_capacity);
            const auto* src =
                mem.Ptr(
                    source,
                    source_length);

            if (!dst || !src) {
                result.message =
                    name +
                    " attempted to access outside guest memory.";
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            if (!V91AllowRelroWrite(
                    destination,
                    guest_capacity,
                    name.c_str())) {
                regs[0] =
                    static_cast<std::uint32_t>(
                        Z_BUF_ERROR);
                ++supported_calls;
                return;
            }

            uLongf host_length =
                guest_capacity;

            const int status =
                name == "compress"
                    ? ::compress(
                        reinterpret_cast<Bytef*>(dst),
                        &host_length,
                        reinterpret_cast<const Bytef*>(src),
                        source_length)
                    : ::uncompress(
                        reinterpret_cast<Bytef*>(dst),
                        &host_length,
                        reinterpret_cast<const Bytef*>(src),
                        source_length);

            mem.Write32Guest(
                destination_length_ptr,
                static_cast<std::uint32_t>(
                    host_length));

            regs[0] =
                static_cast<std::uint32_t>(
                    status);

            ++supported_calls;
            return;
        }

        auto sync_zstream_from_guest =
            [&](std::uint32_t guest_stream,
                z_stream& stream) -> bool {

                const std::uint32_t next_in =
                    mem.Read32Guest(
                        guest_stream + 0);
                const std::uint32_t avail_in =
                    mem.Read32Guest(
                        guest_stream + 4);
                const std::uint32_t next_out =
                    mem.Read32Guest(
                        guest_stream + 12);
                const std::uint32_t avail_out =
                    mem.Read32Guest(
                        guest_stream + 16);

                stream.next_in =
                    avail_in == 0
                        ? nullptr
                        : reinterpret_cast<Bytef*>(
                            mem.Ptr(
                                next_in,
                                avail_in));

                stream.avail_in =
                    avail_in;

                stream.next_out =
                    avail_out == 0
                        ? nullptr
                        : reinterpret_cast<Bytef*>(
                            mem.Ptr(
                                next_out,
                                avail_out));

                stream.avail_out =
                    avail_out;

                return
                    (avail_in == 0 || stream.next_in) &&
                    (avail_out == 0 || stream.next_out);
            };

        auto sync_zstream_to_guest =
            [&](std::uint32_t guest_stream,
                const z_stream& stream,
                std::uint32_t original_next_in,
                std::uint32_t original_avail_in,
                std::uint32_t original_next_out,
                std::uint32_t original_avail_out) {

                const std::uint32_t consumed =
                    original_avail_in -
                    stream.avail_in;
                const std::uint32_t produced =
                    original_avail_out -
                    stream.avail_out;

                mem.Write32Guest(
                    guest_stream + 0,
                    original_next_in + consumed);
                mem.Write32Guest(
                    guest_stream + 4,
                    stream.avail_in);
                mem.Write32Guest(
                    guest_stream + 8,
                    static_cast<std::uint32_t>(
                        stream.total_in));
                mem.Write32Guest(
                    guest_stream + 12,
                    original_next_out + produced);
                mem.Write32Guest(
                    guest_stream + 16,
                    stream.avail_out);
                mem.Write32Guest(
                    guest_stream + 20,
                    static_cast<std::uint32_t>(
                        stream.total_out));
                mem.Write32Guest(
                    guest_stream + 44,
                    static_cast<std::uint32_t>(
                        stream.data_type));
                mem.Write32Guest(
                    guest_stream + 48,
                    static_cast<std::uint32_t>(
                        stream.adler));
            };

        if (name == "deflateInit_" ||
            name == "inflateInit_" ||
            name == "deflateInit2_") {

            const std::uint32_t guest_stream =
                regs[0];
            const bool deflate_mode =
                name != "inflateInit_";

            // zlib's state object remembers the exact z_stream* used by init.
            // Initialize the map node itself, never a temporary copied later.
            auto previous =
                zstreams.find(guest_stream);

            if (previous != zstreams.end()) {
                const auto mode_it =
                    zstream_deflate_mode.find(
                        guest_stream);
                const bool previous_deflate =
                    mode_it != zstream_deflate_mode.end() &&
                    mode_it->second;

                if (previous->second.state != nullptr) {
                    if (previous_deflate) {
                        ::deflateEnd(
                            &previous->second);
                    } else {
                        ::inflateEnd(
                            &previous->second);
                    }
                }

                zstreams.erase(previous);
                zstream_deflate_mode.erase(
                    guest_stream);
            }

            auto [stream_it, inserted] =
                zstreams.try_emplace(
                    guest_stream);
            (void)inserted;

            z_stream& stream =
                stream_it->second;
            stream =
                z_stream{};

            int status = Z_STREAM_ERROR;

            if (name == "deflateInit_") {
                status =
                    ::deflateInit_(
                        &stream,
                        static_cast<int>(regs[1]),
                        ZLIB_VERSION,
                        sizeof(z_stream));
            } else if (name == "inflateInit_") {
                status =
                    ::inflateInit_(
                        &stream,
                        ZLIB_VERSION,
                        sizeof(z_stream));
            } else {
                const std::uint32_t sp =
                    regs[13];

                const int mem_level =
                    static_cast<int>(
                        mem.Read32Guest(sp + 0));
                const int strategy =
                    static_cast<int>(
                        mem.Read32Guest(sp + 4));

                status =
                    ::deflateInit2_(
                        &stream,
                        static_cast<int>(regs[1]),
                        static_cast<int>(regs[2]),
                        static_cast<int>(regs[3]),
                        mem_level,
                        strategy,
                        ZLIB_VERSION,
                        sizeof(z_stream));
            }

            if (status == Z_OK) {
                zstream_deflate_mode[guest_stream] =
                    deflate_mode;
            } else {
                if (stream.state != nullptr) {
                    if (deflate_mode) {
                        ::deflateEnd(&stream);
                    } else {
                        ::inflateEnd(&stream);
                    }
                }
                zstreams.erase(stream_it);
            }

            if (V70Enabled()) {
                ++v70_zlib_init_calls;
                Append(
                    "V70 ZLIB INIT #" +
                    std::to_string(
                        v70_zlib_init_calls) +
                    " api=" + name +
                    " guestStream=" +
                    V46DescribeGuestAddress(
                        guest_stream) +
                    " status=" +
                    std::to_string(status) +
                    " ownership=IN_PLACE_STABLE");
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    status);

            ++supported_calls;
            return;
        }

        if (name == "deflate" ||
            name == "inflate") {

            const std::uint32_t guest_stream =
                regs[0];

            auto it =
                zstreams.find(
                    guest_stream);

            if (it == zstreams.end()) {
                regs[0] =
                    static_cast<std::uint32_t>(
                        Z_STREAM_ERROR);
                ++supported_calls;
                return;
            }

            const std::uint32_t original_next_in =
                mem.Read32Guest(
                    guest_stream + 0);
            const std::uint32_t original_avail_in =
                mem.Read32Guest(
                    guest_stream + 4);
            const std::uint32_t original_next_out =
                mem.Read32Guest(
                    guest_stream + 12);
            const std::uint32_t original_avail_out =
                mem.Read32Guest(
                    guest_stream + 16);

            if (original_avail_out != 0u &&
                !V91AllowRelroWrite(
                    original_next_out,
                    original_avail_out,
                    name == "deflate"
                        ? "zlib.deflate-output"
                        : "zlib.inflate-output")) {

                regs[0] =
                    static_cast<std::uint32_t>(
                        Z_BUF_ERROR);
                ++supported_calls;
                return;
            }

            if (!sync_zstream_from_guest(
                    guest_stream,
                    it->second)) {

                result.message =
                    name +
                    " guest z_stream buffer is outside mapped memory.";

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            const std::uint64_t v89_zlib_begin_ns=V89HostCostEnabled()?V85SteadyNowNs():0u;
            const int status =
                name == "deflate"
                    ? ::deflate(
                        &it->second,
                        static_cast<int>(regs[1]))
                    : ::inflate(
                        &it->second,
                        static_cast<int>(regs[1]));

            const std::uint32_t consumed =
                original_avail_in -
                it->second.avail_in;
            const std::uint32_t produced =
                original_avail_out -
                it->second.avail_out;
            if(V89HostCostEnabled())V89RecordHostCost(name=="inflate"?"zlib.inflate":"zlib.deflate",v89_zlib_begin_ns,static_cast<std::uint64_t>(consumed)+produced);

            if (V70Enabled()) {
                ++v70_zlib_calls;
                v70_zlib_input_bytes += consumed;
                v70_zlib_output_bytes += produced;

                if (status == Z_STREAM_ERROR) {
                    ++v70_zlib_stream_errors;
                }
                if (consumed == 0u &&
                    produced == 0u &&
                    status != Z_STREAM_END) {
                    ++v70_zlib_no_progress;
                }

                const bool power_of_two =
                    (v70_zlib_calls &
                     (v70_zlib_calls - 1u)) == 0u;
                const bool error_sample =
                    status < 0 &&
                    (v70_zlib_stream_errors <= 16u ||
                     (v70_zlib_stream_errors != 0u &&
                      (v70_zlib_stream_errors &
                       (v70_zlib_stream_errors - 1u)) == 0u));

                if (v70_zlib_calls <= 16u ||
                    power_of_two ||
                    status == Z_STREAM_END ||
                    error_sample) {

                    Append(
                        "V70 ZLIB " + name +
                        " #" +
                        std::to_string(
                            v70_zlib_calls) +
                        " guestStream=" +
                        V46DescribeGuestAddress(
                            guest_stream) +
                        " flush=" +
                        std::to_string(
                            static_cast<int>(
                                regs[1])) +
                        " status=" +
                        std::to_string(status) +
                        " consumed=" +
                        std::to_string(consumed) +
                        " produced=" +
                        std::to_string(produced) +
                        " availIn=" +
                        std::to_string(
                            it->second.avail_in) +
                        " availOut=" +
                        std::to_string(
                            it->second.avail_out) +
                        " totalIn=" +
                        std::to_string(
                            static_cast<std::uint64_t>(
                                it->second.total_in)) +
                        " totalOut=" +
                        std::to_string(
                            static_cast<std::uint64_t>(
                                it->second.total_out)) +
                        " streamErrors=" +
                        std::to_string(
                            v70_zlib_stream_errors) +
                        " noProgress=" +
                        std::to_string(
                            v70_zlib_no_progress));
                }
            }

            sync_zstream_to_guest(
                guest_stream,
                it->second,
                original_next_in,
                original_avail_in,
                original_next_out,
                original_avail_out);

            regs[0] =
                static_cast<std::uint32_t>(
                    status);

            ++supported_calls;
            return;
        }

        if (name == "deflateReset" ||
            name == "inflateReset") {

            auto it =
                zstreams.find(
                    regs[0]);

            if (it == zstreams.end()) {
                regs[0] =
                    static_cast<std::uint32_t>(
                        Z_STREAM_ERROR);
            } else {
                regs[0] =
                    static_cast<std::uint32_t>(
                        name == "deflateReset"
                            ? ::deflateReset(
                                &it->second)
                            : ::inflateReset(
                                &it->second));
            }

            ++supported_calls;
            return;
        }

        if (name == "deflateEnd" ||
            name == "inflateEnd") {

            const std::uint32_t guest_stream =
                regs[0];

            auto it =
                zstreams.find(
                    guest_stream);

            if (it == zstreams.end()) {
                regs[0] =
                    static_cast<std::uint32_t>(
                        Z_STREAM_ERROR);
            } else {
                const int status =
                    name == "deflateEnd"
                        ? ::deflateEnd(
                            &it->second)
                        : ::inflateEnd(
                            &it->second);

                regs[0] =
                    static_cast<std::uint32_t>(
                        status);

                zstreams.erase(it);
                zstream_deflate_mode.erase(
                    guest_stream);
            }

            ++supported_calls;
            return;
        }

        // Bulk libc/string compatibility pack. These are implemented together
        // so constructor bring-up no longer needs one release per symbol.
        if (name == "memchr") {
            const std::uint32_t address = regs[0];
            const std::uint8_t wanted =
                static_cast<std::uint8_t>(regs[1]);
            const std::uint32_t size = regs[2];
            const auto* p = mem.Ptr(address, size);

            regs[0] = 0;
            if (p) {
                for (std::uint32_t i = 0; i < size; ++i) {
                    if (p[i] == wanted) {
                        regs[0] = address + i;
                        break;
                    }
                }
            }

            ++supported_calls;
            return;
        }

        if (name == "strchr") {
            const std::uint32_t address = regs[0];
            const unsigned char wanted =
                static_cast<unsigned char>(regs[1]);
            const std::string value =
                mem.ReadCStringGuest(address, 1u << 20);

            regs[0] = 0;
            for (std::size_t i = 0; i <= value.size(); ++i) {
                const unsigned char ch =
                    i == value.size()
                        ? 0
                        : static_cast<unsigned char>(value[i]);
                if (ch == wanted) {
                    regs[0] =
                        address +
                        static_cast<std::uint32_t>(i);
                    break;
                }
            }

            ++supported_calls;
            return;
        }

        if (name == "strstr") {
            const std::uint32_t haystack_address = regs[0];
            const std::string haystack =
                mem.ReadCStringGuest(
                    haystack_address,
                    1u << 20);
            const std::string needle =
                mem.ReadCStringGuest(
                    regs[1],
                    1u << 20);

            const std::size_t found =
                haystack.find(needle);

            regs[0] =
                found == std::string::npos
                    ? 0u
                    : haystack_address +
                        static_cast<std::uint32_t>(found);

            ++supported_calls;
            return;
        }

        if (name == "strcasecmp" ||
            name == "strncasecmp") {

            const std::string a =
                mem.ReadCStringGuest(
                    regs[0],
                    1u << 20);
            const std::string b =
                mem.ReadCStringGuest(
                    regs[1],
                    1u << 20);

            const std::size_t limit =
                name == "strncasecmp"
                    ? regs[2]
                    : std::max(a.size(), b.size()) + 1;

            int comparison = 0;

            for (std::size_t i = 0; i < limit; ++i) {
                const unsigned char ac =
                    i < a.size()
                        ? static_cast<unsigned char>(
                            std::tolower(
                                static_cast<unsigned char>(a[i])))
                        : 0;

                const unsigned char bc =
                    i < b.size()
                        ? static_cast<unsigned char>(
                            std::tolower(
                                static_cast<unsigned char>(b[i])))
                        : 0;

                if (ac != bc) {
                    comparison =
                        ac < bc ? -1 : 1;
                    break;
                }

                if (ac == 0) {
                    break;
                }
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    comparison);

            ++supported_calls;
            return;
        }

        if (name == "strcpy" ||
            name == "strncpy" ||
            name == "strcat" ||
            name == "strncat") {

            const std::uint32_t destination = regs[0];
            const std::string source =
                mem.ReadCStringGuest(
                    regs[1],
                    1u << 20);

            std::string prefix;
            std::size_t count = source.size();

            if (name == "strcat" ||
                name == "strncat") {
                prefix =
                    mem.ReadCStringGuest(
                        destination,
                        1u << 20);
            }

            if (name == "strncpy" ||
                name == "strncat") {
                count =
                    std::min<std::size_t>(
                        count,
                        regs[2]);
            }

            const std::string combined =
                prefix +
                source.substr(0, count);

            const std::size_t bytes =
                combined.size() + 1;

            if (!mem.Ptr(destination, bytes)) {
                result.message =
                    name +
                    " attempted to write outside guest memory.";
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            for (std::size_t i = 0;
                 i < combined.size();
                 ++i) {
                mem.Write8Guest(
                    destination +
                        static_cast<std::uint32_t>(i),
                    static_cast<std::uint8_t>(
                        combined[i]));
            }

            mem.Write8Guest(
                destination +
                    static_cast<std::uint32_t>(
                        combined.size()),
                0);

            if (name == "strncpy" &&
                regs[2] > combined.size() + 1) {
                const std::size_t pad_end =
                    std::min<std::size_t>(
                        regs[2],
                        combined.size() + 4096);

                for (std::size_t i =
                         combined.size() + 1;
                     i < pad_end;
                     ++i) {
                    mem.Write8Guest(
                        destination +
                            static_cast<std::uint32_t>(i),
                        0);
                }
            }

            regs[0] = destination;
            ++supported_calls;
            return;
        }

        if (name == "atoi" ||
            name == "atol" ||
            name == "strtol" ||
            name == "strtoul" ||
            name == "strtod") {

            const std::uint32_t source_address = regs[0];
            const std::string source =
                mem.ReadCStringGuest(
                    source_address,
                    4096);

            char* end = nullptr;

            if (name == "strtod") {
                const double value =
                    std::strtod(
                        source.c_str(),
                        &end);

                std::uint64_t bits = 0;
                static_assert(
                    sizeof(bits) == sizeof(value));
                std::memcpy(
                    &bits,
                    &value,
                    sizeof(bits));

                regs[0] =
                    static_cast<std::uint32_t>(bits);
                regs[1] =
                    static_cast<std::uint32_t>(
                        bits >> 32);
            } else if (name == "strtoul") {
                const unsigned long value =
                    std::strtoul(
                        source.c_str(),
                        &end,
                        static_cast<int>(regs[2]));

                regs[0] =
                    static_cast<std::uint32_t>(value);
            } else {
                const int base =
                    name == "strtol"
                        ? static_cast<int>(regs[2])
                        : 10;

                const long value =
                    std::strtol(
                        source.c_str(),
                        &end,
                        base);

                regs[0] =
                    static_cast<std::uint32_t>(value);
            }

            if ((name == "strtol" ||
                 name == "strtoul" ||
                 name == "strtod") &&
                regs[1] != 0 &&
                end != nullptr) {

                const std::uint32_t end_offset =
                    static_cast<std::uint32_t>(
                        end - source.c_str());

                mem.Write32Guest(
                    regs[1],
                    source_address + end_offset);
            }

            ++supported_calls;
            return;
        }

        // Android ARM uses 32-bit wchar_t. The compatibility layer implements
        // the common C/UTF-8 behaviour directly against guest memory.
        if (name == "wctob") {
            const std::uint32_t wc = regs[0];
            regs[0] =
                wc <= 0xffu
                    ? wc
                    : 0xffffffffu;
            ++supported_calls;
            return;
        }

        if (name == "btowc") {
            const std::uint32_t byte = regs[0];
            regs[0] =
                byte == 0xffffffffu
                    ? 0xffffffffu
                    : (byte & 0xffu);
            ++supported_calls;
            return;
        }

        if (name == "towlower" ||
            name == "towupper") {
            const std::uint32_t wc = regs[0];

            if (wc <= 0x7fu) {
                const unsigned char c =
                    static_cast<unsigned char>(wc);

                regs[0] =
                    name == "towlower"
                        ? static_cast<std::uint32_t>(
                            std::tolower(c))
                        : static_cast<std::uint32_t>(
                            std::toupper(c));
            }

            ++supported_calls;
            return;
        }

        if (name == "iswspace" ||
            name == "iswalnum") {
            const std::uint32_t wc = regs[0];
            int answer = 0;

            if (wc <= 0x7fu) {
                const unsigned char c =
                    static_cast<unsigned char>(wc);
                answer =
                    name == "iswspace"
                        ? std::isspace(c)
                        : std::isalnum(c);
            }

            regs[0] =
                answer ? 1u : 0u;
            ++supported_calls;
            return;
        }

        if (name == "wcslen") {
            regs[0] =
                static_cast<std::uint32_t>(
                    mem.ReadWStringGuest(
                        regs[0],
                        1u << 18)
                        .size());
            ++supported_calls;
            return;
        }

        if (name == "wcscmp" ||
            name == "wcsncmp" ||
            name == "wmemcmp") {

            const auto a =
                mem.ReadWStringGuest(
                    regs[0],
                    1u << 18);
            const auto b =
                mem.ReadWStringGuest(
                    regs[1],
                    1u << 18);

            std::size_t limit =
                std::max(a.size(), b.size()) + 1;

            if (name == "wcsncmp" ||
                name == "wmemcmp") {
                limit = regs[2];
            }

            int comparison = 0;

            for (std::size_t i = 0;
                 i < limit;
                 ++i) {

                const std::uint32_t av =
                    i < a.size() ? a[i] : 0u;
                const std::uint32_t bv =
                    i < b.size() ? b[i] : 0u;

                if (av != bv) {
                    comparison =
                        av < bv ? -1 : 1;
                    break;
                }

                if (name != "wmemcmp" &&
                    av == 0) {
                    break;
                }
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    comparison);

            ++supported_calls;
            return;
        }

        if (name == "wcscpy" ||
            name == "wcsncpy") {

            const auto source =
                mem.ReadWStringGuest(
                    regs[1],
                    1u << 18);

            const std::size_t capacity =
                name == "wcsncpy"
                    ? std::max<std::size_t>(
                        regs[2],
                        1u)
                    : source.size() + 1;

            if (!mem.WriteWStringGuest(
                    regs[0],
                    source,
                    capacity)) {

                result.message =
                    name +
                    " attempted to write outside guest memory.";

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            regs[0] = regs[0];
            ++supported_calls;
            return;
        }

        if (name == "wcschr" ||
            name == "wmemchr") {

            const std::uint32_t address = regs[0];
            const std::uint32_t wanted = regs[1];

            const std::size_t limit =
                name == "wmemchr"
                    ? regs[2]
                    : (1u << 18);

            regs[0] = 0;

            for (std::size_t i = 0;
                 i < limit;
                 ++i) {

                const std::uint32_t ch =
                    mem.Read32Guest(
                        address +
                        static_cast<std::uint32_t>(
                            i * 4u));

                if (ch == wanted) {
                    regs[0] =
                        address +
                        static_cast<std::uint32_t>(
                            i * 4u);
                    break;
                }

                if (name == "wcschr" &&
                    ch == 0) {
                    break;
                }
            }

            ++supported_calls;
            return;
        }

        if (name == "wmemcpy" ||
            name == "wmemmove") {

            const std::uint32_t bytes =
                regs[2] * 4u;

            auto* dst =
                mem.Ptr(
                    regs[0],
                    bytes);

            const auto* src =
                mem.Ptr(
                    regs[1],
                    bytes);

            if (!dst || !src) {
                result.message =
                    name +
                    " attempted to access outside guest memory.";

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            if (!V91AllowRelroWrite(
                    regs[0],
                    bytes,
                    name.c_str())) {
                ++supported_calls;
                return;
            }

            std::memmove(
                dst,
                src,
                bytes);

            ++supported_calls;
            return;
        }

        if (name == "wmemset") {
            const std::uint32_t destination = regs[0];
            const std::uint32_t value = regs[1];
            const std::uint32_t count = regs[2];

            if (!mem.Ptr(
                    destination,
                    static_cast<std::size_t>(count) * 4u)) {

                result.message =
                    "wmemset attempted to write outside guest memory.";

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
                return;
            }

            if (!V91AllowRelroWrite(
                    destination,
                    static_cast<std::size_t>(
                        count) * 4u,
                    "wmemset",
                    value,
                    true)) {
                regs[0] = destination;
                ++supported_calls;
                return;
            }

            for (std::uint32_t i = 0;
                 i < count;
                 ++i) {

                mem.Write32Guest(
                    destination + i * 4u,
                    value);
            }

            regs[0] = destination;
            ++supported_calls;
            return;
        }

        if (name == "wcscspn" ||
            name == "wcsspn") {

            const auto source =
                mem.ReadWStringGuest(
                    regs[0],
                    1u << 18);

            const auto set =
                mem.ReadWStringGuest(
                    regs[1],
                    4096);

            auto in_set =
                [&](std::uint32_t ch) {
                    return
                        std::find(
                            set.begin(),
                            set.end(),
                            ch) != set.end();
                };

            std::size_t count = 0;

            for (const std::uint32_t ch : source) {
                const bool match = in_set(ch);

                if (name == "wcscspn"
                        ? match
                        : !match) {
                    break;
                }

                ++count;
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    count);

            ++supported_calls;
            return;
        }

        if (name == "setlocale") {
            static constexpr char kCLocale[] = "C";

            const std::uint32_t guest =
                mem.AllocateObject(
                    sizeof(kCLocale),
                    1);

            if (guest) {
                for (std::size_t i = 0;
                     i < sizeof(kCLocale);
                     ++i) {
                    mem.Write8Guest(
                        guest +
                            static_cast<std::uint32_t>(i),
                        static_cast<std::uint8_t>(
                            kCLocale[i]));
                }
            }

            regs[0] = guest;
            ++supported_calls;
            return;
        }

        if (name == "strcoll") {
            const std::string a =
                mem.ReadCStringGuest(
                    regs[0],
                    1u << 20);

            const std::string b =
                mem.ReadCStringGuest(
                    regs[1],
                    1u << 20);

            regs[0] =
                static_cast<std::uint32_t>(
                    a.compare(b));

            ++supported_calls;
            return;
        }

        if (name == "strxfrm") {
            const std::uint32_t destination = regs[0];
            const std::string source =
                mem.ReadCStringGuest(
                    regs[1],
                    1u << 20);
            const std::uint32_t capacity = regs[2];

            if (destination != 0 &&
                capacity != 0) {

                const std::size_t copy =
                    std::min<std::size_t>(
                        source.size(),
                        capacity - 1);

                if (mem.Ptr(
                        destination,
                        capacity)) {

                    for (std::size_t i = 0;
                         i < copy;
                         ++i) {
                        mem.Write8Guest(
                            destination +
                                static_cast<std::uint32_t>(i),
                            static_cast<std::uint8_t>(
                                source[i]));
                    }

                    mem.Write8Guest(
                        destination +
                            static_cast<std::uint32_t>(copy),
                        0);
                }
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    source.size());

            ++supported_calls;
            return;
        }

        if (name == "wcscoll") {
            const auto a =
                mem.ReadWStringGuest(
                    regs[0],
                    1u << 18);
            const auto b =
                mem.ReadWStringGuest(
                    regs[1],
                    1u << 18);

            regs[0] =
                static_cast<std::uint32_t>(
                    std::lexicographical_compare(
                        a.begin(), a.end(),
                        b.begin(), b.end())
                        ? -1
                        : (a == b ? 0 : 1));

            ++supported_calls;
            return;
        }

        if (name == "wcsxfrm") {
            const auto source =
                mem.ReadWStringGuest(
                    regs[1],
                    1u << 18);

            if (regs[0] != 0 &&
                regs[2] != 0) {
                mem.WriteWStringGuest(
                    regs[0],
                    source,
                    regs[2]);
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    source.size());

            ++supported_calls;
            return;
        }

        if (name == "wctype") {
            const std::string kind =
                mem.ReadCStringGuest(
                    regs[0],
                    64);

            static const std::array<const char*, 12> names = {
                "alnum", "alpha", "blank", "cntrl",
                "digit", "graph", "lower", "print",
                "punct", "space", "upper", "xdigit"
            };

            regs[0] = 0;

            for (std::size_t i = 0;
                 i < names.size();
                 ++i) {
                if (kind == names[i]) {
                    regs[0] =
                        static_cast<std::uint32_t>(
                            i + 1);
                    break;
                }
            }

            ++supported_calls;
            return;
        }

        if (name == "iswctype") {
            const std::uint32_t wc = regs[0];
            const std::uint32_t kind = regs[1];
            int answer = 0;

            if (wc <= 0x7fu &&
                kind >= 1u &&
                kind <= 12u) {

                const unsigned char ch =
                    static_cast<unsigned char>(wc);

                switch (kind) {
                case 1: answer = std::isalnum(ch); break;
                case 2: answer = std::isalpha(ch); break;
                case 3: answer = (ch == ' ' || ch == '\t'); break;
                case 4: answer = std::iscntrl(ch); break;
                case 5: answer = std::isdigit(ch); break;
                case 6: answer = std::isgraph(ch); break;
                case 7: answer = std::islower(ch); break;
                case 8: answer = std::isprint(ch); break;
                case 9: answer = std::ispunct(ch); break;
                case 10: answer = std::isspace(ch); break;
                case 11: answer = std::isupper(ch); break;
                case 12: answer = std::isxdigit(ch); break;
                default: break;
                }
            }

            regs[0] =
                answer ? 1u : 0u;

            ++supported_calls;
            return;
        }

        if (name == "mbrtowc") {
            const std::uint32_t output = regs[0];
            const std::uint32_t source_address = regs[1];
            const std::size_t available = regs[2];

            if (source_address == 0) {
                regs[0] = 0;
                ++supported_calls;
                return;
            }

            if (available == 0) {
                regs[0] = 0xfffffffeu;
                ++supported_calls;
                return;
            }

            const std::uint8_t b0 =
                mem.Read8(source_address);

            if (b0 == 0) {
                if (output) {
                    mem.Write32Guest(output, 0);
                }
                regs[0] = 0;
                ++supported_calls;
                return;
            }

            std::uint32_t codepoint = 0;
            std::size_t length = 0;

            if (b0 < 0x80u) {
                codepoint = b0;
                length = 1;
            } else if ((b0 & 0xe0u) == 0xc0u &&
                       available >= 2) {
                codepoint =
                    ((b0 & 0x1fu) << 6) |
                    (mem.Read8(source_address + 1) & 0x3fu);
                length = 2;
            } else if ((b0 & 0xf0u) == 0xe0u &&
                       available >= 3) {
                codepoint =
                    ((b0 & 0x0fu) << 12) |
                    ((mem.Read8(source_address + 1) & 0x3fu) << 6) |
                    (mem.Read8(source_address + 2) & 0x3fu);
                length = 3;
            } else if ((b0 & 0xf8u) == 0xf0u &&
                       available >= 4) {
                codepoint =
                    ((b0 & 0x07u) << 18) |
                    ((mem.Read8(source_address + 1) & 0x3fu) << 12) |
                    ((mem.Read8(source_address + 2) & 0x3fu) << 6) |
                    (mem.Read8(source_address + 3) & 0x3fu);
                length = 4;
            } else {
                regs[0] = 0xffffffffu;
                ++supported_calls;
                return;
            }

            if (output) {
                mem.Write32Guest(
                    output,
                    codepoint);
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    length);

            ++supported_calls;
            return;
        }

        if (name == "wcrtomb") {
            const std::uint32_t destination = regs[0];
            const std::uint32_t wc = regs[1];

            if (destination == 0) {
                regs[0] = 1;
                ++supported_calls;
                return;
            }

            std::array<std::uint8_t, 4> bytes{};
            std::size_t length = 0;

            if (wc <= 0x7fu) {
                bytes[0] =
                    static_cast<std::uint8_t>(wc);
                length = 1;
            } else if (wc <= 0x7ffu) {
                bytes[0] =
                    0xc0u | (wc >> 6);
                bytes[1] =
                    0x80u | (wc & 0x3fu);
                length = 2;
            } else if (wc <= 0xffffu) {
                bytes[0] =
                    0xe0u | (wc >> 12);
                bytes[1] =
                    0x80u |
                    ((wc >> 6) & 0x3fu);
                bytes[2] =
                    0x80u |
                    (wc & 0x3fu);
                length = 3;
            } else if (wc <= 0x10ffffu) {
                bytes[0] =
                    0xf0u | (wc >> 18);
                bytes[1] =
                    0x80u |
                    ((wc >> 12) & 0x3fu);
                bytes[2] =
                    0x80u |
                    ((wc >> 6) & 0x3fu);
                bytes[3] =
                    0x80u |
                    (wc & 0x3fu);
                length = 4;
            } else {
                regs[0] = 0xffffffffu;
                ++supported_calls;
                return;
            }

            for (std::size_t i = 0;
                 i < length;
                 ++i) {
                mem.Write8Guest(
                    destination +
                        static_cast<std::uint32_t>(i),
                    bytes[i]);
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    length);

            ++supported_calls;
            return;
        }

        if (name == "wcstombs") {
            const std::uint32_t destination = regs[0];
            const auto source =
                mem.ReadWStringGuest(
                    regs[1],
                    1u << 18);
            const std::size_t capacity = regs[2];

            std::vector<std::uint8_t> encoded;
            encoded.reserve(source.size());

            for (const std::uint32_t wc : source) {
                if (wc <= 0x7fu) {
                    encoded.push_back(
                        static_cast<std::uint8_t>(wc));
                } else if (wc <= 0x7ffu) {
                    encoded.push_back(
                        0xc0u | (wc >> 6));
                    encoded.push_back(
                        0x80u |
                        (wc & 0x3fu));
                } else if (wc <= 0xffffu) {
                    encoded.push_back(
                        0xe0u | (wc >> 12));
                    encoded.push_back(
                        0x80u |
                        ((wc >> 6) & 0x3fu));
                    encoded.push_back(
                        0x80u |
                        (wc & 0x3fu));
                } else if (wc <= 0x10ffffu) {
                    encoded.push_back(
                        0xf0u | (wc >> 18));
                    encoded.push_back(
                        0x80u |
                        ((wc >> 12) & 0x3fu));
                    encoded.push_back(
                        0x80u |
                        ((wc >> 6) & 0x3fu));
                    encoded.push_back(
                        0x80u |
                        (wc & 0x3fu));
                } else {
                    regs[0] = 0xffffffffu;
                    ++supported_calls;
                    return;
                }
            }

            if (destination != 0 &&
                capacity != 0) {
                const std::size_t copy =
                    std::min(
                        capacity,
                        encoded.size());

                for (std::size_t i = 0;
                     i < copy;
                     ++i) {
                    mem.Write8Guest(
                        destination +
                            static_cast<std::uint32_t>(i),
                        encoded[i]);
                }

                if (copy < capacity) {
                    mem.Write8Guest(
                        destination +
                            static_cast<std::uint32_t>(copy),
                        0);
                }
            }

            regs[0] =
                static_cast<std::uint32_t>(
                    encoded.size());

            ++supported_calls;
            return;
        }

        if (name == "wcstol") {
            const auto source =
                mem.ReadWStringGuest(
                    regs[0],
                    4096);

            std::string ascii;
            ascii.reserve(source.size());

            for (const auto wc : source) {
                ascii.push_back(
                    wc <= 0x7fu
                        ? static_cast<char>(wc)
                        : '?');
            }

            char* end = nullptr;
            const long value =
                std::strtol(
                    ascii.c_str(),
                    &end,
                    static_cast<int>(regs[2]));

            regs[0] =
                static_cast<std::uint32_t>(
                    value);

            ++supported_calls;
            return;
        }

        // C-locale fallbacks for rarely used wide stdio/formatting hooks.
        // They are safe during static construction and remain explicitly
        // isolated from the later real file/audio/rendering bridges.
        if (name == "fwide") {
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "getwc" ||
            name == "ungetwc") {
            regs[0] = 0xffffffffu;
            ++supported_calls;
            return;
        }

        if (name == "putwc") {
            regs[0] = regs[0];
            ++supported_calls;
            return;
        }

        if (name == "swscanf" ||
            name == "vswprintf" ||
            name == "wcsftime") {
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_create") {
            const std::uint32_t thread_out = regs[0];
            const std::uint32_t start_routine = regs[2];
            const std::uint32_t argument = regs[3];
            const std::uint32_t thread_id =
                next_synthetic_thread++;

            if (thread_out) {
                mem.Write32Guest(
                    thread_out,
                    thread_id);
            }

            std::string phase;
            switch (return_mode) {
            case ReturnMode::Constructor:
                phase =
                    "constructor[" +
                    std::to_string(current_constructor_index) +
                    "]";
                break;
            case ReturnMode::GameAppInitialize:
                phase = "Native_GameAppInitialize";
                break;
            case ReturnMode::Lifecycle:
                phase =
                    current_lifecycle_name.empty()
                        ? "lifecycle"
                        : current_lifecycle_name;
                break;
            case ReturnMode::JniOnLoad:
            default:
                phase = "JNI_OnLoad";
                break;
            }

            deferred_threads.push_back(
                DeferredThread{
                    thread_id,
                    start_routine,
                    argument,
                    phase});

            constexpr std::uint32_t kV104AkAudioThreadEntryGuest =
                kGuestBase + 0x00bfdb70u;
            constexpr std::uint32_t kV106AkBankThreadEntryGuest =
                kGuestBase + 0x00bc7b8cu;

            if (V106Enabled()) {
                AppendDiagnostic(
                    "V106 WORKER CREATED tid=" +
                    std::to_string(thread_id) +
                    " start=" +
                    V46DescribeGuestAddress(start_routine) +
                    " arg=" +
                    V46DescribeGuestAddress(argument) +
                    " phase=" +
                    phase);

                if ((start_routine & ~1u) ==
                    kV106AkBankThreadEntryGuest) {
                    v106_bank_worker_tid =
                        thread_id;
                    v106_bank_worker_object =
                        argument;
                    AppendDiagnostic(
                        "V106 BANK WORKER FOUND tid=" +
                        std::to_string(thread_id) +
                        " start=" +
                        V46DescribeGuestAddress(start_routine) +
                        " arg=" +
                        V46DescribeGuestAddress(argument));
                }
            }

            if (V104Enabled() &&
                (start_routine & ~1u) ==
                    kV104AkAudioThreadEntryGuest) {
                v104_audio_worker_tid = thread_id;
                if (V108Enabled()) {
                    v108_audio_event_sem = argument;
                    AppendDiagnostic("V108 AUDIO EVENT SEM FOUND tid=" + std::to_string(thread_id) +
                                     " sem=" + V46DescribeGuestAddress(v108_audio_event_sem));
                }
                AppendDiagnostic(
                    "V104 AUDIO WORKER FOUND tid=" +
                    std::to_string(thread_id) +
                    " start=" +
                    V46DescribeGuestAddress(start_routine) +
                    " arg=" +
                    V46DescribeGuestAddress(argument));
            }

            Append(
                "import pthread_create deferred: tid=" +
                std::to_string(thread_id) +
                " start=0x" +
                JniProbeHex(start_routine) +
                " arg=0x" +
                JniProbeHex(argument) +
                " created_in=" +
                phase);

            // v61: 0x109cb6d0 is a tiny generic pthread wrapper:
            //   fn = [arg+0], this = [arg+4], fn(this)
            // Capture the real worker entry/object now so a later stall can
            // be attributed without another diagnostic-only build.
            if ((start_routine & ~1u) ==
                    kV61GenericPthreadWrapperGuest &&
                argument != 0u &&
                mem.Ptr(argument, 8u) != nullptr) {

                const std::uint32_t worker_entry = mem.Read32Guest(argument);
                const std::uint32_t worker_object =
                    mem.Read32Guest(argument + 4u);

                if (V106Enabled()) {
                    AppendDiagnostic(
                        "V106 WORKER WRAPPER tid=" +
                        std::to_string(thread_id) +
                        " entry=" +
                        V46DescribeGuestAddress(worker_entry) +
                        " this=" +
                        V46DescribeGuestAddress(worker_object));

                    if ((worker_entry & ~1u) ==
                        (kGuestBase + 0x00bc7b8cu)) {
                        v106_bank_worker_tid =
                            thread_id;
                        v106_bank_worker_object =
                            worker_object;
                        AppendDiagnostic(
                            "V106 BANK WORKER FOUND tid=" +
                            std::to_string(thread_id) +
                            " wrapperStart=" +
                            V46DescribeGuestAddress(start_routine) +
                            " entry=" +
                            V46DescribeGuestAddress(worker_entry) +
                            " this=" +
                            V46DescribeGuestAddress(worker_object));
                    }
                }

                if (V104Enabled() &&
                    (worker_entry & ~1u) ==
                        (kGuestBase + 0x00bfdb70u)) {
                    v104_audio_worker_tid = thread_id;
                    if (V108Enabled()) {
                        v108_audio_event_sem = worker_object;
                        AppendDiagnostic("V108 AUDIO EVENT SEM FOUND tid=" + std::to_string(thread_id) +
                                         " sem=" + V46DescribeGuestAddress(v108_audio_event_sem));
                    }
                    AppendDiagnostic(
                        "V104 AUDIO WORKER FOUND tid=" +
                        std::to_string(thread_id) +
                        " wrapperStart=" +
                        V46DescribeGuestAddress(start_routine) +
                        " entry=" +
                        V46DescribeGuestAddress(worker_entry) +
                        " this=" +
                        V46DescribeGuestAddress(worker_object));
                }

                Append(
                    "V61 WORKER PAYLOAD tid=" + std::to_string(thread_id) +
                    " entry=0x" + JniProbeHex(worker_entry) +
                    " this=0x" + JniProbeHex(worker_object) +
                    " wrapperArg=0x" + JniProbeHex(argument));

                if (V62Enabled()) {
                    V62WorkerPayload payload{
                        worker_entry,
                        worker_object,
                        worker_object ? worker_object + 0x30u : 0u};
                    v62_worker_payloads[thread_id] = payload;
                    if (thread_id == 1u) v62_tid1_sentinel = payload.sentinel30;

                    Append(
                        "V62 WORKER ALIAS tid=" + std::to_string(thread_id) +
                        " entry=" + V46DescribeGuestAddress(worker_entry) +
                        " this=" + V46DescribeGuestAddress(worker_object) +
                        " thisClass=" + V62HeapPointerClass(worker_object) +
                        " sentinel30=" +
                        V46DescribeGuestAddress(payload.sentinel30) +
                        " sentinelClass=" +
                        V62HeapPointerClass(payload.sentinel30));
                }
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_exit") {
            Append(
                "import pthread_exit ignored during constructor probe");
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutex_unlock") {
            const std::uint32_t mutex_arg = regs[0];
            const std::uint32_t clean_lr = regs[14] & ~1u;

            if (V63Enabled() &&
                !V63ReleaseMutex(mutex_arg)) {
                regs[0] = 1u; // EPERM-like diagnostic failure.
                ++supported_calls;
                if (jit) {
                    jit->HaltExecution(
                        Dynarmic::HaltReason::UserDefined3);
                }
                return;
            }

            if (V62Enabled() &&
                clean_lr == kV61ResStreamsPumpUnlockReturnGuest &&
                v62_pump_mutex == 0u) {
                v62_pump_mutex = mutex_arg;
                if (mutex_arg >= 0x68u)
                    v62_pump_manager = mutex_arg - 0x68u;
                V62RefreshPumpVector();
            }

            if (V62MutexCoherentEnabled() &&
                v62_pump_mutex != 0u &&
                mutex_arg == v62_pump_mutex) {
                if (v62_pump_mutex_locked &&
                    v62_pump_mutex_owner == current_probe_thread_id) {
                    v62_pump_mutex_locked = false;
                    v62_pump_mutex_owner = 0xffffffffu;
                    ++v62_pump_mutex_releases;
                    if (v62_pump_mutex_releases <= 16u ||
                        (v62_pump_mutex_releases % 1000u) == 0u) {
                        Append(
                            "V62 PUMP MUTEX RELEASE #" +
                            std::to_string(v62_pump_mutex_releases) +
                            " thread=" +
                            std::to_string(current_probe_thread_id) +
                            " mutex=" +
                            V46DescribeGuestAddress(mutex_arg));
                    }
                } else {
                    Append(
                        "V62 PUMP MUTEX RELEASE MISMATCH thread=" +
                        std::to_string(current_probe_thread_id) +
                        " trackedOwner=" +
                        std::to_string(v62_pump_mutex_owner) +
                        " locked=" +
                        (v62_pump_mutex_locked ? "YES" : "NO"));
                }
            }

            regs[0] = 0;
            ++supported_calls;

            // Legacy v62 B: the verified pump unlock is an explicit safe
            // worker slice end.
            if (V62MutexCoherentEnabled() &&
                current_probe_thread_id != 0u &&
                clean_lr == kV61ResStreamsPumpUnlockReturnGuest &&
                soft_slice_timeout) {
                Append(
                    "V62 WORKER SAFE UNLOCK tid=" +
                    std::to_string(current_probe_thread_id) +
                    " LR=0x" + JniProbeHex(clean_lr) +
                    " -> end worker slice");
                jit->HaltExecution(Dynarmic::HaltReason::UserDefined4);
                return;
            }

            if (v61_res_stream_pump_signature_ok &&
                return_mode == ReturnMode::Lifecycle &&
                current_probe_thread_id == 0u &&
                current_lifecycle_name == "Native_onDrawFrame" &&
                clean_lr == kV61ResStreamsPumpUnlockReturnGuest &&
                soft_slice_timeout) {

                v61_res_stream_pump_boundary_pending = true;
                ++v61_res_stream_pump_yields;
                const std::uint64_t interval =
                    V63Enabled()
                        ? 5000u
                        : (V62Enabled() ? 1000u : 100u);

                if (v61_res_stream_pump_yields <= 12u ||
                    (v61_res_stream_pump_yields % interval) == 0u) {
                    Append(
                        "V61 RES-STREAM PUMP UNLOCK #" +
                        std::to_string(v61_res_stream_pump_yields) +
                        " LR=0x" + JniProbeHex(clean_lr) +
                        " -> cooperative main-thread yield");
                }

                jit->HaltExecution(Dynarmic::HaltReason::UserDefined4);
            }
            return;
        }

        if (name == "pthread_mutexattr_init") {
            if (V87Enabled() &&
                regs[0] != 0u) {
                v87_mutexattr_types[regs[0]] = 0u;
            }

            regs[0] = 0u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutexattr_settype") {
            if (V87Enabled() &&
                regs[0] != 0u) {
                v87_mutexattr_types[regs[0]] =
                    regs[1];
            }

            regs[0] = 0u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutexattr_setpshared") {
            regs[0] = 0u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutexattr_destroy") {
            if (V87Enabled()) {
                v87_mutexattr_types.erase(regs[0]);
            }

            regs[0] = 0u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutex_init") {
            if (V63Enabled()) {
                V63MutexState state;

                if (V87Enabled()) {
                    state.type = 0u;
                    state.type_known = true;

                    if (regs[1] != 0u) {
                        const auto attr =
                            v87_mutexattr_types.find(
                                regs[1]);

                        if (attr !=
                            v87_mutexattr_types.end()) {
                            state.type =
                                attr->second;
                        }
                    }
                }

                v63_mutexes[regs[0]] =
                    state;
            }

            regs[0] = 0u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutex_destroy") {
            if (V63Enabled()) {
                const auto found =
                    v63_mutexes.find(regs[0]);
                if (found != v63_mutexes.end() &&
                    found->second.depth != 0u) {
                    Append(
                        "V63 MUTEX DESTROY WHILE OWNED mutex=" +
                        V46DescribeGuestAddress(regs[0]) +
                        " ownerTid=" +
                        std::to_string(found->second.owner) +
                        " depth=" +
                        std::to_string(found->second.depth));
                } else if (found != v63_mutexes.end()) {
                    v63_mutexes.erase(found);
                }
            }
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutex_lock") {
            if (V63Enabled()) {
                const std::uint32_t mutex_arg = regs[0];

                v87_last_mutex_error = 0u;

                const bool acquired =
                    V63AcquireMutex(
                        mutex_arg,
                        false);

                ++supported_calls;

                if (acquired) {
                    regs[0] = 0u;
                    return;
                }

                if (V87Enabled() &&
                    v87_last_mutex_error != 0u) {
                    regs[0] =
                        v87_last_mutex_error;
                    return;
                }

                if (V87Enabled() &&
                    V87MutexWaitPending(
                        current_probe_thread_id)) {

                    regs[0] = 0u;

                    if (jit) {
                        jit->HaltExecution(
                            Dynarmic::HaltReason::UserDefined4);
                    }

                    return;
                }

                regs[0] = 16u;

                if (jit) {
                    jit->HaltExecution(
                        Dynarmic::HaltReason::UserDefined3);
                }

                return;
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutex_trylock") {
            const std::uint32_t mutex_arg = regs[0];
            const std::uint32_t clean_lr = regs[14] & ~1u;

            if (V62Enabled() &&
                v61_res_stream_pump_signature_ok &&
                clean_lr == kV62ResStreamsPumpTrylockReturnGuest) {

                if (v62_pump_mutex == 0u) {
                    v62_pump_mutex = mutex_arg;
                    if (mutex_arg >= 0x68u)
                        v62_pump_manager = mutex_arg - 0x68u;
                    V62RefreshPumpVector();

                    Append(
                        "V62 PUMP DISCOVERED manager=" +
                        V46DescribeGuestAddress(v62_pump_manager) +
                        " mutex=" +
                        V46DescribeGuestAddress(v62_pump_mutex) +
                        " vector={begin=0x" +
                        JniProbeHex(v62_pump_vector_begin) +
                        ",end=0x" + JniProbeHex(v62_pump_vector_end) +
                        ",cap=0x" + JniProbeHex(v62_pump_vector_cap) + "}");
                    V62ScanPumpVector("first-trylock");
                }

                V62RefreshPumpVector();

                if (V62MutexCoherentEnabled()) {
                    if (!v62_pump_mutex_locked) {
                        v62_pump_mutex_locked = true;
                        v62_pump_mutex_owner = current_probe_thread_id;
                        ++v62_pump_mutex_acquires;
                        regs[0] = 0u;
                        if (v62_pump_mutex_acquires <= 16u ||
                            (v62_pump_mutex_acquires % 1000u) == 0u) {
                            Append(
                                "V62 PUMP MUTEX ACQUIRE #" +
                                std::to_string(v62_pump_mutex_acquires) +
                                " ownerTid=" +
                                std::to_string(current_probe_thread_id));
                        }
                    } else {
                        ++v62_pump_mutex_contentions;
                        regs[0] = 16u;
                        Append(
                            "V62 PUMP MUTEX BUSY #" +
                            std::to_string(v62_pump_mutex_contentions) +
                            " requesterTid=" +
                            std::to_string(current_probe_thread_id) +
                            " ownerTid=" +
                            std::to_string(v62_pump_mutex_owner));
                    }
                    ++supported_calls;
                    return;
                }
            }

            if (V63Enabled()) {
                const bool acquired =
                    V63AcquireMutex(
                        mutex_arg,
                        true);
                regs[0] = acquired ? 0u : 16u;
                ++supported_calls;
                return;
            }

            // Legacy modes preserve v61's synthetic success.
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_key_create") {
            const std::uint32_t output = regs[0];
            const std::uint32_t key = next_pthread_key++;

            mem.Write32Guest(output, key);
            regs[0] = 0;
            ++supported_calls;

            Append(
                "import pthread_key_create -> key=" +
                std::to_string(key));
            return;
        }

        if (name == "pthread_key_delete") {
            pthread_specific.erase(regs[0]);
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_setspecific") {
            pthread_specific[regs[0]] = regs[1];
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_getspecific") {
            const auto it =
                pthread_specific.find(regs[0]);

            regs[0] =
                it == pthread_specific.end()
                    ? 0u
                    : it->second;

            ++supported_calls;
            return;
        }

        if (name == "sched_yield" &&
            V66Enabled() &&
            current_probe_thread_id != 0u) {

            regs[0] = 0u;
            ++supported_calls;
            ++v66_sched_yields;

            if (v66_sched_yields <= 16u ||
                (v66_sched_yields % 1024u) == 0u) {
                Append(
                    "V66 SCHED YIELD #" +
                    std::to_string(v66_sched_yields) +
                    " tid=" +
                    std::to_string(current_probe_thread_id));
            }

            if (jit) {
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined4);
            }
            return;
        }

        // Bulk single-process pthread/semaphore compatibility. Constructors
        // still use these immediate-success shims; v65/v66 override the real
        // blocking primitives above/below for deferred guest workers.
        if (name == "pthread_attr_init" ||
            name == "pthread_attr_destroy" ||
            name == "pthread_attr_setdetachstate" ||
            name == "pthread_attr_setschedparam" ||
            name == "pthread_attr_setschedpolicy" ||
            name == "pthread_attr_setstack" ||
            name == "pthread_attr_setstacksize" ||
            name == "pthread_condattr_init" ||
            name == "pthread_condattr_destroy" ||
            name == "pthread_cond_init" ||
            name == "pthread_cond_destroy" ||
            name == "pthread_detach" ||
            name == "pthread_join" ||
            name == "pthread_setschedparam" ||
            name == "sched_yield") {

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_self") {
            regs[0] =
                current_probe_thread_id != 0
                    ? current_probe_thread_id
                    : 1u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_getschedparam") {
            if (regs[1]) {
                mem.Write32Guest(regs[1], 0);
            }
            if (regs[2]) {
                mem.Write32Guest(regs[2], 0);
            }
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_attr_getschedparam") {
            if (regs[1]) {
                mem.Write32Guest(regs[1], 0);
            }
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_attr_getstack") {
            if (regs[1]) {
                mem.Write32Guest(
                    regs[1],
                    kJniProbeStackBase);
            }

            if (regs[2]) {
                mem.Write32Guest(
                    regs[2],
                    kJniProbeStackSize);
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_getattr_np") {
            if (regs[1]) {
                if (auto* p =
                        mem.Ptr(regs[1], 64)) {
                    if (V91AllowRelroWrite(
                            regs[1],
                            64u,
                            "pthread_getattr_np")) {
                        std::memset(p, 0, 64);
                    }
                }
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_cond_signal" ||
            name == "pthread_cond_broadcast") {

            if (V65Enabled()) {
                V65NotifyCond(
                    regs[0],
                    name == "pthread_cond_broadcast");
            }

            regs[0] = 0u;
            ++supported_calls;
            return;
        }

        if (name == "pthread_cond_wait" ||
            name == "pthread_cond_timedwait") {

            const bool timed =
                name == "pthread_cond_timedwait";

            if (V65Enabled() &&
                (current_probe_thread_id != 0u ||
                 V96MainBlockingAllowed())) {

                const std::uint32_t cond =
                    regs[0];
                const std::uint32_t mutex =
                    regs[1];
                const std::uint32_t abstime =
                    timed
                        ? regs[2]
                        : 0u;

                if (!V65BeginCondWait(
                        cond,
                        mutex,
                        timed,
                        abstime)) {

                    regs[0] = 22u; // EINVAL-like diagnostic failure.
                    ++supported_calls;

                    if (jit) {
                        jit->HaltExecution(
                            Dynarmic::HaltReason::UserDefined3);
                    }
                    return;
                }

                // The SVC itself is complete. Save the worker immediately
                // after the atomic mutex release; the scheduler will not run
                // it again until signal/broadcast/timeout and mutex reacquire.
                regs[0] = 0u;
                ++supported_calls;

                if (jit) {
                    jit->HaltExecution(
                        Dynarmic::HaltReason::UserDefined4);
                }
                return;
            }

            // Constructor/main-thread compatibility path retained for phases
            // that do not yet participate in the deferred-worker scheduler.
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sched_get_priority_min" ||
            name == "sched_get_priority_max") {

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sem_init") {
            const std::uint32_t sem = regs[0];
            const std::uint32_t initial = regs[2];

            mem.Write32Guest(
                sem,
                initial);

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sem_destroy") {
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sem_getvalue") {
            if (regs[1]) {
                mem.Write32Guest(
                    regs[1],
                    mem.Read32Guest(regs[0]));
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sem_post") {
            const std::uint32_t sem = regs[0];
            const std::uint32_t before =
                mem.Read32Guest(sem);

            mem.Write32Guest(
                sem,
                before + 1u);

            std::uint32_t woke = 0u;
            if (V66Enabled()) {
                woke =
                    V66NotifySemaphore(sem);
                ++v66_sem_posts;

                if (woke != 0u ||
                    v66_sem_posts <= 16u ||
                    (v66_sem_posts % 1024u) == 0u) {
                    Append(
                        "V66 SEM POST #" +
                        std::to_string(v66_sem_posts) +
                        " sem=" +
                        V46DescribeGuestAddress(sem) +
                        " woke=" +
                        std::to_string(woke) +
                        " count=" +
                        std::to_string(
                            mem.Read32Guest(sem)));
                }
            }

            if (V107Enabled() &&
                (regs[14] & ~1u) ==
                    kGuestBase +
                    0x00bc1554u) {
                ++v107_bank_wake_posts;
                AppendDiagnostic(
                    "V107 BANK WAKE POST #" +
                    std::to_string(
                        v107_bank_wake_posts) +
                    " caller=" +
                    V46DescribeGuestAddress(
                        regs[14]) +
                    " sem=" +
                    V46DescribeGuestAddress(
                        sem) +
                    " expectedSem=" +
                    V46DescribeGuestAddress(
                        V106BankWakeSemaphoreAddress()) +
                    " count=" +
                    std::to_string(before) +
                    "->" +
                    std::to_string(
                        mem.Read32Guest(sem)) +
                    " notifyResult=" +
                    std::to_string(woke) +
                    " " +
                    V107BankWorkerWaitSummary());
            }

            if (V108Enabled() && sem == v108_audio_event_sem) {
                ++v108_audio_event_posts;
                if (v108_active_kill_slot != 0u || v108_audio_event_posts <= 16u ||
                    (v108_audio_event_posts & (v108_audio_event_posts - 1u)) == 0u) {
                    AppendDiagnostic("V108 AUDIO EVENT POST #" + std::to_string(v108_audio_event_posts) +
                                     " caller=" + V46DescribeGuestAddress(regs[14]) +
                                     " count=" + std::to_string(before) + "->" +
                                     std::to_string(mem.Read32Guest(sem)) +
                                     " woke=" + std::to_string(woke) + " " + V108BankCompletionSummary());
                }
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "sem_wait" ||
            name == "sem_trywait" ||
            name == "sem_timedwait") {

            const std::uint32_t sem = regs[0];
            const std::uint32_t count =
                mem.Read32Guest(sem);

            const bool v107_bank_wake_wait =
                V107Enabled() &&
                name == "sem_wait" &&
                current_probe_thread_id ==
                    v106_bank_worker_tid &&
                (regs[14] & ~1u) ==
                    kGuestBase +
                    0x00bc7bb8u;

            if (v107_bank_wake_wait) {
                ++v107_bank_wake_waits;
                AppendDiagnostic(
                    "V107 BANK WAKE WAIT #" +
                    std::to_string(
                        v107_bank_wake_waits) +
                    " caller=" +
                    V46DescribeGuestAddress(
                        regs[14]) +
                    " sem=" +
                    V46DescribeGuestAddress(
                        sem) +
                    " expectedSem=" +
                    V46DescribeGuestAddress(
                        V106BankWakeSemaphoreAddress()) +
                    " count=" +
                    std::to_string(count) +
                    " " +
                    V107BankWorkerWaitSummary());
            }

            if (V108Enabled() && name == "sem_wait" &&
                current_probe_thread_id == v104_audio_worker_tid && sem == v108_audio_event_sem) {
                ++v108_audio_event_waits;
                if (v108_active_kill_slot != 0u &&
                    (v108_audio_event_waits <= 32u ||
                     (v108_audio_event_waits & (v108_audio_event_waits - 1u)) == 0u)) {
                    AppendDiagnostic("V108 AUDIO EVENT WAIT #" + std::to_string(v108_audio_event_waits) +
                                     " count=" + std::to_string(count) + " " + V108BankCompletionSummary());
                }
            }

            if (count > 0u) {
                mem.Write32Guest(
                    sem,
                    count - 1u);
                regs[0] = 0u;
                ++supported_calls;
                return;
            }

            if (name == "sem_trywait") {
                if (guest_errno_address == 0u) {
                    guest_errno_address =
                        mem.AllocateObject(4u, 4u);
                }
                if (guest_errno_address != 0u) {
                    mem.Write32Guest(
                        guest_errno_address,
                        11u); // EAGAIN
                }
                regs[0] = 0xffffffffu;
                ++supported_calls;
                return;
            }

            if (V66Enabled() &&
                (current_probe_thread_id != 0u ||
                 V96MainBlockingAllowed())) {

                const bool timed =
                    name == "sem_timedwait";
                const std::uint32_t abstime =
                    timed ? regs[1] : 0u;

                if (V66BeginSemaphoreWait(
                        sem,
                        timed,
                        abstime)) {

                    regs[0] = 0u;
                    ++supported_calls;

                    if (jit) {
                        jit->HaltExecution(
                            Dynarmic::HaltReason::UserDefined4);
                    }
                    return;
                }
            }

            // Constructor/main-thread compatibility: there is no scheduler
            // context that could wake this call yet.
            regs[0] =
                name == "sem_wait"
                    ? 0u
                    : 0xffffffffu;
            ++supported_calls;
            return;
        }

        if (name == "__aeabi_memset" ||
            name == "memset") {

            const std::uint32_t destination = regs[0];

            const std::uint32_t size =
                name == "__aeabi_memset"
                    ? regs[1]
                    : regs[2];

            const std::uint8_t value =
                static_cast<std::uint8_t>(
                    name == "__aeabi_memset"
                        ? regs[2]
                        : regs[1]);

            if (auto* p =
                    mem.Ptr(destination, size)) {

                if (!V91AllowRelroWrite(
                        destination,
                        size,
                        name.c_str(),
                        value,
                        true)) {
                    regs[0] = destination;
                    ++supported_calls;
                    return;
                }

                std::memset(p, value, size);
                regs[0] = destination;
                ++supported_calls;

                ++memset_calls;

                if (memset_calls <= 4u ||
                    (memset_calls % 4096u) == 0u) {
                    Append(
                        "V27 MEMSET #" +
                        std::to_string(
                            memset_calls) +
                        " " +
                        name +
                        "(dest=0x" +
                        JniProbeHex(destination) +
                        ", size=" +
                        std::to_string(size) +
                        ", value=" +
                        std::to_string(value) +
                        ")");
                }
                return;
            }

            if (V86Enabled()) {
                Append(
                    "V86 PERF MEMSET OOB name=" +
                    name +
                    " dest=0x" +
                    JniProbeHex(destination) +
                    " size=" +
                    std::to_string(size) +
                    " value=" +
                    std::to_string(value) +
                    " PC=0x" +
                    JniProbeHex(jit ? jit->Regs()[15] : 0u) +
                    " LR=0x" +
                    JniProbeHex(jit ? jit->Regs()[14] : 0u) +
                    " heap{capacity=" +
                    std::to_string(mem.HeapCapacity()) +
                    ",highWater=" +
                    std::to_string(mem.HeapHighWater()) +
                    ",live=" +
                    std::to_string(mem.HeapLiveBytes()) +
                    ",allocs=" +
                    std::to_string(mem.HeapLiveAllocations()) +
                    "}");
            }

            result.message =
                name +
                " attempted to write outside guest memory.";

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined2);
            return;
        }

        if (name == "__android_log_print" ||
            name == "__android_log_write") {

            const std::string tag =
                mem.ReadCStringGuest(
                    regs[1],
                    128);

            const std::string text =
                name == "__android_log_print"
                    ? format_direct(
                          mem.ReadCStringGuest(
                              regs[2],
                              4096),
                          3u)
                    : mem.ReadCStringGuest(
                          regs[2],
                          4096);

            regs[0] = 0;
            ++supported_calls;
            last_android_log = text;

            Append(
                "import " +
                name +
                " tag=\"" +
                tag +
                "\" text=\"" +
                text +
                "\"");

            const std::size_t missing_resource =
                text.find(
                    "resource not found:");

            if (missing_resource !=
                std::string::npos) {

                RecordSweepIssue(
                    "missing-resource",
                    text,
                    text);

                if (missing_resource_diagnostics < 12u) {
                    ++missing_resource_diagnostics;

                    auto readable_candidate =
                        [&](std::uint32_t address) {
                            if (address == 0u ||
                                mem.Ptr(
                                    address,
                                    1u) == nullptr) {
                                return std::string{};
                            }

                            std::string value =
                                mem.ReadCStringGuest(
                                    address,
                                    192u);

                            if (value.size() < 2u ||
                                value == tag ||
                                value == text) {
                                return std::string{};
                            }

                            std::size_t printable = 0u;
                            for (const unsigned char ch :
                                 value) {
                                if (ch >= 0x20u &&
                                    ch <= 0x7eu) {
                                    ++printable;
                                }
                            }

                            if (printable * 10u <
                                value.size() * 9u) {
                                return std::string{};
                            }

                            return value;
                        };

                    const std::uint32_t
                        wrapper_caller_lr =
                            regs[14] ==
                                    kGuestBase +
                                    0x007aa73cu &&
                                mem.Ptr(
                                    regs[13] + 28u,
                                    4u) != nullptr
                                ? mem.Read32Guest(
                                      regs[13] + 28u)
                                : 0u;

                    std::string
                        recovered_resource_id;

                    std::ostringstream diagnostic;
                    diagnostic
                        << "V33 MISSING RESOURCE CONTEXT #"
                        << missing_resource_diagnostics
                        << " wrapperLR=0x"
                        << JniProbeHex(regs[14])
                        << " callerLR=0x"
                        << JniProbeHex(
                               wrapper_caller_lr)
                        << " SP=0x"
                        << JniProbeHex(regs[13]);

                    auto append_candidate =
                        [&](const std::string& label,
                            std::uint32_t word) {

                            const std::string direct =
                                readable_candidate(
                                    word);

                            if (!direct.empty()) {
                                diagnostic
                                    << " "
                                    << label
                                    << "=\""
                                    << direct
                                    << "\"";

                                if (recovered_resource_id.empty() &&
                                    direct.rfind(
                                        "RESFILE_",
                                        0u) == 0u) {
                                    recovered_resource_id =
                                        direct;
                                }
                            }

                            if (word != 0u &&
                                mem.Ptr(
                                    word,
                                    4u) != nullptr) {

                                const std::uint32_t indirect =
                                    mem.Read32Guest(
                                        word);

                                const std::string nested =
                                    readable_candidate(
                                        indirect);

                                if (!nested.empty() &&
                                    nested != direct) {
                                    diagnostic
                                        << " *"
                                        << label
                                        << "=\""
                                        << nested
                                        << "\"";

                                    if (recovered_resource_id.empty() &&
                                        nested.rfind(
                                            "RESFILE_",
                                            0u) == 0u) {
                                        recovered_resource_id =
                                            nested;
                                    }
                                }
                            }
                        };

                    for (std::uint32_t reg = 3u;
                         reg <= 12u;
                         ++reg) {
                        append_candidate(
                            "r" +
                                std::to_string(reg),
                            regs[reg]);
                    }

                    for (std::uint32_t slot = 0u;
                         slot < 16u;
                         ++slot) {
                        const std::uint32_t word =
                            mem.Read32Guest(
                                regs[13] +
                                slot * 4u);

                        append_candidate(
                            "s" +
                                std::to_string(slot),
                            word);
                    }

                    constexpr char
                        kLevelPrefix[] =
                            "RESFILE_PACKAGES_LEVELS_";

                    if (!recovered_resource_id.empty()) {
                        diagnostic
                            << " recoveredID=\""
                            << recovered_resource_id
                            << "\"";

                        if (recovered_resource_id.rfind(
                                kLevelPrefix,
                                0u) == 0u) {

                            const std::string level_name =
                                recovered_resource_id.substr(
                                    sizeof(kLevelPrefix) - 1u);

                            const std::string physical =
                                "PACKAGES/LEVELS/" +
                                level_name +
                                ".RTON";

                            const auto group =
                                FindOuterRsbGroup(
                                    physical);

                            diagnostic
                                << " physical=\""
                                << physical
                                << "\" outerGroup=";

                            if (group.has_value()) {
                                diagnostic
                                    << *group;
                            } else {
                                diagnostic
                                    << "NOT_FOUND";
                            }

                            if (recovered_missing_resource_ids
                                    .insert(
                                        recovered_resource_id)
                                    .second) {

                                RecordSweepIssue(
                                    "missing-resource-id",
                                    recovered_resource_id,
                                    recovered_resource_id +
                                        (group.has_value()
                                            ? " (physical RSB member exists; registry lookup missing)"
                                            : " (no matching outer RSB member found)"));
                            }
                        }
                    }

                    Append(
                        diagnostic.str());
                }
            }

            return;
        }

        if (name == "__stack_chk_fail") {
            result.first_unsupported_import = name;
            result.message =
                "PvZ2 triggered __stack_chk_fail.";

            RecordSweepIssue(
                "hard-fault",
                "__stack_chk_fail",
                result.message);

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined2);
            return;
        }

        // v13 complete-import baseline: every symbol in the verified 328-name
        // import inventory gets a deterministic category fallback. These are
        // deliberately probe semantics, not the final gameplay backends.
        // They let GameAppInitialize reveal semantic/runtime requirements
        // without forcing one IPA release per newly reached import.
        auto log_fallback_once =
            [&](const std::string& category) {
                if (fallback_logged.insert(name).second) {
                    Append(
                        "COMPAT FALLBACK [" +
                        category +
                        "]: " +
                        name);
                }
            };

        auto set_guest_errno =
            [&](std::uint32_t value) {
                if (guest_errno_address == 0) {
                    guest_errno_address =
                        mem.AllocateObject(4, 4);
                }

                if (guest_errno_address) {
                    mem.Write32Guest(
                        guest_errno_address,
                        value);
                }
            };

        auto normalize_guest_path =
            [&](std::string path) {
                constexpr char kAssetPrefix[] =
                    "ASSET:";

                if (path.rfind(kAssetPrefix, 0) == 0) {
                    path.erase(
                        0,
                        sizeof(kAssetPrefix) - 1);
                }

                for (char& ch : path) {
                    if (ch == '\\') {
                        ch = '/';
                    }
                }

                return path;
            };

        auto normalize_v51_user_path =
            [&](std::string path) {
                path =
                    normalize_guest_path(
                        std::move(path));

                while (path.size() > 1u &&
                       path.back() == '/') {
                    path.pop_back();
                }

                return path;
            };

        auto v51_is_user_data_path =
            [&](const std::string& raw) {
                const std::string path =
                    normalize_v51_user_path(raw);

                static constexpr char kFiles[] =
                    "/data/data/com.ea.game.pvz2_row/files";
                static constexpr char kCache[] =
                    "/data/data/com.ea.game.pvz2_row/cache";

                const auto under =
                    [&](const char* root) {
                        const std::string prefix{root};
                        return
                            path == prefix ||
                            (path.size() > prefix.size() &&
                             path.compare(
                                 0u,
                                 prefix.size(),
                                 prefix) == 0 &&
                             path[prefix.size()] == '/');
                    };

                return
                    under(kFiles) ||
                    under(kCache);
            };

        auto v128_host_path_for_guest =
            [&](const std::string& raw)
                -> std::string {
                if (!V128Enabled()) {
                    return {};
                }

                const char* home_env = std::getenv("HOME");
                if (home_env == nullptr || *home_env == '\0') {
                    return {};
                }

                const std::string path =
                    normalize_v51_user_path(raw);
                static const std::string kFiles =
                    "/data/data/com.ea.game.pvz2_row/files";
                static const std::string kCache =
                    "/data/data/com.ea.game.pvz2_row/cache";

                const auto suffix_for =
                    [&](const std::string& root)
                        -> std::optional<std::string> {
                        if (path == root) return std::string{};
                        if (path.size() <= root.size() ||
                            path.compare(0u, root.size(), root) != 0 ||
                            path[root.size()] != '/') {
                            return std::nullopt;
                        }
                        const std::string suffix = path.substr(root.size());
                        if (suffix.find("/../") != std::string::npos ||
                            (suffix.size() >= 3u &&
                             suffix.compare(suffix.size() - 3u, 3u, "/..") == 0)) {
                            return std::nullopt;
                        }
                        return suffix;
                    };

                if (const auto suffix = suffix_for(kFiles); suffix.has_value()) {
                    return std::string{home_env} +
                        "/Library/Application Support/PvZ2forIOS/UserData" +
                        *suffix;
                }
                if (const auto suffix = suffix_for(kCache); suffix.has_value()) {
                    return std::string{home_env} +
                        "/Library/Caches/PvZ2forIOS" + *suffix;
                }
                return {};
            };

        auto v128_mkdirs_for_file =
            [&](const std::string& full_path)
                -> bool {
                const std::size_t last = full_path.find_last_of('/');
                const std::string directory =
                    last == std::string::npos
                        ? std::string{}
                        : full_path.substr(0u, last);
                if (directory.empty()) return true;

                std::size_t pos = 1u;
                while (true) {
                    pos = directory.find('/', pos);
                    const std::string prefix =
                        pos == std::string::npos
                            ? directory
                            : directory.substr(0u, pos);
                    if (!prefix.empty() &&
                        ::mkdir(prefix.c_str(), 0755) != 0 &&
                        errno != EEXIST) {
                        ++v128_userfs_disk_failures;
                        return false;
                    }
                    if (pos == std::string::npos) break;
                    ++pos;
                }
                return true;
            };

        auto v128_load_file =
            [&](const std::string& guest_raw)
                -> bool {
                if (!V128Enabled()) return false;
                const std::string guest =
                    normalize_v51_user_path(guest_raw);
                if (v51_writable_files.find(guest) !=
                    v51_writable_files.end()) {
                    return true;
                }

                const std::string host =
                    v128_host_path_for_guest(guest);
                if (host.empty()) return false;

                struct stat st {};
                if (::stat(host.c_str(), &st) != 0 ||
                    !S_ISREG(st.st_mode) || st.st_size < 0) {
                    return false;
                }

                std::FILE* file = std::fopen(host.c_str(), "rb");
                if (file == nullptr) {
                    ++v128_userfs_disk_failures;
                    return false;
                }

                auto bytes = std::make_shared<std::vector<std::uint8_t>>();
                bytes->resize(static_cast<std::size_t>(st.st_size));
                const std::size_t got =
                    bytes->empty()
                        ? 0u
                        : std::fread(bytes->data(), 1u, bytes->size(), file);
                const bool ok = bytes->empty() || got == bytes->size();
                std::fclose(file);
                if (!ok) {
                    ++v128_userfs_disk_failures;
                    return false;
                }

                v51_writable_files[guest] = std::move(bytes);
                ++v128_userfs_disk_loads;
                v128_userfs_disk_load_bytes +=
                    static_cast<std::uint64_t>(st.st_size);
                AppendDiagnostic(
                    "V128 USERFS LOAD guest=\"" + guest +
                    "\" host=\"" + host +
                    "\" bytes=" + std::to_string(st.st_size));
                return true;
            };

        auto v128_flush_file =
            [&](const std::string& guest_raw)
                -> bool {
                if (!V128Enabled()) return true;
                const std::string guest =
                    normalize_v51_user_path(guest_raw);
                const auto found = v51_writable_files.find(guest);
                if (found == v51_writable_files.end() || !found->second) {
                    return false;
                }

                const std::string host =
                    v128_host_path_for_guest(guest);
                if (host.empty() || !v128_mkdirs_for_file(host)) {
                    ++v128_userfs_disk_failures;
                    return false;
                }

                const std::string temp = host + ".tmp";
                std::FILE* file = std::fopen(temp.c_str(), "wb");
                if (file == nullptr) {
                    ++v128_userfs_disk_failures;
                    return false;
                }

                const auto& bytes = *found->second;
                const std::size_t wrote =
                    bytes.empty()
                        ? 0u
                        : std::fwrite(bytes.data(), 1u, bytes.size(), file);
                bool ok = bytes.empty() || wrote == bytes.size();
                if (ok && std::fflush(file) != 0) ok = false;
                if (ok && ::fsync(::fileno(file)) != 0) ok = false;
                if (std::fclose(file) != 0) ok = false;
                if (ok && ::rename(temp.c_str(), host.c_str()) != 0) ok = false;

                if (!ok) {
                    ::unlink(temp.c_str());
                    ++v128_userfs_disk_failures;
                    AppendDiagnostic(
                        "V128 USERFS FLUSH FAILED guest=\"" + guest +
                        "\" host=\"" + host + "\"");
                    return false;
                }

                v128_userfs_dirty_paths.erase(guest);
                ++v128_userfs_disk_flushes;
                v128_userfs_disk_flush_bytes +=
                    static_cast<std::uint64_t>(bytes.size());
                AppendDiagnostic(
                    "V128 USERFS FLUSH guest=\"" + guest +
                    "\" host=\"" + host +
                    "\" bytes=" + std::to_string(bytes.size()));
                return true;
            };

        auto v51_open_memory_file =
            [&](const std::string& raw,
                bool create,
                bool truncate,
                bool append,
                bool writable)
                -> std::optional<ProbeObbHandle> {

                const std::string path =
                    normalize_v51_user_path(raw);

                if (path == "/dev/null") {
                    ProbeObbHandle handle;
                    handle.owned =
                        std::make_shared<
                            std::vector<std::uint8_t>>();
                    handle.writable = true;
                    handle.dev_null = true;
                    handle.virtual_path = path;
                    handle.label = "v51-dev-null";
                    return handle;
                }

                if (!v51_is_user_data_path(path)) {
                    return std::nullopt;
                }

                auto it =
                    v51_writable_files.find(path);

                if (it == v51_writable_files.end() && V128Enabled()) {
                    v128_load_file(path);
                    it = v51_writable_files.find(path);
                }

                if (it == v51_writable_files.end()) {
                    if (!create) {
                        return std::nullopt;
                    }

                    auto bytes =
                        std::make_shared<
                            std::vector<std::uint8_t>>();
                    it =
                        v51_writable_files
                            .emplace(
                                path,
                                std::move(bytes))
                            .first;
                }

                if (truncate) {
                    it->second->clear();
                    if (V128Enabled()) {
                        v128_userfs_dirty_paths.insert(path);
                    }
                }

                ProbeObbHandle handle;
                handle.base = 0u;
                handle.length =
                    static_cast<std::uint64_t>(
                        it->second->size());
                handle.offset =
                    append
                        ? handle.length
                        : 0u;
                handle.eof = false;
                handle.writable = writable;
                handle.dev_null = false;
                handle.virtual_path = path;
                handle.label =
                    "v51-userfs:" + path;
                handle.owned = it->second;
                return handle;
            };

        auto v51_path_exists =
            [&](const std::string& raw,
                std::uint64_t* size_out,
                bool* directory_out) {
                const std::string path =
                    normalize_v51_user_path(raw);

                if (path == "/dev/null") {
                    if (size_out) {
                        *size_out = 0u;
                    }
                    if (directory_out) {
                        *directory_out = false;
                    }
                    return true;
                }

                const auto file =
                    v51_writable_files.find(path);
                if (file !=
                    v51_writable_files.end()) {
                    if (size_out) {
                        *size_out =
                            static_cast<std::uint64_t>(
                                file->second->size());
                    }
                    if (directory_out) {
                        *directory_out = false;
                    }
                    return true;
                }

                if (V128Enabled()) {
                    const std::string host =
                        v128_host_path_for_guest(path);
                    if (!host.empty()) {
                        struct stat host_stat {};
                        if (::stat(host.c_str(), &host_stat) == 0) {
                            if (size_out) {
                                *size_out = S_ISREG(host_stat.st_mode)
                                    ? static_cast<std::uint64_t>(host_stat.st_size)
                                    : 0u;
                            }
                            if (directory_out) {
                                *directory_out = S_ISDIR(host_stat.st_mode);
                            }
                            return true;
                        }
                    }
                }

                const bool known_root =
                    path ==
                        "/data/data/com.ea.game.pvz2_row/files" ||
                    path ==
                        "/data/data/com.ea.game.pvz2_row/cache";
                const bool known_directory =
                    known_root ||
                    v51_writable_directories.count(path) !=
                        0u;

                if (known_directory) {
                    if (size_out) {
                        *size_out = 0u;
                    }
                    if (directory_out) {
                        *directory_out = true;
                    }
                    return true;
                }

                return false;
            };

        auto is_expansion_path =
            [&](const std::string& raw) {
                std::string path =
                    normalize_guest_path(raw);

                const std::size_t slash =
                    path.find_last_of('/');

                std::string base =
                    slash == std::string::npos
                        ? path
                        : path.substr(slash + 1);

                std::transform(
                    base.begin(),
                    base.end(),
                    base.begin(),
                    [](unsigned char ch) {
                        return
                            static_cast<char>(
                                std::tolower(ch));
                    });

                if (base == "main.rsb" ||
                    base == "main.pak" ||
                    base == "main.7.com.ea.game.pvz2_row.obb") {
                    return true;
                }

                return
                    base.size() >= 4u &&
                    base.compare(
                        base.size() - 4u,
                        4u,
                        ".obb") == 0;
            };

        auto resolve_obb_virtual_file =
            [&](const std::string& raw)
                -> std::optional<ProbeObbHandle> {

                V50ObservePath(
                    raw,
                    "VFS");

                if (obb_data == nullptr ||
                    obb_size < 0x70u) {
                    return std::nullopt;
                }

                if (const SyntheticAsset* synthetic =
                        GetOrBuildSyntheticTga(
                            raw);
                    synthetic != nullptr &&
                    synthetic->bytes != nullptr) {

                    ProbeObbHandle handle;
                    handle.base = 0u;
                    handle.length =
                        synthetic->bytes->size();
                    handle.offset = 0u;
                    handle.eof = false;
                    handle.label =
                        "virtual-tga:" +
                        NormalizeVirtualAssetKey(
                            raw);
                    handle.owned =
                        synthetic->bytes;

                    return handle;
                }

                if (is_expansion_path(raw)) {
                    ProbeObbHandle handle;
                    handle.base = 0u;
                    handle.length =
                        static_cast<std::uint64_t>(
                            obb_size);
                    handle.offset = 0u;
                    handle.eof = false;
                    handle.label = "expansion";
                    return handle;
                }

                auto normalized =
                    normalize_guest_path(raw);

                while (normalized.rfind("./", 0) == 0) {
                    normalized.erase(0, 2);
                }

                while (!normalized.empty() &&
                       normalized.front() == '/') {
                    normalized.erase(
                        normalized.begin());
                }

                std::transform(
                    normalized.begin(),
                    normalized.end(),
                    normalized.begin(),
                    [](unsigned char ch) {
                        return
                            static_cast<char>(
                                std::toupper(ch));
                    });

                auto read_u24 =
                    [&](std::uint64_t offset,
                        std::uint32_t& value) {
                        if (offset + 3u >
                            obb_size) {
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
                    };

                auto read_u32 =
                    [&](std::uint64_t offset,
                        std::uint32_t& value) {
                        if (offset + 4u >
                            obb_size) {
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
                    };

                struct PrefixDefault {
                    std::string name;
                    std::uint32_t end_words =
                        0xffffffffu;
                };

                auto find_outer_group =
                    [&](const std::string& target)
                        -> std::optional<std::uint32_t> {

                        std::uint32_t list_length = 0;
                        std::uint32_t list_begin = 0;

                        if (!read_u32(
                                0x10u,
                                list_length) ||
                            !read_u32(
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

                        std::vector<PrefixDefault>
                            defaults;
                        defaults.push_back(
                            PrefixDefault{});

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
                                if (!read_u24(
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
                            if (!read_u32(
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
                    };

                const auto group_index =
                    find_outer_group(
                        normalized);

                if (!group_index.has_value()) {
                    return std::nullopt;
                }

                std::uint32_t group_count = 0;
                std::uint32_t group_info_begin = 0;
                std::uint32_t group_info_each = 0;

                if (!read_u32(
                        0x28u,
                        group_count) ||
                    !read_u32(
                        0x2cu,
                        group_info_begin) ||
                    !read_u32(
                        0x30u,
                        group_info_each) ||
                    group_info_each < 0xa4u ||
                    *group_index >= group_count) {

                    return std::nullopt;
                }

                const std::uint64_t info =
                    static_cast<std::uint64_t>(
                        group_info_begin) +
                    static_cast<std::uint64_t>(
                        *group_index) *
                        group_info_each;

                std::uint32_t group_offset = 0;
                std::uint32_t group_size = 0;
                std::uint32_t part0_offset = 0;
                std::uint32_t part0_zsize = 0;
                std::uint32_t part0_size = 0;

                if (!read_u32(
                        info + 0x80u,
                        group_offset) ||
                    !read_u32(
                        info + 0x84u,
                        group_size) ||
                    !read_u32(
                        info + 0x94u,
                        part0_offset) ||
                    !read_u32(
                        info + 0x98u,
                        part0_zsize) ||
                    !read_u32(
                        info + 0x9cu,
                        part0_size) ||
                    static_cast<std::uint64_t>(
                        group_offset) +
                            group_size >
                        obb_size) {

                    return std::nullopt;
                }

                // The supported 1.5.252752 manifest and package groups store
                // their part-0 files uncompressed. Compressed RSGP members can
                // be added later when a real runtime path reaches one.
                if (part0_zsize != part0_size) {
                    Append(
                        "V26 RSB VFS: internal file " +
                        normalized +
                        " belongs to compressed part0; deferred.");
                    return std::nullopt;
                }

                std::uint32_t rsgp_magic = 0;
                std::uint32_t file_list_length = 0;
                std::uint32_t file_list_begin = 0;

                if (!read_u32(
                        group_offset,
                        rsgp_magic) ||
                    rsgp_magic != 0x72736770u ||
                    !read_u32(
                        static_cast<std::uint64_t>(
                            group_offset) +
                            0x48u,
                        file_list_length) ||
                    !read_u32(
                        static_cast<std::uint64_t>(
                            group_offset) +
                            0x4cu,
                        file_list_begin)) {

                    return std::nullopt;
                }

                const std::uint64_t list_begin =
                    static_cast<std::uint64_t>(
                        group_offset) +
                    file_list_begin;
                const std::uint64_t list_end =
                    list_begin +
                    file_list_length;

                if (list_end > obb_size) {
                    return std::nullopt;
                }

                std::vector<PrefixDefault>
                    defaults;
                defaults.push_back(
                    PrefixDefault{});

                std::uint64_t pos =
                    list_begin;

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

                    while (pos + 4u <=
                           list_end) {
                        const std::uint8_t ch =
                            obb_data[pos];

                        std::uint32_t cover = 0;
                        if (!read_u24(
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
                        pos + 12u >
                            list_end) {
                        return std::nullopt;
                    }

                    std::uint32_t type = 0;
                    std::uint32_t file_offset = 0;
                    std::uint32_t file_size = 0;

                    if (!read_u32(
                            pos,
                            type) ||
                        !read_u32(
                            pos + 4u,
                            file_offset) ||
                        !read_u32(
                            pos + 8u,
                            file_size)) {

                        return std::nullopt;
                    }

                    pos +=
                        type == 0u
                            ? 12u
                            : 32u;

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

                    if (full != normalized) {
                        continue;
                    }

                    if (type != 0u) {
                        Append(
                            "V26 RSB VFS: " +
                            normalized +
                            " is a texture/part1 member; not exposed as a flat file.");
                        return std::nullopt;
                    }

                    const std::uint64_t base =
                        static_cast<std::uint64_t>(
                            group_offset) +
                        part0_offset +
                        file_offset;

                    if (base + file_size >
                        obb_size) {
                        return std::nullopt;
                    }

                    ProbeObbHandle handle;
                    handle.base = base;
                    handle.length = file_size;
                    handle.offset = 0u;
                    handle.eof = false;
                    handle.label =
                        "rsb:" + normalized;

                    if (fallback_logged.insert(
                            "v26-rsb-index:" +
                            normalized).second) {

                        ++rsb_resolved_files;
                        result.rsb_resolved_files =
                            rsb_resolved_files;

                        if (normalized ==
                            "PROPERTIES/RESOURCES.RTON") {
                            result.rsb_manifest_resolved =
                                true;
                        }

                        Append(
                            "V27 RSB VFS resolved \"" +
                            raw +
                            "\" -> group=" +
                            std::to_string(
                                *group_index) +
                            " base=0x" +
                            JniProbeHex(
                                static_cast<std::uint32_t>(
                                    base)) +
                            " size=" +
                            std::to_string(
                                file_size));
                    }

                    return handle;
                }

                return std::nullopt;
            };

        auto write_armeabi_stat =
            [&](std::uint32_t address,
                std::uint64_t size) {
                constexpr std::uint32_t kStatSize =
                    104u;

                if (!mem.Ptr(address, kStatSize)) {
                    return false;
                }

                for (std::uint32_t i = 0;
                     i < kStatSize;
                     i += 4u) {
                    mem.Write32Guest(
                        address + i,
                        0);
                }

                // armeabi-v7a bionic struct stat fields used by PvZ2.
                mem.Write32Guest(
                    address + 0x10u,
                    0100644u);
                mem.Write32Guest(
                    address + 0x30u,
                    static_cast<std::uint32_t>(
                        size));
                mem.Write32Guest(
                    address + 0x34u,
                    static_cast<std::uint32_t>(
                        size >> 32));

                return true;
            };

        auto write_armeabi_dir_stat =
            [&](std::uint32_t address) {
                constexpr std::uint32_t kStatSize =
                    0x68u;

                if (address == 0u ||
                    mem.Ptr(
