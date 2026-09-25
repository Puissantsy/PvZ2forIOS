namespace {

std::uint64_t V85SteadyNowNs() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

constexpr const char* kPvZ2Path = "lib/armeabi-v7a/libPVZ2.so";

constexpr std::uint32_t kZipLocal = 0x04034b50u;
constexpr std::uint32_t kZipCentral = 0x02014b50u;
constexpr std::uint32_t kZipEocd = 0x06054b50u;

constexpr std::uint32_t kElfMagic = 0x464c457fu;
constexpr std::uint16_t kElfTypeDyn = 3;
constexpr std::uint16_t kElfMachineArm = 40;
constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kPtDynamic = 2;
constexpr std::uint32_t kPtGnuRelro = 0x6474e552u;
constexpr std::uint32_t kShtDynsym = 11;
constexpr std::uint32_t kShtArmExidx = 0x70000001u;
constexpr std::uint32_t kShtRel = 9;

constexpr std::int32_t kDtNull = 0;
constexpr std::int32_t kDtNeeded = 1;
constexpr std::int32_t kDtSoname = 14;
constexpr std::int32_t kDtInitArray = 25;
constexpr std::int32_t kDtInitArraySz = 27;

constexpr std::uint32_t kRArmGlobDat = 21;
constexpr std::uint32_t kRArmJumpSlot = 22;
constexpr std::uint32_t kRArmRelative = 23;

constexpr std::uint32_t kGuestBase = 0x10000000u;

#pragma pack(push, 1)
struct Elf32Ehdr {
    std::uint8_t ident[16];
    std::uint16_t type;
    std::uint16_t machine;
    std::uint32_t version;
    std::uint32_t entry;
    std::uint32_t phoff;
    std::uint32_t shoff;
    std::uint32_t flags;
    std::uint16_t ehsize;
    std::uint16_t phentsize;
    std::uint16_t phnum;
    std::uint16_t shentsize;
    std::uint16_t shnum;
    std::uint16_t shstrndx;
};

struct Elf32Phdr {
    std::uint32_t type;
    std::uint32_t offset;
    std::uint32_t vaddr;
    std::uint32_t paddr;
    std::uint32_t filesz;
    std::uint32_t memsz;
    std::uint32_t flags;
    std::uint32_t align;
};

struct Elf32Shdr {
    std::uint32_t name;
    std::uint32_t type;
    std::uint32_t flags;
    std::uint32_t addr;
    std::uint32_t offset;
    std::uint32_t size;
    std::uint32_t link;
    std::uint32_t info;
    std::uint32_t addralign;
    std::uint32_t entsize;
};

struct Elf32Sym {
    std::uint32_t name;
    std::uint32_t value;
    std::uint32_t size;
    std::uint8_t info;
    std::uint8_t other;
    std::uint16_t shndx;
};

struct Elf32Rel {
    std::uint32_t offset;
    std::uint32_t info;
};

struct Elf32Dyn {
    std::int32_t tag;
    std::uint32_t value;
};
#pragma pack(pop)

static_assert(sizeof(Elf32Ehdr) == 52);
static_assert(sizeof(Elf32Phdr) == 32);
static_assert(sizeof(Elf32Shdr) == 40);
static_assert(sizeof(Elf32Sym) == 16);
static_assert(sizeof(Elf32Rel) == 8);
static_assert(sizeof(Elf32Dyn) == 8);

bool RangeOk(std::size_t offset, std::size_t size, std::size_t total) {
    return offset <= total && size <= total - offset;
}

std::uint16_t Read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) |
           static_cast<std::uint16_t>(p[1]) << 8;
}

std::uint32_t Read32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           static_cast<std::uint32_t>(p[1]) << 8 |
           static_cast<std::uint32_t>(p[2]) << 16 |
           static_cast<std::uint32_t>(p[3]) << 24;
}

void Write32(std::uint8_t* p, std::uint32_t value) {
    p[0] = static_cast<std::uint8_t>(value);
    p[1] = static_cast<std::uint8_t>(value >> 8);
    p[2] = static_cast<std::uint8_t>(value >> 16);
    p[3] = static_cast<std::uint8_t>(value >> 24);
}

// Android PvZ2 1.5.252752 PTX format 0x93 stores the RGB plane as ETC1 and
// the alpha plane separately as 8-bit GL_ALPHA. Our host context is GLES2 on
// iOS, where GL_ETC1_RGB8_OES is not accepted. Decode only the ETC1 RGB plane
// here; the existing guest upload keeps the independent alpha plane unchanged.
constexpr GLenum kPvZ2Etc1Rgb8Oes = 0x8d64u;

constexpr std::int32_t kEtc1Modifiers[8][4] = {
    {  2,   8,   -2,   -8},
    {  5,  17,   -5,  -17},
    {  9,  29,   -9,  -29},
    { 13,  42,  -13,  -42},
    { 18,  60,  -18,  -60},
    { 24,  80,  -24,  -80},
    { 33, 106,  -33, -106},
    { 47, 183,  -47, -183},
};

std::uint32_t Read32BigEndian(
    const std::uint8_t* p) {

    return
        static_cast<std::uint32_t>(p[0]) << 24u |
        static_cast<std::uint32_t>(p[1]) << 16u |
        static_cast<std::uint32_t>(p[2]) << 8u |
        static_cast<std::uint32_t>(p[3]);
}

std::int32_t Etc1Signed3(
    std::uint32_t value) {

    value &= 7u;
    return
        (value & 4u) != 0u
            ? static_cast<std::int32_t>(value) - 8
            : static_cast<std::int32_t>(value);
}

std::uint8_t Etc1Expand4(
    std::uint32_t value) {

    value &= 0x0fu;
    return static_cast<std::uint8_t>(
        (value << 4u) | value);
}

std::uint8_t Etc1Expand5(
    std::int32_t value) {

    value =
        std::clamp<std::int32_t>(
            value,
            0,
            31);

    return static_cast<std::uint8_t>(
        (static_cast<std::uint32_t>(value) << 3u) |
        (static_cast<std::uint32_t>(value) >> 2u));
}

std::uint8_t Etc1Clamp8(
    std::int32_t value) {

    return static_cast<std::uint8_t>(
        std::clamp<std::int32_t>(
            value,
            0,
            255));
}

bool DecodeEtc1Rgb(
    const void* compressed_data,
    std::size_t compressed_size,
    GLsizei width,
    GLsizei height,
    std::vector<std::uint8_t>& rgb) {

    if (compressed_data == nullptr ||
        width <= 0 ||
        height <= 0) {
        return false;
    }

    const std::size_t blocks_x =
        (static_cast<std::size_t>(width) + 3u) / 4u;
    const std::size_t blocks_y =
        (static_cast<std::size_t>(height) + 3u) / 4u;

    if (blocks_x >
            std::numeric_limits<std::size_t>::max() /
                std::max<std::size_t>(blocks_y, 1u) ||
        blocks_x * blocks_y >
            std::numeric_limits<std::size_t>::max() / 8u) {
        return false;
    }

    const std::size_t expected =
        blocks_x * blocks_y * 8u;

    if (compressed_size < expected) {
        return false;
    }

    const std::size_t pixel_count =
        static_cast<std::size_t>(width) *
        static_cast<std::size_t>(height);

    if (pixel_count >
        std::numeric_limits<std::size_t>::max() / 3u) {
        return false;
    }

    rgb.assign(pixel_count * 3u, 0u);

    const auto* source =
        static_cast<const std::uint8_t*>(
            compressed_data);

    for (std::size_t by = 0u;
         by < blocks_y;
         ++by) {
        for (std::size_t bx = 0u;
             bx < blocks_x;
             ++bx) {

            const std::uint8_t* block =
                source +
                (by * blocks_x + bx) * 8u;

            const std::uint32_t high =
                Read32BigEndian(block);
            const std::uint32_t low =
                Read32BigEndian(block + 4u);

            const bool differential =
                (high & 0x2u) != 0u;
            const bool flip =
                (high & 0x1u) != 0u;

            const std::uint32_t table0 =
                (high >> 5u) & 7u;
            const std::uint32_t table1 =
                (high >> 2u) & 7u;

            std::array<std::uint8_t, 3> color0{};
            std::array<std::uint8_t, 3> color1{};

            if (differential) {
                const std::int32_t r0 =
                    static_cast<std::int32_t>(
                        (high >> 27u) & 31u);
                const std::int32_t g0 =
                    static_cast<std::int32_t>(
                        (high >> 19u) & 31u);
                const std::int32_t b0 =
                    static_cast<std::int32_t>(
                        (high >> 11u) & 31u);

                const std::int32_t r1 =
                    r0 + Etc1Signed3(
                        (high >> 24u) & 7u);
                const std::int32_t g1 =
                    g0 + Etc1Signed3(
                        (high >> 16u) & 7u);
                const std::int32_t b1 =
                    b0 + Etc1Signed3(
                        (high >> 8u) & 7u);

                color0 = {
                    Etc1Expand5(r0),
                    Etc1Expand5(g0),
                    Etc1Expand5(b0)};
                color1 = {
                    Etc1Expand5(r1),
                    Etc1Expand5(g1),
                    Etc1Expand5(b1)};
            } else {
                color0 = {
                    Etc1Expand4(
                        (high >> 28u) & 15u),
                    Etc1Expand4(
                        (high >> 20u) & 15u),
                    Etc1Expand4(
                        (high >> 12u) & 15u)};
                color1 = {
                    Etc1Expand4(
                        (high >> 24u) & 15u),
                    Etc1Expand4(
                        (high >> 16u) & 15u),
                    Etc1Expand4(
                        (high >> 8u) & 15u)};
            }

            for (std::size_t y = 0u;
                 y < 4u;
                 ++y) {
                for (std::size_t x = 0u;
                     x < 4u;
                     ++x) {

                    const std::size_t dst_x =
                        bx * 4u + x;
                    const std::size_t dst_y =
                        by * 4u + y;

                    if (dst_x >=
                            static_cast<std::size_t>(width) ||
                        dst_y >=
                            static_cast<std::size_t>(height)) {
                        continue;
                    }

                    // ETC1 selector bits are column-major within a 4x4 block:
                    // k = x*4+y, low plane first, high plane at k+16.
                    const std::uint32_t k =
                        static_cast<std::uint32_t>(
                            x * 4u + y);
                    const std::uint32_t selector =
                        ((low >> k) & 1u) |
                        (((low >> (k + 16u)) & 1u)
                         << 1u);

                    const bool first_partition =
                        flip
                            ? y < 2u
                            : x < 2u;

                    const auto& base =
                        first_partition
                            ? color0
                            : color1;
                    const std::uint32_t table =
                        first_partition
                            ? table0
                            : table1;

                    const std::int32_t modifier =
                        kEtc1Modifiers[
                            table][selector];

                    const std::size_t dst =
                        (dst_y *
                             static_cast<std::size_t>(
                                 width) +
                         dst_x) *
                        3u;

                    rgb[dst + 0u] =
                        Etc1Clamp8(
                            static_cast<std::int32_t>(
                                base[0]) +
                            modifier);
                    rgb[dst + 1u] =
                        Etc1Clamp8(
                            static_cast<std::int32_t>(
                                base[1]) +
                            modifier);
                    rgb[dst + 2u] =
                        Etc1Clamp8(
                            static_cast<std::int32_t>(
                                base[2]) +
                            modifier);
                }
            }
        }
    }

    return true;
}

std::string Join(const std::vector<std::string>& values) {
    std::ostringstream out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) {
            out << ", ";
        }
        out << values[i];
    }
    return out.str();
}

bool ReadCString(
    const std::uint8_t* base,
    std::size_t size,
    std::uint32_t offset,
    std::string& out) {

    if (offset >= size) {
        return false;
    }
    const char* s = reinterpret_cast<const char*>(base + offset);
    const void* terminator = std::memchr(s, '\0', size - offset);
    if (!terminator) {
        return false;
    }
    out.assign(s, static_cast<const char*>(terminator) - s);
    return true;
}

struct ZipEntry {
    std::uint16_t method = 0;
    std::uint16_t flags = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t compressed_size = 0;
    std::uint32_t uncompressed_size = 0;
    std::uint32_t local_offset = 0;
};

bool FindZipEntry(
    const std::uint8_t* data,
    std::size_t size,
    const std::string& wanted,
    ZipEntry& entry,
    std::string& error) {

    if (size < 22) {
        error = "APK is too small to contain a ZIP EOCD.";
        return false;
    }

    const std::size_t search_window = std::min<std::size_t>(size, 22 + 0xffff);
    const std::size_t search_start = size - search_window;

    std::size_t eocd = std::numeric_limits<std::size_t>::max();
    for (std::size_t pos = size - 22;; --pos) {
        if (Read32(data + pos) == kZipEocd) {
            eocd = pos;
            break;
        }
        if (pos == search_start) {
            break;
        }
    }

    if (eocd == std::numeric_limits<std::size_t>::max()) {
        error = "APK ZIP EOCD not found.";
        return false;
    }

    if (!RangeOk(eocd, 22, size)) {
        error = "APK ZIP EOCD is truncated.";
        return false;
    }

    const std::uint16_t disk = Read16(data + eocd + 4);
    const std::uint16_t central_disk = Read16(data + eocd + 6);
    const std::uint16_t entries = Read16(data + eocd + 10);
    const std::uint32_t central_size = Read32(data + eocd + 12);
    const std::uint32_t central_offset = Read32(data + eocd + 16);

    if (disk != 0 || central_disk != 0) {
        error = "Multi-disk APK ZIP files are not supported.";
        return false;
    }

    if (!RangeOk(central_offset, central_size, size)) {
        error = "APK central directory is outside the file.";
        return false;
    }

    std::size_t pos = central_offset;
    for (std::uint16_t i = 0; i < entries; ++i) {
        if (!RangeOk(pos, 46, size) || Read32(data + pos) != kZipCentral) {
            error = "APK central directory entry is invalid.";
            return false;
        }

        const std::uint16_t flags = Read16(data + pos + 8);
        const std::uint16_t method = Read16(data + pos + 10);
        const std::uint32_t crc = Read32(data + pos + 16);
        const std::uint32_t compressed = Read32(data + pos + 20);
        const std::uint32_t uncompressed = Read32(data + pos + 24);
        const std::uint16_t name_len = Read16(data + pos + 28);
        const std::uint16_t extra_len = Read16(data + pos + 30);
        const std::uint16_t comment_len = Read16(data + pos + 32);
        const std::uint32_t local_offset = Read32(data + pos + 42);

        const std::size_t total_entry =
            46u + static_cast<std::size_t>(name_len) + extra_len + comment_len;
        if (!RangeOk(pos, total_entry, size)) {
            error = "APK central directory filename is truncated.";
            return false;
        }

        const std::string name(
            reinterpret_cast<const char*>(data + pos + 46),
            name_len);

        if (name == wanted) {
            entry.method = method;
            entry.flags = flags;
            entry.crc32 = crc;
            entry.compressed_size = compressed;
            entry.uncompressed_size = uncompressed;
            entry.local_offset = local_offset;
            return true;
        }

        pos += total_entry;
    }

    error = "APK does not contain lib/armeabi-v7a/libPVZ2.so.";
    return false;
}

bool ExtractZipEntry(
    const std::uint8_t* data,
    std::size_t size,
    const ZipEntry& entry,
    std::vector<std::uint8_t>& output,
    std::string& error) {

    const std::size_t local = entry.local_offset;
    if (!RangeOk(local, 30, size) || Read32(data + local) != kZipLocal) {
        error = "libPVZ2.so local ZIP header is invalid.";
        return false;
    }

    if ((entry.flags & 0x1u) != 0) {
        error = "Encrypted APK entries are not supported.";
        return false;
    }

    const std::uint16_t name_len = Read16(data + local + 26);
    const std::uint16_t extra_len = Read16(data + local + 28);
    const std::size_t payload =
        local + 30u + static_cast<std::size_t>(name_len) + extra_len;

    if (!RangeOk(payload, entry.compressed_size, size)) {
        error = "libPVZ2.so compressed data is outside the APK.";
        return false;
    }

    output.assign(entry.uncompressed_size, 0);

    if (entry.method == 0) {
        if (entry.compressed_size != entry.uncompressed_size) {
            error = "Stored ZIP entry has inconsistent sizes.";
            return false;
        }
        std::memcpy(output.data(), data + payload, entry.uncompressed_size);
    } else if (entry.method == 8) {
        z_stream stream{};
        stream.next_in = const_cast<Bytef*>(
            reinterpret_cast<const Bytef*>(data + payload));
        stream.avail_in = entry.compressed_size;
        stream.next_out = reinterpret_cast<Bytef*>(output.data());
        stream.avail_out = entry.uncompressed_size;

        const int init = inflateInit2(&stream, -MAX_WBITS);
        if (init != Z_OK) {
            error = "zlib inflateInit2 failed.";
            return false;
        }

        const int status = inflate(&stream, Z_FINISH);
        inflateEnd(&stream);

        if (status != Z_STREAM_END || stream.total_out != entry.uncompressed_size) {
            error = "zlib could not inflate libPVZ2.so completely.";
            return false;
        }
    } else {
        error = "Unsupported APK compression method " + std::to_string(entry.method) + ".";
        return false;
    }

    const uLong crc = ::crc32(
        0,
        reinterpret_cast<const Bytef*>(output.data()),
        static_cast<uInt>(output.size()));

    if (static_cast<std::uint32_t>(crc) != entry.crc32) {
        error = "libPVZ2.so CRC32 check failed after extraction.";
        return false;
    }

    return true;
}

template <typename T>
const T* CheckedAt(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (!RangeOk(offset, sizeof(T), data.size())) {
        return nullptr;
    }
    return reinterpret_cast<const T*>(data.data() + offset);
}

struct ElfSections {
    const Elf32Shdr* dynsym = nullptr;
    const Elf32Shdr* dynstr = nullptr;
    const Elf32Shdr* arm_exidx = nullptr;
    std::vector<const Elf32Shdr*> rels;
    const Elf32Shdr* dynamic = nullptr;
};

bool ParseSections(
    const std::vector<std::uint8_t>& elf,
    const Elf32Ehdr& eh,
    ElfSections& sections,
    std::string& error) {

    if (eh.shentsize != sizeof(Elf32Shdr) ||
        !RangeOk(eh.shoff, static_cast<std::size_t>(eh.shnum) * eh.shentsize, elf.size())) {
        error = "ELF section table is invalid.";
        return false;
    }

    for (std::uint16_t i = 0; i < eh.shnum; ++i) {
        const auto* sh = CheckedAt<Elf32Shdr>(
            elf,
            eh.shoff + static_cast<std::size_t>(i) * eh.shentsize);
        if (!sh) {
            error = "ELF section header is truncated.";
            return false;
        }

        if (!RangeOk(sh->offset, sh->size, elf.size()) && sh->type != 8) {
            error = "ELF section payload is outside the file.";
            return false;
        }

        if (sh->type == kShtDynsym) {
            sections.dynsym = sh;
            if (sh->link >= eh.shnum) {
                error = "ELF .dynsym has an invalid string-table link.";
                return false;
            }
            sections.dynstr = CheckedAt<Elf32Shdr>(
                elf,
                eh.shoff + static_cast<std::size_t>(sh->link) * eh.shentsize);
        } else if (sh->type == kShtRel) {
            sections.rels.push_back(sh);
        } else if (sh->type == kShtArmExidx) {
            sections.arm_exidx = sh;
        } else if (sh->type == 6) {
            sections.dynamic = sh;
        }
    }

    if (!sections.dynsym || !sections.dynstr) {
        error = "ELF .dynsym/.dynstr sections were not found.";
        return false;
    }

    if (sections.dynsym->entsize != sizeof(Elf32Sym) ||
        sections.dynstr->type != 3 ||
        !RangeOk(sections.dynstr->offset, sections.dynstr->size, elf.size())) {
        error = "ELF dynamic symbol/string table is invalid.";
        return false;
    }

    return true;
}

bool InspectAndMapElf(
    const std::vector<std::uint8_t>& elf,
    PvZ2ApkProbeResult& result,
    std::string& error) {

    const auto* eh = CheckedAt<Elf32Ehdr>(elf, 0);
    if (!eh) {
        error = "libPVZ2.so is too small for an ELF32 header.";
        return false;
    }

    if (Read32(eh->ident) != kElfMagic ||
        eh->ident[4] != 1 ||
        eh->ident[5] != 1 ||
        eh->type != kElfTypeDyn ||
        eh->machine != kElfMachineArm) {
        error = "libPVZ2.so is not an ELF32 little-endian ARM shared object.";
        return false;
    }

    if (eh->phentsize != sizeof(Elf32Phdr) ||
        !RangeOk(eh->phoff, static_cast<std::size_t>(eh->phnum) * eh->phentsize, elf.size())) {
        error = "ELF program-header table is invalid.";
        return false;
    }

    std::uint64_t image_end = 0;
    std::vector<Elf32Phdr> loads;

    for (std::uint16_t i = 0; i < eh->phnum; ++i) {
        const auto* ph = CheckedAt<Elf32Phdr>(
            elf,
            eh->phoff + static_cast<std::size_t>(i) * eh->phentsize);
        if (!ph) {
            error = "ELF program header is truncated.";
            return false;
        }

        if (ph->type == kPtLoad) {
            if (ph->filesz > ph->memsz || !RangeOk(ph->offset, ph->filesz, elf.size())) {
                error = "ELF PT_LOAD segment is invalid.";
                return false;
            }
            image_end = std::max<std::uint64_t>(
                image_end,
                static_cast<std::uint64_t>(ph->vaddr) + ph->memsz);
            loads.push_back(*ph);
        }
    }

    if (loads.empty() || image_end == 0 || image_end > 0x20000000ull) {
        error = "ELF PT_LOAD image size is unreasonable.";
        return false;
    }

    result.load_segments = static_cast<std::uint32_t>(loads.size());
    result.image_size = static_cast<std::uint32_t>(image_end);
    result.guest_base = kGuestBase;

    std::vector<std::uint8_t> image(result.image_size, 0);
    for (const auto& ph : loads) {
        if (!RangeOk(ph.vaddr, ph.memsz, image.size())) {
            error = "ELF PT_LOAD virtual range exceeds mapped image.";
            return false;
        }
        std::memcpy(image.data() + ph.vaddr, elf.data() + ph.offset, ph.filesz);
    }

    ElfSections sections;
    if (!ParseSections(elf, *eh, sections, error)) {
        return false;
    }

    const auto* dynstr = elf.data() + sections.dynstr->offset;
    const std::size_t dynstr_size = sections.dynstr->size;

    result.dynsym_count =
        sections.dynsym->size / static_cast<std::uint32_t>(sizeof(Elf32Sym));

    for (std::uint32_t i = 0; i < result.dynsym_count; ++i) {
        const auto* sym = CheckedAt<Elf32Sym>(
            elf,
            sections.dynsym->offset + static_cast<std::size_t>(i) * sizeof(Elf32Sym));
        if (!sym) {
            error = "ELF dynamic symbol table is truncated.";
            return false;
        }

        std::string name;
        if (!ReadCString(dynstr, dynstr_size, sym->name, name)) {
            error = "ELF dynamic symbol name is invalid.";
            return false;
        }

        if (sym->shndx == 0 && !name.empty()) {
            ++result.undefined_symbol_count;
        }

        if (name == "JNI_OnLoad" && sym->shndx != 0) {
            result.jni_onload_value = sym->value;
            result.jni_onload_guest = kGuestBase + sym->value;
        }
    }

    std::vector<std::string> needed;
    if (sections.dynamic) {
        if (sections.dynamic->entsize != 0 &&
            sections.dynamic->entsize != sizeof(Elf32Dyn)) {
            error = "ELF dynamic section entry size is invalid.";
            return false;
        }

        const std::size_t count = sections.dynamic->size / sizeof(Elf32Dyn);
        for (std::size_t i = 0; i < count; ++i) {
            const auto* dyn = CheckedAt<Elf32Dyn>(
                elf,
                sections.dynamic->offset + i * sizeof(Elf32Dyn));
            if (!dyn) {
                error = "ELF dynamic section is truncated.";
                return false;
            }
            if (dyn->tag == kDtNull) {
                break;
            }

            if (dyn->tag == kDtNeeded || dyn->tag == kDtSoname) {
                std::string value;
                if (!ReadCString(dynstr, dynstr_size, dyn->value, value)) {
                    error = "ELF DT_NEEDED/DT_SONAME string is invalid.";
                    return false;
                }
                if (dyn->tag == kDtNeeded) {
                    needed.push_back(value);
                } else {
                    result.soname = value;
                }
            } else if (dyn->tag == kDtInitArraySz) {
                result.init_array_count = dyn->value / 4u;
            }
        }
    }

    result.needed_library_count = static_cast<std::uint32_t>(needed.size());
    result.needed_libraries = Join(needed);

    for (const Elf32Shdr* rel_section : sections.rels) {
        if (rel_section->entsize != 0 && rel_section->entsize != sizeof(Elf32Rel)) {
            error = "ELF relocation section entry size is invalid.";
            return false;
        }

        const std::size_t count = rel_section->size / sizeof(Elf32Rel);
        for (std::size_t i = 0; i < count; ++i) {
            const auto* rel = CheckedAt<Elf32Rel>(
                elf,
                rel_section->offset + i * sizeof(Elf32Rel));
            if (!rel) {
                error = "ELF relocation table is truncated.";
                return false;
            }

            const std::uint32_t type = rel->info & 0xffu;
            if (type == kRArmRelative) {
                ++result.relative_relocations;
                if (!RangeOk(rel->offset, 4, image.size())) {
                    error = "R_ARM_RELATIVE target is outside mapped image.";
                    return false;
                }
                const std::uint32_t addend = Read32(image.data() + rel->offset);
                Write32(image.data() + rel->offset, kGuestBase + addend);
                ++result.relative_applied;
            } else if (type == kRArmGlobDat) {
                ++result.glob_dat_relocations;
            } else if (type == kRArmJumpSlot) {
                ++result.jump_slot_relocations;
            } else {
                ++result.unsupported_relocations;
            }
        }
    }

    if (result.jni_onload_value == 0 ||
        !RangeOk(result.jni_onload_value, 4, image.size())) {
        error = "JNI_OnLoad was not found inside the mapped ELF image.";
        return false;
    }

    // Exact facts observed from the user's legally supplied PvZ2 1.5.252752 APK.
    result.exact_15252752_profile =
        result.elf_size == 13950396u &&
        result.image_size == 0x00df9700u &&
        result.load_segments == 2u &&
        result.jni_onload_value == 0x009ead80u &&
        result.relative_relocations == 48754u &&
        result.glob_dat_relocations == 13u &&
        result.jump_slot_relocations == 316u &&
        result.init_array_count == 619u &&
        result.soname == "libPVZ2.so";

    return true;
}

} // namespace

namespace {

constexpr std::uint64_t ProbeCap(PvZ2ProbeCapability capability) {
    return static_cast<std::uint64_t>(capability);
}

constexpr std::uint64_t kCapLive =
    ProbeCap(PvZ2ProbeCapability::LivePresentation);
constexpr std::uint64_t kCapCpuFrame =
    ProbeCap(PvZ2ProbeCapability::CpuLiveFrame);
constexpr std::uint64_t kCapTransform =
    ProbeCap(PvZ2ProbeCapability::TransformProbe);
constexpr std::uint64_t kCapHitTest =
    ProbeCap(PvZ2ProbeCapability::HitTestTrace);
constexpr std::uint64_t kCapLogicalTouch =
    ProbeCap(PvZ2ProbeCapability::LogicalTouch);
constexpr std::uint64_t kCapProfile =
    ProbeCap(PvZ2ProbeCapability::ProfileProbe);
constexpr std::uint64_t kCapPerf =
    ProbeCap(PvZ2ProbeCapability::PerformanceBaseline);
constexpr std::uint64_t kCapHeap128 =
    ProbeCap(PvZ2ProbeCapability::Heap128);
constexpr std::uint64_t kCapMutex =
    ProbeCap(PvZ2ProbeCapability::PreemptiveMutex);
constexpr std::uint64_t kCapAdaptive =
    ProbeCap(PvZ2ProbeCapability::AdaptiveMutex);
constexpr std::uint64_t kCapHeavyProfiler =
    ProbeCap(PvZ2ProbeCapability::HeavyPerformanceProfiler);
constexpr std::uint64_t kCapHostCost =
    ProbeCap(PvZ2ProbeCapability::HostCostProfiler);
constexpr std::uint64_t kCapDirect =
    ProbeCap(PvZ2ProbeCapability::DirectPresentation);
constexpr std::uint64_t kCapIndexedRelro =
    ProbeCap(PvZ2ProbeCapability::IndexedAllocatorRelro);
constexpr std::uint64_t kCapLongRun =
    ProbeCap(PvZ2ProbeCapability::LongRunInteractive);
constexpr std::uint64_t kCapReturnProvenance =
    ProbeCap(PvZ2ProbeCapability::ReturnProvenance);
constexpr std::uint64_t kCapCallerReturnWatch =
    ProbeCap(PvZ2ProbeCapability::CallerReturnWatch);
constexpr std::uint64_t kCapAllocatorProfiling =
    ProbeCap(PvZ2ProbeCapability::AllocatorProfiling);
constexpr std::uint64_t kCapPreciseCallerReturnWatch =
    ProbeCap(PvZ2ProbeCapability::PreciseCallerReturnWatch);
constexpr std::uint64_t kCapMainThreadBlocking =
    ProbeCap(PvZ2ProbeCapability::MainThreadBlocking);
constexpr std::uint64_t kCapGrantedMutexWaitGraph =
    ProbeCap(PvZ2ProbeCapability::GrantedMutexWaitGraph);
constexpr std::uint64_t kCapPresentationRgbFidelity =
    ProbeCap(PvZ2ProbeCapability::PresentationRgbFidelity);
constexpr std::uint64_t kCapAudioOpenSLBridge =
    ProbeCap(PvZ2ProbeCapability::AudioOpenSLBridge);
constexpr std::uint64_t kCapRawGuestCallbackABI =
    ProbeCap(PvZ2ProbeCapability::RawGuestCallbackABI);
constexpr std::uint64_t kCapAudioClockContract =
    ProbeCap(PvZ2ProbeCapability::AudioClockContract);
constexpr std::uint64_t kCapAudioRealtimePump =
    ProbeCap(PvZ2ProbeCapability::AudioRealtimePump);
constexpr std::uint64_t kCapAudioDrawFramePump =
    ProbeCap(PvZ2ProbeCapability::AudioDrawFramePump);
constexpr std::uint64_t kCapAudioWorkerHandshake =
    ProbeCap(PvZ2ProbeCapability::AudioWorkerHandshake);
constexpr std::uint64_t kCapWwiseResamplerProbe =
    ProbeCap(PvZ2ProbeCapability::WwiseResamplerProbe);
constexpr std::uint64_t kCapAudioRateBankWait =
    ProbeCap(PvZ2ProbeCapability::AudioRateBankWait);
constexpr std::uint64_t kCapSemaphoreWakeRepair =
    ProbeCap(PvZ2ProbeCapability::SemaphoreWakeRepair);
constexpr std::uint64_t kCapBankCompletionLiveness =
    ProbeCap(PvZ2ProbeCapability::BankCompletionLiveness);
constexpr std::uint64_t kCapLeanAudioPerformance =
    ProbeCap(PvZ2ProbeCapability::LeanAudioPerformance);

constexpr std::uint64_t kCapsTransformBase =
    kCapLive | kCapCpuFrame | kCapTransform |
    kCapHitTest | kCapProfile;
constexpr std::uint64_t kCapsPerfBase =
    kCapLive | kCapCpuFrame | kCapPerf;
constexpr std::uint64_t kCapsV86 =
    kCapsPerfBase | kCapHeap128;
constexpr std::uint64_t kCapsV87 =
    kCapsV86 | kCapMutex;
constexpr std::uint64_t kCapsV88 =
    kCapsV87 | kCapAdaptive;
constexpr std::uint64_t kCapsV89 =
    kCapsV88 | kCapHeavyProfiler | kCapHostCost;
constexpr std::uint64_t kCapsV90 =
    (kCapsV88 & ~kCapCpuFrame) | kCapHostCost | kCapDirect |
    kCapAllocatorProfiling;
constexpr std::uint64_t kCapsV91 =
    kCapsV90 | kCapIndexedRelro;
constexpr std::uint64_t kCapsV92 =
    kCapsV91 | kCapLongRun;
constexpr std::uint64_t kCapsV93 =
    kCapsV92 | kCapReturnProvenance;
constexpr std::uint64_t kCapsV94 =
    kCapsV93 | kCapCallerReturnWatch;
constexpr std::uint64_t kCapsV95 =
    kCapsV94 | kCapPreciseCallerReturnWatch;
constexpr std::uint64_t kCapsV96 =
    kCapsV95 | kCapMainThreadBlocking;
constexpr std::uint64_t kCapsV97 =
    kCapsV96 | kCapGrantedMutexWaitGraph;
constexpr std::uint64_t kCapsV98 =
    kCapsV97 | kCapPresentationRgbFidelity;
constexpr std::uint64_t kCapsV99 =
    kCapsV98 | kCapAudioOpenSLBridge;
constexpr std::uint64_t kCapsV100 =
    kCapsV99 | kCapRawGuestCallbackABI;
constexpr std::uint64_t kCapsV101 =
    kCapsV100 | kCapAudioClockContract;
constexpr std::uint64_t kCapsV102 =
    kCapsV101 | kCapAudioRealtimePump;
constexpr std::uint64_t kCapsV103 =
    kCapsV102 | kCapAudioDrawFramePump;
constexpr std::uint64_t kCapsV104 =
    kCapsV103 | kCapAudioWorkerHandshake;
constexpr std::uint64_t kCapsV105 =
    kCapsV104 | kCapWwiseResamplerProbe;
constexpr std::uint64_t kCapsV106 =
    kCapsV105 | kCapAudioRateBankWait;
constexpr std::uint64_t kCapsV107 =
    kCapsV106 | kCapSemaphoreWakeRepair;
constexpr std::uint64_t kCapsV108 =
    kCapsV107 | kCapBankCompletionLiveness;
constexpr std::uint64_t kCapsV109 =
    (kCapsV108 & ~kCapWwiseResamplerProbe) |
    kCapLeanAudioPerformance;
// v110 changes input/profiling/package selection only. Keep the validated
// v109 runtime capability set byte-for-byte identical.
constexpr std::uint64_t kCapsV110 = kCapsV109;
// v111 is diagnostic-only: no runtime capability is added or removed.
constexpr std::uint64_t kCapsV111 = kCapsV110;
// v112 remains observational and preserves the validated v110 runtime.
constexpr std::uint64_t kCapsV112 = kCapsV110;
// v113 changes only Dynarmic memory access for the guest heap after startup.
constexpr std::uint64_t kCapsV113 = kCapsV112;
// v114 is diagnostic-only and keeps the v113 runtime/capabilities unchanged.
constexpr std::uint64_t kCapsV114 = kCapsV113;
// v115 changes only Dynarmic memory access for the lower 255/256 main-stack
// pages; all v114 runtime capabilities and telemetry remain enabled.
constexpr std::uint64_t kCapsV115 = kCapsV114;
// v116 additionally changes only Dynarmic memory access for complete pages of
// the exact non-writable RX PT_LOAD. Runtime capabilities remain unchanged.
constexpr std::uint64_t kCapsV116 = kCapsV115;
// v117 keeps all functional v116 capabilities but removes purely observational
// hot-path diagnostics that are no longer needed for a production-like timing
// pass. Direct presentation, long-run execution, scheduler/audio fixes,
// indexed allocation and RELRO remain enabled.
constexpr std::uint64_t kCapsV117 =
    kCapsV116 &
    ~(kCapHostCost |
      kCapAllocatorProfiling |
      kCapReturnProvenance |
      kCapCallerReturnWatch |
      kCapPreciseCallerReturnWatch);
// v118 is deliberately capability-identical to v117. It changes only the
// amount of diagnostic work performed on validated hot functional paths.
constexpr std::uint64_t kCapsV118 = kCapsV117;
// v121 changes no guest/runtime capability. It adds host-only atomic telemetry.
constexpr std::uint64_t kCapsV121 = kCapsV118;
constexpr std::uint64_t kCapsV122 = kCapsV121;
constexpr std::uint64_t kCapsV123 = kCapsV122;
constexpr std::uint64_t kCapsV124 = kCapsV123;
constexpr std::uint64_t kCapsV125 = kCapsV124;
// v126 is observational only: no guest scheduling/audio capability changes.
constexpr std::uint64_t kCapsV126 = kCapsV125;
constexpr std::uint64_t kCapsV127 = kCapsV126;
constexpr std::uint64_t kCapsV128 = kCapsV127;
constexpr std::uint64_t kCapsV129 = kCapsV128;
constexpr std::uint64_t kCapsV130 = kCapsV129;

constexpr PvZ2DiagnosticModeDescriptor kDiagnosticModes[] = {
    {PvZ2DiagnosticMode::PassiveRegistry, "PASSIVE_REGISTRY", nullptr, 0u, false},
    {PvZ2DiagnosticMode::GateAScout, "GATE_A_SCOUT", nullptr, 0u, false},
    {PvZ2DiagnosticMode::FullMatrix, "V56_BASELINE", "V56 Base", 0u, true},
    {PvZ2DiagnosticMode::CtypeCompatNativePath, "CTYPE_COMPAT_NATIVE_PATH", nullptr, 0u, false},
    {PvZ2DiagnosticMode::CtypeCompatDeepScout, "CTYPE_COMPAT_DEEP_SCOUT", "Ctype Scout", 0u, true},
    {PvZ2DiagnosticMode::V62TaskProvenanceControlA, "V62_TASK_PROVENANCE_CONTROL_A", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V62PumpMutexCoherentB, "V62_PUMP_MUTEX_COHERENT_B", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V63CriticalSectionScheduler, "V63_CRITICAL_SECTION_SCHEDULER", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V64ReleaseBoundaryScheduler, "V64_RELEASE_BOUNDARY_SCHEDULER", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V65ConditionVariableScheduler, "V65_CONDITION_VARIABLE_SCHEDULER", "V65 Cond", 0u, true},
    {PvZ2DiagnosticMode::V66BlockingWaitScheduler, "V66_BLOCKING_WAIT_SCHEDULER", "V66 Waits", 0u, true},
    {PvZ2DiagnosticMode::V67CompletionTokenProvenance, "V67_COMPLETION_TOKEN_PROVENANCE", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V68CompletionTokenSemantics, "V68_COMPLETION_TOKEN_SEMANTICS", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V69TaskResourceLifecycle, "V69_TASKRESOURCE_LIFECYCLE", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V70ZlibStreamOwnership, "V70_ZLIB_STREAM_OWNERSHIP", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V71Etc1TextureBridge, "V71_ETC1_TEXTURE_BRIDGE", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V72LiveTouchBridge, "V72_LIVE_TOUCH_BRIDGE", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V73KeyboardFullscreenBridge, "V73_KEYBOARD_FULLSCREEN_BRIDGE", nullptr, 0u, false},
    {PvZ2DiagnosticMode::V74RetinaInputPolish, "V74_RETINA_INPUT_POLISH", "V74 Retina", kCapLive | kCapCpuFrame, true},
    {PvZ2DiagnosticMode::V75IpadUiPackage, "V75_IPAD_UI_PACKAGE", "V75 iPad UI", kCapLive | kCapCpuFrame | kCapProfile, true},
    {PvZ2DiagnosticMode::V76IosScaleContract, "V76_IOS_SCALE_CONTRACT", "V76 iOS Scale", kCapLive | kCapCpuFrame, true},
    {PvZ2DiagnosticMode::V77LegacyIpadGeometry, "V77_LEGACY_IPAD_GEOMETRY", "V77 Legacy iPad", kCapLive | kCapCpuFrame | kCapProfile, true},
    {PvZ2DiagnosticMode::V80GlobalTransformProbe, "V80_GLOBAL_TRANSFORM_PROBE", "V80 Transform", kCapsTransformBase, true},
    {PvZ2DiagnosticMode::V81HitTestLogicalPoints, "V81_HITTEST_LOGICAL_POINTS", "V81 HitTest", kCapsTransformBase | kCapLogicalTouch, true},
    {PvZ2DiagnosticMode::V82ProfileLayoutRadar, "V82_PROFILE_LAYOUT_RADAR", "V82 Radar", kCapsTransformBase | kCapLogicalTouch, true},
    {PvZ2DiagnosticMode::V83ProfileButtonDispatch, "V83_PROFILE_BUTTON_DISPATCH", "V83 Buttons", kCapsTransformBase, true},
    {PvZ2DiagnosticMode::V84FinalBlitTrace, "V84_FINAL_BLIT_TRACE", "V84 Blit", kCapsTransformBase, true},
    {PvZ2DiagnosticMode::V84PointsEqualPixels, "V84_POINTS_EQUAL_PIXELS", "V84 P=PX", kCapsTransformBase, true},
    {PvZ2DiagnosticMode::V84AndroidGraphicsContract, "V84_ANDROID_GRAPHICS_CONTRACT", "V84 Android", kCapsTransformBase, true},
    {PvZ2DiagnosticMode::V85PerformanceBaseline, "V85_PERFORMANCE_BASELINE", "V85 Perf", kCapsPerfBase, true},
    {PvZ2DiagnosticMode::V86HeapPerformanceFix, "V86_HEAP_PERFORMANCE_FIX", "V86 Heap+Perf", kCapsV86, true},
    {PvZ2DiagnosticMode::V87PreemptiveMutexScheduler, "V87_PREEMPTIVE_MUTEX_SCHEDULER", "V87 Mutex", kCapsV87, true},
    {PvZ2DiagnosticMode::V88AdaptiveMutexStartup, "V88_ADAPTIVE_MUTEX_STARTUP", "V88 Adaptive", kCapsV88, true},
    {PvZ2DiagnosticMode::V89PerformanceProfiler, "V89_PERFORMANCE_PROFILER", "V89 Profiler", kCapsV89, true},
    {PvZ2DiagnosticMode::V90DirectPresentationProfiler, "V90_DIRECT_PRESENTATION_PROFILER", "V90 Direct", kCapsV90, true},
    {PvZ2DiagnosticMode::V91IndexedAllocatorRelro, "V91_INDEXED_ALLOCATOR_RELRO", "V91 Alloc+RELRO", kCapsV91, true},
    {PvZ2DiagnosticMode::V92LongRunInteractive, "V92_LONG_RUN_INTERACTIVE", "V92 Long Run", kCapsV92, true},
    {PvZ2DiagnosticMode::V93ReturnProvenance, "V93_RETURN_PROVENANCE", "V93 Return", kCapsV93, true},
    {PvZ2DiagnosticMode::V94CallerReturnWatch, "V94_CALLER_RETURN_WATCH", "V94 LR Watch", kCapsV94, true},
    {PvZ2DiagnosticMode::V95PreciseCallerReturnWatch, "V95_PRECISE_CALLER_RETURN_WATCH", "V95 Precise LR", kCapsV95, true},
    {PvZ2DiagnosticMode::V96MainThreadBlocking, "V96_MAIN_THREAD_BLOCKING", "V96 Main Waits", kCapsV96, true},
    {PvZ2DiagnosticMode::V97GrantedMutexWaitGraph, "V97_GRANTED_MUTEX_WAIT_GRAPH", "V97 Mutex", kCapsV97, true},
    {PvZ2DiagnosticMode::V98PresentationRgbFidelity, "V98_PRESENTATION_RGB_FIDELITY", "V98 RGB", kCapsV98, true},
    {PvZ2DiagnosticMode::V99AudioOpenSLBridge, "V99_AUDIO_OPENSL_BRIDGE", "V99 Audio", kCapsV99, true},
    {PvZ2DiagnosticMode::V100OpenSLCallbackABI, "V100_OPENSL_CALLBACK_ABI", "V100 Audio ABI", kCapsV100, true},
    {PvZ2DiagnosticMode::V101AudioClockContract, "V101_AUDIO_CLOCK_CONTRACT", "V101 Audio Clock", kCapsV101, true},
    {PvZ2DiagnosticMode::V102AudioRealtimePump, "V102_AUDIO_REALTIME_PUMP", "V102 Audio Pump", kCapsV102, true},
    {PvZ2DiagnosticMode::V103AudioDrawFramePump, "V103_AUDIO_DRAWFRAME_PUMP", "V103 Audio Draw Pump", kCapsV103, true},
    {PvZ2DiagnosticMode::V104AudioWorkerHandshake, "V104_AUDIO_WORKER_HANDSHAKE", "V104 Audio Worker", kCapsV104, true},
    {PvZ2DiagnosticMode::V105WwiseResamplerProbe, "V105_WWISE_RESAMPLER_PROBE", "V105 Wwise Resampler", kCapsV105, true},
    {PvZ2DiagnosticMode::V106AudioRateBankWait, "V106_AUDIO_RATE_BANK_WAIT", "V106 Audio+Bank", kCapsV106, true},
    {PvZ2DiagnosticMode::V107SemaphoreWakeRepair, "V107_SEMAPHORE_WAKE_REPAIR", "V107 Semaphore Wake", kCapsV107, true},
    {PvZ2DiagnosticMode::V108BankCompletionLiveness, "V108_BANK_COMPLETION_LIVENESS", "V108 Bank Completion", kCapsV108, true},
    {PvZ2DiagnosticMode::V109LeanAudioPerformance, "V109_LEAN_AUDIO_PERFORMANCE", "V109 Lean Audio", kCapsV109, false},
    {PvZ2DiagnosticMode::V110AudioPinchUiAndroid, "V110_AUDIO_PINCH_UI_ANDROID", "V110 Android UI", kCapsV110, false},
    {PvZ2DiagnosticMode::V110AudioPinchUiIpad, "V110_AUDIO_PINCH_UI_IPAD", "V110 iPad UI", kCapsV110, false},
    {PvZ2DiagnosticMode::V111AudioSamplingProfiler, "V111_AUDIO_SAMPLING_PROFILER", "V111 Audio Sampling", kCapsV111, false},
    {PvZ2DiagnosticMode::V112AudioBoundaryProfiler, "V112_AUDIO_BOUNDARY_PROFILER", "V112 Audio Boundary", kCapsV112, false},
    {PvZ2DiagnosticMode::V113DynarmicHeapPageTable, "V113_DYNARMIC_HEAP_PAGETABLE", "V113 Heap Page Table", kCapsV113, false},
    {PvZ2DiagnosticMode::V114MainBoundaryProfiler, "V114_MAIN_BOUNDARY_PROFILER", "V114 Main Boundary", kCapsV114, false},
    {PvZ2DiagnosticMode::V115DynarmicMainStackPageTable, "V115_DYNARMIC_MAIN_STACK_PAGETABLE", "V115 Main Stack", kCapsV115, false},
    {PvZ2DiagnosticMode::V116DynarmicReadOnlyImagePageTable, "V116_DYNARMIC_READONLY_IMAGE_PAGETABLE", "V116 RX Image", kCapsV116, false},
    {PvZ2DiagnosticMode::V117LeanPerformance, "V117_LEAN_PERFORMANCE", "V117 Lean Performance", kCapsV117, false},
    {PvZ2DiagnosticMode::V118ProductionLean, "V118_PRODUCTION_LEAN", "V118 Production Lean", kCapsV118, false},
    {PvZ2DiagnosticMode::V121HostAudioTelemetry, "V121_HOST_AUDIO_TELEMETRY", "V121 Host Audio", kCapsV121, false},
    {PvZ2DiagnosticMode::V122PcmContinuityTelemetry, "V122_PCM_CONTINUITY_TELEMETRY", "V122 PCM Continuity", kCapsV122, false},
    {PvZ2DiagnosticMode::V123NonSilentRepeatTelemetry, "V123_NONSILENT_REPEAT_TELEMETRY", "V123 Non-silent Repeat", kCapsV123, false},
    {PvZ2DiagnosticMode::V124ExactPcmRepeatProvenance, "V124_EXACT_PCM_REPEAT_PROVENANCE", "V124 Exact PCM", kCapsV124, false},
    {PvZ2DiagnosticMode::V125RepeatEnqueueContext, "V125_REPEAT_ENQUEUE_CONTEXT", "V125 Repeat Context", kCapsV125, false},
    {PvZ2DiagnosticMode::V126AudioFlightRecorder, "V126_AUDIO_FLIGHT_RECORDER", "V126 Audio Flight", kCapsV126, false},
    {PvZ2DiagnosticMode::V127AudioWorkerDrain, "V127_AUDIO_WORKER_DRAIN", "V127 Audio Worker Drain", kCapsV127, false},
    {PvZ2DiagnosticMode::V128PersistentUserFs, "V128_PERSISTENT_USERFS", "V128 Persistent Save", kCapsV128, false},
    {PvZ2DiagnosticMode::V129IosBoardScale, "V129_IOS_BOARD_SCALE", "V129 iOS Board Scale", kCapsV129, false},
    {PvZ2DiagnosticMode::V130UserFriendlyRuntime, "V130_USER_FRIENDLY_RUNTIME", "V130 Game Launcher", kCapsV130, true},
};

constexpr PvZ2DiagnosticMode kSelectableDiagnosticModes[] = {
    PvZ2DiagnosticMode::V130UserFriendlyRuntime,
};

} // namespace

const PvZ2DiagnosticModeDescriptor*
PvZ2DescribeDiagnosticMode(PvZ2DiagnosticMode mode) {
    for (const auto& descriptor : kDiagnosticModes) {
        if (descriptor.mode == mode) {
            return &descriptor;
        }
    }
    return nullptr;
}

std::uint64_t PvZ2DiagnosticModeCapabilityMask(
    PvZ2DiagnosticMode mode) {

    const auto* descriptor =
        PvZ2DescribeDiagnosticMode(mode);
    return descriptor != nullptr
        ? descriptor->capabilities
        : 0u;
}

bool PvZ2DiagnosticModeHasCapability(
    PvZ2DiagnosticMode mode,
    PvZ2ProbeCapability capability) {

    const std::uint64_t capabilities =
        PvZ2DiagnosticModeCapabilityMask(mode);
    const std::uint64_t mask =
        static_cast<std::uint64_t>(capability);
    return mask == 0u ||
        (capabilities & mask) == mask;
}

std::size_t PvZ2SelectableDiagnosticModeCount() {
    return
        sizeof(kSelectableDiagnosticModes) /
        sizeof(kSelectableDiagnosticModes[0]);
}

const PvZ2DiagnosticModeDescriptor*
PvZ2SelectableDiagnosticModeAt(std::size_t index) {
    if (index >= PvZ2SelectableDiagnosticModeCount()) {
        return nullptr;
    }
    return PvZ2DescribeDiagnosticMode(
        kSelectableDiagnosticModes[index]);
}

PvZ2ApkProbeResult InspectAndMapPvZ2Apk(
    const std::uint8_t* apk_data,
    std::size_t apk_size) {

    PvZ2ApkProbeResult result;
    result.apk_size = apk_size;

    if (!apk_data || apk_size == 0) {
        result.message = "No APK data was supplied.";
        return result;
    }

    ZipEntry entry;
    std::string error;
    if (!FindZipEntry(apk_data, apk_size, kPvZ2Path, entry, error)) {
        result.message = error;
        return result;
    }

    result.elf_compressed_size = entry.compressed_size;
    result.elf_size = entry.uncompressed_size;

    std::vector<std::uint8_t> elf;
    if (!ExtractZipEntry(apk_data, apk_size, entry, elf, error)) {
        result.message = error;
        return result;
    }

    if (!InspectAndMapElf(elf, result, error)) {
        result.message = error;
        return result;
    }

    std::ostringstream message;
    message
        << "Extracted and validated " << kPvZ2Path
        << "; mapped " << result.load_segments
        << " PT_LOAD segments at guest base 0x" << std::hex << result.guest_base
        << ", applied " << std::dec << result.relative_applied
        << " R_ARM_RELATIVE relocations, and located JNI_OnLoad at guest 0x"
        << std::hex << result.jni_onload_guest << ".";

    if (result.exact_15252752_profile) {
        message << " Exact PvZ2 1.5.252752 ELF profile matched.";
    }

    result.ok = true;
    result.message = message.str();
    return result;
}


namespace {

constexpr std::uint32_t kJniProbeStackBase = 0x20000000u;
constexpr std::uint32_t kJniProbeStackSize = 0x00100000u;
constexpr std::uint32_t kJniProbeHeapBase = 0x30000000u;
constexpr std::uint32_t kJniProbeHeapSize = 0x04000000u;
constexpr std::uint32_t kJniProbeHeapSizeV86 = 0x08000000u;
constexpr std::uint32_t kJniProbeTrampolineBase = 0x40000000u;
constexpr std::uint32_t kJniProbeTrampolineSize = 0x00100000u;
constexpr std::uint32_t kJniProbeJniBase = 0x50000000u;
constexpr std::uint32_t kJniProbeJniSize = 0x00010000u;
constexpr std::uint32_t kJniProbeObjectBase = 0x51000000u;
constexpr std::uint32_t kJniProbeObjectSize = 0x00010000u;

// v72 exact AndroidUIEventManager touch ABI, recovered from the supplied
// classes.dex and cross-checked against the native decoder at 0x109f073c.
// ProcessEvents reserves a 16-byte header; touch records are exactly 48 bytes.
struct V72TouchEvent {
    std::uint32_t pointer_id = 0u;
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::int32_t previous_x = 0;
    std::int32_t previous_y = 0;
    std::uint32_t phase = 0u;
    double timestamp_ms = 0.0;
    std::uint64_t queued_steady_ns = 0u;
};

constexpr std::size_t kV72EventHeaderBytes = 16u;
constexpr std::size_t kV72TouchRecordBytes = 48u;
constexpr std::size_t kV72MaxQueuedTouches = 256u;

std::mutex gV72TouchMutex;
std::deque<V72TouchEvent> gV72TouchQueue;
std::atomic<bool> gV72StopRequested{false};
std::atomic<std::uint64_t> gV72TouchGeneration{0u};
std::atomic<std::uint64_t> gV72QueuedTouches{0u};
std::atomic<std::uint64_t> gV72DroppedTouches{0u};

// v110: exact classes.dex UIPinchEvent payload: type=3, midpoint X/Y,
// scaleDistSq, scaleDelta and three 0xDEADBEEF sentinels (32 bytes).
struct V110PinchEvent {
    std::int32_t x = 0;
    std::int32_t y = 0;
    float scale_dist_sq = 0.0f;
    float scale_delta = 0.0f;
};

constexpr std::size_t kV110PinchRecordBytes = 32u;
constexpr std::size_t kV110MaxQueuedPinches = 128u;
std::mutex gV110PinchMutex;
std::deque<V110PinchEvent> gV110PinchQueue;
std::atomic<std::uint64_t> gV110QueuedPinches{0u};
std::atomic<std::uint64_t> gV110DroppedPinches{0u};

std::vector<V110PinchEvent> V110TakePinchEvents(
    std::size_t max_events,
    bool& more) {
    std::lock_guard<std::mutex> lock(gV110PinchMutex);
    const std::size_t count =
        std::min<std::size_t>(max_events, gV110PinchQueue.size());
    std::vector<V110PinchEvent> events;
    events.reserve(count);
    for (std::size_t i = 0u; i < count; ++i) {
        events.push_back(gV110PinchQueue.front());
        gV110PinchQueue.pop_front();
    }
    more = !gV110PinchQueue.empty();
    return events;
}

std::size_t V110PendingPinchCount() {
    std::lock_guard<std::mutex> lock(gV110PinchMutex);
    return gV110PinchQueue.size();
}

// v73 classes.dex facts:
//   UITextInputEvent.Serialize(ByteBuffer)
//     putInt(6); putInt(action); putInt(utf8.length); put(utf8);
//     pad with zero bytes to a 4-byte boundary.
// EditInputConnection.commitText() sends action 0, while
// deleteSurroundingText() sends action 3 with an empty UTF-8 payload.
// The historical decrypted iOS 1.5 binary independently exposes
// sharedUITextField / UITextFieldDelegate / activateTextField, so the host
// UIKit bridge below follows the same platform strategy instead of inventing
// a synthetic guest text field.
struct V73TextInputEvent {
    std::uint32_t action = 0u;
    std::vector<std::uint8_t> utf8;
};

constexpr std::size_t kV73MaxQueuedTextEvents = 256u;

std::mutex gV73TextMutex;
std::deque<V73TextInputEvent> gV73TextQueue;
std::atomic<std::uint64_t> gV73QueuedTextEvents{0u};
std::atomic<std::uint64_t> gV73DroppedTextEvents{0u};

std::vector<V72TouchEvent> V72TakeTouchEvents(
    std::size_t max_events,
    bool& more) {

    std::lock_guard<std::mutex> lock(
        gV72TouchMutex);

    const std::size_t count =
        std::min<std::size_t>(
            max_events,
            gV72TouchQueue.size());

    std::vector<V72TouchEvent> events;
    events.reserve(count);

    for (std::size_t i = 0u;
         i < count;
         ++i) {
        events.push_back(
            gV72TouchQueue.front());
        gV72TouchQueue.pop_front();
    }

    more = !gV72TouchQueue.empty();
    return events;
}

std::size_t V72PendingTouchCount() {
    std::lock_guard<std::mutex> lock(
        gV72TouchMutex);
    return gV72TouchQueue.size();
}

std::size_t V73PendingTextCount() {
    std::lock_guard<std::mutex> lock(
        gV73TextMutex);
    return gV73TextQueue.size();
}

constexpr std::uint32_t kJniProbeImportSvcBase = 0x001000u;
constexpr std::uint32_t kJniProbeSvcGetEnv = 0x00f001u;
constexpr std::uint32_t kJniProbeSvcFindClass = 0x00f002u;
constexpr std::uint32_t kJniProbeSvcRegisterNatives = 0x00f003u;
constexpr std::uint32_t kJniProbeSvcReturn = 0x00f004u;
constexpr std::uint32_t kJniProbeSvcNewGlobalRef = 0x00f005u;
constexpr std::uint32_t kJniProbeSvcGetObjectClass = 0x00f006u;
constexpr std::uint32_t kJniProbeSvcGetMethodID = 0x00f007u;
// v35: inline trap replacing the two GenericResFileRes ID lookup calls.
// It preserves exact-ID lookup semantics, then falls back to the already
// populated global ResourceInfo path map using the physical RSB member path.
constexpr std::uint32_t kJniProbeSvcResourceRegistryLookup = 0x00f020u;
// v38: unlike the broad v35 callsite bridge, these traps replace only the
// two ARM instructions that would return NULL after PvZ2's native resource
// lookup has exhausted its own key transformations.
constexpr std::uint32_t kJniProbeSvcResourceRegistryMissGroup = 0x00f021u;
constexpr std::uint32_t kJniProbeSvcResourceRegistryMissGlobal = 0x00f022u;
// v43: capture the exact third argument at 0x1086f674 before the native
// lookup transforms/reuses registers. The SVC emulates the original MOV
// r4,r2 exactly, so successful native ImageRes/RESFILE lookups stay native.
constexpr std::uint32_t kJniProbeSvcResourceRegistryEntry = 0x00f023u;
// v45: 0x1086fa84 is the global-tree "found node" return. The original
// instruction is LDR r0,[r10,#0x14]. A found key can still carry a null
// ResourceInfo* value, which is exactly the path v44 did not observe.
constexpr std::uint32_t kJniProbeSvcResourceRegistryGlobalValue = 0x00f024u;
// v48: observe the two final return points in the GenericResFile wrapper,
// where the requested ID and manager/group arguments are still intact.
constexpr std::uint32_t kJniProbeSvcResourceWrapperDirectReturn = 0x00f025u;
constexpr std::uint32_t kJniProbeSvcResourceWrapperExhausted = 0x00f026u;
// v53: passive traps for the exact GameStateMgrState transition functions.
// Each trap replaces a MOV r4,r0 and the callback emulates that instruction.
constexpr std::uint32_t kJniProbeSvcGameStateApply = 0x00f030u;
constexpr std::uint32_t kJniProbeSvcGameStateRequest = 0x00f031u;

// v54: passive StartupLogo.Update gate/depth instrumentation. Every trap
// replaces one verified ARM instruction and emulates that exact instruction
// before returning to guest code. No branch, return value, state field, or
// transition target is forced.
constexpr std::uint32_t kJniProbeSvcStartupGateAResource = 0x00f040u;
constexpr std::uint32_t kJniProbeSvcStartupGateATotals = 0x00f041u;
constexpr std::uint32_t kJniProbeSvcStartupGateAResult = 0x00f042u;
constexpr std::uint32_t kJniProbeSvcStartupGateCState = 0x00f043u;
constexpr std::uint32_t kJniProbeSvcStartupGateDCounter = 0x00f044u;
constexpr std::uint32_t kJniProbeSvcStartupAfterD = 0x00f045u;
constexpr std::uint32_t kJniProbeSvcStartupGateEByte = 0x00f046u;
constexpr std::uint32_t kJniProbeSvcStartupGateFResult = 0x00f047u;
constexpr std::uint32_t kJniProbeSvcStartupGateGResult = 0x00f048u;
constexpr std::uint32_t kJniProbeSvcStartupGateHResult = 0x00f049u;
constexpr std::uint32_t kJniProbeSvcStartupGateIResult = 0x00f04au;
constexpr std::uint32_t kJniProbeSvcStartupGateJObject = 0x00f04bu;
constexpr std::uint32_t kJniProbeSvcStartupPatchMarker = 0x00f04cu;
constexpr std::uint32_t kJniProbeSvcStartupMainFlow = 0x00f04du;
constexpr std::uint32_t kJniProbeSvcStartupProgressResult = 0x00f04eu;
constexpr std::uint32_t kJniProbeSvcStartupFindResult = 0x00f04fu;
constexpr std::uint32_t kJniProbeSvcStartupLateResult = 0x00f050u;
constexpr std::uint32_t kJniProbeSvcStartupMainMenuMarker = 0x00f051u;

// v55: passive diagnosis inside Gate A's resource-group progress helper.
// The constructor trap snapshots the global vector after its four std::string
// entries are built. The other traps observe the native group lookup and the
// two per-group values accumulated into completed/total. Nothing is forced.
constexpr std::uint32_t kJniProbeSvcStartupGroupsCtorSnapshot = 0x00f060u;
constexpr std::uint32_t kJniProbeSvcStartupGroupsLookupResult = 0x00f061u;
constexpr std::uint32_t kJniProbeSvcStartupGroupsContribution = 0x00f062u;
constexpr std::uint32_t kV55StartupGroupsVectorGuest = 0x10d54698u;

// v56 Diagnostic Matrix: direct observation of the ResourceManager registry
// construction pipeline plus an optional post-proof Gate-A scout. Full Matrix
// additionally traces the compact trie lookup helper globally for selected
// startup keys.
constexpr std::uint32_t kJniProbeSvcV56RegistryPipelineEntry = 0x00f070u;
constexpr std::uint32_t kJniProbeSvcV56RegistrySource28 = 0x00f071u;
constexpr std::uint32_t kJniProbeSvcV56RegistryPost28 = 0x00f072u;
constexpr std::uint32_t kJniProbeSvcV56RegistrySource30 = 0x00f073u;
constexpr std::uint32_t kJniProbeSvcV56RegistryPost30 = 0x00f074u;
constexpr std::uint32_t kJniProbeSvcV56RegistryPipelineReturn = 0x00f075u;
constexpr std::uint32_t kJniProbeSvcV56TrieEntry = 0x00f076u;
constexpr std::uint32_t kJniProbeSvcV56TrieMissBranch = 0x00f077u;
constexpr std::uint32_t kJniProbeSvcV56TrieFound = 0x00f078u;
constexpr std::uint32_t kJniProbeSvcV56TrieMissZero = 0x00f079u;

// v57: character-by-character compact-trie trace. This replaces only
// UXTB r0,r5 and emulates it exactly after observing the current key/node.
constexpr std::uint32_t kJniProbeSvcV57TrieCompare = 0x00f080u;

constexpr std::uint32_t kV57TolowerGotGuest = 0x10d010d8u;
constexpr std::uint32_t kV57ToupperGotGuest = 0x10d010dcu;
constexpr std::uint32_t kV57CtypeGotGuest = 0x10d01280u;

// v61: verified PvZ2 1.5.252752 resource-stream task pump. The pump acquires
// manager+0x68 through pthread_mutex_trylock and releases it at 0x10868f6c.
// Yielding only after that unlock preserves the v29 "never interleave while
// guest containers are being mutated" invariant while still allowing the
// real deferred workers to advance between pump iterations.
constexpr std::uint32_t kV61ResStreamsPumpUnlockReturnGuest =
    kGuestBase + 0x00868f70u;
constexpr std::uint32_t kV61GenericPthreadWrapperGuest =
    kGuestBase + 0x009cb6d0u;

// v62: exact return after the same pump trylock plus an observational trap
// for LDR r1,[r0,#0x14] immediately before TaskResource::vfn14 dispatch.
constexpr std::uint32_t kV62ResStreamsPumpTrylockReturnGuest =
    kGuestBase + 0x00868ba4u;
constexpr std::uint32_t kJniProbeSvcV62TaskDispatch = 0x00f081u;

// v66: observational traps immediately after the TaskResource dependency/
// child vfnC calls. Each replaces only CMP r0,#0 and reproduces that compare
// in CallSVC after recording the returned readiness value.
constexpr std::uint32_t kJniProbeSvcV66TaskADepResult = 0x00f082u;
constexpr std::uint32_t kJniProbeSvcV66TaskAChild78Result = 0x00f083u;
constexpr std::uint32_t kJniProbeSvcV66TaskAChild84Result = 0x00f084u;
constexpr std::uint32_t kJniProbeSvcV66TaskBDepResult = 0x00f085u;
constexpr std::uint32_t kJniProbeSvcV66TaskBChildResult = 0x00f086u;

// v67: exact STR r1,[r0,#4] stores in the shared completion-token
// increment/decrement methods. CallSVC logs provenance, then performs the
// original store without changing any counter semantics.
constexpr std::uint32_t kJniProbeSvcV67TokenIncrementStore = 0x00f087u;
constexpr std::uint32_t kJniProbeSvcV67TokenDecrementStore = 0x00f088u;

// v69: one batched TaskResource lifecycle probe. Traps are placed after
// virtual calls (or on simple MOV/LDR/STR/CMP instructions) so the real
// guest virtual methods still execute naturally.
constexpr std::uint32_t kJniProbeSvcV69WorkerPreWait = 0x00f089u;
constexpr std::uint32_t kJniProbeSvcV69ActiveReadyResult = 0x00f08au;
constexpr std::uint32_t kJniProbeSvcV69ActivePhaseResult = 0x00f08bu;
constexpr std::uint32_t kJniProbeSvcV69StartWorkReturn = 0x00f08cu;
constexpr std::uint32_t kJniProbeSvcV69MoveCompleted = 0x00f08du;
constexpr std::uint32_t kJniProbeSvcV69CompletedPollReturn = 0x00f08eu;
constexpr std::uint32_t kJniProbeSvcV69CompletedReadyResult = 0x00f08fu;
constexpr std::uint32_t kJniProbeSvcV69CompletedTerminalResult = 0x00f090u;
constexpr std::uint32_t kJniProbeSvcV69FinalizerReturn = 0x00f091u;

// v79: first-run Profile/Facebook/EULA provenance. These traps are enabled
// only in the already-validated V75 and V77 controls. Every replaced
// instruction is emulated exactly; no rectangle, scale, state or resource is
// changed. The goal is to observe the live parent dimensions and the exact
// integer geometry produced by the statically matched Android/iOS paths.
constexpr std::uint32_t kJniProbeSvcV79SetWidthHeightEntry = 0x00f0a0u;
constexpr std::uint32_t kJniProbeSvcV79ProfileEntry = 0x00f0a1u;
constexpr std::uint32_t kJniProbeSvcV79CheckboxEntry = 0x00f0a2u;
constexpr std::uint32_t kJniProbeSvcV79CheckboxRect = 0x00f0a3u;
constexpr std::uint32_t kJniProbeSvcV79FacebookEntry = 0x00f0a4u;
constexpr std::uint32_t kJniProbeSvcV79FacebookRect = 0x00f0a5u;
constexpr std::uint32_t kJniProbeSvcV79ContainerEntry = 0x00f0a6u;
constexpr std::uint32_t kJniProbeSvcV79ContainerRect = 0x00f0a7u;
constexpr std::uint32_t kJniProbeSvcV79TextEntry = 0x00f0a8u;
constexpr std::uint32_t kJniProbeSvcV79TextRectA = 0x00f0a9u;
constexpr std::uint32_t kJniProbeSvcV79TextRectB = 0x00f0aau;
constexpr std::uint32_t kJniProbeSvcV79GenericEntry = 0x00f0abu;
constexpr std::uint32_t kJniProbeSvcV79GenericRect = 0x00f0acu;

// v82: Profile candidate widget provenance. Static analysis of the broad
// first-run Profile constructor identifies button-constructor IDs 5/7/6, but
// their semantic labels are intentionally left unresolved until runtime.
constexpr std::uint32_t kJniProbeSvcV82Candidate5Post = 0x00f0b0u;
constexpr std::uint32_t kJniProbeSvcV82Candidate7Post = 0x00f0b1u;
constexpr std::uint32_t kJniProbeSvcV82Candidate6Pre = 0x00f0b2u;
constexpr std::uint32_t kJniProbeSvcV82Candidate6Post = 0x00f0b3u;

// v83: Profile button-listener dispatcher entry. The original instruction is
// MOV r9,r0 at libPVZ2.so+0x0030b8f8, eight bytes after the function prologue.
constexpr std::uint32_t kJniProbeSvcV83ButtonDispatchEntry = 0x00f0b4u;
constexpr std::uint32_t kJniProbeSvcV89BlxTarget0 = 0x00f0c0u;
constexpr std::uint32_t kJniProbeSvcV89BlxTarget1 = 0x00f0c1u;
constexpr std::uint32_t kJniProbeSvcV90FontScanBegin = 0x00f0c2u;
constexpr std::uint32_t kJniProbeSvcV90FontScanEnd = 0x00f0c3u;
constexpr std::uint32_t kJniProbeSvcV95WrapperPush = 0x00f0c4u;
constexpr std::uint32_t kJniProbeSvcV95WrapperPop = 0x00f0c5u;

// v105: low-frequency observational probes in the Wwise resampler lifecycle.
// Each SVC replaces one verified ARM instruction and emulates that instruction
// exactly after capturing state; no sample-rate/pitch value is modified.
constexpr std::uint32_t kJniProbeSvcV105ResamplerInitState = 0x00f0c6u;
constexpr std::uint32_t kJniProbeSvcV105SetPitchState = 0x00f0c7u;
constexpr std::uint32_t kJniProbeSvcV105SwitchToState = 0x00f0c8u;

// v108: exact low-frequency probes for the asynchronous SoundBank teardown
// path. Each replaces one verified ARM instruction and emulates it exactly.
constexpr std::uint32_t kJniProbeSvcV108KillSlotEntry = 0x00f0c9u;
constexpr std::uint32_t kJniProbeSvcV108KillBankMsg = 0x00f0cau;
constexpr std::uint32_t kJniProbeSvcV108UsageSlotRelease = 0x00f0cbu;
constexpr std::uint32_t kJniProbeSvcV108UnloadCompletion = 0x00f0ccu;
constexpr std::uint32_t kJniProbeSvcV108DefaultBankCallback = 0x00f0cdu;

// v129: three exact Android adaptive Board-scale stores. Each SVC replaces
// only the final VSTR of Board+0x678. The callback derives the Board pointer
// from that destination and applies the historical iOS triplet 1.0/0/0.
constexpr std::uint32_t kJniProbeSvcV129BoardScaleState = 0x00f0d0u;
constexpr std::uint32_t kJniProbeSvcV129BoardScaleInit = 0x00f0d1u;
constexpr std::uint32_t kJniProbeSvcV129BoardScaleRefresh = 0x00f0d2u;

constexpr std::uint32_t kJniProbeSvcUnsupportedJniBase = 0x00e000u;
constexpr std::uint32_t kJniProbeJniSlotCount = 256u;

constexpr std::uint32_t kPvZ2JniOnLoad15252752 = 0x009ead80u;
constexpr std::uint32_t kJniVersion14 = 0x00010004u;
constexpr std::uint32_t kJniVersion16 = 0x00010006u;

struct JniProbeLoadedElf {
    std::vector<std::uint8_t> image;
    std::vector<Elf32Sym> dynsyms;
    std::vector<std::uint32_t> function_starts;
    std::vector<Elf32Rel> relocs;
    const std::uint8_t* dynstr = nullptr;
    std::size_t dynstr_size = 0;
    std::uint32_t jni_onload = 0;
    std::uint32_t init_array = 0;
    std::uint32_t init_array_size = 0;

    // v91: GNU_RELRO is part of the ELF loader contract. The real Android
    // linker makes this range read-only after relocation; the synthetic
    // runtime previously left the whole image writable.
    std::uint32_t gnu_relro_vaddr = 0u;
    std::uint32_t gnu_relro_size = 0u;
};

bool BuildJniProbeElf(
    const std::vector<std::uint8_t>& elf,
    JniProbeLoadedElf& loaded,
    std::string& error) {

    const auto* eh = CheckedAt<Elf32Ehdr>(elf, 0);
    if (!eh ||
        Read32(eh->ident) != kElfMagic ||
        eh->ident[4] != 1 ||
        eh->ident[5] != 1 ||
        eh->type != kElfTypeDyn ||
        eh->machine != kElfMachineArm) {
        error = "JNI probe expected an ELF32 little-endian ARM shared object.";
        return false;
    }

    if (eh->phentsize != sizeof(Elf32Phdr) ||
        !RangeOk(
            eh->phoff,
            static_cast<std::size_t>(eh->phnum) * eh->phentsize,
            elf.size())) {
        error = "JNI probe found an invalid ELF program-header table.";
        return false;
    }

    std::uint64_t image_end = 0;
    std::vector<Elf32Phdr> loads;

    for (std::uint16_t i = 0; i < eh->phnum; ++i) {
        const auto* ph = CheckedAt<Elf32Phdr>(
            elf,
            eh->phoff + static_cast<std::size_t>(i) * eh->phentsize);
        if (!ph) {
            error = "JNI probe ELF program header is truncated.";
            return false;
        }

        if (ph->type == kPtGnuRelro) {
            loaded.gnu_relro_vaddr =
                ph->vaddr;
            loaded.gnu_relro_size =
                ph->memsz;
        }

        if (ph->type == kPtLoad) {
            if (ph->filesz > ph->memsz ||
                !RangeOk(ph->offset, ph->filesz, elf.size())) {
                error = "JNI probe encountered an invalid PT_LOAD segment.";
                return false;
            }

            image_end = std::max<std::uint64_t>(
                image_end,
                static_cast<std::uint64_t>(ph->vaddr) + ph->memsz);
            loads.push_back(*ph);
        }
    }

    if (loads.size() != 2 || image_end != 0x00df9700ull) {
        error = "JNI probe ELF load profile does not match PvZ2 1.5.252752.";
        return false;
    }

    // v116 relies on the exact Android linker permissions of this build:
    // PT_LOAD[0] is RX and contains code/rodata, PT_LOAD[1] is RW and contains
    // mutable data/GOT/RELRO. Refuse the profile if that contract ever differs.
    if (loads[0].vaddr != 0x00000000u ||
        loads[0].memsz != 0x00ccaad4u ||
        loads[0].flags != 5u ||
        loads[1].vaddr != 0x00ccbf90u ||
        loads[1].memsz != 0x0012d770u ||
        loads[1].flags != 6u) {
        error = "JNI probe ELF PT_LOAD permission profile does not match PvZ2 1.5.252752.";
        return false;
    }

    if (loaded.gnu_relro_size != 0u) {
        const std::uint64_t relro_end =
            static_cast<std::uint64_t>(
                loaded.gnu_relro_vaddr) +
            loaded.gnu_relro_size;

        if (relro_end > image_end) {
            error =
                "JNI probe GNU_RELRO range exceeds the mapped image.";
            return false;
        }
    }

    loaded.image.assign(static_cast<std::size_t>(image_end), 0);
    for (const auto& ph : loads) {
        std::memcpy(
            loaded.image.data() + ph.vaddr,
            elf.data() + ph.offset,
            ph.filesz);
    }

    ElfSections sections;
    if (!ParseSections(elf, *eh, sections, error)) {
        return false;
    }

    // v46: .ARM.exidx survives stripping. Its PREL31 entries provide stable
    // function starts for symbolizing PC/LR values even when the original C++
    // function name is absent from .dynsym.
    if (sections.arm_exidx != nullptr &&
        (sections.arm_exidx->size % 8u) == 0u &&
        RangeOk(
            sections.arm_exidx->offset,
            sections.arm_exidx->size,
            elf.size())) {

        const std::uint32_t entries =
            sections.arm_exidx->size / 8u;

        loaded.function_starts.reserve(
            entries);

        for (std::uint32_t i = 0u;
             i < entries;
             ++i) {

            const std::uint32_t rel =
                i * 8u;

            const std::uint32_t word =
                Read32(
                    elf.data() +
                    sections.arm_exidx->offset +
                    rel);

            std::int64_t delta =
                static_cast<std::int64_t>(
                    word & 0x7fffffffu);

            if ((word & 0x40000000u) != 0u) {
                delta -= 0x80000000ll;
            }

            const std::int64_t place =
                static_cast<std::int64_t>(
                    sections.arm_exidx->addr) +
                rel;

            const std::int64_t target =
                place + delta;

            if (target > 0 &&
                target <
                    static_cast<std::int64_t>(
                        loaded.image.size())) {

                loaded.function_starts.push_back(
                    static_cast<std::uint32_t>(
                        target) &
                    ~1u);
            }
        }

        std::sort(
            loaded.function_starts.begin(),
            loaded.function_starts.end());

        loaded.function_starts.erase(
            std::unique(
                loaded.function_starts.begin(),
                loaded.function_starts.end()),
            loaded.function_starts.end());
    }

    loaded.dynstr = elf.data() + sections.dynstr->offset;
    loaded.dynstr_size = sections.dynstr->size;

    const std::size_t symbol_count =
        sections.dynsym->size / sizeof(Elf32Sym);
    loaded.dynsyms.reserve(symbol_count);

    for (std::size_t i = 0; i < symbol_count; ++i) {
        const auto* sym = CheckedAt<Elf32Sym>(
            elf,
            sections.dynsym->offset + i * sizeof(Elf32Sym));
        if (!sym) {
            error = "JNI probe dynamic symbol table is truncated.";
            return false;
        }

        loaded.dynsyms.push_back(*sym);

        std::string name;
        if (!ReadCString(
                loaded.dynstr,
                loaded.dynstr_size,
                sym->name,
                name)) {
            error = "JNI probe encountered an invalid dynamic symbol name.";
            return false;
        }

        if (name == "JNI_OnLoad" && sym->shndx != 0) {
            loaded.jni_onload = sym->value;
        }
    }

    for (const Elf32Shdr* rel_section : sections.rels) {
        const std::size_t count =
            rel_section->size / sizeof(Elf32Rel);

        for (std::size_t i = 0; i < count; ++i) {
            const auto* rel = CheckedAt<Elf32Rel>(
                elf,
                rel_section->offset + i * sizeof(Elf32Rel));
            if (!rel) {
                error = "JNI probe relocation table is truncated.";
                return false;
            }
            loaded.relocs.push_back(*rel);
        }
    }

    if (sections.dynamic) {
        const std::size_t dynamic_count =
            sections.dynamic->size / sizeof(Elf32Dyn);

        for (std::size_t i = 0; i < dynamic_count; ++i) {
            const auto* dyn = CheckedAt<Elf32Dyn>(
                elf,
                sections.dynamic->offset + i * sizeof(Elf32Dyn));

            if (!dyn) {
                error = "JNI probe dynamic section is truncated.";
                return false;
            }

            if (dyn->tag == kDtNull) {
                break;
            }

            if (dyn->tag == kDtInitArray) {
                loaded.init_array = dyn->value;
            } else if (dyn->tag == kDtInitArraySz) {
                loaded.init_array_size = dyn->value;
            }
        }
    }

    if (loaded.jni_onload != kPvZ2JniOnLoad15252752) {
        error = "JNI_OnLoad address does not match PvZ2 1.5.252752.";
        return false;
    }

    if (loaded.init_array == 0 ||
        loaded.init_array_size == 0 ||
        (loaded.init_array_size & 3u) != 0 ||
        !RangeOk(
            loaded.init_array,
            loaded.init_array_size,
            loaded.image.size())) {
        error = "PvZ2 .init_array metadata is invalid.";
        return false;
    }

    return true;
}

std::string JniProbeSymbolName(
    const JniProbeLoadedElf& loaded,
    std::uint32_t symbol_index) {

    if (symbol_index >= loaded.dynsyms.size()) {
        return {};
    }

    std::string name;
    if (!ReadCString(
            loaded.dynstr,
            loaded.dynstr_size,
            loaded.dynsyms[symbol_index].name,
            name)) {
        return {};
    }

    return name;
}

class JniProbeGuestMemory {
public:
    explicit JniProbeGuestMemory(
        std::uint32_t heap_size = kJniProbeHeapSize)
        : heap(
              std::max<std::uint32_t>(
                  heap_size,
                  1u),
              0) {}

    std::vector<std::uint8_t> image;
    std::vector<std::uint8_t> stack =
        std::vector<std::uint8_t>(kJniProbeStackSize, 0);
    std::vector<std::uint8_t> heap;
    std::vector<std::uint8_t> trampolines =
        std::vector<std::uint8_t>(kJniProbeTrampolineSize, 0);
    std::vector<std::uint8_t> jni =
        std::vector<std::uint8_t>(kJniProbeJniSize, 0);
    std::vector<std::uint8_t> objects =
        std::vector<std::uint8_t>(kJniProbeObjectSize, 0);

    std::uint32_t heap_next = 0;
    std::uint32_t heap_high_water = 0;
    std::uint32_t heap_live_bytes = 0;
    std::uint32_t object_next = 0;
    std::unordered_map<std::uint32_t, std::uint32_t> heap_allocations;
    std::vector<std::pair<std::uint32_t, std::uint32_t>>
        heap_retired_allocations;
    std::map<std::uint32_t, std::uint32_t> heap_free_blocks;

    // v91 allocator: preserve the old address-ordered first-fit result exactly
    // while avoiding a full std::map walk. Free blocks stay authoritative in
    // heap_free_blocks; this is only an address-bucket max index.
    static constexpr std::uint32_t kV91BucketShift = 12u;
    static constexpr std::uint32_t kV91BucketSize =
        1u << kV91BucketShift;
    static constexpr std::size_t kV91AlignmentClassCount = 8u;

    bool v91_allocator_index_enabled = false;
    std::uint32_t v91_bucket_count = 0u;
    std::uint32_t v91_tree_base = 0u;
    std::array<std::vector<std::uint32_t>,
               kV91AlignmentClassCount>
        v91_fit_trees;
    std::uint64_t v91_index_queries = 0u;
    std::uint64_t v91_index_hits = 0u;
    std::uint64_t v91_index_fallbacks = 0u;
    std::uint64_t v91_index_inconsistencies = 0u;
    std::uint64_t v91_local_scan_total = 0u;
    std::uint64_t v91_local_scan_max = 0u;
    std::uint64_t v91_bucket_refreshes = 0u;

    // v91 loader protection. This is armed only after all relocation/import
    // and static compatibility patches have been installed.
    std::uint32_t v91_relro_begin = 0u;
    std::uint32_t v91_relro_end = 0u;
    bool v91_relro_armed = false;
    std::uint64_t v91_memory_blocked_writes = 0u;
    std::uint32_t v91_first_blocked_address = 0u;
    std::uint32_t v91_first_blocked_size = 0u;

    // v90: exact first-fit scan-depth accounting plus sparse wall-time
    // sampling. Wall time is sampled once per 1024 alloc/free calls so this
    // profiler does not become the allocator bottleneck it is measuring.
    bool v90_allocator_profile = false;
    std::uint64_t v90_alloc_calls_internal = 0u;
    std::uint64_t v90_free_calls_internal = 0u;
    std::uint64_t v90_alloc_from_free = 0u;
    std::uint64_t v90_alloc_scan_total = 0u;
    std::uint64_t v90_alloc_scan_max = 0u;
    std::array<std::uint64_t, 6> v90_alloc_scan_hist{};
    std::uint64_t v90_alloc_sample_count = 0u;
    std::uint64_t v90_alloc_sample_ns = 0u;
    std::uint64_t v90_alloc_sample_max_ns = 0u;
    std::uint64_t v90_free_sample_count = 0u;
    std::uint64_t v90_free_sample_ns = 0u;
    std::uint64_t v90_free_sample_max_ns = 0u;
    std::size_t v90_free_blocks_peak = 0u;

    static std::uint64_t V90AllocatorNowNs() {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<
                std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now()
                        .time_since_epoch())
                .count());
    }

    void EnableV90AllocatorProfiling(
        bool enabled) {
        v90_allocator_profile = enabled;
        if (enabled) {
            v90_free_blocks_peak =
                heap_free_blocks.size();
        }
    }

    void V90ObserveFreeBlocks() {
        if (!v90_allocator_profile) {
            return;
        }
        v90_free_blocks_peak =
            std::max(
                v90_free_blocks_peak,
                heap_free_blocks.size());
    }

    void V90FinishAllocProfile(
        std::uint64_t scan_steps,
        bool from_free,
        bool sampled,
        std::uint64_t begin_ns) {

        if (!v90_allocator_profile) {
            return;
        }

        v90_alloc_scan_total += scan_steps;
        v90_alloc_scan_max =
            std::max(
                v90_alloc_scan_max,
                scan_steps);

        std::size_t bucket = 0u;
        if (scan_steps == 0u) bucket = 0u;
        else if (scan_steps <= 4u) bucket = 1u;
        else if (scan_steps <= 16u) bucket = 2u;
        else if (scan_steps <= 64u) bucket = 3u;
        else if (scan_steps <= 256u) bucket = 4u;
        else bucket = 5u;
        ++v90_alloc_scan_hist[bucket];

        if (from_free) {
            ++v90_alloc_from_free;
        }

        V90ObserveFreeBlocks();

        if (sampled) {
            const std::uint64_t now =
                V90AllocatorNowNs();
            const std::uint64_t elapsed =
                now >= begin_ns
                    ? now - begin_ns
                    : 0u;
            ++v90_alloc_sample_count;
            v90_alloc_sample_ns += elapsed;
            v90_alloc_sample_max_ns =
                std::max(
                    v90_alloc_sample_max_ns,
                    elapsed);
        }
    }

    std::string V90AllocatorSummary() const {
        std::ostringstream out;
        out << std::fixed
            << std::setprecision(3)
            << "V90 ALLOC SUMMARY"
            << " allocCalls=" << v90_alloc_calls_internal
            << " freeCalls=" << v90_free_calls_internal
            << " fromFree=" << v90_alloc_from_free
            << " scanTotal=" << v90_alloc_scan_total
            << " scanAvg="
            << (v90_alloc_calls_internal != 0u
                    ? static_cast<double>(v90_alloc_scan_total) /
                          static_cast<double>(v90_alloc_calls_internal)
                    : 0.0)
            << " scanMax=" << v90_alloc_scan_max
            << " scanHist{0=" << v90_alloc_scan_hist[0]
            << ",1-4=" << v90_alloc_scan_hist[1]
            << ",5-16=" << v90_alloc_scan_hist[2]
            << ",17-64=" << v90_alloc_scan_hist[3]
            << ",65-256=" << v90_alloc_scan_hist[4]
            << ",257+=" << v90_alloc_scan_hist[5]
            << "}"
            << " freeBlocks{live=" << heap_free_blocks.size()
            << ",peak=" << v90_free_blocks_peak
            << "}"
            << " allocSample{n=" << v90_alloc_sample_count
            << ",avgUs="
            << (v90_alloc_sample_count != 0u
                    ? static_cast<double>(v90_alloc_sample_ns) /
                          static_cast<double>(v90_alloc_sample_count) /
                          1000.0
                    : 0.0)
            << ",maxUs="
            << static_cast<double>(v90_alloc_sample_max_ns) /
                   1000.0
            << "}"
            << " freeSample{n=" << v90_free_sample_count
            << ",avgUs="
            << (v90_free_sample_count != 0u
                    ? static_cast<double>(v90_free_sample_ns) /
                          static_cast<double>(v90_free_sample_count) /
                          1000.0
                    : 0.0)
            << ",maxUs="
            << static_cast<double>(v90_free_sample_max_ns) /
                   1000.0
            << "}";
        return out.str();
    }

    const std::uint8_t* Ptr(
        std::uint32_t address,
        std::size_t size = 1) const {

        auto inside = [&](std::uint32_t base,
                          const std::vector<std::uint8_t>& region)
            -> const std::uint8_t* {

            if (address < base) {
                return nullptr;
            }

            const std::uint64_t offset =
                static_cast<std::uint64_t>(address) - base;

            if (offset > region.size() ||
                size > region.size() - static_cast<std::size_t>(offset)) {
                return nullptr;
            }

            return region.data() + static_cast<std::size_t>(offset);
        };

        if (const auto* p = inside(kGuestBase, image)) return p;
        if (const auto* p = inside(kJniProbeStackBase, stack)) return p;
        if (const auto* p = inside(kJniProbeHeapBase, heap)) return p;
        if (const auto* p = inside(kJniProbeTrampolineBase, trampolines)) return p;
        if (const auto* p = inside(kJniProbeJniBase, jni)) return p;
        if (const auto* p = inside(kJniProbeObjectBase, objects)) return p;
        return nullptr;
    }

    std::uint8_t* Ptr(
        std::uint32_t address,
        std::size_t size = 1) {

        return const_cast<std::uint8_t*>(
            static_cast<const JniProbeGuestMemory*>(this)->Ptr(address, size));
    }

    std::uint8_t Read8(std::uint32_t address) const {
        const auto* p = Ptr(address, 1);
        return p ? *p : 0;
    }

    std::uint16_t Read16Guest(std::uint32_t address) const {
        return static_cast<std::uint16_t>(Read8(address)) |
               static_cast<std::uint16_t>(Read8(address + 1)) << 8;
    }

    std::uint32_t Read32Guest(std::uint32_t address) const {
        if (const auto* p = Ptr(address, 4)) {
            return Read32(p);
        }

        return static_cast<std::uint32_t>(Read8(address)) |
               static_cast<std::uint32_t>(Read8(address + 1)) << 8 |
               static_cast<std::uint32_t>(Read8(address + 2)) << 16 |
               static_cast<std::uint32_t>(Read8(address + 3)) << 24;
    }

    std::uint64_t Read64Guest(std::uint32_t address) const {
        return static_cast<std::uint64_t>(Read32Guest(address)) |
               static_cast<std::uint64_t>(Read32Guest(address + 4)) << 32;
    }

    void V91ConfigureRelro(
        std::uint32_t begin,
        std::uint32_t size) {

        v91_relro_begin = begin;
        const std::uint64_t end =
            static_cast<std::uint64_t>(begin) +
            size;
        v91_relro_end =
            end <= std::numeric_limits<std::uint32_t>::max()
                ? static_cast<std::uint32_t>(end)
                : 0u;
        v91_relro_armed = false;
    }

    void V91ArmRelro() {
        v91_relro_armed =
            v91_relro_begin != 0u &&
            v91_relro_end >
                v91_relro_begin;
    }

    bool V91RelroArmed() const {
        return v91_relro_armed;
    }

    bool V91OverlapsRelro(
        std::uint32_t address,
        std::size_t size) const {

        if (!v91_relro_armed ||
            size == 0u ||
            v91_relro_begin == 0u ||
            v91_relro_end <=
                v91_relro_begin) {
            return false;
        }

        const std::uint64_t begin = address;
        const std::uint64_t end =
            begin + size;
        return
            begin <
                v91_relro_end &&
            end >
                v91_relro_begin;
    }

    void V91RecordBlockedWrite(
        std::uint32_t address,
        std::size_t size) {

        ++v91_memory_blocked_writes;
        if (v91_first_blocked_address == 0u) {
            v91_first_blocked_address =
                address;
            v91_first_blocked_size =
                static_cast<std::uint32_t>(
                    std::min<std::size_t>(
                        size,
                        0xffffffffu));
        }
    }

    void Write8GuestUnchecked(
        std::uint32_t address,
        std::uint8_t value) {
        if (auto* p = Ptr(address, 1u)) {
            *p = value;
        }
    }

    void Write32GuestUnchecked(
        std::uint32_t address,
        std::uint32_t value) {
        if (auto* p = Ptr(address, 4u)) {
            Write32(p, value);
        }
    }

    void Write8Guest(std::uint32_t address, std::uint8_t value) {
        if (V91OverlapsRelro(address, 1u)) {
            V91RecordBlockedWrite(address, 1u);
            return;
        }
        Write8GuestUnchecked(address, value);
    }

    void Write16Guest(std::uint32_t address, std::uint16_t value) {
        if (V91OverlapsRelro(address, 2u)) {
            V91RecordBlockedWrite(address, 2u);
            return;
        }
        if (auto* p = Ptr(address, 2u)) {
            p[0] = static_cast<std::uint8_t>(value);
            p[1] = static_cast<std::uint8_t>(value >> 8u);
        }
    }

    void Write32Guest(std::uint32_t address, std::uint32_t value) {
        if (V91OverlapsRelro(address, 4u)) {
            V91RecordBlockedWrite(address, 4u);
            return;
        }
        Write32GuestUnchecked(address, value);
    }

    void Write64Guest(std::uint32_t address, std::uint64_t value) {
        if (V91OverlapsRelro(address, 8u)) {
            V91RecordBlockedWrite(address, 8u);
            return;
        }
        if (auto* p = Ptr(address, 8u)) {
            for (std::uint32_t i = 0u; i < 8u; ++i) {
                p[i] =
                    static_cast<std::uint8_t>(
                        value >> (i * 8u));
            }
        }
    }

    std::uint32_t AlignHeapOffset(
        std::uint32_t value,
        std::uint32_t alignment) const {

        const std::uint32_t safe_alignment =
            std::max<std::uint32_t>(
                alignment,
                1u);

        const std::uint32_t remainder =
            value % safe_alignment;

        if (remainder == 0u) {
            return value;
        }

        const std::uint64_t aligned =
            static_cast<std::uint64_t>(value) +
            (safe_alignment - remainder);

        return aligned <=
                std::numeric_limits<std::uint32_t>::max()
            ? static_cast<std::uint32_t>(aligned)
            : 0xffffffffu;
    }

    int V91AlignmentClass(
        std::uint32_t alignment) const {

        switch (alignment) {
        case 1u: return 0;
        case 2u: return 1;
        case 4u: return 2;
        case 8u: return 3;
        case 16u: return 4;
        case 32u: return 5;
        case 64u: return 6;
        case 128u: return 7;
        default: return -1;
        }
    }

    std::uint32_t V91ClassAlignment(
        std::size_t klass) const {
        return
            klass <
                kV91AlignmentClassCount
                ? (1u << klass)
                : 1u;
    }

    std::uint32_t V91BlockUsable(
        std::uint32_t offset,
        std::uint32_t size,
        std::uint32_t alignment) const {

        const std::uint32_t aligned =
            AlignHeapOffset(
                offset,
                alignment);

        if (aligned == 0xffffffffu ||
            aligned < offset) {
            return 0u;
        }

        const std::uint32_t prefix =
            aligned - offset;

        return
            prefix <= size
                ? size - prefix
                : 0u;
    }

    void V91BuildAllocatorIndex() {
        if (!v91_allocator_index_enabled) {
            return;
        }

        v91_bucket_count =
            static_cast<std::uint32_t>(
                (heap.size() +
                 kV91BucketSize - 1u) /
                kV91BucketSize);

        v91_tree_base = 1u;
        while (v91_tree_base <
               std::max<std::uint32_t>(
                   v91_bucket_count,
                   1u)) {
            v91_tree_base <<= 1u;
        }

        for (auto& tree : v91_fit_trees) {
            tree.assign(
                static_cast<std::size_t>(
                    v91_tree_base) *
                    2u,
                0u);
        }

        for (const auto& entry :
             heap_free_blocks) {
            const std::uint32_t bucket =
                entry.first >>
                kV91BucketShift;

            if (bucket >=
                v91_bucket_count) {
                continue;
            }

            for (std::size_t klass = 0u;
                 klass <
                     kV91AlignmentClassCount;
                 ++klass) {

                auto& leaf =
                    v91_fit_trees[klass][
                        v91_tree_base +
                        bucket];

                leaf =
                    std::max(
                        leaf,
                        V91BlockUsable(
                            entry.first,
                            entry.second,
                            V91ClassAlignment(
                                klass)));
            }
        }

        for (std::size_t klass = 0u;
             klass <
                 kV91AlignmentClassCount;
             ++klass) {

            auto& tree =
                v91_fit_trees[klass];

            for (std::uint32_t node =
                     v91_tree_base;
                 node-- > 1u;) {
                tree[node] =
                    std::max(
                        tree[node * 2u],
                        tree[node * 2u + 1u]);
            }
        }
    }

    void EnableV91AllocatorIndex(
        bool enabled) {

        v91_allocator_index_enabled =
            enabled;

        if (enabled) {
            V91BuildAllocatorIndex();
        } else {
            for (auto& tree :
                 v91_fit_trees) {
                tree.clear();
            }
            v91_bucket_count = 0u;
            v91_tree_base = 0u;
        }
    }

    void V91RefreshBucket(
        std::uint32_t bucket) {

        if (!v91_allocator_index_enabled ||
            bucket >=
                v91_bucket_count ||
            v91_tree_base == 0u) {
            return;
        }

        ++v91_bucket_refreshes;

        std::array<std::uint32_t,
                   kV91AlignmentClassCount>
            maxima{};

        const std::uint32_t begin =
            bucket <<
            kV91BucketShift;
        const std::uint64_t raw_end =
            static_cast<std::uint64_t>(
                begin) +
            kV91BucketSize;
        const std::uint32_t end =
            static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    raw_end,
                    heap.size()));

        for (auto it =
                 heap_free_blocks.lower_bound(
                     begin);
             it != heap_free_blocks.end() &&
             it->first < end;
             ++it) {

            for (std::size_t klass = 0u;
                 klass <
                     kV91AlignmentClassCount;
                 ++klass) {
                maxima[klass] =
                    std::max(
                        maxima[klass],
                        V91BlockUsable(
                            it->first,
                            it->second,
                            V91ClassAlignment(
                                klass)));
            }
        }

        for (std::size_t klass = 0u;
             klass <
                 kV91AlignmentClassCount;
             ++klass) {

            auto& tree =
                v91_fit_trees[klass];

            std::uint32_t node =
                v91_tree_base +
                bucket;
            tree[node] =
                maxima[klass];

            while (node > 1u) {
                node >>= 1u;
                tree[node] =
                    std::max(
                        tree[node * 2u],
                        tree[node * 2u + 1u]);
            }
        }
    }

    void V91RefreshOffsetBucket(
        std::uint32_t offset) {

        if (v91_allocator_index_enabled) {
            V91RefreshBucket(
                offset >>
                    kV91BucketShift);
        }
    }

    using V91FreeIterator =
        std::map<std::uint32_t,
                 std::uint32_t>::iterator;

    void V91EraseFreeBlock(
        V91FreeIterator it) {

        if (it ==
            heap_free_blocks.end()) {
            return;
        }

        const std::uint32_t offset =
            it->first;
        heap_free_blocks.erase(it);
        V91RefreshOffsetBucket(offset);
    }

    void V91SetFreeBlock(
        std::uint32_t offset,
        std::uint32_t size) {

        heap_free_blocks[offset] =
            size;
        V91RefreshOffsetBucket(offset);
    }

    V91FreeIterator V91FindFirstFit(
        std::uint32_t requested,
        std::uint32_t alignment,
        std::uint64_t& scan_steps) {

        const int klass =
            V91AlignmentClass(
                alignment);

        if (!v91_allocator_index_enabled ||
            klass < 0 ||
            v91_tree_base == 0u) {

            if (v91_allocator_index_enabled) {
                ++v91_index_fallbacks;
            }

            for (auto it =
                     heap_free_blocks.begin();
                 it !=
                     heap_free_blocks.end();
                 ++it) {

                if (v90_allocator_profile) {
                    ++scan_steps;
                }

                if (V91BlockUsable(
                        it->first,
                        it->second,
                        alignment) >=
                    requested) {
                    return it;
                }
            }

            return heap_free_blocks.end();
        }

        ++v91_index_queries;

        const auto& tree =
            v91_fit_trees[
                static_cast<std::size_t>(
                    klass)];

        if (tree.size() <= 1u ||
            tree[1u] <
                requested) {
            return heap_free_blocks.end();
        }

        std::uint32_t node = 1u;

        while (node <
               v91_tree_base) {

            const std::uint32_t left =
                node * 2u;

            if (tree[left] >=
                requested) {
                node = left;
            } else {
                node = left + 1u;
            }
        }

        const std::uint32_t bucket =
            node -
            v91_tree_base;

        if (bucket >=
            v91_bucket_count) {
            ++v91_index_inconsistencies;
            ++v91_index_fallbacks;
            return heap_free_blocks.end();
        }

        const std::uint32_t begin =
            bucket <<
            kV91BucketShift;
        const std::uint64_t raw_end =
            static_cast<std::uint64_t>(
                begin) +
            kV91BucketSize;
        const std::uint32_t end =
            static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    raw_end,
                    heap.size()));

        std::uint64_t local_scan = 0u;

        for (auto it =
                 heap_free_blocks.lower_bound(
                     begin);
             it != heap_free_blocks.end() &&
             it->first < end;
             ++it) {

            if (v90_allocator_profile) {
                ++scan_steps;
            }
            ++local_scan;

            if (V91BlockUsable(
                    it->first,
                    it->second,
                    alignment) >=
                requested) {

                ++v91_index_hits;
                v91_local_scan_total +=
                    local_scan;
                v91_local_scan_max =
                    std::max(
                        v91_local_scan_max,
                        local_scan);
                return it;
            }
        }

        // A segment-tree candidate must contain a fitting start-address block.
        // Never trade correctness for speed: if the index ever disagrees,
        // count it and fall back to the exact legacy scan.
        ++v91_index_inconsistencies;
        ++v91_index_fallbacks;

        for (auto it =
                 heap_free_blocks.begin();
             it !=
                 heap_free_blocks.end();
             ++it) {

            ++scan_steps;

            if (V91BlockUsable(
                    it->first,
                    it->second,
                    alignment) >=
                requested) {
                return it;
            }
        }

        return heap_free_blocks.end();
    }

    std::string V91AllocatorIndexSummary() const {
        std::ostringstream out;
        out << std::fixed
            << std::setprecision(3)
            << "V91 INDEX SUMMARY"
            << " enabled="
            << (v91_allocator_index_enabled
                    ? "YES"
                    : "NO")
            << " queries="
            << v91_index_queries
            << " hits="
            << v91_index_hits
            << " fallbacks="
            << v91_index_fallbacks
            << " inconsistencies="
            << v91_index_inconsistencies
            << " localScanTotal="
            << v91_local_scan_total
            << " localScanAvg="
            << (v91_index_hits != 0u
                    ? static_cast<double>(
                          v91_local_scan_total) /
                          static_cast<double>(
                              v91_index_hits)
                    : 0.0)
            << " localScanMax="
            << v91_local_scan_max
            << " bucketRefreshes="
            << v91_bucket_refreshes
            << " buckets="
            << v91_bucket_count;
        return out.str();
    }

    void InsertFreeHeapBlock(
        std::uint32_t offset,
        std::uint32_t size) {

        if (size == 0u) {
            return;
        }

        auto next =
            heap_free_blocks.lower_bound(offset);

        if (next !=
            heap_free_blocks.begin()) {

            auto previous =
                std::prev(next);

            if (previous->first +
                    previous->second ==
                offset) {

                offset =
                    previous->first;
                size +=
                    previous->second;
                V91EraseFreeBlock(
                    previous);
            }
        }

        next =
            heap_free_blocks.lower_bound(offset);

        if (next !=
                heap_free_blocks.end() &&
            offset + size ==
                next->first) {

            size +=
                next->second;
            V91EraseFreeBlock(next);
        }

        V91SetFreeBlock(
            offset,
            size);

        while (!heap_free_blocks.empty()) {
            auto tail =
                std::prev(
                    heap_free_blocks.end());

            if (tail->first +
                    tail->second !=
                heap_next) {
                break;
            }

            heap_next =
                tail->first;
            V91EraseFreeBlock(tail);
        }
    }

    std::uint32_t AllocateHeap(
        std::uint32_t size,
        std::uint32_t alignment = 16) {

        const std::uint32_t requested =
            std::max<std::uint32_t>(
                size,
                1u);
        const std::uint32_t safe_alignment =
            std::max<std::uint32_t>(
                alignment,
                1u);

        const std::uint64_t profile_call =
            v90_allocator_profile
                ? ++v90_alloc_calls_internal
                : 0u;
        const bool sampled =
            v90_allocator_profile &&
            (profile_call & 0x3ffu) == 1u;
        const std::uint64_t sample_begin_ns =
            sampled
                ? V90AllocatorNowNs()
                : 0u;
        std::uint64_t scan_steps = 0u;

        V91FreeIterator it =
            V91FindFirstFit(
                requested,
                safe_alignment,
                scan_steps);

        if (it !=
            heap_free_blocks.end()) {

            const std::uint32_t block_begin =
                it->first;
            const std::uint32_t block_size =
                it->second;
            const std::uint32_t aligned =
                AlignHeapOffset(
                    block_begin,
                    safe_alignment);
            const std::uint32_t prefix =
                aligned -
                block_begin;
            const std::uint32_t block_end =
                block_begin +
                block_size;
            const std::uint32_t allocation_end =
                aligned +
                requested;

            V91EraseFreeBlock(it);

            if (prefix != 0u) {
                V91SetFreeBlock(
                    block_begin,
                    prefix);
            }

            if (allocation_end <
                block_end) {
                V91SetFreeBlock(
                    allocation_end,
                    block_end -
                        allocation_end);
            }

            const std::uint32_t address =
                kJniProbeHeapBase +
                aligned;

            heap_allocations[address] =
                requested;
            heap_live_bytes +=
                requested;

            V90FinishAllocProfile(
                scan_steps,
                true,
                sampled,
                sample_begin_ns);
            return address;
        }

        const std::uint32_t aligned =
            AlignHeapOffset(
                heap_next,
                safe_alignment);

        const std::uint32_t heap_capacity =
            HeapCapacity();

        if (aligned == 0xffffffffu ||
            aligned > heap_capacity ||
            requested >
                heap_capacity -
                    aligned) {

            V90FinishAllocProfile(
                scan_steps,
                false,
                sampled,
                sample_begin_ns);
            return 0u;
        }

        heap_next =
            aligned +
            requested;
        heap_high_water =
            std::max(
                heap_high_water,
                heap_next);

        const std::uint32_t address =
            kJniProbeHeapBase +
            aligned;

        heap_allocations[address] =
            requested;
        heap_live_bytes +=
            requested;

        V90FinishAllocProfile(
            scan_steps,
            false,
            sampled,
            sample_begin_ns);

        return address;
    }

    std::uint32_t ReallocateHeap(
        std::uint32_t old_address,
        std::uint32_t new_size) {

        if (old_address == 0) {
            return AllocateHeap(
                new_size,
                16);
        }

        if (new_size == 0) {
            FreeHeap(old_address);
            return 0;
        }

        const auto old_it =
            heap_allocations.find(
                old_address);

        if (old_it ==
            heap_allocations.end()) {
            return AllocateHeap(
                new_size,
                16);
        }

        const std::uint32_t old_size =
            old_it->second;
        const std::uint32_t requested =
            std::max<std::uint32_t>(
                new_size,
                1u);

        if (requested <= old_size) {
            const std::uint32_t released =
                old_size - requested;

            old_it->second =
                requested;
            heap_live_bytes -=
                released;

            if (released != 0u) {
                InsertFreeHeapBlock(
                    old_address -
                        kJniProbeHeapBase +
                        requested,
                    released);
            }

            return old_address;
        }

        const std::uint32_t new_address =
            AllocateHeap(
                requested,
                16);

        if (!new_address) {
            return 0;
        }

        auto* dst =
            Ptr(
                new_address,
                old_size);
        const auto* src =
            Ptr(
                old_address,
                old_size);

        if (dst && src) {
            std::memmove(
                dst,
                src,
                old_size);
        }

        FreeHeap(old_address);

        return new_address;
    }

    void FreeHeap(std::uint32_t address) {
        const std::uint64_t profile_call =
            v90_allocator_profile
                ? ++v90_free_calls_internal
                : 0u;
        const bool sampled =
            v90_allocator_profile &&
            (profile_call & 0x3ffu) == 1u;
        const std::uint64_t sample_begin_ns =
            sampled
                ? V90AllocatorNowNs()
                : 0u;

        const auto it =
            heap_allocations.find(address);

        if (it == heap_allocations.end()) {
            if (sampled) {
                const std::uint64_t elapsed =
                    V90AllocatorNowNs() -
                    sample_begin_ns;
                ++v90_free_sample_count;
                v90_free_sample_ns += elapsed;
                v90_free_sample_max_ns =
                    std::max(
                        v90_free_sample_max_ns,
                        elapsed);
            }
            return;
        }

        const std::uint32_t size =
            it->second;
        heap_allocations.erase(it);

        if (heap_live_bytes >= size) {
            heap_live_bytes -= size;
        } else {
            heap_live_bytes = 0;
        }

        InsertFreeHeapBlock(
            address - kJniProbeHeapBase,
            size);
        V90ObserveFreeBlocks();

        if (sampled) {
            const std::uint64_t elapsed =
                V90AllocatorNowNs() -
                sample_begin_ns;
            ++v90_free_sample_count;
            v90_free_sample_ns += elapsed;
            v90_free_sample_max_ns =
                std::max(
                    v90_free_sample_max_ns,
                    elapsed);
        }
    }

    std::uint32_t HeapCapacity() const {
        return static_cast<std::uint32_t>(
            std::min<std::size_t>(
                heap.size(),
                std::numeric_limits<std::uint32_t>::max()));
    }

    std::uint32_t HeapHighWater() const {
        return heap_high_water;
    }

    std::uint32_t HeapLiveBytes() const {
        return heap_live_bytes;
    }

    std::uint32_t HeapLiveAllocations() const {
        return static_cast<std::uint32_t>(
            std::min<std::size_t>(
                heap_allocations.size(),
                std::numeric_limits<std::uint32_t>::max()));
    }

    std::uint32_t AllocateObject(
        std::uint32_t size,
        std::uint32_t alignment = 8) {

        const std::uint32_t aligned =
            (object_next + alignment - 1) & ~(alignment - 1);

        if (aligned > kJniProbeObjectSize ||
            size > kJniProbeObjectSize - aligned) {
            return 0;
        }

        object_next = aligned + size;
        return kJniProbeObjectBase + aligned;
    }

    std::string ReadCStringGuest(
        std::uint32_t address,
        std::size_t max_length = 512) const {

        std::string result;
        result.reserve(64);

        for (std::size_t i = 0; i < max_length; ++i) {
            const char ch =
                static_cast<char>(
                    Read8(address + static_cast<std::uint32_t>(i)));

            if (ch == '\0') {
                break;
            }

            result.push_back(ch);
        }

        return result;
    }

    std::vector<std::uint32_t> ReadWStringGuest(
        std::uint32_t address,
        std::size_t max_length = 4096) const {

        std::vector<std::uint32_t> result;
        result.reserve(
            std::min<std::size_t>(
                max_length,
                128));

        for (std::size_t i = 0;
             i < max_length;
             ++i) {

            const std::uint32_t ch =
                Read32Guest(
                    address +
                    static_cast<std::uint32_t>(i * 4u));

            if (ch == 0) {
                break;
            }

            result.push_back(ch);
        }

        return result;
    }

    bool WriteWStringGuest(
        std::uint32_t address,
        const std::vector<std::uint32_t>& value,
        std::size_t capacity) {

        if (capacity == 0) {
            return false;
        }

        const std::size_t count =
            std::min(
                value.size(),
                capacity - 1);

        if (!Ptr(address, capacity * 4u)) {
            return false;
        }

        for (std::size_t i = 0;
             i < count;
             ++i) {

            Write32Guest(
                address +
                    static_cast<std::uint32_t>(i * 4u),
                value[i]);
        }

        Write32Guest(
            address +
                static_cast<std::uint32_t>(count * 4u),
            0);

        return true;
    }
};

struct JniProbeImportBinding {
    std::uint32_t trampoline = 0;
    std::string name;
};

std::string JniProbeHex(std::uint32_t value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(8, '0');

    for (int i = 7; i >= 0; --i) {
        result[static_cast<std::size_t>(i)] =
            digits[value & 0x0fu];
        value >>= 4;
    }

    return result;
}

class PvZ2JniCallbacks final :
    public Dynarmic::A32::UserCallbacks {

public:
    PvZ2JniCallbacks(
        JniProbeGuestMemory& memory,
        PvZ2JniProbeResult& output,
        PvZ2ProbeProgress progress = {},
        const std::uint8_t* expansion_data = nullptr,
        std::size_t expansion_size = 0,
        PvZ2DiagnosticMode mode =
            PvZ2DiagnosticMode::PassiveRegistry)
        : mem(memory),
          result(output),
          progress_callback(std::move(progress)),
          obb_data(expansion_data),
          obb_size(expansion_size),
          diagnostic_mode(mode),
          diagnostic_capabilities(
              PvZ2DiagnosticModeCapabilityMask(mode)) {}

    Dynarmic::A32::Jit* jit = nullptr;
    const JniProbeLoadedElf* loaded_elf = nullptr;
    std::unordered_map<std::uint32_t, JniProbeImportBinding>
        imports_by_svc;

    struct V91ProtectedImport {
        std::uint32_t expected = 0u;
        std::string name;
        std::uint32_t relocation_type = 0u;
    };

    std::map<std::uint32_t, V91ProtectedImport>
        v91_protected_imports;
    std::uint32_t v91_relro_begin = 0u;
    std::uint32_t v91_relro_end = 0u;
    bool v91_relro_armed = false;
    std::uint64_t v91_relro_write_attempts = 0u;
    std::uint64_t v91_integrity_repairs = 0u;
    bool v91_first_relro_write_seen = false;
    std::uint32_t v91_first_write_pc = 0u;
    std::uint32_t v91_first_write_lr = 0u;
    std::uint32_t v91_first_write_tid = 0u;
    std::uint32_t v91_first_write_dst = 0u;
    std::uint32_t v91_first_write_size = 0u;
    std::uint64_t v91_first_write_value = 0u;
    bool v91_first_write_value_known = false;
    std::string v91_first_write_kind;
    std::string v91_first_write_phase;
    std::uint32_t v91_free_got = 0u;
    std::uint32_t v91_free_expected = 0u;
    bool v91_terminal_summary_emitted = false;

    // v93: non-invasive provenance for the exact delete->free chain whose
    // caller returns through POP {...,pc} at 0x10868b30. At the free SVC the
    // caller's saved PC is still present at SP+36. Capture it before and after
    // host FreeHeap without modifying guest stack/code.
    std::uint64_t v93_target_free_calls = 0u;
    std::uint64_t v93_odd_saved_pc_calls = 0u;
    std::uint64_t v93_invalid_saved_pc_calls = 0u;
    std::uint64_t v93_saved_pc_changed_by_free = 0u;
    bool v93_last_sample_valid = false;
    std::uint32_t v93_last_frame = 0u;
    std::uint32_t v93_last_free_ptr = 0u;
    std::uint32_t v93_last_sp = 0u;
    std::uint32_t v93_last_lr = 0u;
    std::uint32_t v93_last_cpsr = 0u;
    std::uint32_t v93_last_saved_pc_before = 0u;
    std::uint32_t v93_last_saved_pc_after = 0u;
    std::uint32_t v93_last_stack_base = 0u;
    std::array<std::uint32_t, 16> v93_last_stack_words{};
    bool v93_last_exception_valid = false;
    std::uint32_t v93_last_exception_pc = 0u;
    std::uint32_t v93_last_exception_sp = 0u;
    std::uint32_t v93_last_exception_cpsr = 0u;
    std::uint32_t v93_last_exception_sp_minus_4 = 0u;

    // v94: provenance for the caller frame above v93's clean inner frame.
    std::uint64_t v94_wrapper_entries = 0u;
    std::uint64_t v94_watched_guest_writes = 0u;
    bool v94_watch_armed = false;
    std::uint32_t v94_watch_slot = 0u;
    std::uint32_t v94_entry_lr = 0u;
    std::uint32_t v94_last_outer_at_free = 0u;
    bool v94_first_change_seen = false;
    std::uint32_t v94_first_change_frame = 0u;
    std::uint32_t v94_first_change_slot = 0u;
    std::uint32_t v94_first_change_address = 0u;
    std::uint32_t v94_first_change_width = 0u;
    std::uint32_t v94_first_change_old = 0u;
    std::uint32_t v94_first_change_new = 0u;
    std::uint32_t v94_first_change_pc = 0u;
    std::uint32_t v94_first_change_lr = 0u;
    std::uint32_t v94_first_change_sp = 0u;
    std::uint32_t v94_first_change_cpsr = 0u;
    std::uint32_t v94_first_change_tid = 0u;
    std::string v94_first_change_phase;

    enum class ReturnMode {
        JniOnLoad,
        Constructor,
        GameAppInitialize,
        Lifecycle,
        AudioCallback,
    };

    std::uint32_t vm_object = 0;
    std::uint32_t env_object = 0;
    std::uint32_t supported_calls = 0;
    std::uint64_t ticks_left = 1000000;
    std::uint64_t ticks_consumed = 0;
    std::uint64_t next_tick_report = 5000000;
    ReturnMode return_mode = ReturnMode::JniOnLoad;
    bool control_returned = false;
    std::uint32_t current_constructor_index = 0;
    struct DeferredThread {
        std::uint32_t id = 0;
        std::uint32_t start_routine = 0;
        std::uint32_t argument = 0;
        std::string created_in;
        bool runtime_started = false;
        bool runtime_completed = false;
        bool runtime_failed = false;
        std::uint32_t stack_top = 0;
        std::array<std::uint32_t, 16> regs{};
        std::array<std::uint32_t, 64> ext_regs{};
        std::uint32_t cpsr = 0x10u;
        std::uint32_t fpscr = 0u;
        std::uint64_t runtime_ticks = 0;
    };

    std::uint32_t current_constructor_address = 0;
    std::string current_lifecycle_name;
    std::vector<DeferredThread> deferred_threads;
    std::uint32_t current_probe_thread_id = 0;
    bool soft_slice_timeout = false;

    // v99 OpenSL ES / Wwise audio bridge. These are guest addresses: OpenSL
    // interface handles are one-word cells that point to guest vtables whose
    // methods enter this callback object through ordinary import SVC trampolines.
    std::unordered_map<std::string, std::uint32_t> v99_opensl_iids;
    std::unordered_map<std::string, std::uint32_t> v99_opensl_methods;
    std::uint32_t v99_engine_object = 0u;
    std::uint32_t v99_output_mix_object = 0u;
    std::uint32_t v99_player_object = 0u;
    std::uint32_t v99_engine_itf = 0u;
    std::uint32_t v99_play_itf = 0u;
    std::uint32_t v99_queue_itf = 0u;
    std::uint32_t v99_config_itf = 0u;
    std::uint32_t v99_caps_itf = 0u;
    std::uint32_t v99_audio_rate_array = 0u;
    std::uint32_t v99_queue_callback = 0u;
    std::uint32_t v99_queue_context = 0u;
    std::uint32_t v99_audio_sample_rate = 48000u;
    std::uint32_t v99_audio_channels = 2u;
    std::uint32_t v99_audio_queue_capacity = 4u;
    std::uint32_t v99_play_state = 1u;
    bool v99_audio_configured = false;
    std::uint64_t v99_engine_create_calls = 0u;
    std::uint64_t v99_audio_enqueues = 0u;
    std::uint64_t v99_audio_getstate_calls = 0u;
    std::uint64_t v99_audio_clears = 0u;
    std::uint64_t v99_audio_host_consumed = 0u;
    std::uint64_t v99_audio_pending_callbacks = 0u;
    std::uint64_t v99_audio_callback_deliveries = 0u;
    std::uint64_t v99_audio_interface_misses = 0u;

    // v102: CoreAudio is the clock source, but guest execution remains confined
    // to the Dynarmic scheduler thread. AddTicks polls the atomic host completion
    // total at a bounded cadence and requests a soft scheduler checkpoint. The
    // actual OpenSL callback runs there on a private stack with a distinct guest
    // thread id; it is never entered from the CoreAudio render callback.
    bool v102_audio_service_requested = false;
    bool v102_audio_forced_halt_pending = false;
    bool v102_audio_inline_active = false;
    std::uint32_t v102_audio_callback_stack_top = 0u;
    std::uint64_t v102_audio_poll_ticks = 0u;
    std::uint64_t v102_audio_forced_slices = 0u;
    std::uint64_t v102_audio_inline_services = 0u;
    std::uint64_t v102_audio_inline_callbacks = 0u;
    std::uint64_t v102_audio_sink_busy_deferrals = 0u;
    std::uint64_t v102_audio_play_begin_ns = 0u;

    // v104: the real Wwise audio producer is CAkAudioThread::EventMgrThreadFunc
    // (libPVZ2.so+0x00bfdb70). OpenSL completion wakes its semaphore; v104 then
    // gives that exact deferred worker the next cooperative slice before another
    // completion can be delivered. PCM hashes prove whether stale non-zero
    // blocks are still being recycled by the sink starvation path.
    std::uint32_t v104_audio_worker_tid = 0u;
    std::uint64_t v104_audio_worker_handshakes = 0u;
    std::uint64_t v104_audio_worker_misses = 0u;
    std::uint32_t v104_pcm_prev_hash = 0u;
    bool v104_pcm_prev_nonzero = false;
    std::uint64_t v104_pcm_repeat_run = 0u;
    std::uint64_t v104_pcm_repeat_total = 0u;

    // v124: exact provenance, but only in the two broad user-observed crackle
    // windows. Full-buffer hashing is intentionally bounded to those windows.
    bool v124_prev_exact_valid = false;
    std::uint64_t v124_prev_exact_hash = 0u;
    std::uint32_t v124_prev_exact_buffer = 0u;
    std::uint32_t v124_prev_exact_bytes = 0u;
    std::uint32_t v124_prev_exact_frame = 0u;
    bool v124_prev_exact_nonzero = false;
    std::uint64_t v124_exact_repeat_total = 0u;
    std::uint64_t v124_exact_repeat_same_buffer = 0u;
    std::uint64_t v124_exact_repeat_different_buffer = 0u;
    std::uint64_t v124_anim_exact_repeats = 0u;
    std::uint64_t v124_anim_same_buffer = 0u;
    std::uint64_t v124_anim_different_buffer = 0u;
    std::uint32_t v124_anim_first_repeat_frame = 0u;
    std::uint32_t v124_anim_last_repeat_frame = 0u;
    std::uint64_t v124_late_exact_repeats = 0u;
    std::uint64_t v124_late_same_buffer = 0u;
    std::uint64_t v124_late_different_buffer = 0u;
    std::uint32_t v124_late_first_repeat_frame = 0u;
    std::uint32_t v124_late_last_repeat_frame = 0u;
    std::array<std::uint64_t, 5> v124_exact_repeat_queue_depth{};

    // v125: bounded context classification for v124 exact repeats.
    std::uint64_t v125_repeat_events = 0u;
    std::uint64_t v125_repeat_from_audio_callback = 0u;
    std::uint64_t v125_repeat_from_audio_worker = 0u;
    std::uint64_t v125_repeat_from_main = 0u;
    std::uint64_t v125_repeat_from_other_worker = 0u;
    std::uint64_t v125_repeat_with_pending_callback = 0u;
    std::uint64_t v125_repeat_without_pending_callback = 0u;
    std::uint64_t v125_repeat_log_count = 0u;

    // v126: bounded in-memory audio flight recorder. Static ARM analysis of
    // CAkSinkOpenSL::EnqueueBufferCallback proves two OpenSL Enqueue callsites:
    // LR=0x10bb0328 consumes a fresh 1024-frame sink block, while
    // LR=0x10bb0404 is the queue-empty starvation fallback that re-enqueues the
    // current read slot without advancing +0x10 or decrementing +0x18.
    enum class V126FlightEventKind : std::uint8_t {
        HostCompletionInline,
        InlineCallbackPre,
        Enqueue,
        QueueGetState,
        InlineCallbackPost,
        WorkerPre,
        WorkerPost,
        HostCompletionBoundary,
        BoundaryCallbackPre,
        BoundaryCallbackPost,
        BoundaryWorkerSelected,
        BoundaryAudioWorkerPre,
        BoundaryAudioWorkerPost,
    };

    struct V126SinkSnapshot {
        bool valid = false;
        std::uint32_t channel_mask = 0u;
        std::uint32_t channel_count = 0u;
        std::uint32_t read_index = 0u;
        std::uint32_t capacity_frames = 0u;
        std::uint32_t available_frames = 0u;
        std::uint32_t ring_base = 0u;
        std::uint8_t starved = 0u;
        std::uint32_t platform_buffer_count = 0u;
        std::uint32_t silence_run = 0u;
        std::uint32_t enqueue_success_count = 0u;
        std::uint8_t playing = 0u;
        std::uint32_t slot_bytes = 0u;
        std::uint32_t slot_count = 0u;
        bool slot_hashes_valid = false;
        std::array<std::uint64_t, 4> slot_hashes{};
    };

    struct V126FlightEvent {
        std::uint64_t seq = 0u;
        std::uint64_t time_us = 0u;
        V126FlightEventKind kind = V126FlightEventKind::Enqueue;
        std::uint32_t frame = 0u;
        std::uint32_t tid = 0u;
        std::uint32_t pc = 0u;
        std::uint32_t lr = 0u;
        std::uint64_t callback_deliveries = 0u;
        std::uint64_t host_consumed = 0u;
        std::uint64_t pending_callbacks = 0u;
        std::uint64_t worker_handshakes = 0u;
        std::uint64_t correlation = 0u;
        std::uint32_t host_completed_delta = 0u;
        std::uint32_t host_queue_before = 0u;
        std::uint32_t host_queue_after = 0u;
        V126SinkSnapshot sink{};
        std::uint32_t buffer = 0u;
        std::uint32_t bytes = 0u;
        std::uint64_t buffer_hash = 0u;
        std::uint32_t slot_index = 0xffffffffu;
        std::uint8_t enqueue_path = 0u;
        std::uint8_t enqueue_result = 0u;
        bool exact_repeat = false;
        std::uint8_t getstate_source = 0u;
        std::uint8_t boundary_phase = 0u; // 1=pre-frame, 2=frame-boundary.
        std::uint32_t computed_needed_buffers = 0u;
        std::uint32_t worker_changed_slot_mask = 0u;
        std::int32_t worker_available_delta = 0;
        std::uint64_t worker_elapsed_ns = 0u;
    };

    // ~10 MiB worst case with four ring hashes/event; enough headroom to keep
    // both crackle windows instead of filling the recorder during window #1.
    static constexpr std::size_t kV126FlightCapacity = 65536u;
    std::vector<V126FlightEvent> v126_flight_events;
    std::uint64_t v126_flight_seq = 0u;
    std::uint64_t v126_flight_origin_ns = 0u;
    std::uint64_t v126_flight_dropped = 0u;
    std::uint64_t v126_host_completion_events = 0u;
    std::uint64_t v126_host_completed_buffers = 0u;
    std::uint64_t v126_inline_callbacks = 0u;
    std::uint64_t v126_boundary_callbacks = 0u;
    std::uint64_t v126_enqueue_fresh = 0u;
    std::uint64_t v126_enqueue_starvation = 0u;
    std::uint64_t v126_enqueue_other = 0u;
    std::uint64_t v126_enqueue_rejected = 0u;
    std::uint64_t v126_exact_repeat_fresh = 0u;
    std::uint64_t v126_exact_repeat_starvation = 0u;
    std::uint64_t v126_exact_repeat_other = 0u;
    std::uint64_t v126_getstate_producer = 0u;
    std::uint64_t v126_getstate_callback = 0u;
    std::uint64_t v126_getstate_other = 0u;
    std::uint64_t v126_producer_needed_total = 0u;
    std::uint32_t v126_producer_needed_max = 0u;
    std::uint64_t v126_worker_rounds = 0u;
    std::uint64_t v126_worker_produced = 0u;
    std::uint64_t v126_worker_no_production = 0u;
    std::uint64_t v126_worker_total_ns = 0u;
    std::uint64_t v126_worker_max_ns = 0u;
    std::uint64_t v126_handoff_worker_rounds = 0u;
    std::uint64_t v126_handoff_worker_produced = 0u;
    std::uint64_t v126_handoff_worker_no_production = 0u;
    std::uint64_t v126_boundary_worker_selected = 0u;
    std::uint64_t v126_boundary_audio_worker_rounds = 0u;
    std::uint64_t v126_boundary_audio_worker_produced = 0u;
    std::uint64_t v126_boundary_audio_worker_no_production = 0u;
    std::uint32_t v126_ring_hash_rounds_remaining = 0u;
    std::uint64_t v126_ring_hash_rounds = 0u;
    std::uint32_t v126_anim_first_starvation_frame = 0u;
    std::uint32_t v126_anim_last_starvation_frame = 0u;
    std::uint32_t v126_late_first_starvation_frame = 0u;
    std::uint32_t v126_late_last_starvation_frame = 0u;
    bool v126_worker_pre_valid = false;
    V126SinkSnapshot v126_worker_pre_snapshot{};
    std::array<std::uint64_t, 5> v126_anim_inspector_ticks{};
    std::array<std::uint64_t, 5> v126_late_inspector_ticks{};

    // v127: count functional audio handoff continuations and where each
    // callback-triggered drain actually terminates.
    std::uint64_t v127_audio_drain_rounds = 0u;
    std::uint64_t v127_audio_drain_continuations = 0u;
    std::uint64_t v127_audio_drain_reached_sem_wait = 0u;
    std::uint64_t v127_audio_drain_blocked_other = 0u;
    std::uint64_t v127_audio_drain_caps = 0u;

    // v105: observe Wwise resampler state without changing audio semantics.
    // These sites are lifecycle/configuration paths rather than Execute(), so
    // the probe avoids adding an SVC to every mixed audio block.
    std::uint64_t v105_resampler_init_calls = 0u;
    std::uint64_t v105_set_pitch_calls = 0u;
    std::uint64_t v105_switch_to_calls = 0u;

    // v106: identify the real CAkBankMgr worker and prefer it when the main
    // thread is synchronously waiting inside AK::SoundEngine::UnloadBank.
    std::uint32_t v106_bank_worker_tid = 0u;
    std::uint32_t v106_bank_worker_object = 0u;
    std::uint64_t v106_bank_wait_priorities = 0u;

    // v107: semaphore bookkeeping is represented by an authoritative wait map
    // plus a FIFO index. The iPad v106 run proved BankMgr stayed asleep despite
    // QueueBankCommand having an explicit sem_post path, so count repairs and
    // exact BankMgr wake diagnostics live here.
    std::uint64_t v107_sem_index_repairs = 0u;
    std::uint64_t v107_stale_sem_wait_repairs = 0u;
    std::uint64_t v107_stale_mutex_wait_repairs = 0u;
    std::uint64_t v107_bank_wake_posts = 0u;
    std::uint64_t v107_bank_wake_waits = 0u;

    // v108: the final v107 transition stall proved that BankMgr dequeues the
    // command but synchronous UnloadBank never receives DefaultBankCallbackFunc.
    // Track the real CAkUsageSlot teardown and CAkAudioThread event semaphore.
    std::uint32_t v108_audio_event_sem = 0u;
    std::uint32_t v108_active_kill_slot = 0u;
    bool v108_active_kill_msg_seen = false;
    std::uint64_t v108_kill_slot_calls = 0u;
    std::uint64_t v108_kill_msg_calls = 0u;
    std::uint64_t v108_slot_release_calls = 0u;
    std::uint64_t v108_completion_notifications = 0u;
    std::uint64_t v108_default_bank_callbacks = 0u;
    std::uint64_t v108_audio_event_posts = 0u;
    std::uint64_t v108_audio_event_waits = 0u;
    std::uint64_t v108_audio_liveness_pulses = 0u;
    std::uint64_t v108_last_audio_liveness_pulse_ns = 0u;

    // v61 safe cooperative boundary. Set only by the main Native_onDrawFrame
    // thread when the verified resource-stream pump has completed its
    // pthread_mutex_unlock. The lifecycle scheduler consumes it exactly once.
    bool v61_res_stream_pump_signature_ok = false;
    bool v61_res_stream_pump_boundary_pending = false;
    std::uint64_t v61_res_stream_pump_yields = 0;

    struct V62WorkerPayload {
        std::uint32_t entry = 0;
        std::uint32_t object = 0;
        std::uint32_t sentinel30 = 0;
    };
    std::unordered_map<std::uint32_t, V62WorkerPayload> v62_worker_payloads;
    std::uint32_t v62_tid1_sentinel = 0;
    std::uint32_t v62_pump_manager = 0;
    std::uint32_t v62_pump_mutex = 0;
    std::uint32_t v62_pump_vector_begin = 0;
    std::uint32_t v62_pump_vector_end = 0;
    std::uint32_t v62_pump_vector_cap = 0;
    bool v62_pump_mutex_locked = false;
    std::uint32_t v62_pump_mutex_owner = 0xffffffffu;
    std::uint64_t v62_pump_mutex_acquires = 0;
    std::uint64_t v62_pump_mutex_releases = 0;
    std::uint64_t v62_pump_mutex_contentions = 0;
    std::uint64_t v62_mutex_coherence_continuations = 0;
    std::uint64_t v62_pointer_write_events = 0;
    std::uint64_t v62_task_dispatch_events = 0;
    bool v62_first_bad_pointer_writer_seen = false;
    std::uint32_t v62_first_bad_pointer_writer_pc = 0;
    std::uint32_t v62_first_bad_pointer_writer_lr = 0;
    std::uint32_t v62_first_bad_pointer_writer_dst = 0;

    struct V63MutexState {
        std::uint32_t owner = 0xffffffffu;
        std::uint32_t depth = 0u;
        // Bionic 4.x uses 0=normal, 1=recursive, 2=error-checking. Static
        // mutexes remain type_unknown and keep the proven legacy recursive
        // compatibility until their initializer is observed.
        std::uint32_t type = 1u;
        bool type_known = false;
    };
    std::unordered_map<std::uint32_t, V63MutexState> v63_mutexes;
    std::unordered_map<std::uint32_t, std::uint32_t> v63_thread_held_mutexes;
    std::uint64_t v63_mutex_acquires = 0;
    std::uint64_t v63_mutex_releases = 0;
    std::uint64_t v63_mutex_busy = 0;
    std::uint64_t v63_mutex_conflicts = 0;
    std::uint64_t v63_critical_continuations = 0;
    std::uint64_t v63_task_dispatch_events = 0;
    std::uint64_t v63_task_guard_failures = 0;

    struct V87MutexWaitState {
        std::uint32_t mutex = 0u;
        std::uint32_t observed_owner = 0xffffffffu;
        bool granted = false;
        bool cond_reacquire = false;
    };
    std::unordered_map<std::uint32_t, std::uint32_t> v87_mutexattr_types;
    std::unordered_map<std::uint32_t, V87MutexWaitState> v87_mutex_waits;
    std::unordered_map<std::uint32_t, std::deque<std::uint32_t>> v87_mutex_waiters;
    std::uint64_t v87_mutex_wait_calls = 0u;
    std::uint64_t v87_mutex_handoffs = 0u;
    std::uint64_t v87_mutex_resumes = 0u;
    std::uint64_t v87_owner_preemptions = 0u;
    std::uint64_t v87_priority_continuations = 0u;
    std::uint64_t v88_burst_continuations = 0u;
    std::uint64_t v87_deadlock_cycles = 0u;
    std::uint64_t v97_granted_graph_terminals = 0u;
    std::uint32_t v87_last_mutex_error = 0u;
    std::string v87_failure_message;

    // v64 release-boundary continuation. Once a worker exhausts its normal
    // quantum while owning a guest mutex, the scheduler arms this boundary.
    // The first later unlock that takes the worker's held-mutex count to zero
    // halts Dynarmic with the ordinary soft-slice reason before guest code can
    // reacquire and phase-lock with another fixed quantum.
    bool v64_release_boundary_armed = false;
    std::uint32_t v64_release_boundary_thread = 0xffffffffu;
    std::uint64_t v64_release_boundary_arms = 0;
    std::uint64_t v64_release_boundary_yields = 0;

    struct V65CondWaitState {
        std::uint32_t cond = 0u;
        std::uint32_t mutex = 0u;
        bool timed = false;
        bool notified = false;
        std::uint64_t deadline_realtime_ns = 0u;
        std::uint32_t result_code = 0u;
    };
    std::unordered_map<std::uint32_t, V65CondWaitState>
        v65_cond_waits;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>
        v65_cond_waiters;
    std::uint64_t v65_cond_wait_calls = 0u;
    std::uint64_t v65_cond_wake_calls = 0u;
    std::uint64_t v65_cond_resumes = 0u;
    std::uint64_t v65_cond_timeouts = 0u;

    struct V66SemaphoreWaitState {
        std::uint32_t sem = 0u;
        bool timed = false;
        bool notified = false;
        std::uint64_t deadline_realtime_ns = 0u;
    };
    struct V66SleepState {
        std::uint64_t deadline_steady_ns = 0u;
    };
    std::unordered_map<std::uint32_t, V66SemaphoreWaitState>
        v66_sem_waits;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>
        v66_sem_waiters;
    std::unordered_map<std::uint32_t, V66SleepState>
        v66_sleeps;
    std::uint64_t v66_sem_wait_calls = 0u;
    std::uint64_t v66_sem_posts = 0u;
    std::uint64_t v66_sem_resumes = 0u;
    std::uint64_t v66_sem_timeouts = 0u;
    std::uint64_t v66_sleep_calls = 0u;
    std::uint64_t v66_sleep_resumes = 0u;
    std::uint64_t v66_sched_yields = 0u;
    std::uint64_t v66_task_substate_events = 0u;
    std::uint64_t v66_task_substate_zeroes = 0u;
    std::uint64_t v66_task_stagnation_failures = 0u;
    std::string v66_failure_message;
    std::unordered_map<std::uint64_t, std::uint64_t>
        v66_task_substate_hits;

    struct V67AllocationProvenance {
        std::uint32_t size = 0u;
        std::uint32_t tid = 0u;
        std::uint32_t import_lr = 0u;
        std::uint32_t creator_lr = 0u;
        std::uint64_t malloc_index = 0u;
        bool via_operator_new = false;
    };
    struct V67TokenHistory {
        std::uint64_t increments = 0u;
        std::uint64_t decrements = 0u;
        std::uint32_t last_tid = 0u;
        std::uint32_t last_lr = 0u;
        std::uint32_t last_old = 0u;
        std::uint32_t last_new = 0u;
    };
    std::unordered_map<std::uint32_t, V67AllocationProvenance>
        v67_small_allocations;
    std::unordered_map<std::uint32_t, V67TokenHistory>
        v67_token_history;
    std::uint64_t v67_token_events = 0u;

    // v69 bounded lifecycle counters. The probe deliberately records aggregate
    // state and changes instead of emitting one line per hot-loop dispatch.
    struct V69TaskASnapshot {
        bool valid = false;
        std::uint32_t state18 = 0u;
        std::uint32_t owner = 0u;
        std::uint32_t owner8 = 0xffffffffu;
        std::uint32_t dep20 = 0u;
        std::uint32_t child28 = 0u;
    };
    std::unordered_map<std::uint32_t, V69TaskASnapshot>
        v69_task_a_snapshots;
    std::uint64_t v69_worker_wait_calls = 0u;
    std::uint64_t v69_worker_wait_zero = 0u;
    std::uint64_t v69_worker_wait_nonzero = 0u;
    std::uint32_t v69_last_worker_wait_flag = 0xffffffffu;
    std::uint64_t v69_active_ready_calls = 0u;
    std::uint64_t v69_active_ready_true = 0u;
    std::uint64_t v69_active_phase_calls = 0u;
    std::uint64_t v69_active_phase_true = 0u;
    std::uint64_t v69_start_work_returns = 0u;
    std::uint64_t v69_completed_moves = 0u;
    std::uint64_t v69_completed_poll_returns = 0u;
    std::uint64_t v69_completed_ready_calls = 0u;
    std::uint64_t v69_completed_ready_true = 0u;
    std::uint64_t v69_completed_terminal_calls = 0u;
    std::uint64_t v69_completed_terminal_true = 0u;
    std::uint64_t v69_finalizer_returns = 0u;
    std::uint32_t v69_max_active_count = 0u;
    std::uint32_t v69_max_completed_count = 0u;
    std::uint64_t v69_task_a_change_events = 0u;
    bool v69_summary_emitted = false;

    std::uint32_t next_pthread_key = 1;
    std::uint32_t next_synthetic_thread = 1;
    std::uint32_t next_synthetic_class = 1;
    std::uint32_t next_synthetic_method = 1;
    std::uint32_t next_synthetic_field = 1;
    std::uint32_t next_synthetic_object = 1;
    struct ProbeObbHandle {
        std::uint64_t base = 0;
        std::uint64_t length = 0;
        std::uint64_t offset = 0;
        bool eof = false;
        bool writable = false;
        bool dev_null = false;
        std::string label;
        std::string virtual_path;
        std::shared_ptr<std::vector<std::uint8_t>> owned;
    };

    struct SyntheticAsset {
        std::shared_ptr<std::vector<std::uint8_t>> bytes;
        std::string source_path;
        std::uint32_t width = 0;
        std::uint32_t height = 0;
    };

    std::uint32_t next_gl_object = 1;
    bool host_gles_ready = false;
    std::uint32_t host_default_framebuffer = 0;
    std::uint32_t host_surface_width = 1180u;
    std::uint32_t host_surface_height = 820u;
    std::uint32_t guest_errno_address = 0;
    const std::uint8_t* obb_data = nullptr;
    std::size_t obb_size = 0;
    std::uint32_t next_probe_fd = 0x00004000u;
    std::uint32_t next_probe_file = 0xf1000000u;
    std::uint64_t obb_read_calls = 0;
    std::uint64_t obb_nonzero_read_calls = 0;
    std::uint64_t obb_bytes_returned = 0;
    std::uint64_t obb_max_read_end = 0;
    std::uint64_t obb_seek_calls = 0;
    std::uint64_t last_obb_read_offset = 0;
    std::uint32_t last_obb_read_requested = 0;
    std::uint32_t last_obb_read_returned = 0;
    std::uint64_t last_obb_seek_target = 0;
    std::uint32_t null_execute_recoveries = 0;
    std::string last_android_log;
    std::uint64_t malloc_calls = 0;
    std::uint64_t free_calls = 0;
    std::uint64_t realloc_calls = 0;
    std::uint64_t memset_calls = 0;
    std::uint32_t rsb_resolved_files = 0;
    std::uint32_t missing_resource_diagnostics = 0;
    std::uint64_t gles_draw_calls = 0;
    std::uint64_t gles_clear_calls = 0;
    std::uint64_t gles_texture_uploads = 0;
    std::uint64_t gles_shader_source_calls = 0;
    std::uint64_t gles_uniform4_calls = 0;
    std::uint64_t gles_blend_state_changes = 0;
    bool gles_blend_enabled = false;
    GLenum gles_blend_src = GL_ONE;
    GLenum gles_blend_dst = GL_ZERO;
    bool gles_scissor_enabled = false;
    std::array<GLboolean, 4> gles_color_mask{
        GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE};
    std::array<GLfloat, 4> gles_clear_color{
        0.0f, 0.0f, 0.0f, 0.0f};
    GLuint gles_current_program = 0u;
    std::unordered_map<std::uint64_t, std::string>
        gles_uniform_names;
    std::unordered_map<std::uint64_t, GLint>
        gles_uniform1i_values;

    // v80: retain the latest matrix uploaded to each program/location.
    // Nothing here changes guest or host GL state; it only lets sampled UI
    // draws be related to the exact screenMatrix that was active.
    std::unordered_map<
        std::uint64_t,
        std::array<GLfloat, 16>>
        gles_uniform_matrix4_values;
    std::uint64_t v80_screen_matrix_uploads = 0u;
    std::uint64_t v80_screen_matrix_changes = 0u;
    std::uint64_t v80_array_draws_seen = 0u;
    std::uint64_t v80_transform_draw_traces = 0u;
    std::uint32_t v80_trace_frame = 0xffffffffu;
    std::uint32_t v80_traces_this_frame = 0u;

    // v84: final/default-FBO composite tracing. v80 intentionally ignored
    // guest FBO 0, which is exactly where the 1024x768 projection appears.
    std::uint64_t v84_final_blit_draw_traces = 0u;
    std::uint64_t v84_final_blit_canvas_1024 = 0u;
    std::uint64_t v84_final_blit_canvas_2048 = 0u;
    std::uint64_t v84_final_blit_canvas_other = 0u;
    std::uint32_t v84_final_trace_frame = 0xffffffffu;
    std::uint32_t v84_final_traces_this_frame = 0u;

    // Exact APK AndroidSurfaceView scale-field semantics for the v84 Android
    // contract mode. Constructor writes 0.5f; Get/Set simply load/store it.
    std::uint32_t v84_android_view_scale_factor_bits = 0x3f000000u;
    std::uint64_t v84_points_calls = 0u;
    std::uint64_t v84_point_size_calls = 0u;
    std::uint64_t v84_can_scale_calls = 0u;
    std::uint64_t v84_get_scale_calls = 0u;
    std::uint64_t v84_set_scale_calls = 0u;

    std::uint64_t v85_log_lines_kept = 0u;
    std::uint64_t v85_log_lines_suppressed = 0u;
    std::uint64_t v85_guest_draw_samples = 0u;
    std::uint64_t v85_guest_draw_total_ns = 0u;
    std::uint64_t v85_guest_draw_max_ns = 0u;
    std::uint64_t v85_capture_samples = 0u;
    std::uint64_t v85_capture_total_ns = 0u;
    std::uint64_t v85_capture_max_ns = 0u;
    std::uint64_t v85_touch_process_samples = 0u;
    std::uint64_t v85_touch_process_total_ns = 0u;
    std::uint64_t v85_touch_process_max_ns = 0u;
    std::uint64_t v85_touch_action_samples = 0u;
    std::uint64_t v85_touch_action_total_ns = 0u;
    std::uint64_t v85_touch_action_max_ns = 0u;
    std::uint64_t v85_last_touch_queued_ns = 0u;
    std::uint32_t v85_last_touch_phase = 0u;
    std::int32_t v85_last_touch_x = 0;
    std::int32_t v85_last_touch_y = 0;

    struct V89HostBucket { std::uint64_t calls=0u,total_ns=0u,max_ns=0u,bytes=0u; };
    struct V89PcSample { std::uint64_t count=0u; std::uint32_t pc=0u,lr=0u,tid=0u; std::string phase; };
    std::unordered_map<std::string,V89HostBucket> v89_host_buckets;
    std::unordered_map<std::string,V89PcSample> v89_pc_samples;
    std::unordered_map<std::uint32_t,std::uint64_t> v89_tid_samples;
    std::uint64_t v89_quantum_samples=0u,v89_blx_events=0u,v89_blx_odd_targets=0u;
    bool v89_terminal_summaries_emitted=false;

    // v90 deterministic profiler state.
    std::unordered_map<std::uint32_t,std::uint64_t> v90_font_begin_ns;
    std::unordered_map<std::string,std::pair<std::uint64_t,std::uint64_t>>
        v90_font_by_phase;
    std::uint64_t v90_font_scans=0u,v90_font_total_ns=0u,v90_font_max_ns=0u,v90_font_unmatched=0u;
    std::unordered_map<std::uint32_t,std::uint64_t> v90_worker_ns_by_tid;
    std::uint64_t v90_worker_wait_ns_total=0u,v90_boundary_worker_ns_total=0u;
    std::uint64_t v90_present_calls=0u,v90_present_failures=0u,v90_present_ns_total=0u,v90_present_max_ns=0u;
    std::uint32_t v90_last_drawable_width=0u,v90_last_drawable_height=0u;
    std::uint32_t v90_profile_frame=0u;
    std::uint64_t v90_frame_worker_wait_ns=0u,v90_frame_boundary_worker_ns=0u,v90_frame_present_ns=0u,v90_frame_font_ns=0u;
    std::uint64_t v90_frame_alloc_calls_begin=0u,v90_frame_alloc_scan_begin=0u;
    std::uint64_t v90_frames_profiled=0u,v90_guest_ns_total=0u,v90_active_ns_total=0u;
    bool v90_terminal_summaries_emitted=false;

    // v110: no SVC probes in Wwise. AddTicks only accumulates guest ticks by
    // current PC; existing scheduler boundaries provide the wall-time quantum.
    enum class V110AudioBucket : std::uint32_t {
        AudioMgr = 0u,
        VplMixer = 1u,
        ResamplerPitch = 2u,
        VorbisMdct = 3u,
        Other = 4u,
    };
    std::array<std::uint64_t, 5> v110_audio_wall_ns{};
    std::array<std::uint64_t, 5> v110_audio_quanta{};
    std::array<std::uint64_t, 5> v110_audio_guest_ticks{};
    std::array<std::uint64_t, 5> v110_quantum_guest_ticks{};
    std::array<std::uint64_t, 5> v110_frame_audio_ns{};
    std::array<std::uint64_t, 5> v110_frame_audio_quanta{};
    std::uint64_t v110_audio_quantum_count = 0u;
    std::uint64_t v110_audio_max_quantum_ns = 0u;
    std::uint64_t v110_pinch_batches = 0u;
    std::uint64_t v110_pinch_events_delivered = 0u;

    // v111: sample the *saved* tid5 PC at sparse internal Dynarmic
    // checkpoints. A checkpoint resumes the same worker immediately, so it
    // does not introduce a guest-visible scheduler handoff.
    static constexpr std::uint64_t kV111AudioSampleIntervalTicks = 131072ull;
    std::uint64_t v111_audio_sample_tick_accumulator = 0u;
    bool v111_audio_sample_due = false;
    bool v111_audio_sample_halt_pending = false;
    std::array<std::uint64_t, 5> v111_audio_samples{};
    std::array<std::uint64_t, 5> v111_frame_audio_samples{};
    std::uint64_t v111_audio_sample_count = 0u;
    std::uint64_t v111_audio_forced_halts = 0u;
    std::uint64_t v111_audio_pc_overflow = 0u;
    std::unordered_map<std::uint32_t, std::uint64_t>
        v111_audio_pc_samples;

    // v112: natural import-boundary profiler. No new HaltExecution is used.
    // Fixed-size tables keep the hot tid5 path allocation-free.
    struct V112ImportStats {
        std::uint64_t calls = 0u;
        std::uint64_t guest_gap_ns = 0u;
        std::uint64_t guest_gap_max_ns = 0u;
        std::uint64_t host_ns = 0u;
        std::uint64_t host_max_ns = 0u;
    };
    struct V112CallsiteStats {
        std::uint64_t key = 0u;
        std::uint64_t calls = 0u;
        std::uint64_t guest_gap_ns = 0u;
        std::uint64_t guest_gap_max_ns = 0u;
        std::uint64_t host_ns = 0u;
        std::uint64_t host_max_ns = 0u;
    };
    struct V112ImportToken {
        bool active = false;
        std::uint32_t import_index = 0u;
        std::uint32_t callsite_slot = 0xffffffffu;
        std::uint64_t entry_ns = 0u;
    };
    static constexpr std::size_t kV112MaxImportSlots = 512u;
    static constexpr std::size_t kV112CallsiteSlots = 1024u;
    std::array<V112ImportStats, kV112MaxImportSlots> v112_import_stats{};
    std::array<V112CallsiteStats, kV112CallsiteSlots> v112_callsite_stats{};
    std::uint64_t v112_callsite_overflow = 0u;
    bool v112_audio_run_active = false;
    bool v112_audio_run_had_import = false;
    std::uint64_t v112_audio_run_start_ns = 0u;
    std::uint64_t v112_audio_prev_import_exit_ns = 0u;
    std::uint64_t v112_audio_runs = 0u;
    std::uint64_t v112_audio_run_wall_ns = 0u;
    std::uint64_t v112_import_calls = 0u;
    std::uint64_t v112_guest_gap_ns = 0u;
    std::uint64_t v112_guest_gap_max_ns = 0u;
    std::uint64_t v112_import_host_ns = 0u;
    std::uint64_t v112_import_host_max_ns = 0u;
    std::uint64_t v112_tail_ns = 0u;
    std::uint64_t v112_no_import_run_ns = 0u;
    std::uint64_t v112_frame_run_ns = 0u;
    std::uint64_t v112_frame_guest_gap_ns = 0u;
    std::uint64_t v112_frame_import_host_ns = 0u;
    std::uint64_t v112_frame_tail_ns = 0u;
    std::uint64_t v112_frame_no_import_ns = 0u;
    std::uint64_t v112_frame_import_calls = 0u;
    std::uint64_t v112_frame_guest_gap_max_ns = 0u;
    std::uint64_t v112_frame_import_host_max_ns = 0u;

    // v113: Dynarmic page table exists from JIT construction but starts with
    // every entry null, so startup/constructor memory accesses still use the
    // exact callback path. At frame 1 only the stable 128 MiB heap region is
    // mapped direct. Image/GOT/RELRO, main stack, trampolines, JNI and object
    // regions deliberately remain callback-backed.
    using V113PageTable = std::array<
        std::uint8_t*,
        Dynarmic::A32::UserConfig::NUM_PAGE_TABLE_ENTRIES>;
    V113PageTable* v113_page_table = nullptr;
    bool v113_heap_page_table_active = false;
    std::uint32_t v113_heap_pages_mapped = 0u;
    std::uint32_t v113_activation_frame = 0u;
    std::uint64_t v113_activation_ns = 0u;

    // v115: direct-map the lower 255/256 pages of the fixed 1 MiB main stack.
    // The final page 0x200ff000..0x200fffff remains callback-backed because
    // every v114 LR-slot observation landed there and the v94/v95 provenance
    // probes depend on callback visibility for those watched addresses.
    bool v115_stack_page_table_active = false;
    std::uint32_t v115_stack_pages_mapped = 0u;
    std::uint32_t v115_stack_callback_pages = 1u;
    std::uint64_t v115_stack_activation_ns = 0u;

    // v116: direct-map only *complete* 4 KiB pages covered by the exact RX
    // PT_LOAD (ELF offsets 0x00000000..0x00ccaad3). The mixed/partial page at
    // 0x00cca000 and the complete RW PT_LOAD remain callback-backed.
    bool v116_image_page_table_active = false;
    std::uint32_t v116_image_pages_mapped = 0u;
    std::uint32_t v116_image_callback_tail_pages = 0u;
    std::uint64_t v116_image_activation_ns = 0u;

    // v114: natural Native_onDrawFrame/main-thread boundary profiler. No
    // periodic halt or guest patch is installed. Each existing main jit.Run
    // span is timed, imports are attributed to their exact guest LR/callsite,
    // and no-import spans retain their natural start/end PCs.
    struct V114ImportStats {
        std::uint64_t calls = 0u;
        std::uint64_t guest_gap_ns = 0u;
        std::uint64_t guest_gap_max_ns = 0u;
        std::uint64_t host_ns = 0u;
        std::uint64_t host_max_ns = 0u;
    };
    struct V114CallsiteStats {
        std::uint64_t key = 0u;
        std::uint64_t calls = 0u;
        std::uint64_t guest_gap_ns = 0u;
        std::uint64_t guest_gap_max_ns = 0u;
        std::uint64_t host_ns = 0u;
        std::uint64_t host_max_ns = 0u;
    };
    struct V114SpanStats {
        std::uint64_t key = 0u;
        std::uint64_t calls = 0u;
        std::uint64_t wall_ns = 0u;
        std::uint64_t wall_max_ns = 0u;
    };
    struct V114ImportToken {
        bool active = false;
        std::uint32_t import_index = 0u;
        std::uint32_t callsite_slot = 0xffffffffu;
        std::uint64_t entry_ns = 0u;
    };
    static constexpr std::size_t kV114MaxImportSlots = 512u;
    static constexpr std::size_t kV114CallsiteSlots = 2048u;
    static constexpr std::size_t kV114SpanSlots = 512u;
    std::array<V114ImportStats, kV114MaxImportSlots> v114_import_stats{};
    std::array<V114CallsiteStats, kV114CallsiteSlots> v114_callsite_stats{};
    std::array<V114SpanStats, kV114SpanSlots> v114_noimport_span_stats{};
    std::uint64_t v114_callsite_overflow = 0u;
    std::uint64_t v114_span_overflow = 0u;
    bool v114_main_run_active = false;
    bool v114_main_run_had_import = false;
    std::uint32_t v114_main_run_start_pc = 0u;
    std::uint64_t v114_main_run_start_ns = 0u;
    std::uint64_t v114_main_prev_import_exit_ns = 0u;
    std::uint64_t v114_main_spans = 0u;
    std::uint64_t v114_main_run_wall_ns = 0u;
    std::uint64_t v114_import_calls = 0u;
    std::uint64_t v114_guest_gap_ns = 0u;
    std::uint64_t v114_guest_gap_max_ns = 0u;
    std::uint64_t v114_import_host_ns = 0u;
    std::uint64_t v114_import_host_max_ns = 0u;
    std::uint64_t v114_tail_ns = 0u;
    std::uint64_t v114_no_import_run_ns = 0u;
    std::uint64_t v114_frame_spans = 0u;
    std::uint64_t v114_frame_run_ns = 0u;
    std::uint64_t v114_frame_guest_gap_ns = 0u;
    std::uint64_t v114_frame_import_host_ns = 0u;
    std::uint64_t v114_frame_tail_ns = 0u;
    std::uint64_t v114_frame_no_import_ns = 0u;
    std::uint64_t v114_frame_import_calls = 0u;
    std::uint64_t v114_frame_guest_gap_max_ns = 0u;
    std::uint64_t v114_frame_import_host_max_ns = 0u;

    // v81: detailed event serialization provenance. The host-side mapper logs
    // UIKit -> framebuffer-pixel -> logical-point candidates; this counter
    // bounds the matching guest events actually written to ProcessEvents.
    std::uint64_t v81_touch_events_logged = 0u;

    std::uint64_t gles_transition_draw_traces = 0u;
    std::uint64_t gles_transition_clear_traces = 0u;

    // v42: the splash shaders do not use a color uniform; they multiply
    // texture samples by the per-vertex "color" attribute. Track the real
    // client-array state so the dark-splash factor can be observed and, only
    // for the detected 1024x1024 startup atlas, normalized relative to the
    // first stable tint rather than globally patching rendering.
    struct V42AttribState {
        GLint size = 0;
        GLenum type = 0u;
        GLboolean normalized = GL_FALSE;
        GLsizei stride = 0;
        std::uint32_t guest_pointer = 0u;
        bool enabled = false;
    };

    struct V42TextureInfo {
        GLsizei width = 0;
        GLsizei height = 0;
        GLenum format = 0u;
        GLenum type = 0u;
        bool has_pixels = false;
    };

    std::array<V42AttribState, 16> gles_attrib_state{};
    std::unordered_map<std::uint64_t, std::string>
        gles_attrib_names;
    GLenum gles_active_texture_unit = GL_TEXTURE0;
    std::array<GLuint, 8> gles_bound_texture_2d{};
    std::unordered_map<GLuint, V42TextureInfo>
        gles_texture_info;

    // v47: expose the guest render-target topology. Guest FBO 0 is mapped
    // to the host system framebuffer; generated guest FBO ids are the actual
    // GLES ids returned by the host and can be sampled independently.
    GLuint gles_bound_guest_framebuffer = 0u;
    GLuint gles_bound_host_framebuffer = 0u;
    std::unordered_set<GLuint>
        gles_generated_framebuffers;
    std::unordered_map<GLuint, GLuint>
        gles_framebuffer_color_texture;
    std::unordered_map<GLuint, std::uint64_t>
        gles_draws_by_framebuffer;
    std::uint64_t gles_framebuffer_bind_changes = 0u;
    std::uint32_t current_frame_number = 0u;

    GLuint gles_splash_texture_candidate = 0u;
    std::uint32_t gles_splash_color_baseline = 0u;
    std::uint64_t gles_vertex_color_traces = 0u;
    std::uint64_t gles_splash_color_corrections = 0u;

    std::uint64_t gles_viewport_calls = 0;
    std::uint64_t gles_scissor_calls = 0;
    bool gles_viewport_seen = false;
    bool gles_scissor_seen = false;
    std::array<std::int32_t, 4> last_gles_viewport{};
    std::array<std::int32_t, 4> last_gles_scissor{};
    std::unordered_set<std::string>
        recovered_missing_resource_ids;

    // v35 resource-registry bridge caches. The RSB outer index already
    // gives us a trustworthy ID -> physical path relation for RESFILE_* RTON
    // entries. The native ResourceManager also keeps a global path ->
    // ResourceInfo* tree even when a group-local ID lookup misses.
    bool rsb_resource_id_index_built = false;
    std::unordered_map<std::string, std::string>
        rsb_resource_id_to_path;
    std::uint32_t resource_path_index_manager = 0u;
    std::unordered_map<std::string, std::uint32_t>
        resource_path_index;
    std::uint32_t resource_id_index_manager = 0u;
    std::unordered_map<std::string, std::uint32_t>
        resource_id_index;
    std::unordered_set<std::string>
        resource_registry_logged_ids;
    std::uint32_t resource_native_miss_diagnostics = 0u;
    std::size_t resource_id_index_last_logged_entries =
        std::numeric_limits<std::size_t>::max();
    std::uint32_t resource_live_id_recoveries = 0u;
    std::uint32_t resource_group_key_diagnostics = 0u;
    std::uint32_t resource_entry_id_diagnostics = 0u;
    std::uint32_t resource_null_node_diagnostics = 0u;
    std::uint32_t resource_null_node_heals = 0u;
    std::uint32_t resource_global_null_node_diagnostics = 0u;
    std::uint32_t resource_global_null_node_heals = 0u;
    std::uint32_t resource_wrapper_direct_nulls = 0u;
    std::uint32_t resource_wrapper_exhausted_nulls = 0u;
    std::uint32_t resource_wrapper_recoveries = 0u;
    std::unordered_map<std::uint32_t, std::string>
        resource_lookup_entry_ids;

    void V50ObserveResourceId(
        const std::string& id) {

        if (V85PerformanceEnabled()) return;
        std::string key = id;
        std::transform(
            key.begin(),
            key.end(),
            key.begin(),
            [](unsigned char ch) {
                return static_cast<char>(
                    std::toupper(ch));
            });

        const bool is_android =
            key == "RESFILE_PACKAGES_UI_ANDROID";
        const bool is_ipad =
            key == "RESFILE_PACKAGES_UI_IPAD";

        if (!is_android && !is_ipad) {
            return;
        }

        if (is_android) {
            v50_ui_android_seen = true;
        }
        if (is_ipad) {
            v50_ui_ipad_seen = true;
        }

        if (v50_resource_milestone_keys
                .insert("id:" + key)
                .second) {
            Append(
                "V50 RESOURCE MILESTONE frame=" +
                std::to_string(
                    current_frame_number) +
                " id=\"" +
                id +
                "\"");
        }
    }

    void V50ObservePath(
        const std::string& raw,
        const char* source) {

        if (V85PerformanceEnabled()) return;
        std::string key = raw;

        for (char& ch : key) {
            if (ch == '\\') {
                ch = '/';
            } else {
                ch = static_cast<char>(
                    std::toupper(
                        static_cast<unsigned char>(
                            ch)));
            }
        }

        const bool ui_android =
            key.find("PACKAGES/UI_ANDROID.RTON") !=
            std::string::npos;
        const bool ui_ipad =
            key.find("PACKAGES/UI_IPAD.RTON") !=
            std::string::npos;
        const bool mainmenu_background =
            key.find("MAINMENU_BACKGROUND") !=
            std::string::npos;
        const bool ui_mainmenu =
            key.find("UI_MAINMENU") !=
            std::string::npos;
        const bool init_atlas =
            key.find("ATLASES/INIT_") !=
                std::string::npos ||
            key.find("ATLASES/_INIT_") !=
                std::string::npos;

        if (ui_android) {
            v50_ui_android_seen = true;
        }
        if (ui_ipad) {
            v50_ui_ipad_seen = true;
        }
        if (mainmenu_background) {
            v50_mainmenu_background_seen = true;
            if (v50_mainmenu_background_first_frame ==
                0u) {
                v50_mainmenu_background_first_frame =
                    current_frame_number;
            }
        }
        if (ui_mainmenu) {
            v50_ui_mainmenu_seen = true;
            if (v50_ui_mainmenu_first_frame == 0u) {
                v50_ui_mainmenu_first_frame =
                    current_frame_number;
            }
        }
        if (init_atlas) {
            v50_init_atlas_seen = true;
        }

        if (!ui_android &&
            !ui_ipad &&
            !mainmenu_background &&
            !ui_mainmenu &&
            !init_atlas) {
            return;
        }

        std::string category;
        if (ui_android) {
            category = "UI_ANDROID";
        } else if (ui_ipad) {
            category = "UI_IPAD";
        } else if (mainmenu_background) {
            category = "MAINMENU_BACKGROUND";
        } else if (ui_mainmenu) {
            category = "UI_MAINMENU";
        } else {
            category = "INIT_ATLAS";
        }

        const std::string dedupe =
            "path:" +
            category +
            ":" +
            key;

        if (v50_resource_milestone_keys
                .insert(dedupe)
                .second) {
            Append(
                "V50 ASSET MILESTONE frame=" +
                std::to_string(
                    current_frame_number) +
                " source=" +
                std::string{
                    source != nullptr
                        ? source
                        : "?"} +
                " category=" +
                category +
                " path=\"" +
                raw +
                "\"");
        }
    }

    void V80TraceArrayTransform(
        GLint first,
        GLsizei count) {

        ++v80_array_draws_seen;

        const bool final_blit =
            gles_bound_guest_framebuffer == 0u;

        if (!V80Enabled() ||
            first < 0 ||
            count <= 0 ||
            (final_blit && !V84FinalBlitEnabled())) {
            return;
        }

        // Three bounded windows: early EA, title/loading, then Profile.
        const bool sample_frame =
            current_frame_number <= 12u ||
            (current_frame_number >= 50u &&
             current_frame_number <= 95u &&
             (current_frame_number % 5u) == 0u) ||
            (current_frame_number >= 108u &&
             (current_frame_number % 3u) == 0u);

