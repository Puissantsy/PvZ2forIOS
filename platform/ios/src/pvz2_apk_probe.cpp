#include "pvz2_apk_probe.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>

#include <dynarmic/interface/A32/a32.h>
#include <zlib.h>

namespace {

constexpr const char* kPvZ2Path = "lib/armeabi-v7a/libPVZ2.so";

constexpr std::uint32_t kZipLocal = 0x04034b50u;
constexpr std::uint32_t kZipCentral = 0x02014b50u;
constexpr std::uint32_t kZipEocd = 0x06054b50u;

constexpr std::uint32_t kElfMagic = 0x464c457fu;
constexpr std::uint16_t kElfTypeDyn = 3;
constexpr std::uint16_t kElfMachineArm = 40;
constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kPtDynamic = 2;
constexpr std::uint32_t kShtDynsym = 11;
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
constexpr std::uint32_t kJniProbeHeapSize = 0x00800000u;
constexpr std::uint32_t kJniProbeTrampolineBase = 0x40000000u;
constexpr std::uint32_t kJniProbeTrampolineSize = 0x00100000u;
constexpr std::uint32_t kJniProbeJniBase = 0x50000000u;
constexpr std::uint32_t kJniProbeJniSize = 0x00010000u;
constexpr std::uint32_t kJniProbeObjectBase = 0x51000000u;
constexpr std::uint32_t kJniProbeObjectSize = 0x00010000u;

constexpr std::uint32_t kJniProbeImportSvcBase = 0x001000u;
constexpr std::uint32_t kJniProbeSvcGetEnv = 0x00f001u;
constexpr std::uint32_t kJniProbeSvcFindClass = 0x00f002u;
constexpr std::uint32_t kJniProbeSvcRegisterNatives = 0x00f003u;
constexpr std::uint32_t kJniProbeSvcReturn = 0x00f004u;

constexpr std::uint32_t kPvZ2JniOnLoad15252752 = 0x009ead80u;
constexpr std::uint32_t kJniVersion14 = 0x00010004u;
constexpr std::uint32_t kJniVersion16 = 0x00010006u;

struct JniProbeLoadedElf {
    std::vector<std::uint8_t> image;
    std::vector<Elf32Sym> dynsyms;
    std::vector<Elf32Rel> relocs;
    const std::uint8_t* dynstr = nullptr;
    std::size_t dynstr_size = 0;
    std::uint32_t jni_onload = 0;
    std::uint32_t init_array = 0;
    std::uint32_t init_array_size = 0;
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
    std::vector<std::uint8_t> image;
    std::vector<std::uint8_t> stack =
        std::vector<std::uint8_t>(kJniProbeStackSize, 0);
    std::vector<std::uint8_t> heap =
        std::vector<std::uint8_t>(kJniProbeHeapSize, 0);
    std::vector<std::uint8_t> trampolines =
        std::vector<std::uint8_t>(kJniProbeTrampolineSize, 0);
    std::vector<std::uint8_t> jni =
        std::vector<std::uint8_t>(kJniProbeJniSize, 0);
    std::vector<std::uint8_t> objects =
        std::vector<std::uint8_t>(kJniProbeObjectSize, 0);

    std::uint32_t heap_next = 0;
    std::uint32_t object_next = 0;

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

    void Write8Guest(std::uint32_t address, std::uint8_t value) {
        if (auto* p = Ptr(address, 1)) {
            *p = value;
        }
    }

    void Write16Guest(std::uint32_t address, std::uint16_t value) {
        Write8Guest(address, static_cast<std::uint8_t>(value));
        Write8Guest(address + 1, static_cast<std::uint8_t>(value >> 8));
    }

    void Write32Guest(std::uint32_t address, std::uint32_t value) {
        if (auto* p = Ptr(address, 4)) {
            Write32(p, value);
            return;
        }

        for (int i = 0; i < 4; ++i) {
            Write8Guest(
                address + static_cast<std::uint32_t>(i),
                static_cast<std::uint8_t>(value >> (i * 8)));
        }
    }

    void Write64Guest(std::uint32_t address, std::uint64_t value) {
        Write32Guest(address, static_cast<std::uint32_t>(value));
        Write32Guest(address + 4, static_cast<std::uint32_t>(value >> 32));
    }

    std::uint32_t AllocateHeap(
        std::uint32_t size,
        std::uint32_t alignment = 16) {

        const std::uint32_t aligned =
            (heap_next + alignment - 1) & ~(alignment - 1);

        if (aligned > kJniProbeHeapSize ||
            size > kJniProbeHeapSize - aligned) {
            return 0;
        }

        heap_next = aligned + size;
        return kJniProbeHeapBase + aligned;
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

            if (ch >= 0x20 && ch <= 0x7e) {
                result.push_back(ch);
            } else {
                result.push_back('?');
            }
        }

        return result;
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
        PvZ2JniProbeResult& output)
        : mem(memory), result(output) {}

    Dynarmic::A32::Jit* jit = nullptr;
    std::unordered_map<std::uint32_t, JniProbeImportBinding>
        imports_by_svc;

    enum class ReturnMode {
        JniOnLoad,
        Constructor,
    };

    std::uint32_t vm_object = 0;
    std::uint32_t env_object = 0;
    std::uint32_t supported_calls = 0;
    std::uint64_t ticks_left = 1000000;
    ReturnMode return_mode = ReturnMode::JniOnLoad;
    bool control_returned = false;
    std::uint32_t current_constructor_index = 0;
    std::uint32_t current_constructor_address = 0;

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
        return mem.Read32Guest(address);
    }

    std::uint64_t MemoryRead64(std::uint32_t address) override {
        return mem.Read64Guest(address);
    }

    void MemoryWrite8(
        std::uint32_t address,
        std::uint8_t value) override {
        mem.Write8Guest(address, value);
    }

    void MemoryWrite16(
        std::uint32_t address,
        std::uint16_t value) override {
        mem.Write16Guest(address, value);
    }

    void MemoryWrite32(
        std::uint32_t address,
        std::uint32_t value) override {
        mem.Write32Guest(address, value);
    }

    void MemoryWrite64(
        std::uint32_t address,
        std::uint64_t value) override {
        mem.Write64Guest(address, value);
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

    void CallSVC(std::uint32_t swi) override {
        if (!jit) {
            return;
        }

        auto& regs = jit->Regs();

        if (swi == kJniProbeSvcGetEnv) {
            const std::uint32_t output_address = regs[1];
            const std::uint32_t version = regs[2];

            mem.Write32Guest(output_address, env_object);
            regs[0] = 0;

            Append(
                "JavaVM.GetEnv(version=0x" +
                JniProbeHex(version) +
                ") -> JNI_OK, env=0x" +
                JniProbeHex(env_object));
            return;
        }

        if (swi == kJniProbeSvcFindClass) {
            ++result.find_class_calls;

            const std::string class_name =
                mem.ReadCStringGuest(regs[1], 256);

            const std::uint32_t class_handle =
                0x52000000u +
                result.find_class_calls * 0x100u;

            regs[0] = class_handle;

            Append(
                "JNIEnv.FindClass(\"" +
                class_name +
                "\") -> 0x" +
                JniProbeHex(class_handle));
            return;
        }

        if (swi == kJniProbeSvcRegisterNatives) {
            ++result.register_natives_calls;

            const std::uint32_t class_handle = regs[1];
            const std::uint32_t methods = regs[2];
            const std::uint32_t count = regs[3];

            result.registered_native_methods += count;

            Append(
                "JNIEnv.RegisterNatives(clazz=0x" +
                JniProbeHex(class_handle) +
                ", count=" +
                std::to_string(count) +
                ")");

            const std::uint32_t visible =
                std::min<std::uint32_t>(count, 64);

            for (std::uint32_t i = 0;
                 i < visible;
                 ++i) {

                const std::uint32_t entry =
                    methods + i * 12u;

                const std::uint32_t name_ptr =
                    mem.Read32Guest(entry + 0);
                const std::uint32_t signature_ptr =
                    mem.Read32Guest(entry + 4);
                const std::uint32_t function_ptr =
                    mem.Read32Guest(entry + 8);

                Append(
                    "  native[" +
                    std::to_string(i) +
                    "] " +
                    mem.ReadCStringGuest(name_ptr, 192) +
                    " " +
                    mem.ReadCStringGuest(signature_ptr, 256) +
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

        const auto binding =
            imports_by_svc.find(swi);

        if (binding == imports_by_svc.end()) {
            result.message =
                "Unknown guest SVC 0x" +
                JniProbeHex(swi);
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined4);
            return;
        }

        const std::string& name = binding->second.name;

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

            Append(
                "import " +
                name +
                "(" +
                std::to_string(requested) +
                ") -> 0x" +
                JniProbeHex(address));
            return;
        }

        if (name == "free") {
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "__cxa_atexit") {
            ++result.cxa_atexit_calls;
            ++supported_calls;
            regs[0] = 0;

            Append(
                "import __cxa_atexit(func=0x" +
                JniProbeHex(regs[0]) +
                ") -> 0");
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

            auto* dst = mem.Ptr(destination, size);
            const auto* src = mem.Ptr(source, size);

            if (!dst || !src) {
                result.message =
                    name +
                    " attempted to access outside guest memory.";

                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined2);
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

                std::memset(p, value, size);
                regs[0] = destination;
                ++supported_calls;

                Append(
                    "import " +
                    name +
                    "(dest=0x" +
                    JniProbeHex(destination) +
                    ", size=" +
                    std::to_string(size) +
                    ", value=" +
                    std::to_string(value) +
                    ")");
                return;
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
                mem.ReadCStringGuest(regs[1], 128);

            const std::string text =
                mem.ReadCStringGuest(regs[2], 256);

            regs[0] = 0;
            ++supported_calls;

            Append(
                "import " +
                name +
                " tag=\"" +
                tag +
                "\" text=\"" +
                text +
                "\"");
            return;
        }

        if (name == "__stack_chk_fail") {
            result.first_unsupported_import = name;
            result.message =
                "PvZ2 triggered __stack_chk_fail.";

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined2);
            return;
        }

        result.first_unsupported_import = name;
        result.message =
            "First unsupported Android import reached: " +
            name;

        Append(
            "UNSUPPORTED IMPORT: " +
            name +
            " via guest trampoline 0x" +
            JniProbeHex(binding->second.trampoline));

        jit->HaltExecution(
            Dynarmic::HaltReason::UserDefined2);
    }

    void ExceptionRaised(
        std::uint32_t pc,
        Dynarmic::A32::Exception exception) override {

        std::ostringstream out;
        out
            << "Dynarmic exception at PC=0x"
            << std::hex << pc
            << " type="
            << std::dec
            << static_cast<unsigned>(exception);

        result.message = out.str();

        if (jit) {
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined3);
        }
    }

    void AddTicks(std::uint64_t ticks) override {
        if (ticks >= ticks_left) {
            ticks_left = 0;
            result.message =
                "JNI_OnLoad exceeded the probe instruction budget.";

            if (jit) {
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined4);
            }
            return;
        }

        ticks_left -= ticks;
    }

    std::uint64_t GetTicksRemaining() override {
        return ticks_left;
    }

    void Append(const std::string& line) {
        trace << line << '\n';
    }

    std::string Trace() const {
        return trace.str();
    }

private:
    JniProbeGuestMemory& mem;
    PvZ2JniProbeResult& result;
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

std::uint32_t JniProbeAllocateImportedObject(
    JniProbeGuestMemory& memory,
    const std::string& name) {

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
                    name);

            if (!object) {
                error =
                    "JNI probe imported-object arena exhausted.";
                return false;
            }

            Write32(
                memory.image.data() +
                rel.offset,
                object);

            ++result.imports_patched;
        }
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

    if (!return_trampoline ||
        !get_env ||
        !find_class ||
        !register_natives) {
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

    memory.Write32Guest(
        env_table + 0x18u,
        find_class);

    memory.Write32Guest(
        env_table + 0x35cu,
        register_natives);

    callbacks.vm_object = vm_object;
    callbacks.env_object = env_object;

    return true;
}

} // namespace

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

        Dynarmic::A32::UserConfig config;
        config.callbacks = &callbacks;
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
