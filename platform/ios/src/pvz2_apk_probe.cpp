#include "pvz2_apk_probe.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <cwctype>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <chrono>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>

#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/exclusive_monitor.h>
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
constexpr std::uint32_t kJniProbeHeapSize = 0x04000000u;
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
constexpr std::uint32_t kJniProbeSvcNewGlobalRef = 0x00f005u;
constexpr std::uint32_t kJniProbeSvcGetObjectClass = 0x00f006u;
constexpr std::uint32_t kJniProbeSvcGetMethodID = 0x00f007u;
constexpr std::uint32_t kJniProbeSvcUnsupportedJniBase = 0x00e000u;
constexpr std::uint32_t kJniProbeJniSlotCount = 256u;

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
    std::unordered_map<std::uint32_t, std::uint32_t> heap_allocations;

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
        const std::uint32_t address =
            kJniProbeHeapBase + aligned;

        heap_allocations[address] = size;
        return address;
    }

    std::uint32_t ReallocateHeap(
        std::uint32_t old_address,
        std::uint32_t new_size) {

        if (old_address == 0) {
            return AllocateHeap(new_size, 16);
        }

        if (new_size == 0) {
            heap_allocations.erase(old_address);
            return 0;
        }

        const std::uint32_t new_address =
            AllocateHeap(new_size, 16);

        if (!new_address) {
            return 0;
        }

        const auto it =
            heap_allocations.find(old_address);

        if (it != heap_allocations.end()) {
            const std::uint32_t copy_size =
                std::min(it->second, new_size);

            auto* dst = Ptr(new_address, copy_size);
            const auto* src = Ptr(old_address, copy_size);

            if (dst && src) {
                std::memmove(dst, src, copy_size);
            }

            heap_allocations.erase(it);
        }

        return new_address;
    }

    void FreeHeap(std::uint32_t address) {
        heap_allocations.erase(address);
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
        PvZ2ProbeProgress progress = {})
        : mem(memory),
          result(output),
          progress_callback(std::move(progress)) {}

    Dynarmic::A32::Jit* jit = nullptr;
    std::unordered_map<std::uint32_t, JniProbeImportBinding>
        imports_by_svc;

    enum class ReturnMode {
        JniOnLoad,
        Constructor,
        GameAppInitialize,
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
    std::uint32_t current_constructor_address = 0;
    std::uint32_t next_pthread_key = 1;
    std::uint32_t next_synthetic_thread = 1;
    std::uint32_t next_synthetic_class = 1;
    std::uint32_t next_synthetic_method = 1;
    std::uint32_t guest_errno_address = 0;
    std::unordered_map<std::uint32_t, std::uint32_t> pthread_specific;
    std::unordered_map<std::uint32_t, z_stream> zstreams;
    std::unordered_map<std::uint32_t, bool> zstream_deflate_mode;

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
        mem.Write8Guest(address, value);
        return true;
    }

    bool MemoryWriteExclusive16(
        std::uint32_t address,
        std::uint16_t value,
        [[maybe_unused]] std::uint16_t expected) override {
        mem.Write16Guest(address, value);
        return true;
    }

    bool MemoryWriteExclusive32(
        std::uint32_t address,
        std::uint32_t value,
        [[maybe_unused]] std::uint32_t expected) override {
        mem.Write32Guest(address, value);
        return true;
    }

    bool MemoryWriteExclusive64(
        std::uint32_t address,
        std::uint64_t value,
        [[maybe_unused]] std::uint64_t expected) override {
        mem.Write64Guest(address, value);
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

        if (swi == kJniProbeSvcNewGlobalRef) {
            regs[0] = regs[1];
            Append(
                "JNIEnv.NewGlobalRef(0x" +
                JniProbeHex(regs[1]) +
                ") -> 0x" +
                JniProbeHex(regs[0]));
            return;
        }

        if (swi == kJniProbeSvcGetObjectClass) {
            const std::uint32_t class_handle =
                0x53000000u +
                (next_synthetic_class++ * 0x100u);

            regs[0] = class_handle;

            Append(
                "JNIEnv.GetObjectClass(0x" +
                JniProbeHex(regs[1]) +
                ") -> 0x" +
                JniProbeHex(class_handle));
            return;
        }

        if (swi == kJniProbeSvcGetMethodID) {
            const std::string method_name =
                mem.ReadCStringGuest(regs[2], 256);
            const std::string signature =
                mem.ReadCStringGuest(regs[3], 512);

            const std::uint32_t method_id =
                0x54000000u +
                (next_synthetic_method++ * 0x100u);

            regs[0] = method_id;

            Append(
                "JNIEnv.GetMethodID(clazz=0x" +
                JniProbeHex(regs[1]) +
                ", name="" +
                method_name +
                "", sig="" +
                signature +
                "") -> 0x" +
                JniProbeHex(method_id));
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

                const std::string native_name =
                    mem.ReadCStringGuest(name_ptr, 192);
                const std::string native_signature =
                    mem.ReadCStringGuest(signature_ptr, 512);

                if (native_name == "Native_GameAppInitialize") {
                    result.game_app_initialize_address =
                        function_ptr;
                    result.game_app_initialize_signature =
                        native_signature;
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

            result.unsupported_jni_slot = slot;
            result.message =
                "First unsupported JNIEnv function slot reached: " +
                std::to_string(slot) +
                " (table offset 0x" +
                JniProbeHex(slot * 4u) +
                ").";

            Append(
                "UNSUPPORTED JNI: slot=" +
                std::to_string(slot) +
                " offset=0x" +
                JniProbeHex(slot * 4u));

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
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined4);
            return;
        }

        const std::string& name = binding->second.name;

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

            Append(
                "import __android_log_assert condition=\"" +
                condition +
                "\" tag=\"" +
                tag +
                "\" format=\"" +
                format +
                "\" (suppressed during probe)");

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
            mem.FreeHeap(regs[0]);
            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "realloc") {
            const std::uint32_t address =
                mem.ReallocateHeap(
                    regs[0],
                    regs[1]);

            regs[0] = address;
            ++supported_calls;
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
            // Constructor probing must not stall the host. These startup
            // sleeps are treated as completed.
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

            z_stream stream{};
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
                zstreams[guest_stream] =
                    stream;

                zstream_deflate_mode[guest_stream] =
                    name != "inflateInit_";
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

            const int status =
                name == "deflate"
                    ? ::deflate(
                        &it->second,
                        static_cast<int>(regs[1]))
                    : ::inflate(
                        &it->second,
                        static_cast<int>(regs[1]));

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
                case 3: answer = (ch == ' ' || ch == '\\t'); break;
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

            Append(
                "import pthread_create deferred: tid=" +
                std::to_string(thread_id) +
                " start=0x" +
                JniProbeHex(start_routine) +
                " arg=0x" +
                JniProbeHex(argument));

            // During constructor probing we must not run the guest worker
            // synchronously: many pthread entry points are intentionally
            // long-lived loops. Real concurrent guest threads are a later
            // runtime subsystem.
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

        if (name == "pthread_mutexattr_init" ||
            name == "pthread_mutexattr_settype" ||
            name == "pthread_mutexattr_setpshared" ||
            name == "pthread_mutexattr_destroy" ||
            name == "pthread_mutex_init" ||
            name == "pthread_mutex_destroy" ||
            name == "pthread_mutex_lock" ||
            name == "pthread_mutex_unlock") {

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_mutex_trylock") {
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

        // Bulk single-process pthread/semaphore compatibility. This is
        // intentionally sufficient for static construction; real concurrent
        // guest threads will be introduced as a separate runtime subsystem.
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
            name == "pthread_cond_signal" ||
            name == "pthread_cond_broadcast" ||
            name == "pthread_detach" ||
            name == "pthread_join" ||
            name == "pthread_setschedparam" ||
            name == "sched_yield") {

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_self") {
            regs[0] = 1;
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
                    std::memset(p, 0, 64);
                }
            }

            regs[0] = 0;
            ++supported_calls;
            return;
        }

        if (name == "pthread_cond_wait" ||
            name == "pthread_cond_timedwait") {

            // No competing guest thread exists during constructor probing.
            // Returning success prevents a fake single-thread deadlock.
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

            mem.Write32Guest(
                sem,
                mem.Read32Guest(sem) + 1u);

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

            if (count > 0) {
                mem.Write32Guest(
                    sem,
                    count - 1u);
                regs[0] = 0;
            } else {
                // During constructor bring-up there is no other guest thread
                // capable of posting, so do not block the host forever.
                regs[0] =
                    name == "sem_wait"
                        ? 0u
                        : 0xffffffffu;
            }

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
        ticks_consumed += ticks;

        if (return_mode == ReturnMode::Constructor &&
            ticks_consumed >= next_tick_report) {

            Append(
                "constructor[" +
                std::to_string(current_constructor_index) +
                "] long-run progress: ticks=" +
                std::to_string(ticks_consumed) +
                " PC=0x" +
                JniProbeHex(jit ? jit->Regs()[15] : 0u));

            while (next_tick_report <= ticks_consumed) {
                next_tick_report += 5000000ull;
            }
        }

        if (ticks >= ticks_left) {
            ticks_left = 0;
            result.message =
                return_mode == ReturnMode::Constructor
                    ? ("Constructor[" +
                       std::to_string(current_constructor_index) +
                       "] exceeded the extended 50M-tick budget at guest PC 0x" +
                       JniProbeHex(jit ? jit->Regs()[15] : 0u) +
                       " after " +
                       std::to_string(ticks_consumed) +
                       " ticks.")
                    : "JNI_OnLoad exceeded the probe instruction budget.";

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

        if (progress_callback) {
            progress_callback(line);
        }
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
    PvZ2ProbeProgress progress) {

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
            result,
            std::move(progress));

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

        Dynarmic::A32::Jit jit{config};
        callbacks.jit = &jit;

        callbacks.Append(
            "PvZ2 full-load probe: .init_array slots=" +
            std::to_string(result.init_array_slots) +
            ", non-null constructors=" +
            std::to_string(result.constructors_total));

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

            const Dynarmic::HaltReason app_halt =
                jit.Run();

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
                result.ok = true;
                result.message =
                    "Native_GameAppInitialize executed to return under Dynarmic; jboolean result=" +
                    std::to_string(
                        result.game_app_initialize_return & 0xffu) +
                    ".";
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
