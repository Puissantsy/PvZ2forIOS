#include "pvz2_apk_probe.hpp"
#include "host_gles.hpp"

#include <OpenGLES/ES2/gl.h>
#include <OpenGLES/ES2/glext.h>

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
#include <fnmatch.h>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>

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
    std::uint32_t heap_high_water = 0;
    std::uint32_t heap_live_bytes = 0;
    std::uint32_t object_next = 0;
    std::unordered_map<std::uint32_t, std::uint32_t> heap_allocations;
    std::map<std::uint32_t, std::uint32_t> heap_free_blocks;

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

    void InsertFreeHeapBlock(
        std::uint32_t offset,
        std::uint32_t size) {

        if (size == 0u) {
            return;
        }

        auto next =
            heap_free_blocks.lower_bound(offset);

        if (next != heap_free_blocks.begin()) {
            auto previous =
                std::prev(next);

            if (previous->first +
                    previous->second ==
                offset) {

                offset =
                    previous->first;
                size +=
                    previous->second;
                heap_free_blocks.erase(
                    previous);
            }
        }

        next =
            heap_free_blocks.lower_bound(offset);

        if (next != heap_free_blocks.end() &&
            offset + size == next->first) {

            size +=
                next->second;
            heap_free_blocks.erase(next);
        }

        heap_free_blocks[offset] =
            size;

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
            heap_free_blocks.erase(tail);
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

        for (auto it =
                 heap_free_blocks.begin();
             it != heap_free_blocks.end();
             ++it) {

            const std::uint32_t block_begin =
                it->first;
            const std::uint32_t block_size =
                it->second;
            const std::uint32_t aligned =
                AlignHeapOffset(
                    block_begin,
                    safe_alignment);

            if (aligned == 0xffffffffu ||
                aligned < block_begin) {
                continue;
            }

            const std::uint32_t prefix =
                aligned - block_begin;

            if (prefix > block_size ||
                requested >
                    block_size - prefix) {
                continue;
            }

            const std::uint32_t block_end =
                block_begin + block_size;
            const std::uint32_t allocation_end =
                aligned + requested;

            heap_free_blocks.erase(it);

            if (prefix != 0u) {
                heap_free_blocks[
                    block_begin] =
                    prefix;
            }

            if (allocation_end <
                block_end) {
                heap_free_blocks[
                    allocation_end] =
                    block_end -
                    allocation_end;
            }

            const std::uint32_t address =
                kJniProbeHeapBase +
                aligned;

            heap_allocations[address] =
                requested;
            heap_live_bytes +=
                requested;

            return address;
        }

        const std::uint32_t aligned =
            AlignHeapOffset(
                heap_next,
                safe_alignment);

        if (aligned == 0xffffffffu ||
            aligned > kJniProbeHeapSize ||
            requested >
                kJniProbeHeapSize -
                    aligned) {
            return 0;
        }

        heap_next =
            aligned + requested;
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
        const auto it =
            heap_allocations.find(
                address);

        if (it ==
            heap_allocations.end()) {
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
            address -
                kJniProbeHeapBase,
            size);
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
        std::size_t expansion_size = 0)
        : mem(memory),
          result(output),
          progress_callback(std::move(progress)),
          obb_data(expansion_data),
          obb_size(expansion_size) {}

    Dynarmic::A32::Jit* jit = nullptr;
    std::unordered_map<std::uint32_t, JniProbeImportBinding>
        imports_by_svc;

    enum class ReturnMode {
        JniOnLoad,
        Constructor,
        GameAppInitialize,
        Lifecycle,
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
        std::string label;
    };

    std::uint32_t next_gl_object = 1;
    bool host_gles_ready = false;
    std::uint32_t host_default_framebuffer = 0;
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

    static constexpr std::uint32_t kSweepRecoveryLimit = 48u;
    std::uint32_t sweep_recoveries = 0;
    bool sweep_speculative = false;
    std::unordered_set<std::string> sweep_issue_keys;
    std::unordered_set<std::string> sweep_recovery_keys;
    std::vector<std::string> sweep_issues;

    std::unordered_map<std::uint32_t, ProbeObbHandle> obb_fds;
    std::unordered_map<std::uint32_t, ProbeObbHandle> obb_files;
    std::unordered_set<std::string> fallback_logged;
    std::unordered_map<std::uint32_t, std::uint32_t> pthread_specific;
    std::unordered_map<std::uint32_t, std::string> jni_method_names;
    std::unordered_map<std::uint32_t, std::string> jni_method_signatures;
    std::unordered_map<std::uint32_t, std::string> jni_strings;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_array_lengths;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_array_data;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_array_element_sizes;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> jni_object_arrays;
    std::unordered_map<std::uint32_t, std::uint32_t> jni_direct_buffer_address;
    std::unordered_map<std::uint32_t, std::uint64_t> jni_direct_buffer_capacity;
    std::unordered_map<std::uint32_t, z_stream> zstreams;
    std::unordered_map<std::uint32_t, bool> zstream_deflate_mode;

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

            jni_method_names[method_id] =
                method_name;
            jni_method_signatures[method_id] =
                signature;

            regs[0] = method_id;

            Append(
                "JNIEnv.GetMethodID(clazz=0x" +
                JniProbeHex(regs[1]) +
                ", name=\"" +
                method_name +
                "\", sig=\"" +
                signature +
                "\") -> 0x" +
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
            } else if (return_mode == ReturnMode::Lifecycle) {
                Append(
                    current_lifecycle_name +
                    " returned.");
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
                Append(
                    "JNIEnv.IsSameObject(0x" +
                    JniProbeHex(regs[1]) +
                    ", 0x" +
                    JniProbeHex(regs[2]) +
                    ") -> " +
                    std::to_string(regs[0]));
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
            case 30: // NewObjectA
                regs[0] = new_object();
                log_jni_fallback("object construction");
                return;

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

                        // Connected/available. Networking itself is still a
                        // separate compatibility surface.
                        regs[0] = 1u;
                        Append(
                            "JNI bridge: GetNetworkStatus -> 1");
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

                        if (data_it !=
                                jni_array_data.end() &&
                            length_it !=
                                jni_array_lengths.end() &&
                            length_it->second >= 2u &&
                            data_it->second != 0u) {

                            // iPad 10th-generation native pixel resolution in
                            // the current landscape orientation.
                            mem.Write32Guest(
                                data_it->second + 0u,
                                2360u);
                            mem.Write32Guest(
                                data_it->second + 4u,
                                1640u);
                        }

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: Graphics_GetScreenSizeInPixels -> 2360x1640");
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Config_ConfigKeyExists") {

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: Config_ConfigKeyExists -> false");
                        return true;
                    }

                    if (family == 1 &&
                        (method_name ==
                             "Config_ConfigWriteInteger" ||
                         method_name ==
                             "Config_ConfigWriteString")) {

                        regs[0] = 1u;
                        Append(
                            "JNI bridge: " +
                            method_name +
                            " -> true");
                        return true;
                    }

                    if (family == 0 &&
                        method_name ==
                            "Config_ConfigReadString") {

                        const std::uint32_t default_value =
                            java_arg_word(1u);

                        regs[0] =
                            default_value != 0u
                                ? default_value
                                : new_string("");

                        Append(
                            "JNI bridge: Config_ConfigReadString -> caller default");
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

                    // v29: the first real draw reached Android's event
                    // pump. UI_ProcessEvents receives a DirectByteBuffer whose
                    // first word is an event count. The old generic boolean
                    // fallback returned false without touching that guest
                    // memory, so stale stack bytes were interpreted as a huge
                    // event count and eventually indexed a null dispatch-table
                    // entry (BLX r2 with r2 == 0 at guest 0x109f0860).
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
                            }
                        }

                        // No iOS touch/key events are queued by the probe yet.
                        // A zeroed event block + false is the safe empty-pump
                        // result expected by the native decoder.
                        regs[0] = 0u;

                        Append(
                            "JNI bridge: UI_ProcessEvents -> false; zeroed direct buffer bytes=" +
                            std::to_string(cleared));
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

                        if (data_it !=
                                jni_array_data.end() &&
                            length_it !=
                                jni_array_lengths.end() &&
                            length_it->second >= 2u &&
                            data_it->second != 0u) {

                            // iPad 10th-generation logical landscape size:
                            // 2360x1640 native pixels at a 2x point scale.
                            mem.Write32Guest(
                                data_it->second + 0u,
                                1180u);
                            mem.Write32Guest(
                                data_it->second + 4u,
                                820u);
                        }

                        regs[0] = 0u;
                        Append(
                            "JNI bridge: Graphics_GetScreenSizeInPoints -> 1180x820");
                        return true;
                    }

                    if (family == 1 &&
                        method_name ==
                            "Graphics_CanSetGLViewScaleFactor") {

                        // The probe does not expose a real Android GLSurfaceView
                        // scaling control. Reporting false avoids asking Java
                        // to mutate a view that does not exist on iOS.
                        regs[0] = 0u;
                        Append(
                            "JNI bridge: Graphics_CanSetGLViewScaleFactor -> false");
                        return true;
                    }

                    if (family == 5 &&
                        method_name ==
                            "Graphics_GetGLViewSysFBO") {

                        // OpenGL ES default framebuffer.
                        regs[0] = 0u;
                        Append(
                            "JNI bridge: Graphics_GetGLViewSysFBO -> 0");
                        return true;
                    }

                    if (family == 7 &&
                        method_name ==
                            "Graphics_GetPointSizeInPixels") {

                        regs[0] = 0x40000000u; // 2.0f
                        Append(
                            "JNI bridge: Graphics_GetPointSizeInPixels -> 2.0");
                        return true;
                    }

                    if (family == 7 &&
                        method_name ==
                            "Graphics_GetGLViewScaleFactor") {

                        regs[0] = 0x3f800000u; // 1.0f
                        Append(
                            "JNI bridge: Graphics_GetGLViewScaleFactor -> 1.0");
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
                            "Cloud_attemptSilentSync",
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

                        // AndroidGameApp implements this with
                        // AssetManager.openFd(). The supported APK contains
                        // no assets/ files; IOException returns -1L.
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
            mem.FreeHeap(regs[0]);
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
            const std::uint32_t address =
                mem.ReallocateHeap(
                    regs[0],
                    regs[1]);

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
                                    kJniProbeHeapSize) {
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

            Append(
                "import pthread_create deferred: tid=" +
                std::to_string(thread_id) +
                " start=0x" +
                JniProbeHex(start_routine) +
                " arg=0x" +
                JniProbeHex(argument) +
                " created_in=" +
                phase);

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
                    text.substr(
                        missing_resource),
                    text);
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

                if (obb_data == nullptr ||
                    obb_size < 0x70u) {
                    return std::nullopt;
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

        static const std::unordered_set<std::string> kStdio = {
            "fclose","fdopen","feof","ferror","fflush","fgetc","fgets",
            "fopen","fprintf","fputc","fputs","fread","fscanf","fseek",
            "fsetpos","ftell","fwrite","getc","printf","putc","puts",
            "setvbuf","snprintf","sprintf","sscanf","ungetc","vsnprintf",
            "vsprintf","qsort","lrand48","srand48","strtok"
        };

        if (kStdio.count(name) != 0) {
            if (name == "fopen") {
                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);

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

            if (name == "fclose") {
                const auto erased =
                    obb_files.erase(regs[0]);

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
                    std::memcpy(
                        mem.Ptr(
                            dst,
                            static_cast<std::size_t>(
                                bytes)),
                        obb_data +
                            static_cast<std::size_t>(
                                it->second.base +
                                it->second.offset),
                        static_cast<std::size_t>(
                            bytes));
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
                    static_cast<std::uint64_t>(
                        next) >
                        it->second.length) {

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
            } else if (name == "lrand48") {
                regs[0] = 0x12345678u;
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

                // The probe VFS currently exposes individual APK/OBB/RSB
                // files, not a writable Android directory hierarchy. v27
                // returned the generic -1 value as a non-null DIR*, which
                // made PvZ2 call readdir(-1) forever. POSIX opendir failure is
                // NULL, so unavailable directories must return 0.
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
                // No synthetic DIR handle is currently produced. Keep failure
                // semantics correct rather than pretending an invalid handle
                // closed successfully.
                set_guest_errno(9u);
                regs[0] = 0xffffffffu;
                ++supported_calls;
                return;
            }

            if (name == "open") {
                const std::string guest_path =
                    mem.ReadCStringGuest(
                        regs[0],
                        2048);

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
                const auto erased =
                    obb_fds.erase(regs[0]);

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

                if (bytes != 0u) {
                    std::memcpy(
                        mem.Ptr(
                            dst,
                            static_cast<std::size_t>(
                                bytes)),
                        obb_data +
                            static_cast<std::size_t>(
                                it->second.base +
                                it->second.offset),
                        static_cast<std::size_t>(
                            bytes));
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
                    static_cast<std::uint64_t>(
                        next) >
                        it->second.length) {

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

                const auto resolved =
                    resolve_obb_virtual_file(
                        guest_path);

                const bool exists =
                    resolved.has_value();

                if (name == "access") {
                    regs[0] =
                        exists
                            ? 0u
                            : 0xffffffffu;
                } else if (exists &&
                           write_armeabi_stat(
                               regs[1],
                               resolved->length)) {
                    regs[0] = 0;
                } else {
                    regs[0] = 0xffffffffu;
                }

                if (!exists) {
                    set_guest_errno(2u);
                }

                ++supported_calls;
                return;
            }

            log_fallback_once("posix-fs");

            if (name == "write") {
                regs[0] = regs[2];
            } else if (name == "writev") {
                regs[0] = 0;
            } else if (name == "mkdir" ||
                       name == "fsync" ||
                       name == "unlink") {
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
                        mem.Write32Guest(
                            output +
                                static_cast<std::uint32_t>(
                                    i) *
                                    4u,
                            static_cast<std::uint32_t>(
                                objects[
                                    static_cast<std::size_t>(
                                        i)]));
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

                    glBindAttribLocation(
                        static_cast<GLuint>(
                            guest_arg(0u)),
                        static_cast<GLuint>(
                            guest_arg(1u)),
                        attribute.c_str());

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
                            std::memcpy(
                                out,
                                buffer.data(),
                                copy);
                            out[copy] = 0u;
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

                    regs[0] =
                        static_cast<std::uint32_t>(
                            glGetUniformLocation(
                                static_cast<GLuint>(
                                    guest_arg(0u)),
                                uniform.c_str()));
                } else if (name == "glUseProgram") {
                    glUseProgram(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glUniform1i") {
                    glUniform1i(
                        static_cast<GLint>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)));
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

                    glUniform4fv(
                        static_cast<GLint>(
                            guest_arg(0u)),
                        count,
                        values);
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

                    glUniformMatrix4fv(
                        static_cast<GLint>(
                            guest_arg(0u)),
                        count,
                        static_cast<GLboolean>(
                            guest_arg(2u)),
                        values);
                    regs[0] = 0u;
                } else if (name == "glBindTexture") {
                    glBindTexture(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLuint>(
                            guest_arg(1u)));
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
                    regs[0] = 0u;
                } else if (name == "glTexSubImage2D") {
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
                    regs[0] = 0u;
                } else if (
                    name == "glCompressedTexImage2D") {

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

                    glCompressedTexImage2D(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLenum>(
                            guest_arg(2u)),
                        static_cast<GLsizei>(
                            guest_arg(3u)),
                        static_cast<GLsizei>(
                            guest_arg(4u)),
                        static_cast<GLint>(
                            guest_arg(5u)),
                        image_size,
                        data);
                    regs[0] = 0u;
                } else if (
                    name == "glBindFramebuffer" ||
                    name == "glBindFramebufferOES") {

                    GLuint framebuffer =
                        static_cast<GLuint>(
                            guest_arg(1u));

                    if (framebuffer == 0u) {
                        framebuffer =
                            static_cast<GLuint>(
                                host_default_framebuffer);
                    }

                    glBindFramebuffer(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        framebuffer);
                    regs[0] = 0u;
                } else if (
                    name == "glFramebufferTexture2D" ||
                    name == "glFramebufferTexture2DOES") {

                    glFramebufferTexture2D(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLenum>(
                            guest_arg(1u)),
                        static_cast<GLenum>(
                            guest_arg(2u)),
                        static_cast<GLuint>(
                            guest_arg(3u)),
                        static_cast<GLint>(
                            guest_arg(4u)));
                    regs[0] = 0u;
                } else if (name == "glViewport") {
                    glViewport(
                        static_cast<GLint>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLsizei>(
                            guest_arg(2u)),
                        static_cast<GLsizei>(
                            guest_arg(3u)));
                    regs[0] = 0u;
                } else if (name == "glScissor") {
                    glScissor(
                        static_cast<GLint>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLsizei>(
                            guest_arg(2u)),
                        static_cast<GLsizei>(
                            guest_arg(3u)));
                    regs[0] = 0u;
                } else if (name == "glClearColor") {
                    glClearColor(
                        guest_f32(0u),
                        guest_f32(1u),
                        guest_f32(2u),
                        guest_f32(3u));
                    regs[0] = 0u;
                } else if (name == "glClear") {
                    glClear(
                        static_cast<GLbitfield>(
                            guest_arg(0u)));
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
                    glEnable(
                        static_cast<GLenum>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glDisable") {
                    glDisable(
                        static_cast<GLenum>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (name == "glBlendFunc") {
                    glBlendFunc(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLenum>(
                            guest_arg(1u)));
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
                    glColorMask(
                        static_cast<GLboolean>(
                            guest_arg(0u)),
                        static_cast<GLboolean>(
                            guest_arg(1u)),
                        static_cast<GLboolean>(
                            guest_arg(2u)),
                        static_cast<GLboolean>(
                            guest_arg(3u)));
                    regs[0] = 0u;
                } else if (name == "glActiveTexture") {
                    glActiveTexture(
                        static_cast<GLenum>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (
                    name == "glEnableVertexAttribArray") {
                    glEnableVertexAttribArray(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (
                    name == "glDisableVertexAttribArray") {
                    glDisableVertexAttribArray(
                        static_cast<GLuint>(
                            guest_arg(0u)));
                    regs[0] = 0u;
                } else if (
                    name == "glVertexAttribPointer") {
                    const std::uint32_t pointer_address =
                        guest_arg(5u);
                    const void* pointer =
                        pointer_address != 0u
                            ? mem.Ptr(
                                  pointer_address,
                                  1u)
                            : nullptr;

                    glVertexAttribPointer(
                        static_cast<GLuint>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLenum>(
                            guest_arg(2u)),
                        static_cast<GLboolean>(
                            guest_arg(3u)),
                        static_cast<GLsizei>(
                            guest_arg(4u)),
                        pointer);
                    regs[0] = 0u;
                } else if (name == "glDrawArrays") {
                    glDrawArrays(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        static_cast<GLint>(
                            guest_arg(1u)),
                        static_cast<GLsizei>(
                            guest_arg(2u)));
                    regs[0] = 0u;
                } else if (name == "glDrawElements") {
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

                    glDrawElements(
                        static_cast<GLenum>(
                            guest_arg(0u)),
                        count,
                        type,
                        indices);
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
            log_fallback_once("opensl-probe");
            // Report unavailable audio cleanly. The real backend will map
            // OpenSL ES to iOS audio instead of constructing fake vtables.
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
            return;
        }

        result.first_unsupported_import = name;

        const std::uint32_t lr =
            jit ? jit->Regs()[14] : 0u;

        const std::string unsupported_import =
            "Unsupported Android import " +
            name +
            " reached at LR=0x" +
            JniProbeHex(lr) +
            " via trampoline 0x" +
            JniProbeHex(
                binding->second.trampoline);

        RecordSweepIssue(
            "unsupported-import",
            name,
            unsupported_import);

        if (ConsumeSweepRecovery(
                "unsupported-import",
                unsupported_import)) {

            regs[0] = 0u;
            regs[1] = 0u;
            ++supported_calls;
            return;
        }

        result.message =
            unsupported_import;

        jit->HaltExecution(
            Dynarmic::HaltReason::UserDefined2);
    }

    void ExceptionRaised(
        std::uint32_t pc,
        Dynarmic::A32::Exception exception) override {

        auto exception_name =
            [&]() -> const char* {
                switch (exception) {
                case Dynarmic::A32::Exception::UndefinedInstruction:
                    return "UndefinedInstruction";
                case Dynarmic::A32::Exception::UnpredictableInstruction:
                    return "UnpredictableInstruction";
                case Dynarmic::A32::Exception::DecodeError:
                    return "DecodeError";
                case Dynarmic::A32::Exception::SendEvent:
                    return "SendEvent";
                case Dynarmic::A32::Exception::SendEventLocal:
                    return "SendEventLocal";
                case Dynarmic::A32::Exception::WaitForInterrupt:
                    return "WaitForInterrupt";
                case Dynarmic::A32::Exception::WaitForEvent:
                    return "WaitForEvent";
                case Dynarmic::A32::Exception::Yield:
                    return "Yield";
                case Dynarmic::A32::Exception::Breakpoint:
                    return "Breakpoint";
                case Dynarmic::A32::Exception::PreloadData:
                    return "PreloadData";
                case Dynarmic::A32::Exception::PreloadDataWithIntentToWrite:
                    return "PreloadDataWithIntentToWrite";
                case Dynarmic::A32::Exception::PreloadInstruction:
                    return "PreloadInstruction";
                case Dynarmic::A32::Exception::NoExecuteFault:
                    return "NoExecuteFault";
                default:
                    return "Unknown";
                }
            };

        const std::uint32_t lr =
            jit ? jit->Regs()[14] : 0u;
        const std::uint32_t sp =
            jit ? jit->Regs()[13] : 0u;
        const std::uint32_t return_pc =
            lr & ~1u;

        std::ostringstream out;
        out
            << "Dynarmic exception "
            << exception_name()
            << " type="
            << static_cast<unsigned>(exception)
            << " PC=0x"
            << JniProbeHex(pc)
            << " LR=0x"
            << JniProbeHex(lr)
            << " returnPC=0x"
            << JniProbeHex(return_pc)
            << " SP=0x"
            << JniProbeHex(sp)
            << " phase="
            << (current_lifecycle_name.empty()
                    ? "n/a"
                    : current_lifecycle_name)
            << " pthread="
            << current_probe_thread_id
            << " nullRecoveries="
            << null_execute_recoveries;

        if (jit) {
            out
                << " CPSR=0x"
                << JniProbeHex(jit->Cpsr());

            for (std::size_t reg = 0;
                 reg < 13;
                 ++reg) {
                out
                    << " r"
                    << reg
                    << "=0x"
                    << JniProbeHex(
                        jit->Regs()[reg]);
            }

            out
                << " stack={";

            for (std::uint32_t off = 0;
                 off < 32u;
                 off += 4u) {
                if (off != 0u) {
                    out << ",";
                }
                out
                    << "0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            sp + off));
            }

            out << "}";

            if (return_pc >= 8u) {
                out
                    << " codeAroundLR={0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc - 8u))
                    << ",0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc - 4u))
                    << ",0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc))
                    << ",0x"
                    << JniProbeHex(
                        mem.Read32Guest(
                            return_pc + 4u))
                    << "}";
            }
        }

        out
            << " VFS{reads="
            << obb_read_calls
            << ",nonzero="
            << obb_nonzero_read_calls
            << ",bytes="
            << obb_bytes_returned
            << ",maxEnd=0x"
            << JniProbeHex(
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        obb_max_read_end,
                        0xffffffffull)))
            << ",seeks="
            << obb_seek_calls
            << ",lastReadOff=0x"
            << JniProbeHex(
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        last_obb_read_offset,
                        0xffffffffull)))
            << ",lastReq="
            << last_obb_read_requested
            << ",lastRet="
            << last_obb_read_returned
            << ",lastSeek=0x"
            << JniProbeHex(
                static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(
                        last_obb_seek_target,
                        0xffffffffull)))
            << "}";

        if (!last_android_log.empty()) {
            out
                << " lastLog=\""
                << last_android_log
                << "\"";
        }

        const char packages_version[] =
            "RESFILE_PACKAGES_VERSION";

        if (obb_data &&
            obb_size >=
                sizeof(packages_version) - 1u) {

            const auto* begin =
                obb_data;
            const auto* end =
                obb_data + obb_size;
            const auto* hit =
                std::search(
                    begin,
                    end,
                    packages_version,
                    packages_version +
                        sizeof(packages_version) - 1u);

            if (hit != end) {
                out
                    << " packagesVersionInOBB=0x"
                    << JniProbeHex(
                        static_cast<std::uint32_t>(
                            hit - begin));
            } else {
                out
                    << " packagesVersionInOBB=NOT_FOUND";
            }
        }

        const std::string diagnostic =
            out.str();

        Append(
            "V23 EXCEPTION: " +
            diagnostic);

        // A direct branch/call through address 0 is a common artifact of an
        // optional Android callback/resource hook that is absent from the
        // probe environment. For lifecycle/worker execution, recover a small
        // bounded number of such calls exactly like a null callback returning
        // 0. We still log the complete callsite first so the recovery is
        // auditable and can be replaced by a real bridge later.
        const bool recoverable_null_call =
            exception ==
                Dynarmic::A32::Exception::NoExecuteFault &&
            pc == 0u &&
            jit != nullptr &&
            return_mode == ReturnMode::Lifecycle &&
            return_pc != 0u &&
            mem.Ptr(return_pc, 2) != nullptr &&
            sweep_recoveries <
                kSweepRecoveryLimit;

        if (recoverable_null_call) {
            ++null_execute_recoveries;

            RecordSweepIssue(
                "null-call",
                JniProbeHex(return_pc),
                "NoExecuteFault at PC=0 returned to LR=0x" +
                    JniProbeHex(lr) +
                    " phase=" +
                    (current_lifecycle_name.empty()
                        ? std::string{"n/a"}
                        : current_lifecycle_name));

            if (!ConsumeSweepRecovery(
                    "null-call",
                    "resume at LR=0x" +
                        JniProbeHex(lr))) {

                result.message =
                    diagnostic;
                jit->HaltExecution(
                    Dynarmic::HaltReason::UserDefined3);
                return;
            }

            auto& regs =
                jit->Regs();

            regs[0] = 0u;
            regs[15] =
                return_pc;

            std::uint32_t cpsr =
                jit->Cpsr();

            if ((lr & 1u) != 0u) {
                cpsr |= 0x20u;
            } else {
                cpsr &= ~0x20u;
            }

            jit->SetCpsr(cpsr);
            jit->ClearExclusiveState();

            Append(
                "V23 NULL-CALL RECOVERY #" +
                std::to_string(
                    null_execute_recoveries) +
                ": synthesized r0=0 and resumed at LR=0x" +
                JniProbeHex(lr));

            result.message.clear();

            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined4);
            return;
        }

        result.message =
            diagnostic;

        if (jit) {
            jit->HaltExecution(
                Dynarmic::HaltReason::UserDefined3);
        }
    }

    void AddTicks(std::uint64_t ticks) override {
        ticks_consumed += ticks;

        auto phase_name =
            [&]() -> std::string {
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

        if (ticks_consumed >= next_tick_report) {
            std::ostringstream progress;
            progress
                << phase_name()
                << " long-run progress: ticks="
                << ticks_consumed
                << " PC=0x"
                << JniProbeHex(jit ? jit->Regs()[15] : 0u)
                << " LR=0x"
                << JniProbeHex(jit ? jit->Regs()[14] : 0u)
                << " SP=0x"
                << JniProbeHex(jit ? jit->Regs()[13] : 0u);

            Append(progress.str());

            while (next_tick_report <= ticks_consumed) {
                next_tick_report += 5000000ull;
            }
        }

        if (ticks >= ticks_left) {
            ticks_left = 0;

            if (soft_slice_timeout) {
                if (jit) {
                    jit->HaltExecution(
                        Dynarmic::HaltReason::UserDefined4);
                }
                return;
            }

            const std::uint32_t pc =
                jit ? jit->Regs()[15] : 0u;
            const std::uint32_t lr =
                jit ? jit->Regs()[14] : 0u;
            const std::uint32_t sp =
                jit ? jit->Regs()[13] : 0u;

            std::ostringstream timeout;
            timeout
                << phase_name()
                << " exceeded the 50M-tick probe budget"
                << " at PC=0x" << JniProbeHex(pc)
                << " LR=0x" << JniProbeHex(lr)
                << " caller=0x"
                << JniProbeHex(lr >= 4u ? lr - 4u : lr)
                << " SP=0x" << JniProbeHex(sp)
                << " after " << ticks_consumed
                << " ticks";

            if (jit) {
                timeout
                    << "; r0=0x" << JniProbeHex(jit->Regs()[0])
                    << " r1=0x" << JniProbeHex(jit->Regs()[1])
                    << " r2=0x" << JniProbeHex(jit->Regs()[2])
                    << " r3=0x" << JniProbeHex(jit->Regs()[3])
                    << " r4=0x" << JniProbeHex(jit->Regs()[4])
                    << " r5=0x" << JniProbeHex(jit->Regs()[5])
                    << " r6=0x" << JniProbeHex(jit->Regs()[6])
                    << " r7=0x" << JniProbeHex(jit->Regs()[7]);
            }

            timeout << ".";

            result.message = timeout.str();
            Append("EXECUTION BUDGET: " + result.message);

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
        // Guest-derived strings can contain arbitrary bytes. Keep the trace
        // valid UTF-8/ASCII so one bad Android log/method string cannot make
        // the entire diagnostic disappear in NSStringFromStd.
        constexpr char hex[] = "0123456789abcdef";
        std::string safe;
        safe.reserve(
            std::min<std::size_t>(
                line.size() * 2u,
                8192u));

        const std::size_t limit =
            std::min<std::size_t>(
                line.size(),
                4096u);

        for (std::size_t i = 0; i < limit; ++i) {
            const unsigned char ch =
                static_cast<unsigned char>(line[i]);

            if ((ch >= 0x20u && ch <= 0x7eu) ||
                ch == '\t') {
                safe.push_back(
                    static_cast<char>(ch));
            } else {
                safe += "\\x";
                safe.push_back(hex[(ch >> 4) & 0x0fu]);
                safe.push_back(hex[ch & 0x0fu]);
            }
        }

        if (line.size() > limit) {
            safe += "...<truncated>";
        }

        trace << safe << '\n';

        if (progress_callback) {
            progress_callback(safe);
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
    const std::uint8_t* obb_data,
    std::size_t obb_size,
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
            std::move(progress),
            obb_data,
            obb_size);

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
            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined2);
            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined3);
            jit.ClearHalt(
                Dynarmic::HaltReason::UserDefined4);

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
                if ((result.game_app_initialize_return & 0xffu) == 0u) {
                    result.message =
                        "Native_GameAppInitialize returned JNI_FALSE; lifecycle probe not started.";
                    return result;
                }

                callbacks.Append(
                    "Native_GameAppInitialize returned JNI_TRUE; entering real PvZ2 lifecycle/surface sequence.");

                auto run_lifecycle =
                    [&](const char* name,
                        std::uint32_t function,
                        std::uint32_t thiz,
                        std::uint32_t arg2,
                        std::uint32_t arg3,
                        bool first_draw) -> bool {

                        auto clear_probe_halts =
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

                        auto async_future_snapshot =
                            [&](std::uint32_t future) {
                                const std::uint32_t vtable =
                                    memory.Read32Guest(future);

                                std::ostringstream out;
                                out
                                    << "future=0x"
                                    << JniProbeHex(future)
                                    << " vtable=0x"
                                    << JniProbeHex(vtable)
                                    << " vfn8=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x08u))
                                    << " vfnC=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x0cu))
                                    << " vfn10=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            vtable + 0x10u))
                                    << " done="
                                    << static_cast<unsigned>(
                                        memory.Read8(
                                            future + 0x14u))
                                    << " failed="
                                    << static_cast<unsigned>(
                                        memory.Read8(
                                            future + 0x15u))
                                    << " w18=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x18u))
                                    << " w1C=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x1cu))
                                    << " w20=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x20u))
                                    << " w24=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x24u))
                                    << " w28=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x28u))
                                    << " w2C=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x2cu))
                                    << " w30=0x"
                                    << JniProbeHex(
                                        memory.Read32Guest(
                                            future + 0x30u));

                                return out.str();
                            };

                        auto wait_kind =
                            [&](std::uint32_t pc) -> const char* {
                                if (pc >=
                                        kGuestBase + 0x009f6f24u &&
                                    pc <=
                                        kGuestBase + 0x009f7050u) {
                                    return "future-poll";
                                }

                                // Verified by disassembly of 1.5.252752:
                                // 0x864968 and 0x864a40 repeatedly invoke the
                                // async stream status virtual at +0x2c while
                                // reading the 1bsr resource header/body.
                                if ((pc >=
                                         kGuestBase + 0x00864960u &&
                                     pc <=
                                         kGuestBase + 0x00864998u) ||
                                    (pc >=
                                         kGuestBase + 0x00864a38u &&
                                     pc <=
                                         kGuestBase + 0x00864a70u)) {
                                    return "rsb-read-wait";
                                }

                                return "timeslice";
                            };

                        auto wait_object_for_pc =
                            [&](std::uint32_t pc) {
                                const char* kind =
                                    wait_kind(pc);

                                if (std::strcmp(
                                        kind,
                                        "rsb-read-wait") == 0) {
                                    return jit.Regs()[5];
                                }

                                return jit.Regs()[4];
                            };

                        callbacks.return_mode =
                            PvZ2JniCallbacks::ReturnMode::Lifecycle;
                        callbacks.current_lifecycle_name =
                            name;
                        callbacks.current_probe_thread_id = 0;
                        callbacks.control_returned = false;
                        callbacks.soft_slice_timeout = true;

                        result.message.clear();
                        result.first_unsupported_import.clear();
                        result.unsupported_jni_slot = 0xffffffffu;

                        clear_probe_halts();

                        jit.Regs().fill(0);
                        jit.ExtRegs().fill(0);
                        jit.Regs()[0] =
                            callbacks.env_object;
                        jit.Regs()[1] =
                            thiz;
                        jit.Regs()[2] =
                            arg2;
                        jit.Regs()[3] =
                            arg3;
                        jit.Regs()[13] =
                            kJniProbeStackBase +
                            kJniProbeStackSize -
                            0x200u;
                        jit.Regs()[14] =
                            return_trampoline;
                        jit.Regs()[15] =
                            function & ~1u;

                        jit.SetCpsr(
                            (function & 1u)
                                ? 0x30u
                                : 0x10u);
                        jit.SetFpscr(0u);
                        jit.ClearExclusiveState();

                        if (first_draw) {
                            result.reached_first_draw_frame = true;
                        }

                        callbacks.Append(
                            "Entering " +
                            std::string{name} +
                            " at 0x" +
                            JniProbeHex(function) +
                            " with v22 general cooperative worker scheduling; deferred_threads=" +
                            std::to_string(
                                callbacks.deferred_threads.size()));

                        constexpr std::uint64_t kMainSliceTicks =
                            1000000ull;
                        constexpr std::uint64_t kWorkerSliceTicks =
                            750000ull;
                        // v26 proved that onSurfaceCreated can still be doing
                        // real CPU/resource work after 200M main-thread ticks.
                        // Keep a large absolute safety ceiling, but report
                        // concrete progress instead of treating 200M as a
                        // deadlock by itself.
                        constexpr std::uint64_t kLifecycleTotalBudget =
                            2000000000ull;
                        constexpr std::uint32_t kWorkerStackSize =
                            64u * 1024u;

                        std::uint64_t lifecycle_ticks = 0;
                        std::uint32_t async_round = 0;

                        while (lifecycle_ticks <
                               kLifecycleTotalBudget) {

                            callbacks.return_mode =
                                PvZ2JniCallbacks::ReturnMode::Lifecycle;
                            callbacks.current_lifecycle_name =
                                name;
                            callbacks.current_probe_thread_id = 0;
                            callbacks.control_returned = false;
                            callbacks.soft_slice_timeout = true;
                            callbacks.ticks_left =
                                kMainSliceTicks;
                            callbacks.ticks_consumed = 0;
                            callbacks.next_tick_report =
                                kMainSliceTicks;

                            result.message.clear();
                            clear_probe_halts();

                            const Dynarmic::HaltReason lifecycle_halt =
                                jit.Run();

                            lifecycle_ticks +=
                                callbacks.ticks_consumed;

                            result.final_pc =
                                jit.Regs()[15];

                            result.halt_reason =
                                static_cast<std::uint32_t>(
                                    lifecycle_halt);

                            result.supported_import_calls =
                                callbacks.supported_calls;

                            const bool lifecycle_fatal =
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined2) ||
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined3);

                            if (callbacks.control_returned &&
                                !lifecycle_fatal &&
                                Dynarmic::Has(
                                    lifecycle_halt,
                                    Dynarmic::HaltReason::UserDefined1)) {

                                callbacks.soft_slice_timeout = false;

                                ++result.lifecycle_calls_completed;

                                if (first_draw) {
                                    result.returned_first_draw_frame =
                                        true;
                                }

                                callbacks.Append(
                                    "V22 LIFECYCLE RETURN: " +
                                    std::string{name} +
                                    " completed after " +
                                    std::to_string(
                                        lifecycle_ticks) +
                                    " scheduled ticks.");

                                result.trace =
                                    callbacks.Trace();

                                return true;
                            }

                            if (lifecycle_fatal) {
                                callbacks.soft_slice_timeout = false;
                                result.lifecycle_failure_name =
                                    name;
                                result.trace =
                                    callbacks.Trace();

                                if (result.message.empty()) {
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
                            if (callbacks.deferred_threads.empty()) {
                                continue;
                            }

                            ++async_round;

                            const char* current_wait_kind =
                                wait_kind(result.final_pc);

                            const bool concrete_wait =
                                std::strcmp(
                                    current_wait_kind,
                                    "timeslice") != 0;

                            const std::uint32_t future =
                                concrete_wait
                                    ? wait_object_for_pc(
                                          result.final_pc)
                                    : 0u;

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
                                callbacks.Append(
                                    "V30 SCHED WAIT " +
                                    std::to_string(async_round) +
                                    ": kind=" +
                                    current_wait_kind +
                                    " main PC=0x" +
                                    JniProbeHex(
                                        result.final_pc) +
                                    " wait_object{" +
                                    async_future_snapshot(
                                        future) +
                                    "} workers=" +
                                    std::to_string(
                                        callbacks.deferred_threads.size()));
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

                            const auto main_regs =
                                jit.Regs();
                            const auto main_ext_regs =
                                jit.ExtRegs();
                            const std::uint32_t main_cpsr =
                                jit.Cpsr();
                            const std::uint32_t main_fpscr =
                                jit.Fpscr();

                            bool future_changed = false;
                            bool any_worker_ran = false;

                            const std::size_t worker_limit =
                                std::min<std::size_t>(
                                    callbacks.deferred_threads.size(),
                                    64u);

                            for (std::size_t wi = 0;
                                 wi < worker_limit;
                                 ++wi) {

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
                                    kWorkerSliceTicks;

                                result.message.clear();
                                clear_probe_halts();

                                any_worker_ran = true;

                                const Dynarmic::HaltReason worker_halt =
                                    jit.Run();

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

                                const bool worker_returned =
                                    callbacks.control_returned &&
                                    Dynarmic::Has(
                                        worker_halt,
                                        Dynarmic::HaltReason::UserDefined1);

                                const bool worker_fatal =
                                    Dynarmic::Has(
                                        worker_halt,
                                        Dynarmic::HaltReason::UserDefined2) ||
                                    Dynarmic::Has(
                                        worker_halt,
                                        Dynarmic::HaltReason::UserDefined3);

                                if (worker_returned) {
                                    worker_state.runtime_completed =
                                        true;
                                }

                                if (worker_fatal) {
                                    worker_state.runtime_failed =
                                        true;
                                }

                                // Re-acquire by index after jit.Run(): guest
                                // pthread_create may have appended more
                                // deferred threads and reallocated the vector.
                                if (wi <
                                    callbacks.deferred_threads.size()) {
                                    callbacks.deferred_threads[wi] =
                                        worker_state;
                                }

                                callbacks.Append(
                                    "V22 WORKER SLICE tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " PC=0x" +
                                    JniProbeHex(
                                        worker_state.regs[15]) +
                                    " total_ticks=" +
                                    std::to_string(
                                        worker_state.runtime_ticks) +
                                    " returned=" +
                                    (worker_state.runtime_completed
                                        ? "YES"
                                        : "NO") +
                                    " failed=" +
                                    (worker_state.runtime_failed
                                        ? "YES"
                                        : "NO"));

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

                                if (object_changed) {
                                    future_changed = true;

                                    callbacks.Append(
                                        "V30 WAIT OBJECT PROGRESS by tid=" +
                                        std::to_string(
                                            worker_state.id) +
                                        ": " +
                                        async_future_snapshot(
                                            future));

                                    break;
                                }
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

                            if (!any_worker_ran) {
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

                callbacks.host_gles_ready =
                    PvZ2HostGLESBegin(
                        1180u,
                        820u);

                callbacks.host_default_framebuffer =
                    callbacks.host_gles_ready
                        ? PvZ2HostGLESDefaultFramebuffer()
                        : 0u;

                result.host_gles_active =
                    callbacks.host_gles_ready;

                callbacks.Append(
                    std::string{
                        "V31 HOST GLES: "} +
                    (callbacks.host_gles_ready
                        ? "READY offscreen=1180x820 hostFBO=0x" +
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

                // iPad 10th generation logical landscape size. The first-frame
                // probe only needs a sane positive surface size; real drawable
                // pixel dimensions will come from the Metal/GLES presentation
                // bridge.
                if (!run_lifecycle(
                        "Native_onSurfaceChanged",
                        kNativeOnSurfaceChanged,
                        kSurfaceThis,
                        1180,
                        820,
                        false)) {
                    return result;
                }

                constexpr std::uint32_t kV31FrameCount = 3u;

                for (std::uint32_t frame = 0u;
                     frame < kV31FrameCount;
                     ++frame) {

                    callbacks.Append(
                        "V31 FRAME LOOP: begin frame " +
                        std::to_string(frame + 1u) +
                        "/" +
                        std::to_string(kV31FrameCount));

                    if (!run_lifecycle(
                            "Native_onDrawFrame",
                            kNativeOnDrawFrame,
                            kSurfaceThis,
                            0,
                            0,
                            true)) {

                        if (callbacks.host_gles_ready) {
                            const char* partial =
                                PvZ2HostGLESCapturePNG();

                            if (partial != nullptr &&
                                *partial != '\0') {
                                result.host_frame_png_path =
                                    partial;
                            }
                        }

                        return result;
                    }

                    result.draw_frames_completed =
                        frame + 1u;

                    callbacks.Append(
                        "V31 FRAME LOOP: returned frame " +
                        std::to_string(frame + 1u) +
                        "/" +
                        std::to_string(kV31FrameCount));
                }

                if (callbacks.host_gles_ready) {
                    const char* capture =
                        PvZ2HostGLESCapturePNG();

                    if (capture != nullptr &&
                        *capture != '\0') {
                        result.host_frame_png_path =
                            capture;

                        callbacks.Append(
                            "V31 HOST GLES CAPTURE: " +
                            result.host_frame_png_path);
                    } else {
                        callbacks.Append(
                            "V31 HOST GLES CAPTURE: failed");
                    }
                }

                result.ok = true;
                result.message =
                    "PvZ2 completed GameAppInitialize, lifecycle, surface setup, and three consecutive Native_onDrawFrame calls with the v31 host GLES bridge.";
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
