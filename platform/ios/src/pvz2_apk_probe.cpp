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
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <map>
#include <memory>
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
        std::size_t expansion_size = 0,
        PvZ2DiagnosticMode mode =
            PvZ2DiagnosticMode::PassiveRegistry)
        : mem(memory),
          result(output),
          progress_callback(std::move(progress)),
          obb_data(expansion_data),
          obb_size(expansion_size),
          diagnostic_mode(mode) {}

    Dynarmic::A32::Jit* jit = nullptr;
    const JniProbeLoadedElf* loaded_elf = nullptr;
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
        std::string key;
        bool relevant = false;
    };
    std::unordered_map<std::uint32_t, V56TrieContext>
        v56_trie_contexts;

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
            plain < kJniProbeHeapBase + kJniProbeHeapSize) {
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
        switch (diagnostic_mode) {
        case PvZ2DiagnosticMode::PassiveRegistry:
            return "PASSIVE_REGISTRY";
        case PvZ2DiagnosticMode::GateAScout:
            return "GATE_A_SCOUT";
        case PvZ2DiagnosticMode::FullMatrix:
            return "FULL_MATRIX";
        }

        return "UNKNOWN";
    }

    bool V56ScoutEnabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::GateAScout ||
            diagnostic_mode ==
                PvZ2DiagnosticMode::FullMatrix;
    }

    bool V56FullMatrixEnabled() const {
        return
            diagnostic_mode ==
                PvZ2DiagnosticMode::FullMatrix;
    }

    bool V56IsTargetLookupKey(
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
            if (stat.lookup_hits == 0u ||
                stat.lookup_misses == 0u) {
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

    void V52ObserveJniCallsite(
        const std::string& method_name) {

        if (current_frame_number < 75u ||
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
                        kJniProbeHeapSize ||
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
        const std::uint8_t old =
            mem.Read8(address);
        mem.Write8Guest(address, value);
        V56ObserveRegistryWrite(
            address,
            1u,
            old,
            value);
    }

    void MemoryWrite16(
        std::uint32_t address,
        std::uint16_t value) override {
        const std::uint16_t old =
            mem.Read16Guest(address);
        mem.Write16Guest(address, value);
        V56ObserveRegistryWrite(
            address,
            2u,
            old,
            value);
    }

    void MemoryWrite32(
        std::uint32_t address,
        std::uint32_t value) override {
        const std::uint32_t old =
            mem.Read32Guest(address);
        mem.Write32Guest(address, value);
        V56ObserveRegistryWrite(
            address,
            4u,
            old,
            value);
    }

    void MemoryWrite64(
        std::uint32_t address,
        std::uint64_t value) override {
        const std::uint64_t old =
            mem.Read64Guest(address);
        mem.Write64Guest(address, value);
        V56ObserveRegistryWrite(
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
        const std::uint8_t old =
            mem.Read8(address);
        mem.Write8Guest(address, value);
        V56ObserveRegistryWrite(
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
        const std::uint16_t old =
            mem.Read16Guest(address);
        mem.Write16Guest(address, value);
        V56ObserveRegistryWrite(
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
        const std::uint32_t old =
            mem.Read32Guest(address);
        mem.Write32Guest(address, value);
        V56ObserveRegistryWrite(
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
        const std::uint64_t old =
            mem.Read64Guest(address);
        mem.Write64Guest(address, value);
        V56ObserveRegistryWrite(
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
            static_cast<std::uint64_t>(
                group_offset) +
                part1_offset +
                part1_zsize >
                obb_size) {
            return nullptr;
        }

        auto unpacked =
            std::make_shared<
                std::vector<std::uint8_t>>(
                    part1_size);

        const std::uint8_t* compressed =
            obb_data +
            static_cast<std::size_t>(
                group_offset) +
            part1_offset;

        if (part1_zsize ==
            part1_size) {

            std::memcpy(
                unpacked->data(),
                compressed,
                part1_size);
        } else {
            uLongf destination_size =
                static_cast<uLongf>(
                    part1_size);

            const int z_result =
                ::uncompress(
                    unpacked->data(),
                    &destination_size,
                    compressed,
                    static_cast<uLong>(
                        part1_zsize));

            if (z_result != Z_OK ||
                destination_size !=
                    part1_size) {
                Append(
                    "V31 PTX bridge: zlib inflate failed for " +
                    ptx_path +
                    " rc=" +
                    std::to_string(z_result));
                return nullptr;
            }
        }

        if (static_cast<std::uint64_t>(
                file_offset) +
                file_size >
            unpacked->size()) {
            return nullptr;
        }

        const std::uint64_t block_columns =
            (static_cast<std::uint64_t>(
                 width) +
             3u) /
            4u;
        const std::uint64_t block_rows =
            (static_cast<std::uint64_t>(
                 height) +
             3u) /
            4u;
        const std::uint64_t etc_bytes =
            block_columns *
            block_rows *
            8u;
        const std::uint64_t alpha_bytes =
            static_cast<std::uint64_t>(
                width) *
            height;
        const std::uint64_t expected =
            etc_bytes +
            alpha_bytes;

        if (expected >
                file_size ||
            file_offset + expected >
                unpacked->size()) {
            Append(
                "V31 PTX bridge: unsupported PTX payload shape " +
                ptx_path +
                " size=" +
                std::to_string(file_size) +
                " expected>=" +
                std::to_string(expected));
            return nullptr;
        }

        const std::uint8_t* texture =
            unpacked->data() +
            file_offset;
        const std::uint8_t* alpha =
            texture +
            etc_bytes;

        const std::uint64_t rgba_bytes =
            static_cast<std::uint64_t>(
                width) *
            height *
            4u;

        if (rgba_bytes >
            std::numeric_limits<
                std::size_t>::max() -
                18u) {
            return nullptr;
        }

        auto tga =
            std::make_shared<
                std::vector<std::uint8_t>>(
                    18u +
                    static_cast<std::size_t>(
                        rgba_bytes),
                    0u);

        (*tga)[2] = 2u;
        (*tga)[12] =
            static_cast<std::uint8_t>(
                width & 0xffu);
        (*tga)[13] =
            static_cast<std::uint8_t>(
                (width >> 8u) & 0xffu);
        (*tga)[14] =
            static_cast<std::uint8_t>(
                height & 0xffu);
        (*tga)[15] =
            static_cast<std::uint8_t>(
                (height >> 8u) & 0xffu);
        (*tga)[16] = 32u;
        (*tga)[17] = 0x28u;

        constexpr int modifiers[8][4] = {
            {2, 8, -2, -8},
            {5, 17, -5, -17},
            {9, 29, -9, -29},
            {13, 42, -13, -42},
            {18, 60, -18, -60},
            {24, 80, -24, -80},
            {33, 106, -33, -106},
            {47, 183, -47, -183},
        };

        auto clamp8 =
            [](int value) {
                return
                    static_cast<std::uint8_t>(
                        std::max(
                            0,
                            std::min(
                                255,
                                value)));
            };

        auto expand4 =
            [](int value) {
                return
                    (value << 4) |
                    value;
            };

        auto expand5 =
            [](int value) {
                return
                    (value << 3) |
                    (value >> 2);
            };

        auto signed3 =
            [](int value) {
                return
                    (value & 4)
                        ? value - 8
                        : value;
            };

        std::uint64_t block_index = 0;

        for (std::uint32_t by = 0;
             by < height;
             by += 4u) {

            for (std::uint32_t bx = 0;
                 bx < width;
                 bx += 4u) {

                const std::uint8_t* block =
                    texture +
                    block_index *
                    8u;
                ++block_index;

                const bool differential =
                    (block[3] & 0x02u) !=
                    0u;
                const bool flip =
                    (block[3] & 0x01u) !=
                    0u;

                const int table1 =
                    (block[3] >> 5u) &
                    7u;
                const int table2 =
                    (block[3] >> 2u) &
                    7u;

                int colors[2][3] = {};

                if (differential) {
                    const int r1 =
                        block[0] >> 3u;
                    const int g1 =
                        block[1] >> 3u;
                    const int b1 =
                        block[2] >> 3u;

                    const int r2 =
                        std::max(
                            0,
                            std::min(
                                31,
                                r1 +
                                signed3(
                                    block[0] &
                                    7u)));
                    const int g2 =
                        std::max(
                            0,
                            std::min(
                                31,
                                g1 +
                                signed3(
                                    block[1] &
                                    7u)));
                    const int b2 =
                        std::max(
                            0,
                            std::min(
                                31,
                                b1 +
                                signed3(
                                    block[2] &
                                    7u)));

                    colors[0][0] =
                        expand5(r1);
                    colors[0][1] =
                        expand5(g1);
                    colors[0][2] =
                        expand5(b1);
                    colors[1][0] =
                        expand5(r2);
                    colors[1][1] =
                        expand5(g2);
                    colors[1][2] =
                        expand5(b2);
                } else {
                    colors[0][0] =
                        expand4(
                            block[0] >> 4u);
                    colors[0][1] =
                        expand4(
                            block[1] >> 4u);
                    colors[0][2] =
                        expand4(
                            block[2] >> 4u);
                    colors[1][0] =
                        expand4(
                            block[0] & 0x0fu);
                    colors[1][1] =
                        expand4(
                            block[1] & 0x0fu);
                    colors[1][2] =
                        expand4(
                            block[2] & 0x0fu);
                }

                const std::uint32_t selector_bits =
                    (static_cast<std::uint32_t>(
                         block[4])
                     << 24u) |
                    (static_cast<std::uint32_t>(
                         block[5])
                     << 16u) |
                    (static_cast<std::uint32_t>(
                         block[6])
                     << 8u) |
                    static_cast<std::uint32_t>(
                        block[7]);

                for (std::uint32_t py = 0;
                     py < 4u;
                     ++py) {

                    for (std::uint32_t px = 0;
                         px < 4u;
                         ++px) {

                        const std::uint32_t x =
                            bx + px;
                        const std::uint32_t y =
                            by + py;

                        if (x >= width ||
                            y >= height) {
                            continue;
                        }

                        const std::uint32_t bit =
                            px * 4u + py;

                        const int selector =
                            static_cast<int>(
                                ((selector_bits >>
                                      (bit + 16u)) &
                                     1u)
                                    << 1u) |
                            static_cast<int>(
                                (selector_bits >>
                                 bit) &
                                1u);

                        const int subblock =
                            flip
                                ? (py >= 2u
                                    ? 1
                                    : 0)
                                : (px >= 2u
                                    ? 1
                                    : 0);

                        const int modifier =
                            modifiers[
                                subblock
                                    ? table2
                                    : table1][
                                selector];

                        const std::size_t pixel =
                            static_cast<std::size_t>(
                                y) *
                                width +
                            x;

                        const std::size_t out =
                            18u +
                            pixel *
                                4u;

                        const std::uint8_t r =
                            clamp8(
                                colors[subblock][0] +
                                modifier);
                        const std::uint8_t g =
                            clamp8(
                                colors[subblock][1] +
                                modifier);
                        const std::uint8_t b =
                            clamp8(
                                colors[subblock][2] +
                                modifier);

                        (*tga)[out + 0u] = b;
                        (*tga)[out + 1u] = g;
                        (*tga)[out + 2u] = r;
                        (*tga)[out + 3u] =
                            alpha[pixel];
                    }
                }
            }
        }

        SyntheticAsset asset;
        asset.bytes = tga;
        asset.source_path = ptx_path;
        asset.width = width;
        asset.height = height;

        auto inserted =
            synthetic_assets.emplace(
                asset_key,
                std::move(asset));

        Append(
            "V31 PTX->TGA bridge: \"" +
            requested +
            "\" <= " +
            ptx_path +
            " group=" +
            std::to_string(
                *group_index) +
            " " +
            std::to_string(width) +
            "x" +
            std::to_string(height) +
            " ptxBytes=" +
            std::to_string(file_size) +
            " tgaBytes=" +
            std::to_string(
                inserted.first
                    ->second
                    .bytes
                    ->size()));

        return
            &inserted.first->second;
    }

    void CallSVC(std::uint32_t swi) override {
        if (!jit) {
            return;
        }

        auto& regs = jit->Regs();

        // v31: real ARM32 printf-family formatting. Before this bridge,
        // snprintf/sprintf/vsnprintf/vsprintf returned zero without writing
        // their destination buffers. That is not just cosmetic: PvZ2 builds
        // resource identifiers and paths through libc formatting, so the
        // no-op fallback could turn valid resource names into empty strings.
        auto format_guest_printf =
            [&](const std::string& format,
                auto&& next32,
                auto&& next64) {
                std::string out;

                auto pad =
                    [](std::string value,
                       int width,
                       bool left,
                       char fill) {
                        if (width <= 0 ||
                            static_cast<int>(
                                value.size()) >= width) {
                            return value;
                        }

                        const std::size_t count =
                            static_cast<std::size_t>(
                                width -
                                static_cast<int>(
                                    value.size()));

                        if (left) {
                            value.append(
                                count,
                                ' ');
                            return value;
                        }

                        return
                            std::string(
                                count,
                                fill) +
                            value;
                    };

                for (std::size_t i = 0;
                     i < format.size();) {

                    if (format[i] != '%') {
                        out.push_back(
                            format[i++]);
                        continue;
                    }

                    ++i;

                    if (i < format.size() &&
                        format[i] == '%') {
                        out.push_back('%');
                        ++i;
                        continue;
                    }

                    bool left = false;
                    bool plus = false;
                    bool space = false;
                    bool alternate = false;
                    bool zero = false;

                    for (;;) {
                        if (i >= format.size()) {
                            break;
                        }

                        const char flag =
                            format[i];

                        if (flag == '-') {
                            left = true;
                        } else if (flag == '+') {
                            plus = true;
                        } else if (flag == ' ') {
                            space = true;
                        } else if (flag == '#') {
                            alternate = true;
                        } else if (flag == '0') {
                            zero = true;
                        } else {
                            break;
                        }

                        ++i;
                    }

                    int width = -1;

                    if (i < format.size() &&
                        format[i] == '*') {
                        width =
                            static_cast<std::int32_t>(
                                next32());
                        ++i;

                        if (width < 0) {
                            left = true;
                            width = -width;
                        }
                    } else {
                        int parsed = 0;
                        bool any = false;

                        while (i < format.size() &&
                               std::isdigit(
                                   static_cast<unsigned char>(
                                       format[i]))) {
                            any = true;
                            parsed =
                                parsed * 10 +
                                (format[i] - '0');
                            ++i;
                        }

                        if (any) {
                            width = parsed;
                        }
                    }

                    int precision = -1;

                    if (i < format.size() &&
                        format[i] == '.') {
                        ++i;
                        precision = 0;

                        if (i < format.size() &&
                            format[i] == '*') {
                            precision =
                                static_cast<std::int32_t>(
                                    next32());
                            ++i;

                            if (precision < 0) {
                                precision = -1;
                            }
                        } else {
                            while (i < format.size() &&
                                   std::isdigit(
                                       static_cast<unsigned char>(
                                           format[i]))) {
                                precision =
                                    precision * 10 +
                                    (format[i] - '0');
                                ++i;
                            }
                        }
                    }

                    enum class Length {
                        Default,
                        HH,
                        H,
                        L,
                        LL,
                        Z,
                        T,
                        J,
                        BigL,
                    };

                    Length length =
                        Length::Default;

                    if (i + 1u < format.size() &&
                        format[i] == 'h' &&
                        format[i + 1u] == 'h') {
                        length = Length::HH;
                        i += 2u;
                    } else if (
                        i < format.size() &&
                        format[i] == 'h') {
                        length = Length::H;
                        ++i;
                    } else if (
                        i + 1u < format.size() &&
                        format[i] == 'l' &&
                        format[i + 1u] == 'l') {
                        length = Length::LL;
                        i += 2u;
                    } else if (
                        i < format.size() &&
                        format[i] == 'l') {
                        length = Length::L;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 'z') {
                        length = Length::Z;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 't') {
                        length = Length::T;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 'j') {
                        length = Length::J;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 'L') {
                        length = Length::BigL;
                        ++i;
                    }

                    if (i >= format.size()) {
                        out.push_back('%');
                        break;
                    }

                    const char conversion =
                        format[i++];

                    auto configure_numeric =
                        [&](std::ostringstream& stream) {
                            if (plus) {
                                stream.setf(
                                    std::ios::showpos);
                            }

                            if (alternate) {
                                stream.setf(
                                    std::ios::showbase);
                            }

                            if (precision >= 0) {
                                stream
                                    << std::setprecision(
                                           precision);
                            }
                        };

                    std::string value;

                    switch (conversion) {
                    case 's': {
                        const std::uint32_t address =
                            next32();

                        value =
                            address != 0u
                                ? mem.ReadCStringGuest(
                                      address,
                                      1u << 20)
                                : "(null)";

                        if (precision >= 0 &&
                            static_cast<std::size_t>(
                                precision) <
                                value.size()) {
                            value.resize(
                                static_cast<std::size_t>(
                                    precision));
                        }

                        break;
                    }

                    case 'c':
                        value.push_back(
                            static_cast<char>(
                                next32() & 0xffu));
                        break;

                    case 'd':
                    case 'i': {
                        std::ostringstream stream;
                        configure_numeric(stream);

                        if (length == Length::LL ||
                            length == Length::J) {
                            stream
                                << static_cast<std::int64_t>(
                                       next64());
                        } else {
                            stream
                                << static_cast<std::int32_t>(
                                       next32());
                        }

                        value = stream.str();
                        break;
                    }

                    case 'u':
                    case 'o':
                    case 'x':
                    case 'X': {
                        std::ostringstream stream;
                        configure_numeric(stream);

                        if (conversion == 'o') {
                            stream << std::oct;
                        } else if (
                            conversion == 'x' ||
                            conversion == 'X') {
                            stream << std::hex;

                            if (conversion == 'X') {
                                stream.setf(
                                    std::ios::uppercase);
                            }
                        }

                        if (length == Length::LL ||
                            length == Length::J) {
                            stream
                                << static_cast<std::uint64_t>(
                                       next64());
                        } else {
                            stream
                                << static_cast<std::uint32_t>(
                                       next32());
                        }

                        value = stream.str();
                        break;
                    }

                    case 'p': {
                        std::ostringstream stream;
                        stream
                            << "0x"
                            << std::hex
                            << next32();
                        value = stream.str();
                        break;
                    }

                    case 'f':
                    case 'F':
                    case 'e':
                    case 'E':
                    case 'g':
                    case 'G': {
                        const std::uint64_t bits =
                            next64();
                        double number = 0.0;

                        std::memcpy(
                            &number,
                            &bits,
                            sizeof(number));

                        std::ostringstream stream;
                        configure_numeric(stream);

                        if (conversion == 'f' ||
                            conversion == 'F') {
                            stream << std::fixed;
                        } else if (
                            conversion == 'e' ||
                            conversion == 'E') {
                            stream
                                << std::scientific;
                        }

                        if (conversion == 'E' ||
                            conversion == 'F' ||
                            conversion == 'G') {
                            stream.setf(
                                std::ios::uppercase);
                        }

                        stream << number;
                        value = stream.str();
                        break;
                    }

                    case 'n': {
                        const std::uint32_t address =
                            next32();

                        if (address != 0u) {
                            mem.Write32Guest(
                                address,
                                static_cast<std::uint32_t>(
                                    out.size()));
                        }

                        continue;
                    }

                    default:
                        value.push_back('%');
                        value.push_back(
                            conversion);
                        break;
                    }

                    if (space &&
                        !value.empty() &&
                        value.front() != '-' &&
                        value.front() != '+') {
                        value.insert(
                            value.begin(),
                            ' ');
                    }

                    value =
                        pad(
                            std::move(value),
                            width,
                            left,
                            zero && !left
                                ? '0'
                                : ' ');

                    out += value;
                }

                return out;
            };

        auto format_direct =
            [&](const std::string& format,
                std::uint32_t first_register) {

                // Treat r0-r3 followed by stack words as one AAPCS argument
                // stream. 64-bit varargs are aligned to an even word slot.
                std::uint32_t cursor =
                    first_register;

                auto read_absolute_word =
                    [&](std::uint32_t absolute) {
                        if (absolute < 4u) {
                            return regs[absolute];
                        }

                        return
                            mem.Read32Guest(
                                regs[13] +
                                (absolute - 4u) *
                                    4u);
                    };

                auto next32 =
                    [&]() {
                        return
                            read_absolute_word(
                                cursor++);
                    };

                auto next64 =
                    [&]() -> std::uint64_t {
                        if ((cursor & 1u) != 0u) {
                            ++cursor;
                        }

                        const std::uint64_t lo =
                            read_absolute_word(
                                cursor++);
                        const std::uint64_t hi =
                            read_absolute_word(
                                cursor++);

                        return
                            lo |
                            (hi << 32u);
                    };

                return
                    format_guest_printf(
                        format,
                        next32,
                        next64);
            };

        auto format_va_list =
            [&](const std::string& format,
                std::uint32_t va_address) {

                // ARMv7 bionic/NDK va_list is pointer-like for this ABI.
                std::uint32_t cursor =
                    va_address;

                auto next32 =
                    [&]() {
                        const std::uint32_t value =
                            mem.Read32Guest(
                                cursor);
                        cursor += 4u;
                        return value;
                    };

                auto next64 =
                    [&]() -> std::uint64_t {
                        cursor =
                            (cursor + 7u) &
                            ~7u;

                        const std::uint64_t value =
                            mem.Read64Guest(
                                cursor);
                        cursor += 8u;
                        return value;
                    };

                return
                    format_guest_printf(
                        format,
                        next32,
                        next64);
            };

        if (swi == kJniProbeSvcStartupGroupsCtorSnapshot ||
            swi == kJniProbeSvcStartupGroupsLookupResult ||
            swi == kJniProbeSvcStartupGroupsContribution) {

            switch (swi) {
            case kJniProbeSvcStartupGroupsCtorSnapshot: {
                // Original @ 0x100f66e4: ADD sp,sp,#0xb0.
                regs[13] += 0xb0u;

                ++v55_ctor_snapshot_hits;
                const std::string snapshot =
                    V55StartupGroupVectorState();
                v55_ctor_vector_snapshot =
                    snapshot;

                Append(
                    "V55 STARTUP GROUPS ctor-snapshot #" +
                    std::to_string(
                        v55_ctor_snapshot_hits) +
                    " " +
                    snapshot);
                return;
            }

            case kJniProbeSvcStartupGroupsLookupResult: {
                // Original @ 0x102c85cc: MOV r4,r0.
                const std::uint32_t result_index =
                    regs[0];
                const std::uint32_t vector_object =
                    regs[7];
                const std::uint32_t byte_offset =
                    regs[8];

                regs[4] = regs[0];

                if (vector_object !=
                    kV55StartupGroupsVectorGuest) {
                    return;
                }

                const std::string group =
                    V55CurrentGateAGroup(
                        vector_object,
                        byte_offset);

                ++v55_lookup_total;

                const int slot =
                    V55StartupGroupSlot(group);

                bool should_log = false;

                if (slot >= 0) {
                    auto& stat =
                        v55_group_stats[
                            static_cast<std::size_t>(
                                slot)];

                    const std::uint32_t previous =
                        stat.last_lookup;

                    ++stat.lookup_hits;
                    if (result_index ==
                        0xffffffffu) {
                        ++stat.lookup_misses;
                    }

                    stat.last_lookup =
                        result_index;

                    should_log =
                        stat.lookup_hits <= 4u ||
                        previous !=
                            result_index ||
                        (stat.lookup_hits %
                            100u) == 0u;
                } else {
                    ++v55_lookup_unknown;
                    should_log =
                        v55_lookup_unknown <= 8u;
                }

                if (should_log) {
                    std::string source;

                    if (result_index ==
                        0xffffffffu) {
                        source = "MISS";
                    } else if (
                        (result_index &
                         0x10000000u) != 0u) {
                        source = "table+0x30";
                    } else {
                        source = "table+0x28";
                    }

                    Append(
                        "V55 STARTUP GROUPS lookup group=\"" +
                        group +
                        "\" offset=" +
                        std::to_string(
                            byte_offset) +
                        " result=0x" +
                        JniProbeHex(
                            result_index) +
                        " source=" +
                        source +
                        " totalLookup#=" +
                        std::to_string(
                            v55_lookup_total));
                }

                return;
            }

            case kJniProbeSvcStartupGroupsContribution: {
                // Original @ 0x102c85f4:
                // ADD r10,r6,r10. At this point r6 is the first
                // per-group value and r0 is the second.
                const std::uint32_t vector_object =
                    regs[7];
                const std::uint32_t byte_offset =
                    regs[8];
                const std::uint32_t completed =
                    regs[6];
                const std::uint32_t total =
                    regs[0];

                regs[10] =
                    regs[6] +
                    regs[10];

                if (vector_object !=
                    kV55StartupGroupsVectorGuest) {
                    return;
                }

                const std::string group =
                    V55CurrentGateAGroup(
                        vector_object,
                        byte_offset);

                ++v55_contribution_total;

                const int slot =
                    V55StartupGroupSlot(group);

                bool should_log = false;

                if (slot >= 0) {
                    auto& stat =
                        v55_group_stats[
                            static_cast<std::size_t>(
                                slot)];

                    const bool changed =
                        stat.last_completed !=
                            completed ||
                        stat.last_total !=
                            total;

                    ++stat.contribution_hits;
                    stat.last_completed =
                        completed;
                    stat.last_total =
                        total;

                    should_log =
                        stat.contribution_hits <=
                            4u ||
                        changed ||
                        (stat.contribution_hits %
                            100u) == 0u;
                } else {
                    should_log =
                        v55_contribution_total <=
                            8u;
                }

                if (should_log) {
                    Append(
                        "V55 STARTUP GROUPS contribution group=\"" +
                        group +
                        "\" index=0x" +
                        JniProbeHex(
                            regs[4]) +
                        " completed+=" +
                        std::to_string(
                            completed) +
                        " total+=" +
                        std::to_string(
                            total) +
                        " runningCompleted=" +
                        std::to_string(
                            regs[10]) +
                        " runningTotalBeforeAdd=" +
                        std::to_string(
                            regs[11]));
                }

                return;
            }

            default:
                break;
            }
        }

        if (swi >= kJniProbeSvcStartupGateAResource &&
            swi <= kJniProbeSvcStartupMainMenuMarker) {

            const bool logo_state =
                V53CurrentGameState() == 2;

            auto append_gate =
                [&](const std::string& text) {
                    if (logo_state) {
                        Append(
                            "V54 STARTUPLOGO " +
                            text);
                    }
                };

            switch (swi) {
            case kJniProbeSvcStartupGateAResource: {
                // Original: LDR r0,[r5,#0x64c].
                const std::uint32_t base =
                    regs[5];
                regs[0] =
                    mem.Read32Guest(
                        base + 0x64cu);
                ++v54_gate_a_resource_hits;
                v54_gate_a_resource = regs[0];

                if (logo_state) {
                    const std::string snapshot =
                        V55StartupGroupVectorState();

                    if (snapshot !=
                        v55_gate_vector_snapshot) {
                        v55_gate_vector_snapshot =
                            snapshot;

                        Append(
                            "V55 STARTUP GROUPS GateA-vector-change hit=" +
                            std::to_string(
                                v54_gate_a_resource_hits) +
                            " " +
                            snapshot);
                    }
                }

                append_gate(
                    "GateA.resource hit=" +
                    std::to_string(
                        v54_gate_a_resource_hits) +
                    " owner=" +
                    V46DescribeGuestAddress(base) +
                    " resource=0x" +
                    JniProbeHex(regs[0]) +
                    (regs[0] == 0u
                        ? " BLOCK(resource-null)"
                        : " present"));
                return;
            }

            case kJniProbeSvcStartupGateATotals: {
                // Original: VMOV s0,r11. At this exact point r10/r11 are
                // the accumulated completed/total counters used by VDIV.
                if (jit != nullptr) {
                    jit->ExtRegs()[0] =
                        regs[11];
                }

                ++v54_gate_a_totals_hits;
                v54_gate_a_completed =
                    regs[10];
                v54_gate_a_total =
                    regs[11];

                std::ostringstream line;
                line
                    << "GateA.totals hit="
                    << v54_gate_a_totals_hits
                    << " completed="
                    << v54_gate_a_completed
                    << " total="
                    << v54_gate_a_total;

                if (v54_gate_a_total != 0u) {
                    line
                        << " ratio="
                        << (static_cast<double>(
                                v54_gate_a_completed) /
                            static_cast<double>(
                                v54_gate_a_total));
                } else {
                    line << " ratio=DIV0";
                }

                append_gate(line.str());
                return;
            }

            case kJniProbeSvcStartupGateAResult: {
                // Original: VMOV s2,r0.
                if (jit != nullptr) {
                    jit->ExtRegs()[2] =
                        regs[0];
                }

                ++v54_gate_a_result_hits;
                v54_gate_a_result_bits =
                    regs[0];

                float value = 0.0f;
                std::memcpy(
                    &value,
                    &v54_gate_a_result_bits,
                    sizeof(value));

                std::ostringstream line;
                line
                    << "GateA.result hit="
                    << v54_gate_a_result_hits
                    << " bits=0x"
                    << JniProbeHex(
                           v54_gate_a_result_bits)
                    << " float="
                    << value
                    << " => "
                    << (value >= 1.0f
                        ? "PASS"
                        : "BLOCK(<1.0)");

                append_gate(line.str());
                return;
            }

            case kJniProbeSvcStartupGateCState: {
                // Original: LDR r1,[r0,#0x98].
                const std::uint32_t object =
                    regs[0];
                regs[1] =
                    mem.Read32Guest(
                        object + 0x98u);

                if (logo_state) {
                    ++v54_gate_c_hits;
                    v54_gate_c_object =
                        object;
                    v54_gate_c_state =
                        regs[1];
                }

                append_gate(
                    "GateC hit=" +
                    std::to_string(
                        v54_gate_c_hits) +
                    " object=" +
                    V46DescribeGuestAddress(object) +
                    " state98=" +
                    std::to_string(regs[1]) +
                    (regs[1] == 4u
                        ? " => PASS"
                        : " => BLOCK(!=4)"));
                return;
            }

            case kJniProbeSvcStartupGateDCounter: {
                // Original: LDR r0,[r4,#0x430].
                const std::uint32_t manager =
                    regs[4];
                regs[0] =
                    mem.Read32Guest(
                        manager + 0x430u);

                if (logo_state) {
                    ++v54_gate_d_hits;
                    v54_gate_d_counter =
                        regs[0];
                }

                append_gate(
                    "GateD hit=" +
                    std::to_string(
                        v54_gate_d_hits) +
                    " counter430=" +
                    std::to_string(regs[0]) +
                    (regs[0] >= 3u
                        ? " => PASS"
                        : " => BLOCK(<3)"));
                return;
            }

            case kJniProbeSvcStartupAfterD:
                // Original: LDR r0,[pc,#0x3c8], literal @ +0x276e0c.
                regs[0] =
                    mem.Read32Guest(
                        kGuestBase +
                        0x00276e0cu);
                if (logo_state) {
                    ++v54_after_d_hits;
                }
                append_gate(
                    "after-A-D reached #" +
                    std::to_string(
                        v54_after_d_hits));
                return;

            case kJniProbeSvcStartupGateEByte: {
                // Original: LDRB r0,[r0,#0xb7a].
                const std::uint32_t object =
                    regs[0];
                regs[0] =
                    mem.Read8(
                        object + 0xb7au);
                if (logo_state) {
                    ++v54_gate_e_hits;
                    v54_gate_e_value =
                        regs[0];
                }
                append_gate(
                    "GateE hit=" +
                    std::to_string(
                        v54_gate_e_hits) +
                    " app.b7a=" +
                    std::to_string(regs[0]) +
                    (regs[0] != 0u
                        ? " => alternate-main-flow"
                        : " => patch-decision-flow"));
                return;
            }

            case kJniProbeSvcStartupGateFResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_gate_f_hits;
                    v54_gate_f_value =
                        regs[0];
                }
                append_gate(
                    "GateF.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_f_hits));
                return;

            case kJniProbeSvcStartupGateGResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_gate_g_hits;
                    v54_gate_g_value =
                        regs[0];
                }
                append_gate(
                    "GateG.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_g_hits));
                return;

            case kJniProbeSvcStartupGateHResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_gate_h_hits;
                    v54_gate_h_value =
                        regs[0];
                }
                append_gate(
                    "GateH.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_h_hits));
                return;

            case kJniProbeSvcStartupGateIResult:
                // Original helper epilogue: MOV r0,r5.
                regs[0] = regs[5];
                if (logo_state) {
                    ++v54_gate_i_hits;
                    v54_gate_i_value =
                        regs[0];
                }
                append_gate(
                    "GateI.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_i_hits));
                return;

            case kJniProbeSvcStartupGateJObject: {
                // Original helper entry: MOV r1,r0. The helper returns true
                // iff byte+0x20 != 0 and byte+0x02 == 0.
                const std::uint32_t object =
                    regs[0];
                regs[1] = regs[0];

                const std::uint32_t byte20 =
                    mem.Read8(
                        object + 0x20u);
                const std::uint32_t byte02 =
                    mem.Read8(
                        object + 0x02u);

                if (logo_state) {
                    ++v54_gate_j_hits;
                    v54_gate_j_byte20 =
                        byte20;
                    v54_gate_j_byte02 =
                        byte02;
                }

                append_gate(
                    "GateJ object=" +
                    V46DescribeGuestAddress(object) +
                    " byte20=" +
                    std::to_string(byte20) +
                    " byte02=" +
                    std::to_string(byte02) +
                    " predictedResult=" +
                    ((byte20 != 0u &&
                      byte02 == 0u)
                        ? "1"
                        : "0"));
                return;
            }

            case kJniProbeSvcStartupPatchMarker:
                // Original: MOV r0,r4 immediately before target=3.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_patch_marker_hits;
                }
                append_gate(
                    "PATCH REQUEST PATH reached #" +
                    std::to_string(
                        v54_patch_marker_hits));
                return;

            case kJniProbeSvcStartupMainFlow:
                // Original: MOV r5,r0.
                regs[5] = regs[0];
                if (logo_state) {
                    ++v54_main_flow_hits;
                }
                append_gate(
                    "late/main flow entered #" +
                    std::to_string(
                        v54_main_flow_hits) +
                    " object=0x" +
                    JniProbeHex(regs[5]));
                return;

            case kJniProbeSvcStartupProgressResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_progress_result_hits;
                    v54_progress_value =
                        regs[0];
                }
                append_gate(
                    "late.progressResult=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_progress_result_hits));
                return;

            case kJniProbeSvcStartupFindResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_find_result_hits;
                    v54_find_value =
                        regs[0];
                }
                append_gate(
                    "late.findResult=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_find_result_hits));
                return;

            case kJniProbeSvcStartupLateResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_late_result_hits;
                    v54_late_value =
                        regs[0];
                }
                append_gate(
                    "late.booleanResult=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_late_result_hits));
                return;

            case kJniProbeSvcStartupMainMenuMarker:
                // Original: MOV r0,r4 immediately before target=4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_mainmenu_marker_hits;
                }
                append_gate(
                    "MAINMENU REQUEST PATH reached #" +
                    std::to_string(
                        v54_mainmenu_marker_hits));
                return;

            default:
                break;
            }
        }

        if (swi ==
                kJniProbeSvcGameStateApply ||
            swi ==
                kJniProbeSvcGameStateRequest) {

            const bool request =
                swi ==
                    kJniProbeSvcGameStateRequest;

            // Both patched instructions are MOV r4,r0.
            regs[4] = regs[0];

            const std::uint32_t manager =
                regs[0];
            const std::int32_t target =
                static_cast<std::int32_t>(
                    regs[1]);

            V53CacheGameStateManager(
                manager,
                request
                    ? "RequestTransition-hook"
                    : "ApplyState-hook");

            const std::int32_t current =
                V53IsGameStateManager(manager)
                    ? static_cast<std::int32_t>(
                          mem.Read32Guest(
                              manager +
                              0x374u))
                    : -999;

            if (request) {
                ++v53_state_request_calls;
            } else {
                ++v53_state_apply_calls;
            }

            result.game_state_manager =
                v53_game_state_manager;
            result.game_state_current =
                current;
            result.game_state_pending =
                V53PendingGameState();
            result.game_state_request_calls =
                v53_state_request_calls;
            result.game_state_apply_calls =
                v53_state_apply_calls;

            Append(
                std::string{
                    request
                        ? "V53 GAMESTATE REQUEST #"
                        : "V53 GAMESTATE APPLY #"} +
                std::to_string(
                    request
                        ? v53_state_request_calls
                        : v53_state_apply_calls) +
                " current=" +
                std::to_string(current) +
                "(" +
                V53GameStateName(current) +
                ") target=" +
                std::to_string(target) +
                "(" +
                V53GameStateName(target) +
                ") manager=0x" +
                JniProbeHex(manager) +
                " callerLR=" +
                V46DescribeGuestAddress(
                    regs[14]) +
                (request
                    ? " arg2=0x" +
                          JniProbeHex(regs[2]) +
                          " arg3=0x" +
                          JniProbeHex(regs[3])
                    : std::string{}));

            return;
        }

        if (swi ==
                kJniProbeSvcResourceWrapperDirectReturn ||
            swi ==
                kJniProbeSvcResourceWrapperExhausted) {

            const bool direct_return =
                swi ==
                    kJniProbeSvcResourceWrapperDirectReturn;

            const std::uint32_t manager =
                regs[5];
            const std::uint32_t group =
                direct_return
                    ? regs[8]
                    : 0u;
            const std::uint32_t id_object =
                regs[6];

            const std::string requested_id =
                RecoverGuestResfileWord(
                    id_object);

            const bool resfile =
                requested_id.rfind(
                    "RESFILE_",
                    0u) == 0u;

            if (resfile &&
                (!direct_return ||
                 regs[0] == 0u)) {

                if (direct_return) {
                    ++resource_wrapper_direct_nulls;
                } else {
                    ++resource_wrapper_exhausted_nulls;
                }

                if (resource_wrapper_direct_nulls +
                        resource_wrapper_exhausted_nulls <=
                    48u) {
                    Append(
                        "V48 WRAPPER NULL #" +
                        std::to_string(
                            resource_wrapper_direct_nulls +
                            resource_wrapper_exhausted_nulls) +
                        " kind=" +
                        (direct_return
                            ? std::string{"direct-group"}
                            : std::string{"all-groups-exhausted"}) +
                        " id=\"" +
                        requested_id +
                        "\" manager=0x" +
                        JniProbeHex(manager) +
                        " group=0x" +
                        JniProbeHex(group));
                }

                const std::uint32_t recovered =
                    ResolveResourceRegistryNativeMiss(
                        manager,
                        group,
                        id_object,
                        direct_return
                            ? "0x1087a708-wrapper-direct"
                            : "0x1087a76c-wrapper-exhausted",
                        requested_id);

                if (recovered != 0u) {
                    regs[0] = recovered;
                    ++resource_wrapper_recoveries;

                    if (resource_wrapper_recoveries <=
                        48u) {
                        Append(
                            "V48 WRAPPER RESFILE HEAL #" +
                            std::to_string(
                                resource_wrapper_recoveries) +
                            " id=\"" +
                            requested_id +
                            "\" -> ResourceInfo*=0x" +
                            JniProbeHex(recovered));
                    }
                } else if (!direct_return) {
                    regs[0] = 0u;
                }
            } else if (!direct_return) {
                // Original instruction at 0x1087a76c was MOV r0,#0.
                regs[0] = 0u;
            }

            if (direct_return) {
                // Original instruction at 0x1087a708 was B 0x1087a770.
                regs[15] =
                    kGuestBase +
                    0x0087a770u;
            }

            return;
        }

        if (swi ==
                kJniProbeSvcResourceRegistryEntry) {

            // Original instruction at guest 0x1086f674 is MOV r4,r2.
            // Preserve its semantics first.
            regs[4] = regs[2];

            const std::string entry_id =
                RecoverGuestResfileWord(
                    regs[2]);

            if (!entry_id.empty()) {
                resource_lookup_entry_ids[
                    regs[13]] =
                    entry_id;

                V50ObserveResourceId(
                    entry_id);

                if (resource_entry_id_diagnostics <
                    24u) {
                    ++resource_entry_id_diagnostics;

                    Append(
                        "V45 RES ENTRY #" +
                        std::to_string(
                            resource_entry_id_diagnostics) +
                        " sp=0x" +
                        JniProbeHex(
                            regs[13]) +
                        " r2=0x" +
                        JniProbeHex(
                            regs[2]) +
                        " id=\"" +
                        entry_id +
                        "\"");
                }
            } else {
                resource_lookup_entry_ids.erase(
                    regs[13]);
            }

            return;
        }

        if (swi ==
            kJniProbeSvcResourceRegistryGlobalValue) {

            // Original 0x1086fa84 instruction:
            //     LDR r0,[r10,#0x14]
            // r10 is the node returned by the global ResourceInfo tree.
            const std::uint32_t node =
                regs[10];

            const std::uint32_t native_value =
                node != 0u &&
                mem.Ptr(
                    node + 0x14u,
                    4u) != nullptr
                    ? mem.Read32Guest(
                          node + 0x14u)
                    : 0u;

            if (native_value != 0u) {
                // Exact emulation of the original LDR for normal native hits.
                regs[0] =
                    native_value;
                return;
            }

            std::string recovered_id;

            // Same exact per-stack-frame ID captured at 0x1086f674.
            if (const auto entry =
                    resource_lookup_entry_ids.find(
                        regs[13]);
                entry !=
                    resource_lookup_entry_ids.end()) {
                recovered_id =
                    entry->second;
            }

            if (recovered_id.empty()) {
                recovered_id =
                    RecoverGuestResfileWord(
                        regs[4]);
            }

            if (recovered_id.empty()) {
                for (std::uint32_t reg = 3u;
                     reg <= 12u &&
                     recovered_id.empty();
                     ++reg) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            regs[reg]);
                }
            }

            if (recovered_id.empty() &&
                mem.Ptr(
                    regs[13],
                    32u * 4u) != nullptr) {
                for (std::uint32_t slot = 0u;
                     slot < 32u &&
                     recovered_id.empty();
                     ++slot) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            mem.Read32Guest(
                                regs[13] +
                                slot * 4u));
                }
            }

            // In the global scan, r8 retains the original manager. r6 is the
            // selected group's std::map end sentinel after ADD r6,r6,#60, so
            // subtracting 60 recovers the group base for the narrow exact-ID
            // fallback.
            const std::uint32_t manager =
                regs[8];

            const std::uint32_t group =
                regs[6] >= 60u
                    ? regs[6] - 60u
                    : 0u;

            if (resource_global_null_node_diagnostics <
                32u) {
                ++resource_global_null_node_diagnostics;

                Append(
                    "V45 GLOBAL NULL RESOURCE NODE #" +
                    std::to_string(
                        resource_global_null_node_diagnostics) +
                    " id=\"" +
                    recovered_id +
                    "\" node=0x" +
                    JniProbeHex(
                        node) +
                    " manager=0x" +
                    JniProbeHex(
                        manager) +
                    " group=0x" +
                    JniProbeHex(
                        group) +
                    " value=0");
            }

            const std::uint32_t recovered =
                ResolveResourceRegistryNativeMiss(
                    manager,
                    group,
                    regs[4],
                    "0x1086fa84",
                    recovered_id);

            if (recovered != 0u &&
                node != 0u &&
                mem.Ptr(
                    node + 0x14u,
                    4u) != nullptr) {

                // Heal the same native node so subsequent lookups no longer
                // need the bridge. This mirrors v44's group-node repair, but
                // on the global-tree success path that v44 never trapped.
                mem.Write32Guest(
                    node + 0x14u,
                    recovered);

                ++resource_global_null_node_heals;

                if (resource_global_null_node_heals <=
                    32u) {
                    Append(
                        "V45 GLOBAL NULL NODE HEAL #" +
                        std::to_string(
                            resource_global_null_node_heals) +
                        " id=\"" +
                        recovered_id +
                        "\" node=0x" +
                        JniProbeHex(
                            node) +
                        " -> ResourceInfo*=0x" +
                        JniProbeHex(
                            recovered));
                }
            }

            // The replaced instruction was itself the return-value load.
            regs[0] =
                recovered;
            return;
        }

        if (swi ==
                kJniProbeSvcResourceRegistryMissGroup ||
            swi ==
                kJniProbeSvcResourceRegistryMissGlobal) {

            const bool group_site =
                swi ==
                kJniProbeSvcResourceRegistryMissGroup;

            bool group_null_value_node = false;

            if (group_site &&
                regs[7] != regs[8]) {

                // 0x1086f8a0 is shared by both a genuine native hit and the
                // final group-tree lookup. v43 treated every non-end node as
                // success. The v43 run shows that this is too coarse: the
                // std::map can contain the requested key while its
                // ResourceInfo* value at node+0x14 is still null. In that
                // case the very next guest LDR returns null and the caller
                // reports "resource not found" without ever entering our
                // old miss recovery.
                const std::uint32_t native_value =
                    mem.Ptr(
                        regs[7] + 0x14u,
                        4u) != nullptr
                        ? mem.Read32Guest(
                              regs[7] + 0x14u)
                        : 0u;

                if (native_value != 0u) {
                    // Preserve the original MOV r0,#0; the following guest
                    // LDR r0,[r7,#0x14] restores the real native value.
                    regs[0] = 0u;
                    return;
                }

                group_null_value_node = true;

                if (resource_null_node_diagnostics <
                    24u) {
                    ++resource_null_node_diagnostics;

                    Append(
                        "V45 GROUP NULL RESOURCE NODE #" +
                        std::to_string(
                            resource_null_node_diagnostics) +
                        " node=0x" +
                        JniProbeHex(
                            regs[7]) +
                        " end=0x" +
                        JniProbeHex(
                            regs[8]) +
                        " value=0");
                }
            }

            const std::uint32_t manager =
                group_site
                    ? regs[10]
                    : regs[8];

            const std::uint32_t group =
                group_site &&
                regs[8] >= 60u
                    ? regs[8] - 60u
                    : 0u;

            std::string recovered_id;

            // v43: use the exact lookup ID captured at 0x1086f674 for this
            // ARM stack frame. The old late-state reconstruction can miss
            // every other request after native key transformations.
            if (const auto entry =
                    resource_lookup_entry_ids.find(
                        regs[13]);
                entry !=
                    resource_lookup_entry_ids.end()) {
                recovered_id =
                    entry->second;
            }

            // Preserve the v42 late-state scan as a fallback.
            if (recovered_id.empty()) {
                recovered_id =
                    RecoverGuestResfileWord(
                        regs[4]);
            }

            if (recovered_id.empty()) {
                for (std::uint32_t reg = 3u;
                     reg <= 12u &&
                     recovered_id.empty();
                     ++reg) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            regs[reg]);
                }
            }

            if (recovered_id.empty() &&
                mem.Ptr(
                    regs[13],
                    32u * 4u) != nullptr) {
                for (std::uint32_t slot = 0u;
                     slot < 32u &&
                     recovered_id.empty();
                     ++slot) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            mem.Read32Guest(
                                regs[13] +
                                slot * 4u));
                }
            }

            if (!recovered_id.empty() &&
                resource_live_id_recoveries < 16u) {
                ++resource_live_id_recoveries;

                Append(
                    "V45 LIVE RESFILE RECOVERY #" +
                    std::to_string(
                        resource_live_id_recoveries) +
                    " site=" +
                    (group_site
                        ? std::string{"0x1086f8a0"}
                        : std::string{"0x1086fa78"}) +
                    " r4=0x" +
                    JniProbeHex(
                        regs[4]) +
                    " id=\"" +
                    recovered_id +
                    "\"");
            }

            const std::uint32_t recovered =
                ResolveResourceRegistryNativeMiss(
                    manager,
                    group,
                    regs[4],
                    group_site
                        ? "0x1086f8a0"
                        : "0x1086fa78",
                    recovered_id);

            if (group_null_value_node) {
                if (recovered != 0u &&
                    mem.Ptr(
                        regs[7] + 0x14u,
                        4u) != nullptr) {

                    mem.Write32Guest(
                        regs[7] + 0x14u,
                        recovered);

                    ++resource_null_node_heals;

                    if (resource_null_node_heals <=
                        24u) {
                        Append(
                            "V45 GROUP NULL NODE HEAL #" +
                            std::to_string(
                                resource_null_node_heals) +
                            " id=\"" +
                            recovered_id +
                            "\" node=0x" +
                            JniProbeHex(
                                regs[7]) +
                            " -> ResourceInfo*=0x" +
                            JniProbeHex(
                                recovered));
                    }
                }

                // Emulate the original MOV r0,#0. Because r7!=r8, guest code
                // proceeds to LDR r0,[r7,#0x14], which now reads the healed
                // value if recovery succeeded.
                regs[0] = 0u;
            } else {
                // True end-node miss: guest branches directly to the epilogue,
                // so r0 itself carries the recovered pointer back to caller.
                regs[0] = recovered;
            }

            return;
        }

        if (swi ==
            kJniProbeSvcResourceRegistryLookup) {

            const std::uint32_t manager =
                regs[0];
            const std::uint32_t group =
                regs[1];
            const std::uint32_t id_object =
                regs[2];

            regs[0] =
                ResolveResourceRegistryLookup(
                    manager,
                    group,
                    id_object);

            return;
        }

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

                        ++v52_ui_process_events_calls;

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

                        if (copy != 0u) {
                            std::memcpy(
                                output,
                                formatted.data(),
                                copy);
                        }

                        output[copy] = 0u;
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

            if (name == "fclose") {
                const std::uint32_t token =
                    regs[0];
                const auto path_it =
                    v51_file_token_paths.find(
                        token);

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

                    std::memcpy(
                        mem.Ptr(
                            dst,
                            static_cast<std::size_t>(
                                bytes)),
                        source,
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

                    std::memcpy(
                        mem.Ptr(
                            dst,
                            static_cast<std::size_t>(
                                bytes)),
                        source,
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
                        v51_writable_files.erase(
                            guest_path);
                    regs[0] =
                        erased != 0u
                            ? 0u
                            : 0xffffffffu;
                    if (erased == 0u) {
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

                    ++gles_texture_uploads;
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
                            ") hostFBO=1180x820 phase=" +
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
                            ") hostFBO=1180x820 phase=" +
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

        V46AppendControlFlowMap(
            "exception",
            pc,
            lr,
            sp);

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

            V46AppendControlFlowMap(
                "execution-budget",
                pc,
                lr,
                sp);

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
    callbacks.loaded_elf = &loaded;

    callbacks.Append(
        "V46 ADDRESS MAP READY: guestBase=0x" +
        JniProbeHex(kGuestBase) +
        " imageSize=0x" +
        JniProbeHex(
            static_cast<std::uint32_t>(
                loaded.image.size())) +
        " dynsyms=" +
        std::to_string(loaded.dynsyms.size()) +
        " exidxFunctionStarts=" +
        std::to_string(loaded.function_starts.size()) +
        " regions={libPVZ2:0x10000000,stack:0x20000000,heap:0x30000000,trampoline:0x40000000,JNI:0x50000000,objects:0x51000000}");

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

    // v45: keep 0x86f66c's native lookup logic intact, but observe the exact
    // entry plus all three relevant return shapes. v44 proved the group path
    // never produced a null-valued found node. The missing alternating IDs
    // instead bypass both old miss traps, so v45 additionally replaces the
    // global found-node LDR at 0x86fa84 and checks node+0x14 directly.
    auto patch_resource_native_miss =
        [&](std::uint32_t offset,
            std::uint32_t expected,
            std::uint32_t svc) {

            if (offset + 4u >
                    memory.image.size() ||
                Read32(
                    memory.image.data() +
                    offset) != expected) {
                return false;
            }

            Write32(
                memory.image.data() +
                    offset,
                0xEF000000u |
                (svc & 0x00ffffffu));

            return true;
        };

    if (!patch_resource_native_miss(
            0x0086f674u,
            0xe1a04002u,
            kJniProbeSvcResourceRegistryEntry) ||
        !patch_resource_native_miss(
            0x0086f8a0u,
            0xe3a00000u,
            kJniProbeSvcResourceRegistryMissGroup) ||
        !patch_resource_native_miss(
            0x0086fa78u,
            0xe3a00000u,
            kJniProbeSvcResourceRegistryMissGlobal) ||
        !patch_resource_native_miss(
            0x0086fa84u,
            0xe59a0014u,
            kJniProbeSvcResourceRegistryGlobalValue) ||
        !patch_resource_native_miss(
            0x0087a708u,
            0xea000018u,
            kJniProbeSvcResourceWrapperDirectReturn) ||
        !patch_resource_native_miss(
            0x0087a76cu,
            0xe3a00000u,
            kJniProbeSvcResourceWrapperExhausted) ||
        !patch_resource_native_miss(
            0x002747d8u,
            0xe1a04000u,
            kJniProbeSvcGameStateApply) ||
        !patch_resource_native_miss(
            0x00274b4cu,
            0xe1a04000u,
            kJniProbeSvcGameStateRequest) ||
        !patch_resource_native_miss(
            0x000f66e4u,
            0xe28dd0b0u,
            kJniProbeSvcStartupGroupsCtorSnapshot) ||
        !patch_resource_native_miss(
            0x002c84d0u,
            0xe595064cu,
            kJniProbeSvcStartupGateAResource) ||
        !patch_resource_native_miss(
            0x002c85ccu,
            0xe1a04000u,
            kJniProbeSvcStartupGroupsLookupResult) ||
        !patch_resource_native_miss(
            0x002c85f4u,
            0xe086a00au,
            kJniProbeSvcStartupGroupsContribution) ||
        !patch_resource_native_miss(
            0x002c8620u,
            0xee00ba10u,
            kJniProbeSvcStartupGateATotals) ||
        !patch_resource_native_miss(
            0x002769d4u,
            0xee010a10u,
            kJniProbeSvcStartupGateAResult) ||
        !patch_resource_native_miss(
            0x005143a4u,
            0xe5901098u,
            kJniProbeSvcStartupGateCState) ||
        !patch_resource_native_miss(
            0x00276a30u,
            0xe5940430u,
            kJniProbeSvcStartupGateDCounter) ||
        !patch_resource_native_miss(
            0x00276a3cu,
            0xe59f03c8u,
            kJniProbeSvcStartupAfterD) ||
        !patch_resource_native_miss(
            0x00276a60u,
            0xe5d00b7au,
            kJniProbeSvcStartupGateEByte) ||
        !patch_resource_native_miss(
            0x0036bbfcu,
            0xe1a00004u,
            kJniProbeSvcStartupGateFResult) ||
        !patch_resource_native_miss(
            0x002b88ecu,
            0xe1a00004u,
            kJniProbeSvcStartupGateGResult) ||
        !patch_resource_native_miss(
            0x002b8b88u,
            0xe1a00004u,
            kJniProbeSvcStartupGateHResult) ||
        !patch_resource_native_miss(
            0x004855b0u,
            0xe1a00005u,
            kJniProbeSvcStartupGateIResult) ||
        !patch_resource_native_miss(
            0x0037d158u,
            0xe1a01000u,
            kJniProbeSvcStartupGateJObject) ||
        !patch_resource_native_miss(
            0x00276adcu,
            0xe1a00004u,
            kJniProbeSvcStartupPatchMarker) ||
        !patch_resource_native_miss(
            0x00276b20u,
            0xe1a05000u,
            kJniProbeSvcStartupMainFlow) ||
        !patch_resource_native_miss(
            0x002ef188u,
            0xe1a00004u,
            kJniProbeSvcStartupProgressResult) ||
        !patch_resource_native_miss(
            0x00423adcu,
            0xe1a00004u,
            kJniProbeSvcStartupFindResult) ||
        !patch_resource_native_miss(
            0x004ac370u,
            0xe1a00004u,
            kJniProbeSvcStartupLateResult) ||
        !patch_resource_native_miss(
            0x00276d70u,
            0xe1a00004u,
            kJniProbeSvcStartupMainMenuMarker)) {

        error =
            "v55 passive resource/state/StartupLogo/group instrumentation profile did not match the verified PvZ2 1.5.252752 ARM code.";
        return false;
    }

    callbacks.Append(
        "V48 RESFILE WRAPPER-FINAL BRIDGE: v45 internal hooks preserved; direct-group null returns are observed at 0x1087a708 and all-groups-exhausted nulls at 0x1087a76c with the exact wrapper ID still in r6.");
    callbacks.Append(
        "V53 PASSIVE GAMESTATE TRAPS installed: ApplyState@0x102747d8 and RequestTransition@0x10274b4c. No state transition will be injected.");
    callbacks.Append(
        "V54 PASSIVE STARTUPLOGO TRAPS installed: GateA resource/totals/result, GateC state==4, GateD counter>=3, post-A-D depth, patch/main late decisions, and Patch/MainMenu request-path markers. Every replaced ARM instruction is emulated exactly; no gate or transition is forced.");
    callbacks.Append(
        "V55 PASSIVE STARTUP GROUP TRAPS installed: global four-group vector constructor snapshot@0x100f66e4, GateA native group lookup result@0x102c85cc, and per-group completed/total contribution@0x102c85f4. No resource-group index, progress value, vector entry, branch, or GameState is modified.");

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

                // v35: v30 intentionally stopped running deferred workers during
                // ordinary main-thread timeslices because synthetic pthread
                // synchronization made mid-lifecycle interleavings unsafe.
                // That fixed corruption, but it also meant workers created
                // after the last concrete async wait (tid=2..6 in v34) could
                // remain deferred forever. Run them cooperatively only at
                // lifecycle/frame boundaries, where the main guest is not
                // mutating game state.
                std::size_t boundary_worker_cursor = 0u;
                std::uint64_t boundary_worker_slices = 0u;

                auto run_boundary_workers =
                    [&](const char* phase,
                        std::size_t max_slices) -> bool {

                        if (callbacks.deferred_threads.empty() ||
                            max_slices == 0u) {
                            return true;
                        }

                        constexpr std::uint32_t
                            kBoundaryWorkerStackSize =
                                64u * 1024u;
                        constexpr std::uint64_t
                            kBoundaryWorkerSliceTicks =
                                100000ull;

                        const auto saved_regs =
                            jit.Regs();
                        const auto saved_ext_regs =
                            jit.ExtRegs();
                        const std::uint32_t saved_cpsr =
                            jit.Cpsr();
                        const std::uint32_t saved_fpscr =
                            jit.Fpscr();

                        auto clear_boundary_halts =
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

                        std::size_t ran = 0u;
                        std::size_t inspected = 0u;

                        while (ran < max_slices &&
                               inspected <
                                   callbacks
                                       .deferred_threads
                                       .size()) {

                            if (callbacks.deferred_threads.empty()) {
                                break;
                            }

                            boundary_worker_cursor %=
                                callbacks
                                    .deferred_threads
                                    .size();

                            const std::size_t wi =
                                boundary_worker_cursor++;

                            ++inspected;

                            auto worker_state =
                                callbacks
                                    .deferred_threads[wi];

                            if (worker_state.runtime_completed ||
                                worker_state.runtime_failed) {
                                continue;
                            }

                            if (!worker_state.runtime_started) {
                                const std::uint32_t stack_base =
                                    memory.AllocateHeap(
                                        kBoundaryWorkerStackSize,
                                        16u);

                                if (!stack_base) {
                                    callbacks.Append(
                                        "V38 BOUNDARY WORKER: unable to allocate stack for tid=" +
                                        std::to_string(
                                            worker_state.id));
                                    worker_state.runtime_failed =
                                        true;

                                    if (wi <
                                        callbacks
                                            .deferred_threads
                                            .size()) {
                                        callbacks
                                            .deferred_threads[wi] =
                                                worker_state;
                                    }
                                    continue;
                                }

                                worker_state.stack_top =
                                    stack_base +
                                    kBoundaryWorkerStackSize -
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
                                    "V38 BOUNDARY WORKER START tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " start=0x" +
                                    JniProbeHex(
                                        worker_state.start_routine) +
                                    " created_in=" +
                                    worker_state.created_in +
                                    " phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"});
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
                                "V38_boundary_worker_tid_" +
                                std::to_string(
                                    worker_state.id);
                            callbacks.current_probe_thread_id =
                                worker_state.id;
                            callbacks.control_returned = false;
                            callbacks.soft_slice_timeout = true;
                            callbacks.ticks_left =
                                kBoundaryWorkerSliceTicks;
                            callbacks.ticks_consumed = 0u;
                            callbacks.next_tick_report =
                                kBoundaryWorkerSliceTicks;

                            result.message.clear();
                            clear_boundary_halts();

                            const std::uint64_t calls_before =
                                callbacks.supported_calls;

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

                            if (wi <
                                callbacks
                                    .deferred_threads
                                    .size()) {
                                callbacks
                                    .deferred_threads[wi] =
                                        worker_state;
                            }

                            ++ran;
                            ++boundary_worker_slices;

                            if (boundary_worker_slices <= 24u ||
                                (boundary_worker_slices %
                                 100u) == 0u ||
                                worker_state.runtime_completed ||
                                worker_state.runtime_failed) {

                                callbacks.Append(
                                    "V38 BOUNDARY WORKER SLICE phase=" +
                                    std::string{
                                        phase != nullptr
                                            ? phase
                                            : "n/a"} +
                                    " tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " PC=0x" +
                                    JniProbeHex(
                                        worker_state.regs[15]) +
                                    " ticks=" +
                                    std::to_string(
                                        callbacks.ticks_consumed) +
                                    " total=" +
                                    std::to_string(
                                        worker_state.runtime_ticks) +
                                    " calls+=" +
                                    std::to_string(
                                        callbacks.supported_calls -
                                        calls_before) +
                                    " returned=" +
                                    (worker_state.runtime_completed
                                        ? "YES"
                                        : "NO") +
                                    " failed=" +
                                    (worker_state.runtime_failed
                                        ? "YES"
                                        : "NO"));
                            }

                            if (worker_fatal) {
                                callbacks.Append(
                                    "V38 BOUNDARY WORKER STOP: tid=" +
                                    std::to_string(
                                        worker_state.id) +
                                    " halted fatally; preserving main runtime and continuing other diagnostics.");
                            }
                        }

                        clear_boundary_halts();

                        jit.Regs() =
                            saved_regs;
                        jit.ExtRegs() =
                            saved_ext_regs;
                        jit.SetCpsr(
                            saved_cpsr);
                        jit.SetFpscr(
                            saved_fpscr);
                        jit.ClearExclusiveState();

                        callbacks.return_mode =
                            PvZ2JniCallbacks::ReturnMode::Lifecycle;
                        callbacks.current_probe_thread_id = 0u;
                        callbacks.control_returned = false;
                        callbacks.soft_slice_timeout = true;

                        return true;
                    };

                auto drain_cloud_state_callback =
                    [&](const char* phase) -> bool {

                        if (!callbacks.pending_cloud_state_loaded ||
                            callbacks.cloud_state_loaded_delivered) {
                            return true;
                        }

                        if (callbacks.native_cloud_state_loaded_address ==
                            0u) {
                            callbacks.Append(
                                "V49 CLOUD HANDSHAKE: completion pending but Native_CloudStateLoaded was not captured; retaining previous behavior.");
                            return true;
                        }

                        callbacks.Append(
                            "V49 CLOUD DELIVER phase=" +
                            std::string{
                                phase != nullptr
                                    ? phase
                                    : "n/a"} +
                            " callback=0x" +
                            JniProbeHex(
                                callbacks
                                    .native_cloud_state_loaded_address));

                        // Verified in PvZ2 1.5.252752: this callback does not
                        // consume its Java String argument; it signals the
                        // native cloud singleton. Null therefore completes the
                        // async handshake without fabricating cloud payload.
                        if (!run_lifecycle(
                                "V49_Native_CloudStateLoaded",
                                callbacks
                                    .native_cloud_state_loaded_address,
                                kCloud,
                                0u,
                                0u,
                                false)) {
                            callbacks.Append(
                                "V49 CLOUD DELIVER failed.");
                            return false;
                        }

                        callbacks.cloud_state_loaded_delivered =
                            true;
                        callbacks.pending_cloud_state_loaded =
                            false;
                        callbacks.Append(
                            "V49 CLOUD DELIVER returned successfully.");
                        return true;
                    };

                std::size_t http_delivery_cursor = 0u;

                auto drain_offline_http_callbacks =
                    [&](const char* phase) -> bool {

                        constexpr std::uint32_t
                            kHttpTransactionError =
                                kGuestBase +
                                0x00a03410u;
                        constexpr std::size_t
                            kMaxHttpCallbacks = 32u;

                        std::size_t delivered = 0u;

                        while (http_delivery_cursor <
                                   callbacks
                                       .pending_http_failures
                                       .size() &&
                               delivered <
                                   kMaxHttpCallbacks) {

                            const auto item =
                                callbacks
                                    .pending_http_failures[
                                        http_delivery_cursor++];

                            ++callbacks.v52_http_deliveries;

                            callbacks.Append(
                                "V34 HTTP OFFLINE DELIVER phase=" +
                                std::string{
                                    phase != nullptr
                                        ? phase
                                        : "n/a"} +
                                " java=0x" +
                                JniProbeHex(
                                    item.first) +
                                " nativePeer=0x" +
                                JniProbeHex(
                                    item.second));

                            if (!run_lifecycle(
                                    "V34_HttpTransactionError",
                                    kHttpTransactionError,
                                    item.first,
                                    item.second,
                                    0u,
                                    false)) {
                                callbacks.Append(
                                    "V34 HTTP OFFLINE DELIVER failed for nativePeer=0x" +
                                    JniProbeHex(
                                        item.second));
                                return false;
                            }

                            ++delivered;
                        }

                        if (http_delivery_cursor <
                            callbacks
                                .pending_http_failures
                                .size()) {

                            callbacks.Append(
                                "V34 HTTP OFFLINE DELIVER: callback batch capped; remaining=" +
                                std::to_string(
                                    callbacks
                                        .pending_http_failures
                                        .size() -
                                    http_delivery_cursor));
                        }

                        return true;
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

                callbacks.gles_bound_guest_framebuffer =
                    0u;
                callbacks.gles_bound_host_framebuffer =
                    callbacks.host_default_framebuffer;

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

                // v39: this PvZ2 Android native entry point consumes the two
                // dimensions in height,width order even though our first probe
                // supplied width,height. v38 proved it unambiguously: passing
                // 1180,820 caused the game's first/restore viewport to become
                // 820x1180 on a 1180x820 host framebuffer. Feed 820,1180 so
                // the native renderer establishes/restores a true landscape
                // 1180x820 viewport.
                callbacks.Append(
                    "V39 SURFACE GEOMETRY: calling Native_onSurfaceChanged with native-order height=820 width=1180 for hostFBO=1180x820.");

                if (!run_lifecycle(
                        "Native_onSurfaceChanged",
                        kNativeOnSurfaceChanged,
                        kSurfaceThis,
                        820,
                        1180,
                        false)) {
                    return result;
                }

                // v49: finish the Java-side silent cloud sync handshake now
                // that startup + surface setup are complete, before rendering
                // the first frame.
                if (!drain_cloud_state_callback(
                        "pre-frame")) {
                    return result;
                }

                // Android's Java HTTP layer normally resolves Start()
                // asynchronously and calls one of the registered native
                // callbacks. The probe has no Android networking backend, so
                // finish queued startup requests as deterministic offline
                // errors at this lifecycle-safe boundary. This avoids leaving
                // the native transactions permanently "in flight".
                if (!drain_offline_http_callbacks(
                        "pre-frame")) {
                    return result;
                }

                // Give every deferred worker one short slice before rendering.
                // This is the first safe point after surface setup and starts
                // workers that v30 deliberately refused to interleave inside
                // Native_onSurfaceCreated.
                if (!run_boundary_workers(
                        "pre-frame",
                        callbacks.deferred_threads.size())) {
                    return result;
                }

                constexpr std::uint32_t
                    kV36FrameCount = 600u;

                auto should_sample_frame =
                    [](std::uint32_t frame) {
                        return
                            frame <= 3u ||
                            frame == 5u ||
                            frame == 10u ||
                            frame == 15u ||
                            frame == 20u ||
                            frame == 30u ||
                            frame == 45u ||
                            (frame >= 55u &&
                             frame <= 90u) ||
                            frame == 120u ||
                            frame == 150u ||
                            frame == 180u ||
                            frame == 240u ||
                            frame == 300u ||
                            frame == 360u ||
                            frame == 420u ||
                            frame == 480u ||
                            frame == 540u ||
                            frame == 600u ||
                            (frame >= 90u &&
                             (frame % 10u) == 0u);
                    };

                auto should_probe_framebuffers =
                    [](std::uint32_t frame) {
                        return
                            frame == 15u ||
                            frame == 60u ||
                            frame == 70u ||
                            frame == 74u ||
                            frame == 75u ||
                            frame == 76u ||
                            frame == 80u ||
                            frame == 90u ||
                            frame == 120u ||
                            frame == 600u;
                    };

                std::uint64_t best_non_black = 0u;
                std::uint32_t best_frame = 0u;
                std::uint64_t post_ea_best_non_black = 0u;
                std::uint32_t post_ea_best_frame = 0u;
                std::string post_ea_best_path;

                auto should_capture_state_graph =
                    [](std::uint32_t frame) {
                        return
                            frame == 1u ||
                            frame == 15u ||
                            frame == 60u ||
                            frame == 70u ||
                            frame == 74u ||
                            frame == 75u ||
                            frame == 76u ||
                            frame == 80u ||
                            frame == 90u ||
                            frame == 120u ||
                            frame == 180u ||
                            frame == 300u ||
                            frame == 600u;
                    };

                std::uint32_t
                    v52_last_progress_frame = 0u;
                std::uint64_t
                    v52_last_sample_non_black =
                        std::numeric_limits<
                            std::uint64_t>::max();
                std::uint64_t
                    v52_last_texture_uploads =
                        callbacks
                            .gles_texture_uploads;
                std::uint32_t
                    v52_last_resource_lookups =
                        result
                            .resource_registry_lookup_calls;
                std::uint64_t
                    v52_last_http_activity =
                        callbacks.v52_http_starts +
                        callbacks.v52_http_deliveries;
                std::int32_t
                    v53_last_game_state =
                        callbacks.V53CurrentGameState();

                for (std::uint32_t frame = 0u;
                     frame < kV36FrameCount;
                     ++frame) {

                    const std::uint32_t frame_number =
                        frame + 1u;
                    const bool sample =
                        should_sample_frame(
                            frame_number);

                    callbacks.current_frame_number =
                        frame_number;

                    if (sample) {
                        callbacks.Append(
                            "V39 FRAME SOAK: begin frame " +
                            std::to_string(
                                frame_number) +
                            "/" +
                            std::to_string(
                                kV36FrameCount));
                    }

                    if (!run_lifecycle(
                            "Native_onDrawFrame",
                            kNativeOnDrawFrame,
                            kSurfaceThis,
                            0,
                            0,
                            true)) {

                        if (callbacks.host_gles_ready) {
                            const char* partial =
                                PvZ2HostGLESCapturePNGNamed(
                                    "pvz2-v36-stopped-frame.png");

                            if (partial != nullptr &&
                                *partial != '\0') {
                                result.host_frame_png_path =
                                    partial;
                            }
                        }

                        return result;
                    }

                    result.draw_frames_completed =
                        frame_number;

                    // Start() can be reached while a frame is executing
                    // (analytics/live-config/telemetry requests do this).
                    // Deliver any newly queued terminal callbacks only after
                    // Native_onDrawFrame has returned, never in the middle of
                    // guest rendering/state mutation.
                    if (!drain_offline_http_callbacks(
                            "frame-boundary")) {
                        return result;
                    }

                    // One fair background slice per completed frame. No worker
                    // runs while Native_onDrawFrame itself is active.
                    if (!run_boundary_workers(
                            "frame-boundary",
                            1u)) {
                        return result;
                    }

                    if (should_capture_state_graph(
                            frame_number)) {
                        callbacks.V52CaptureStateGraph(
                            frame_number);
                        callbacks.V53AppendGameStateSnapshot(
                            "frame-" +
                            std::to_string(
                                frame_number));
                    }

                    if (callbacks.host_gles_ready &&
                        sample) {

                        const char* stats =
                            PvZ2HostGLESFrameStats();
                        const std::uint64_t non_black =
                            PvZ2HostGLESLastNonBlackPixels();

                        if (non_black > 0u) {
                            result.last_nonblack_frame_number =
                                frame_number;
                            result.last_nonblack_pixels =
                                non_black;
                        }

                        const std::uint64_t
                            v52_http_activity =
                                callbacks.v52_http_starts +
                                callbacks.v52_http_deliveries;
                        const std::int32_t
                            v53_game_state =
                                callbacks.V53CurrentGameState();

                        if (v52_last_sample_non_black !=
                                non_black ||
                            v52_last_texture_uploads !=
                                callbacks
                                    .gles_texture_uploads ||
                            v52_last_resource_lookups !=
                                result
                                    .resource_registry_lookup_calls ||
                            v52_last_http_activity !=
                                v52_http_activity ||
                            v53_last_game_state !=
                                v53_game_state ||
                            callbacks
                                .v50_mainmenu_background_seen ||
                            callbacks
                                .v50_ui_mainmenu_seen) {

                            v52_last_progress_frame =
                                frame_number;
                        }

                        v52_last_sample_non_black =
                            non_black;
                        v52_last_texture_uploads =
                            callbacks
                                .gles_texture_uploads;
                        v52_last_resource_lookups =
                            result
                                .resource_registry_lookup_calls;
                        v52_last_http_activity =
                            v52_http_activity;
                        v53_last_game_state =
                            v53_game_state;

                        callbacks.Append(
                            "V39 FRAME STATS #" +
                            std::to_string(
                                frame_number) +
                            ": " +
                            (stats != nullptr
                                ? stats
                                : "unavailable") +
                            " GL{draws=" +
                            std::to_string(
                                callbacks.gles_draw_calls) +
                            ",clears=" +
                            std::to_string(
                                callbacks.gles_clear_calls) +
                            ",uploads=" +
                            std::to_string(
                                callbacks.gles_texture_uploads) +
                            "}");

                        if (should_probe_framebuffers(
                                frame_number)) {

                            callbacks.Append(
                                "V47 FBO SNAPSHOT #" +
                                std::to_string(
                                    frame_number) +
                                " default guest=0 host=" +
                                std::to_string(
                                    callbacks
                                        .host_default_framebuffer) +
                                " draws=" +
                                std::to_string(
                                    callbacks
                                        .gles_draws_by_framebuffer[
                                            callbacks
                                                .host_default_framebuffer]) +
                                " stats={" +
                                (stats != nullptr
                                    ? std::string{stats}
                                    : std::string{"unavailable"}) +
                                "}");

                            std::vector<GLuint>
                                framebuffers(
                                    callbacks
                                        .gles_generated_framebuffers
                                        .begin(),
                                    callbacks
                                        .gles_generated_framebuffers
                                        .end());

                            std::sort(
                                framebuffers.begin(),
                                framebuffers.end());

                            for (const GLuint framebuffer :
                                 framebuffers) {

                                const auto attached =
                                    callbacks
                                        .gles_framebuffer_color_texture
                                        .find(
                                            framebuffer);

                                if (attached ==
                                    callbacks
                                        .gles_framebuffer_color_texture
                                        .end()) {

                                    callbacks.Append(
                                        "V47 FBO SNAPSHOT #" +
                                        std::to_string(
                                            frame_number) +
                                        " host=" +
                                        std::to_string(
                                            framebuffer) +
                                        " no-color-texture draws=" +
                                        std::to_string(
                                            callbacks
                                                .gles_draws_by_framebuffer[
                                                    framebuffer]));
                                    continue;
                                }

                                const auto info =
                                    callbacks
                                        .gles_texture_info
                                        .find(
                                            attached->second);

                                if (info ==
                                        callbacks
                                            .gles_texture_info
                                            .end() ||
                                    info->second.width <= 0 ||
                                    info->second.height <= 0) {

                                    callbacks.Append(
                                        "V47 FBO SNAPSHOT #" +
                                        std::to_string(
                                            frame_number) +
                                        " host=" +
                                        std::to_string(
                                            framebuffer) +
                                        " colorTex=" +
                                        std::to_string(
                                            attached->second) +
                                        " unknown-size draws=" +
                                        std::to_string(
                                            callbacks
                                                .gles_draws_by_framebuffer[
                                                    framebuffer]));
                                    continue;
                                }

                                const char* internal_stats =
                                    PvZ2HostGLESFramebufferStats(
                                        static_cast<std::uint32_t>(
                                            framebuffer),
                                        static_cast<std::uint32_t>(
                                            info->second.width),
                                        static_cast<std::uint32_t>(
                                            info->second.height));

                                callbacks.Append(
                                    "V47 FBO SNAPSHOT #" +
                                    std::to_string(
                                        frame_number) +
                                    " guest/host=" +
                                    std::to_string(
                                        framebuffer) +
                                    " colorTex=" +
                                    std::to_string(
                                        attached->second) +
                                    " draws=" +
                                    std::to_string(
                                        callbacks
                                            .gles_draws_by_framebuffer[
                                                framebuffer]) +
                                    " stats={" +
                                    (internal_stats != nullptr
                                        ? std::string{
                                              internal_stats}
                                        : std::string{
                                              "unavailable"}) +
                                    "}");
                            }
                        }

                        if (non_black > best_non_black) {
                            const char* best =
                                PvZ2HostGLESCapturePNGNamed(
                                    "pvz2-v48-best-frame.png");

                            if (best != nullptr &&
                                *best != '\0') {
                                best_non_black =
                                    non_black;
                                best_frame =
                                    frame_number;
                                result.best_frame_number =
                                    best_frame;
                                result.best_frame_nonblack =
                                    best_non_black;
                                result.best_frame_png_path =
                                    best;

                                callbacks.Append(
                                    "V48 BEST FRAME: #" +
                                    std::to_string(
                                        best_frame) +
                                    " nonBlack=" +
                                    std::to_string(
                                        best_non_black) +
                                    " path=" +
                                    result.best_frame_png_path);
                            }
                        }

                        // Preserve the richest frame after the EA animation
                        // separately. The globally richest image is EA itself,
                        // so without this a later menu/loading screen with
                        // fewer lit pixels would never be shown to the tester.
                        if (frame_number >= 90u &&
                            non_black >
                                post_ea_best_non_black) {

                            const char* post_ea =
                                PvZ2HostGLESCapturePNGNamed(
                                    "pvz2-v48-post-ea-best.png");

                            if (post_ea != nullptr &&
                                *post_ea != '\0') {
                                post_ea_best_non_black =
                                    non_black;
                                post_ea_best_frame =
                                    frame_number;
                                post_ea_best_path =
                                    post_ea;

                                callbacks.Append(
                                    "V39 POST-EA FRAME: #" +
                                    std::to_string(
                                        post_ea_best_frame) +
                                    " nonBlack=" +
                                    std::to_string(
                                        post_ea_best_non_black) +
                                    " path=" +
                                    post_ea_best_path);
                            }
                        }

                        callbacks.Append(
                            "V39 FRAME SOAK: returned frame " +
                            std::to_string(
                                frame_number) +
                            "/" +
                            std::to_string(
                                kV36FrameCount));

                        // v52 adaptive stop: 600 remains the safety ceiling,
                        // not a mandatory wait. Once EA is fully black and 45
                        // sampled frames have produced no new pixels, texture
                        // uploads, resource lookups, HTTP activity or menu
                        // milestone, additional identical frames are not useful.
                        if (frame_number >= 120u &&
                            non_black == 0u &&
                            !callbacks
                                 .v50_mainmenu_background_seen &&
                            !callbacks
                                 .v50_ui_mainmenu_seen &&
                            !callbacks
                                 .pending_cloud_state_loaded &&
                            callbacks.v52_http_starts ==
                                callbacks
                                    .v52_http_deliveries &&
                            frame_number >=
                                v52_last_progress_frame +
                                    45u) {

                            result.adaptive_frame_stop =
                                true;

                            callbacks.Append(
                                "V52 ADAPTIVE STOP frame=" +
                                std::to_string(
                                    frame_number) +
                                " lastProgressFrame=" +
                                std::to_string(
                                    v52_last_progress_frame) +
                                " exactState=" +
                                std::to_string(
                                    callbacks
                                        .V53CurrentGameState()) +
                                "(" +
                                PvZ2JniCallbacks::
                                    V53GameStateName(
                                        callbacks
                                            .V53CurrentGameState()) +
                                ") reason=post-EA framebuffer/resource/HTTP/GameState stable");
                            break;
                        }
                    }

                    if (frame_number !=
                        kV36FrameCount) {
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(
                                16));
                    }
                }

                if (callbacks.host_gles_ready) {
                    const char* final_capture =
                        PvZ2HostGLESCapturePNGNamed(
                            "pvz2-v48-final-frame.png");

                    callbacks.Append(
                        std::string{
                            "V48 FINAL GLES CAPTURE: "} +
                        (final_capture != nullptr &&
                         *final_capture != '\0'
                            ? final_capture
                            : "failed"));

                    if (final_capture != nullptr &&
                        *final_capture != '\0') {
                        result.final_frame_png_path =
                            final_capture;

                        // v52 deliberately displays the final framebuffer,
                        // not the visually richest splash frame.
                        result.host_frame_png_path =
                            final_capture;
                    }
                }

                callbacks.V53AppendGameStateSnapshot(
                    "final");
                callbacks.V52FinalizeDiagnostics();

                callbacks.Append(
                    "V52 FRAME SUMMARY: frame=" +
                    std::to_string(
                        best_frame) +
                    " nonBlack=" +
                    std::to_string(
                        best_non_black) +
                    " | postEA=" +
                    std::to_string(
                        post_ea_best_frame) +
                    " nonBlack=" +
                    std::to_string(
                        post_ea_best_non_black) +
                    " | boundaryWorkerSlices=" +
                    std::to_string(
                        boundary_worker_slices) +
                    " | wrapperDirectNulls=" +
                    std::to_string(
                        callbacks.resource_wrapper_direct_nulls) +
                    " wrapperExhaustedNulls=" +
                    std::to_string(
                        callbacks.resource_wrapper_exhausted_nulls) +
                    " wrapperRecoveries=" +
                    std::to_string(
                        callbacks.resource_wrapper_recoveries) +
                    " | cloudPending=" +
                    (callbacks.pending_cloud_state_loaded
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " cloudDelivered=" +
                    (callbacks.cloud_state_loaded_delivered
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " | networkStatusCalls=" +
                    std::to_string(
                        callbacks.v50_network_status_calls) +
                    " uiAndroid=" +
                    (callbacks.v50_ui_android_seen
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " uiIPad=" +
                    (callbacks.v50_ui_ipad_seen
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " mainMenuBg=" +
                    (callbacks.v50_mainmenu_background_seen
                        ? std::string{"YES@"} +
                              std::to_string(
                                  callbacks
                                      .v50_mainmenu_background_first_frame)
                        : std::string{"NO"}) +
                    " uiMainMenu=" +
                    (callbacks.v50_ui_mainmenu_seen
                        ? std::string{"YES@"} +
                              std::to_string(
                                  callbacks
                                      .v50_ui_mainmenu_first_frame)
                        : std::string{"NO"}) +
                    " initAtlas=" +
                    (callbacks.v50_init_atlas_seen
                        ? std::string{"YES"}
                        : std::string{"NO"}) +
                    " | userFsFiles=" +
                    std::to_string(
                        callbacks
                            .v51_writable_files
                            .size()) +
                    " userFsWrites=" +
                    std::to_string(
                        callbacks
                            .v51_userfs_write_calls) +
                    " userFsBytes=" +
                    std::to_string(
                        callbacks
                            .v51_userfs_bytes_written) +
                    " snapshot2Bytes=" +
                    std::to_string(
                        callbacks
                            .v51_snapshot2_bytes) +
                    " configKeys=" +
                    std::to_string(
                        callbacks
                            .v51_config_keys
                            .size()));

                result.startup_logo_summary =
                    callbacks.V54StartupLogoSummary();
                callbacks.Append(
                    "V54 STARTUPLOGO SUMMARY: " +
                    result.startup_logo_summary);

                result.startup_resource_group_summary =
                    callbacks.V55StartupResourceGroupSummary();
                callbacks.Append(
                    "V55 STARTUP GROUP SUMMARY: " +
                    result.startup_resource_group_summary);

                result.ok = true;
                result.message =
                    "PvZ2 completed stable v52 lifecycle/host-GLES, passive v53 GameState tracing, passive v54 StartupLogo gate tracing, and passive v55 Gate-A resource-group vector/lookup/progress tracing; nothing was forced (600-frame safety ceiling, adaptive stop preserved).";
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
