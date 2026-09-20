#include "inspector_core.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

constexpr std::uint32_t kGuestBase = 0x10000000u;
constexpr std::uint32_t kStackBase = 0x20000000u;
constexpr std::uint32_t kStackSize = 0x00100000u;
constexpr std::uint32_t kHeapBase = 0x30000000u;
constexpr std::uint32_t kHeapSize = 0x04000000u;
constexpr std::uint32_t kTrampBase = 0x40000000u;
constexpr std::uint32_t kTrampSize = 0x00100000u;
constexpr std::uint32_t kJniBase = 0x50000000u;
constexpr std::uint32_t kJniSize = 0x00010000u;
constexpr std::uint32_t kObjectBase = 0x51000000u;
constexpr std::uint32_t kObjectSize = 0x00010000u;

constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kShtDynamic = 6;
constexpr std::uint32_t kShtDynsym = 11;
constexpr std::uint32_t kShtRel = 9;
constexpr std::uint32_t kShtArmExidx = 0x70000001u;
constexpr std::uint32_t kShfWrite = 0x1u;
constexpr std::uint32_t kShfAlloc = 0x2u;
constexpr std::uint32_t kShfExecInstr = 0x4u;

std::uint16_t U16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) |
           (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t U32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::string Hex(std::uint32_t v, int width = 8) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setfill('0') << std::setw(width) << v;
    return s.str();
}

std::string JsonEscape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4)
                        << std::setfill('0') << static_cast<int>(c);
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string CsvEscape(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos) {
        return s;
    }
    std::string out = "\"";
    for (char c : s) {
        if (c == '\"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

struct ZipMember {
    std::uint16_t method = 0;
    std::uint32_t compressed_size = 0;
    std::uint32_t uncompressed_size = 0;
    std::uint32_t local_header_offset = 0;
};

std::vector<std::uint8_t> ExtractZipMember(
    const std::uint8_t* data,
    std::size_t size,
    const std::string& wanted) {

    if (size < 22) {
        throw std::runtime_error("APK is too small to be a ZIP");
    }

    const std::size_t min_pos =
        size > (0xffffu + 22u) ? size - (0xffffu + 22u) : 0;

    std::optional<std::size_t> eocd;
    for (std::size_t p = size - 22;; --p) {
        if (p + 4 <= size && U32(data + p) == 0x06054b50u) {
            eocd = p;
            break;
        }
        if (p == min_pos) break;
    }

    if (!eocd) {
        throw std::runtime_error("ZIP end-of-central-directory not found");
    }

    const std::uint16_t entries = U16(data + *eocd + 10);
    const std::uint32_t central_size = U32(data + *eocd + 12);
    const std::uint32_t central_offset = U32(data + *eocd + 16);

    if (static_cast<std::uint64_t>(central_offset) + central_size > size) {
        throw std::runtime_error("ZIP central directory is outside APK");
    }

    std::size_t pos = central_offset;
    std::optional<ZipMember> member;

    for (std::uint32_t i = 0; i < entries && pos + 46 <= size; ++i) {
        if (U32(data + pos) != 0x02014b50u) {
            throw std::runtime_error("Invalid ZIP central-directory entry");
        }

        const std::uint16_t method = U16(data + pos + 10);
        const std::uint32_t compressed = U32(data + pos + 20);
        const std::uint32_t uncompressed = U32(data + pos + 24);
        const std::uint16_t name_len = U16(data + pos + 28);
        const std::uint16_t extra_len = U16(data + pos + 30);
        const std::uint16_t comment_len = U16(data + pos + 32);
        const std::uint32_t local_offset = U32(data + pos + 42);

        if (pos + 46u + name_len + extra_len + comment_len > size) {
            throw std::runtime_error("Truncated ZIP central-directory entry");
        }

        const std::string name(
            reinterpret_cast<const char*>(data + pos + 46),
            name_len);

        if (name == wanted) {
            member = ZipMember{method, compressed, uncompressed, local_offset};
            break;
        }

        pos += 46u + name_len + extra_len + comment_len;
    }

    if (!member) {
        throw std::runtime_error(
            "lib/armeabi-v7a/libPVZ2.so was not found in this APK");
    }

    const std::size_t local = member->local_header_offset;
    if (local + 30 > size || U32(data + local) != 0x04034b50u) {
        throw std::runtime_error("Invalid ZIP local header for libPVZ2.so");
    }

    const std::uint16_t name_len = U16(data + local + 26);
    const std::uint16_t extra_len = U16(data + local + 28);
    const std::size_t payload = local + 30u + name_len + extra_len;

    if (payload + member->compressed_size > size) {
        throw std::runtime_error("Compressed libPVZ2.so extends past APK");
    }

    if (member->method == 0) {
        return std::vector<std::uint8_t>(
            data + payload,
            data + payload + member->compressed_size);
    }

    if (member->method != 8) {
        throw std::runtime_error(
            "Unsupported ZIP compression method for libPVZ2.so: " +
            std::to_string(member->method));
    }

    std::vector<std::uint8_t> out(member->uncompressed_size);
    z_stream zs{};
    zs.next_in = const_cast<Bytef*>(
        reinterpret_cast<const Bytef*>(data + payload));
    zs.avail_in = member->compressed_size;
    zs.next_out = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());

    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
        throw std::runtime_error("zlib inflateInit2 failed");
    }

    const int rc = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);

    if (rc != Z_STREAM_END || zs.total_out != member->uncompressed_size) {
        throw std::runtime_error("Failed to inflate libPVZ2.so from APK");
    }

    return out;
}

struct ProgramHeader {
    std::uint32_t type = 0;
    std::uint32_t offset = 0;
    std::uint32_t vaddr = 0;
    std::uint32_t paddr = 0;
    std::uint32_t filesz = 0;
    std::uint32_t memsz = 0;
    std::uint32_t flags = 0;
    std::uint32_t align = 0;
};

struct Section {
    std::uint32_t name_offset = 0;
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint32_t addr = 0;
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint32_t align = 0;
    std::uint32_t entsize = 0;
    std::string name;
};

struct Symbol {
    std::string name;
    std::uint32_t value = 0;
    std::uint32_t size = 0;
    std::uint8_t info = 0;
    std::uint16_t shndx = 0;
};

class Elf32Arm {
public:
    explicit Elf32Arm(std::vector<std::uint8_t> bytes)
        : data_(std::move(bytes)) {
        Parse();
    }

    const std::vector<std::uint8_t>& data() const { return data_; }
    const std::vector<ProgramHeader>& phdrs() const { return phdrs_; }
    const std::vector<Section>& sections() const { return sections_; }
    const std::vector<Symbol>& symbols() const { return symbols_; }
    const std::vector<std::uint32_t>& function_starts() const {
        return function_starts_;
    }
    const std::vector<std::string>& needed_libraries() const {
        return needed_libraries_;
    }
    const std::string& soname() const { return soname_; }
    const std::map<std::uint32_t, std::uint32_t>& relocation_types() const {
        return relocation_types_;
    }
    std::uint32_t relocation_count() const { return relocation_count_; }
    std::uint32_t image_end() const { return image_end_; }

    const Section* SectionAt(std::uint32_t vaddr) const {
        const Section* best = nullptr;
        for (const auto& s : sections_) {
            if (s.size == 0u) continue;
            const std::uint64_t begin = s.addr;
            const std::uint64_t end =
                static_cast<std::uint64_t>(s.addr) + s.size;
            if (vaddr >= begin && vaddr < end) {
                if (best == nullptr ||
                    ((s.flags & kShfAlloc) != 0u &&
                     (best->flags & kShfAlloc) == 0u)) {
                    best = &s;
                }
            }
        }
        return best;
    }

    bool IsExecutable(std::uint32_t vaddr) const {
        const Section* s = SectionAt(vaddr);
        return s != nullptr && (s->flags & kShfExecInstr) != 0u;
    }

    std::string SectionName(std::uint32_t vaddr) const {
        const Section* s = SectionAt(vaddr);
        if (s == nullptr) return "(segment-only)";
        return s->name.empty() ? "(unnamed)" : s->name;
    }

    std::vector<std::string> undefined_symbols() const {
        std::vector<std::string> out;
        for (const auto& s : symbols_) {
            if (s.shndx == 0 && !s.name.empty()) out.push_back(s.name);
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

    std::optional<std::size_t> VaddrToFile(std::uint32_t vaddr) const {
        for (const auto& p : phdrs_) {
            if (p.type == kPtLoad &&
                vaddr >= p.vaddr &&
                vaddr < p.vaddr + p.filesz) {
                return static_cast<std::size_t>(p.offset + (vaddr - p.vaddr));
            }
        }
        return std::nullopt;
    }

    std::vector<std::uint8_t> Read(
        std::uint32_t vaddr,
        std::size_t count) const {

        const auto off = VaddrToFile(vaddr);
        if (!off || *off + count > data_.size()) return {};
        return std::vector<std::uint8_t>(
            data_.begin() + static_cast<std::ptrdiff_t>(*off),
            data_.begin() + static_cast<std::ptrdiff_t>(*off + count));
    }

    std::pair<std::optional<std::uint32_t>,
              std::optional<std::uint32_t>>
    FunctionRange(std::uint32_t off) const {
        if (!IsExecutable(off)) {
            return {std::nullopt, std::nullopt};
        }

        auto it = std::upper_bound(
            function_starts_.begin(),
            function_starts_.end(),
            off);

        if (it == function_starts_.begin()) {
            return {std::nullopt, std::nullopt};
        }

        --it;
        const std::uint32_t start = *it;
        ++it;
        if (it == function_starts_.end()) {
            return {start, std::nullopt};
        }
        return {start, *it};
    }

    std::optional<std::pair<Symbol, std::uint32_t>>
    NearestSymbol(std::uint32_t off) const {
        std::optional<std::pair<Symbol, std::uint32_t>> best;
        for (const auto& s : symbols_) {
            if (s.shndx == 0) continue;
            const std::uint32_t value = s.value & ~1u;
            if (value > off) continue;
            const std::uint32_t delta = off - value;
            const bool contains = s.size != 0 && delta < s.size;
            if (!best ||
                contains ||
                delta < best->second) {
                best = std::make_pair(s, delta);
                if (contains && delta == 0) break;
            }
        }
        if (best && best->second <= 0x10000u) return best;
        return std::nullopt;
    }

private:
    std::vector<std::uint8_t> data_;
    std::vector<ProgramHeader> phdrs_;
    std::vector<Section> sections_;
    std::vector<Symbol> symbols_;
    std::vector<std::uint32_t> function_starts_;
    std::vector<std::string> needed_libraries_;
    std::string soname_;
    std::map<std::uint32_t, std::uint32_t> relocation_types_;
    std::uint32_t relocation_count_ = 0;
    std::uint32_t image_end_ = 0;

    std::string CString(std::size_t off) const {
        if (off >= data_.size()) return {};
        std::size_t end = off;
        while (end < data_.size() && data_[end] != 0) ++end;
        return std::string(
            reinterpret_cast<const char*>(data_.data() + off),
            end - off);
    }

    std::string StringFromSection(
        const Section& strings,
        std::uint32_t off) const {

        if (off >= strings.size) return {};
        return CString(static_cast<std::size_t>(strings.offset) + off);
    }

    void Parse() {
        if (data_.size() < 52 ||
            std::memcmp(data_.data(), "\x7f" "ELF", 4) != 0 ||
            data_[4] != 1 ||
            data_[5] != 1) {
            throw std::runtime_error(
                "Expected ELF32 little-endian libPVZ2.so");
        }

        const std::uint16_t e_type = U16(data_.data() + 16);
        const std::uint16_t e_machine = U16(data_.data() + 18);
        const std::uint32_t e_phoff = U32(data_.data() + 28);
        const std::uint32_t e_shoff = U32(data_.data() + 32);
        const std::uint16_t e_phentsize = U16(data_.data() + 42);
        const std::uint16_t e_phnum = U16(data_.data() + 44);
        const std::uint16_t e_shentsize = U16(data_.data() + 46);
        const std::uint16_t e_shnum = U16(data_.data() + 48);
        const std::uint16_t e_shstrndx = U16(data_.data() + 50);

        if (e_type != 3 || e_machine != 40 ||
            e_phentsize != 32 || e_shentsize != 40) {
            throw std::runtime_error(
                "ELF is not the expected ARM32 shared object");
        }

        if (static_cast<std::uint64_t>(e_phoff) +
                static_cast<std::uint64_t>(e_phnum) * e_phentsize >
            data_.size()) {
            throw std::runtime_error("Truncated ELF program-header table");
        }

        for (std::uint32_t i = 0; i < e_phnum; ++i) {
            const std::size_t p = e_phoff + i * e_phentsize;
            ProgramHeader h;
            h.type = U32(data_.data() + p + 0);
            h.offset = U32(data_.data() + p + 4);
            h.vaddr = U32(data_.data() + p + 8);
            h.paddr = U32(data_.data() + p + 12);
            h.filesz = U32(data_.data() + p + 16);
            h.memsz = U32(data_.data() + p + 20);
            h.flags = U32(data_.data() + p + 24);
            h.align = U32(data_.data() + p + 28);
            phdrs_.push_back(h);

            if (h.type == kPtLoad) {
                image_end_ = std::max(image_end_, h.vaddr + h.memsz);
            }
        }

        if (static_cast<std::uint64_t>(e_shoff) +
                static_cast<std::uint64_t>(e_shnum) * e_shentsize >
            data_.size()) {
            throw std::runtime_error("Truncated ELF section-header table");
        }

        for (std::uint32_t i = 0; i < e_shnum; ++i) {
            const std::size_t p = e_shoff + i * e_shentsize;
            Section h;
            h.name_offset = U32(data_.data() + p + 0);
            h.type = U32(data_.data() + p + 4);
            h.flags = U32(data_.data() + p + 8);
            h.addr = U32(data_.data() + p + 12);
            h.offset = U32(data_.data() + p + 16);
            h.size = U32(data_.data() + p + 20);
            h.link = U32(data_.data() + p + 24);
            h.info = U32(data_.data() + p + 28);
            h.align = U32(data_.data() + p + 32);
            h.entsize = U32(data_.data() + p + 36);
            sections_.push_back(h);
        }

        if (e_shstrndx < sections_.size()) {
            const auto& names = sections_[e_shstrndx];
            for (auto& s : sections_) {
                s.name = StringFromSection(names, s.name_offset);
            }
        }

        for (const auto& sh : sections_) {
            if (static_cast<std::uint64_t>(sh.offset) + sh.size >
                data_.size()) {
                continue;
            }

            if (sh.type == kShtDynsym && sh.link < sections_.size()) {
                const auto& strings = sections_[sh.link];
                const std::uint32_t entsize = sh.entsize ? sh.entsize : 16;
                for (std::uint32_t rel = 0;
                     rel + 16 <= sh.size;
                     rel += entsize) {

                    const std::size_t p = sh.offset + rel;
                    Symbol sym;
                    const std::uint32_t name_off = U32(data_.data() + p);
                    sym.value = U32(data_.data() + p + 4);
                    sym.size = U32(data_.data() + p + 8);
                    sym.info = data_[p + 12];
                    sym.shndx = U16(data_.data() + p + 14);
                    sym.name = StringFromSection(strings, name_off);
                    if (!sym.name.empty()) symbols_.push_back(std::move(sym));
                }
            }

            if (sh.type == kShtArmExidx) {
                std::set<std::uint32_t> starts(
                    function_starts_.begin(),
                    function_starts_.end());

                for (std::uint32_t rel = 0; rel + 8 <= sh.size; rel += 8) {
                    const std::uint32_t word =
                        U32(data_.data() + sh.offset + rel);
                    const std::uint32_t place = sh.addr + rel;
                    std::int64_t delta = word & 0x7fffffffu;
                    if (delta & 0x40000000u) delta -= 0x80000000ll;
                    const std::uint32_t target =
                        static_cast<std::uint32_t>(place + delta) & ~1u;
                    if (target > 0 &&
                        target < image_end_ &&
                        IsExecutable(target)) {
                        starts.insert(target);
                    }
                }

                function_starts_.assign(starts.begin(), starts.end());
            }

            if (sh.type == kShtRel) {
                const std::uint32_t entsize = sh.entsize ? sh.entsize : 8;
                for (std::uint32_t rel = 0;
                     rel + 8 <= sh.size;
                     rel += entsize) {
                    const std::uint32_t info =
                        U32(data_.data() + sh.offset + rel + 4);
                    const std::uint32_t type = info & 0xffu;
                    ++relocation_count_;
                    ++relocation_types_[type];
                }
            }

            if (sh.type == kShtDynamic && sh.link < sections_.size()) {
                const auto& strings = sections_[sh.link];
                const std::uint32_t entsize = sh.entsize ? sh.entsize : 8;

                for (std::uint32_t rel = 0;
                     rel + 8 <= sh.size;
                     rel += entsize) {

                    const std::uint32_t tag =
                        U32(data_.data() + sh.offset + rel);
                    const std::uint32_t val =
                        U32(data_.data() + sh.offset + rel + 4);

                    if (tag == 0) break;
                    if (tag == 1) {
                        needed_libraries_.push_back(
                            StringFromSection(strings, val));
                    } else if (tag == 14) {
                        soname_ = StringFromSection(strings, val);
                    }
                }
            }
        }

        std::sort(function_starts_.begin(), function_starts_.end());
        function_starts_.erase(
            std::unique(function_starts_.begin(), function_starts_.end()),
            function_starts_.end());
    }
};

const std::map<std::uint32_t, std::string>& KnownLabels() {
    static const std::map<std::uint32_t, std::string> labels = {
        {0x00133818u, "GameStateMgr factory (allocates 0x460 bytes)"},
        {0x001492bcu, "GameStateMgr constructor"},
        {0x002732c8u, "GameStateMgr current-state comparison helper"},
        {0x002747d0u, "GameStateMgrState.ApplyState"},
        {0x00274a1cu, "GameStateMgr current-state getter (+0x374)"},
        {0x00274ab8u, "GameStateMgr transition-state getter (+0x3c4)"},
        {0x00274b44u, "GameStateMgrState.RequestTransition"},
        {0x00275478u, "GameStateMgr pending/current transition update"},
        {0x002767b4u, "GameState.MainMenu.Enter(resources)"},
        {0x00276970u, "GameState.StartupLogo.Update"},
        {0x002769d4u, "StartupLogo.GateA result VMOV"},
        {0x002769e0u, "StartupLogo.GateA BLT return"},
        {0x00276a00u, "StartupLogo.GateB BNE return"},
        {0x00276a2cu, "StartupLogo.GateC BNE return"},
        {0x00276a30u, "StartupLogo.GateD counter +0x430 load"},
        {0x00276a38u, "StartupLogo.GateD BLT return"},
        {0x00276a3cu, "StartupLogo.after-A-D marker"},
        {0x00276a60u, "StartupLogo.GateE app +0xb7a load"},
        {0x00276adcu, "StartupLogo.PatchScreen request-path marker"},
        {0x00276b20u, "StartupLogo.main-flow marker"},
        {0x00276d70u, "StartupLogo.MainMenu request-path marker"},
        {0x002b88ecu, "StartupLogo.GateG helper result"},
        {0x002b8b88u, "StartupLogo.GateH helper result"},
        {0x002c84d0u, "StartupLogo.GateA resource load"},
        {0x002c8620u, "StartupLogo.GateA completed/total counters"},
        {0x002ef188u, "StartupLogo.progress helper result"},
        {0x0036bbfcu, "StartupLogo.GateF helper result"},
        {0x0037d158u, "StartupLogo.GateJ object marker"},
        {0x00423adcu, "StartupLogo.find helper result"},
        {0x004855b0u, "StartupLogo.GateI helper result"},
        {0x004ac370u, "StartupLogo.late helper result"},
        {0x005143a4u, "StartupLogo.GateC state +0x98 load"},
        {0x005149c4u, "ImageRes.splash-null virtual-call site observed in v36"},
        {0x005149c8u, "ImageRes.splash-null virtual-call return observed in v36"},
        {0x0086f66cu, "ResourceRegistryLookup.function_start"},
        {0x0086f674u, "ResourceRegistryLookup.entry MOV r4,r2"},
        {0x0086f8a0u, "ResourceRegistryLookup.group return boundary"},
        {0x0086fa78u, "ResourceRegistryLookup.global miss return"},
        {0x0086fa84u, "ResourceRegistryLookup.global found-value load"},
        {0x0087a704u, "GenericResFileRes.lookup callsite A"},
        {0x0087a708u, "GenericResFileRes.direct-group return branch / v48 null recovery"},
        {0x0087a758u, "GenericResFileRes.lookup callsite B"},
        {0x0087a76cu, "GenericResFileRes.all-groups exhausted null / v48 final recovery"},
        {0x009ead80u, "JNI_OnLoad"},
        {0x009ebf80u, "Native_applicationWillFinishLaunching"},
        {0x009ec0a0u, "Native_applicationDidFinishLaunching"},
        {0x009ec0bcu, "Native_applicationWillBecomeForeground"},
        {0x009ec0c8u, "Native_applicationDidBecomeActive"},
        {0x009f1840u, "Native_onSurfaceCreated"},
        {0x009f18dcu, "Native_onSurfaceChanged"},
        {0x009f190cu, "Native_onDrawFrame"},
    };
    return labels;
}

struct GameStateProfileValidation {
    bool request_hook_opcode = false;
    bool apply_hook_opcode = false;
    bool constructor_present = false;
    bool factory_present = false;
    bool main_menu_enter_present = false;
    bool logo_update_present = false;

    bool exact_profile() const {
        return
            request_hook_opcode &&
            apply_hook_opcode &&
            constructor_present &&
            factory_present &&
            main_menu_enter_present &&
            logo_update_present;
    }
};

bool HasCodeAt(
    const Elf32Arm& elf,
    std::uint32_t offset,
    std::size_t bytes = 4u) {

    const auto data =
        elf.Read(offset, bytes);

    return data.size() == bytes;
}

bool HasWordAt(
    const Elf32Arm& elf,
    std::uint32_t offset,
    std::uint32_t expected) {

    const auto data =
        elf.Read(offset, 4u);

    return
        data.size() == 4u &&
        U32(data.data()) == expected;
}

GameStateProfileValidation ValidateGameStateProfile(
    const Elf32Arm& elf) {

    GameStateProfileValidation v;

    // These are the exact ARM instructions replaced by the v53 runtime
    // observation traps. Both are MOV r4,r0 and the trap emulates that MOV.
    v.apply_hook_opcode =
        HasWordAt(
            elf,
            0x002747d8u,
            0xe1a04000u);
    v.request_hook_opcode =
        HasWordAt(
            elf,
            0x00274b4cu,
            0xe1a04000u);

    v.constructor_present =
        HasCodeAt(
            elf,
            0x001492bcu);
    v.factory_present =
        HasCodeAt(
            elf,
            0x00133818u);
    v.main_menu_enter_present =
        HasCodeAt(
            elf,
            0x002767b4u);
    v.logo_update_present =
        HasCodeAt(
            elf,
            0x00276970u);

    return v;
}

struct StartupLogoProfileCheck {
    const char* name = "";
    std::uint32_t offset = 0u;
    std::uint32_t expected = 0u;
    bool match = false;
};

struct StartupLogoProfileValidation {
    std::vector<StartupLogoProfileCheck> checks;

    bool exact_profile() const {
        return
            !checks.empty() &&
            std::all_of(
                checks.begin(),
                checks.end(),
                [](const auto& c) { return c.match; });
    }

    std::size_t matched() const {
        return static_cast<std::size_t>(
            std::count_if(
                checks.begin(),
                checks.end(),
                [](const auto& c) { return c.match; }));
    }
};

StartupLogoProfileValidation ValidateStartupLogoProfile(
    const Elf32Arm& elf) {

    StartupLogoProfileValidation v;

    const std::array<std::tuple<const char*, std::uint32_t, std::uint32_t>, 22>
    expected = {{
        {"GateA.resource LDR",          0x002c84d0u, 0xe595064cu},
        {"GateA.totals VMOV",           0x002c8620u, 0xee00ba10u},
        {"GateA.result VMOV",           0x002769d4u, 0xee010a10u},
        {"GateA.result VCMPE",          0x002769d8u, 0xeeb41ac0u},
        {"GateA.result VMRS",           0x002769dcu, 0xeef1fa10u},
        {"GateA BLT return",            0x002769e0u, 0xba0000efu},
        {"GateB BNE return",            0x00276a00u, 0x1a0000e7u},
        {"GateC.state LDR",             0x005143a4u, 0xe5901098u},
        {"GateC BNE return",            0x00276a2cu, 0x1a0000dcu},
        {"GateD.counter LDR",           0x00276a30u, 0xe5940430u},
        {"GateD BLT return",            0x00276a38u, 0xba0000d9u},
        {"after-A-D marker",            0x00276a3cu, 0xe59f03c8u},
        {"GateE app byte",              0x00276a60u, 0xe5d00b7au},
        {"GateF result",                0x0036bbfcu, 0xe1a00004u},
        {"GateG result",                0x002b88ecu, 0xe1a00004u},
        {"GateH result",                0x002b8b88u, 0xe1a00004u},
        {"GateI result",                0x004855b0u, 0xe1a00005u},
        {"GateJ object",                0x0037d158u, 0xe1a01000u},
        {"Patch request marker",        0x00276adcu, 0xe1a00004u},
        {"Main flow marker",            0x00276b20u, 0xe1a05000u},
        {"Progress helper result",      0x002ef188u, 0xe1a00004u},
        {"MainMenu request marker",     0x00276d70u, 0xe1a00004u},
    }};

    for (const auto& [name, offset, opcode] : expected) {
        v.checks.push_back(
            StartupLogoProfileCheck{
                name,
                offset,
                opcode,
                HasWordAt(elf, offset, opcode)});
    }

    v.checks.push_back(
        {"Find helper result", 0x00423adcu, 0xe1a00004u,
         HasWordAt(elf, 0x00423adcu, 0xe1a00004u)});
    v.checks.push_back(
        {"Late helper result", 0x004ac370u, 0xe1a00004u,
         HasWordAt(elf, 0x004ac370u, 0xe1a00004u)});

    return v;
}

std::string GameStateName(std::int32_t state) {
    switch (state) {
        case -1: return "NONE";
        case 1: return "GAME_Initializing";
        case 2: return "GAME_LogoScreen";
        case 3: return "GAME_PatchScreen";
        case 4: return "GAME_MainMenu";
        case 5: return "GAME_Game";
        case 6: return "GAME_WorldMap";
        case 7: return "GAME_ContentUpdateScreen";
        case 8: return "GAME_Almanac";
        case 9: return "GAME_Store";
        case 10: return "GAME_WaitForNetworkLoad";
        default:
            return "UNKNOWN_" +
                std::to_string(state);
    }
}

struct Classified {
    std::string region;
    std::optional<std::uint32_t> offset;
    std::string section;
    bool executable = false;
};

Classified Classify(std::uint32_t address, const Elf32Arm& elf) {
    const std::uint32_t plain = address & ~1u;

    if (plain >= kGuestBase &&
        plain < kGuestBase + elf.image_end()) {
        const std::uint32_t off = plain - kGuestBase;
        return {
            "libPVZ2.so",
            off,
            elf.SectionName(off),
            elf.IsExecutable(off)};
    }

    const std::array<std::tuple<const char*, std::uint32_t, std::uint32_t>, 5>
    regions = {{
        {"guest-stack", kStackBase, kStackSize},
        {"guest-heap", kHeapBase, kHeapSize},
        {"host-trampoline", kTrampBase, kTrampSize},
        {"synthetic-JNI", kJniBase, kJniSize},
        {"synthetic-object", kObjectBase, kObjectSize},
    }};

    for (const auto& [name, base, size] : regions) {
        if (plain >= base && plain < base + size) {
            return {name, plain - base, "", false};
        }
    }

    if (address == 0) return {"null", 0u, "", false};
    return {"other", std::nullopt, "", false};
}

std::string Resolve(std::uint32_t address, const Elf32Arm& elf) {
    const auto c = Classify(address, elf);

    if (c.region != "libPVZ2.so") {
        if (c.offset) {
            return Hex(address) + " [" + c.region + "+" +
                   Hex(*c.offset, 1) + "]";
        }
        return Hex(address) + " [" + c.region + "]";
    }

    const std::uint32_t off = *c.offset;
    std::ostringstream out;
    out << Hex(address)
        << " [libPVZ2.so+" << Hex(off)
        << " section=" << c.section
        << " " << (c.executable ? "CODE" : "DATA");

    if (c.executable) {
        out << " " << ((address & 1u) ? "Thumb" : "ARM");
    }
    out << "]";

    const auto label = KnownLabels().find(off);
    if (label != KnownLabels().end()) {
        out << " known=" << label->second;
    }

    if (c.executable) {
        const auto [start, end] = elf.FunctionRange(off);
        if (start) {
            out << " fn=+" << Hex(*start)
                << "+" << Hex(off - *start, 1);
            if (end) {
                out << "/size=" << Hex(*end - *start, 1);
            }
        }

        const auto sym = elf.NearestSymbol(off);
        if (sym) {
            out << " symbol=" << sym->first.name
                << "+" << Hex(sym->second, 1);
        }
    }

    return out.str();
}

std::int32_t SignExtend(std::uint32_t value, int bits) {
    const std::uint32_t sign = 1u << (bits - 1);
    return static_cast<std::int32_t>((value ^ sign) - sign);
}

std::string Reg(unsigned n) {
    if (n == 13) return "sp";
    if (n == 14) return "lr";
    if (n == 15) return "pc";
    return "r" + std::to_string(n);
}

std::string DecodeArm(std::uint32_t word, std::uint32_t runtime) {
    const unsigned cond = (word >> 28) & 0xf;
    static const char* kCond[] = {
        "eq","ne","cs","cc","mi","pl","vs","vc",
        "hi","ls","ge","lt","gt","le","","nv"
    };
    const std::string suffix = kCond[cond];

    if ((word & 0x0f000000u) == 0x0f000000u) {
        return "svc" + suffix + " #" + Hex(word & 0x00ffffffu, 1);
    }

    if ((word & 0x0ffffff0u) == 0x012fff10u) {
        return "bx" + suffix + " " + Reg(word & 0xfu);
    }

    if ((word & 0x0ffffff0u) == 0x012fff30u) {
        return "blx" + suffix + " " + Reg(word & 0xfu);
    }

    if ((word & 0x0e000000u) == 0x0a000000u) {
        const std::int32_t delta =
            SignExtend(word & 0x00ffffffu, 24) << 2;
        const std::uint32_t target =
            static_cast<std::uint32_t>(runtime + 8 + delta);
        return std::string((word & 0x01000000u) ? "bl" : "b") +
               suffix + " " + Hex(target);
    }

    if ((word & 0x0c000000u) == 0x04000000u &&
        !(word & (1u << 25))) {
        const bool load = (word & (1u << 20)) != 0;
        const bool up = (word & (1u << 23)) != 0;
        const bool pre = (word & (1u << 24)) != 0;
        const unsigned rn = (word >> 16) & 0xf;
        const unsigned rd = (word >> 12) & 0xf;
        const unsigned imm = word & 0xfff;
        std::ostringstream o;
        o << (load ? "ldr" : "str") << suffix << " "
          << Reg(rd) << ",[" << Reg(rn);
        if (pre) {
            o << ",#" << (up ? "+" : "-") << Hex(imm, 1) << "]";
        } else {
            o << "],#" << (up ? "+" : "-") << Hex(imm, 1);
        }
        return o.str();
    }

    if ((word & 0x0fe00000u) == 0x01a00000u) {
        return "mov" + suffix + " " +
               Reg((word >> 12) & 0xfu) + "," +
               Reg(word & 0xfu);
    }

    return {};
}

std::string DecodeThumb16(std::uint16_t h, std::uint32_t runtime) {
    if ((h & 0xff87u) == 0x4700u) {
        return std::string((h & 0x0080u) ? "blx " : "bx ") +
               Reg((h >> 3) & 0xfu);
    }

    if ((h & 0xf800u) == 0xe000u) {
        const std::int32_t delta =
            SignExtend(h & 0x07ffu, 11) << 1;
        return "b " + Hex(static_cast<std::uint32_t>(runtime + 4 + delta));
    }

    if ((h & 0xf000u) == 0xd000u &&
        ((h >> 8) & 0xfu) != 0xfu) {
        static const char* kCond[] = {
            "eq","ne","cs","cc","mi","pl","vs","vc",
            "hi","ls","ge","lt","gt","le"
        };
        const unsigned cond = (h >> 8) & 0xfu;
        const std::int32_t delta =
            SignExtend(h & 0x00ffu, 8) << 1;
        return std::string("b") + kCond[cond] + " " +
               Hex(static_cast<std::uint32_t>(runtime + 4 + delta));
    }

    if ((h & 0xf800u) == 0x4800u) {
        const unsigned rd = (h >> 8) & 7u;
        const unsigned imm = (h & 0xffu) << 2;
        return "ldr " + Reg(rd) + ",[pc,#" + Hex(imm, 1) + "]";
    }

    if ((h & 0xfe00u) == 0xb400u) return "push {...}";
    if ((h & 0xfe00u) == 0xbc00u) return "pop {...}";

    return {};
}

std::vector<std::string> Disassemble(
    const Elf32Arm& elf,
    std::uint32_t runtime_address,
    int before = 3,
    int after = 5) {

    const auto c = Classify(runtime_address, elf);
    if (c.region != "libPVZ2.so" ||
        !c.offset ||
        !c.executable) {
        return {};
    }

    const bool thumb = (runtime_address & 1u) != 0;
    const std::uint32_t center = *c.offset;
    const std::uint32_t width = thumb ? 2u : 4u;
    const std::uint32_t start =
        center >= static_cast<std::uint32_t>(before) * width
            ? center - static_cast<std::uint32_t>(before) * width
            : 0u;

    const auto blob = elf.Read(
        start,
        static_cast<std::size_t>(before + after + 1) * width);

    std::vector<std::string> out;
    for (std::size_t i = 0; i + width <= blob.size(); i += width) {
        const std::uint32_t off = start + static_cast<std::uint32_t>(i);
        const std::uint32_t runtime = kGuestBase + off;
        const bool hit = off == center;

        std::ostringstream line;
        line << (hit ? "=> " : "   ") << Hex(runtime) << ": ";

        if (thumb) {
            const std::uint16_t h = U16(blob.data() + i);
            line << Hex(h, 4);
            const std::string decoded = DecodeThumb16(h, runtime);
            if (!decoded.empty()) line << "  " << decoded;
        } else {
            const std::uint32_t w = U32(blob.data() + i);
            line << Hex(w);
            const std::string decoded = DecodeArm(w, runtime);
            if (!decoded.empty()) line << "  " << decoded;
        }

        out.push_back(line.str());
    }

    return out;
}

std::string RelocName(std::uint32_t type) {
    switch (type) {
        case 2: return "R_ARM_ABS32";
        case 21: return "R_ARM_GLOB_DAT";
        case 22: return "R_ARM_JUMP_SLOT";
        case 23: return "R_ARM_RELATIVE";
        default: return "R_ARM_" + std::to_string(type);
    }
}

bool IsHex(char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

std::unordered_map<std::uint32_t, std::uint32_t>
CollectHexAddresses(const std::string& text, std::uint32_t& occurrences) {
    std::unordered_map<std::uint32_t, std::uint32_t> counts;
    occurrences = 0;

    for (std::size_t i = 0; i + 9 <= text.size(); ++i) {
        if (text[i] != '0' ||
            (text[i + 1] != 'x' && text[i + 1] != 'X')) {
            continue;
        }

        std::size_t j = i + 2;
        std::size_t digits = 0;
        while (j < text.size() && IsHex(text[j]) && digits < 8) {
            ++j;
            ++digits;
        }

        if (digits < 7) continue;
        if (j < text.size() && IsHex(text[j])) continue;

        const std::string raw = text.substr(i + 2, digits);
        const auto value =
            static_cast<std::uint32_t>(std::stoul(raw, nullptr, 16));
        ++counts[value];
        ++occurrences;
        i = j - 1;
    }

    return counts;
}

std::map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>>
CollectControlAddresses(const std::string& text) {
    const std::array<std::string, 5> keys = {
        "PC", "LR", "returnPC", "callerLR", "SP"
    };

    std::map<std::string, std::unordered_map<std::uint32_t, std::uint32_t>>
        out;

    for (const auto& key : keys) {
        const std::string needle = key + "=0x";
        std::size_t pos = 0;

        while ((pos = text.find(needle, pos)) != std::string::npos) {
            const std::size_t start = pos + needle.size();
            std::size_t end = start;
            while (end < text.size() &&
                   IsHex(text[end]) &&
                   end - start < 8) {
                ++end;
            }

            if (end - start >= 7) {
                const auto value = static_cast<std::uint32_t>(
                    std::stoul(text.substr(start, end - start), nullptr, 16));
                ++out[key][value];
            }
            pos = end;
        }
    }

    return out;
}

template <class Map>
std::vector<std::pair<std::uint32_t, std::uint32_t>>
SortedCounts(const Map& counts) {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> v;
    v.reserve(counts.size());
    for (const auto& [address, count] : counts) {
        v.emplace_back(address, count);
    }
    std::sort(
        v.begin(),
        v.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });
    return v;
}

std::string AnnotateLog(
    const std::string& log,
    const Elf32Arm& elf) {

    if (log.empty()) return {};

    std::ostringstream out;
    std::istringstream input(log);
    std::string line;
    const std::array<std::string, 4> keys = {
        "PC=0x", "LR=0x", "returnPC=0x", "callerLR=0x"
    };

    while (std::getline(input, line)) {
        out << line << "\n";
        std::set<std::uint32_t> emitted;

        for (const auto& key : keys) {
            std::size_t pos = 0;
            while ((pos = line.find(key, pos)) != std::string::npos) {
                const std::size_t start = pos + key.size();
                std::size_t end = start;
                while (end < line.size() &&
                       IsHex(line[end]) &&
                       end - start < 8) {
                    ++end;
                }

                if (end - start >= 7) {
                    const auto value = static_cast<std::uint32_t>(
                        std::stoul(
                            line.substr(start, end - start),
                            nullptr,
                            16));
                    if (emitted.insert(value).second) {
                        out << "    [Inspector] "
                            << Resolve(value, elf)
                            << "\n";
                    }
                }
                pos = end;
            }
        }
    }

    return out.str();
}


std::size_t CountOccurrences(
    const std::string& text,
    const std::string& needle) {

    if (needle.empty()) return 0u;
    std::size_t count = 0u;
    std::size_t pos = 0u;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

std::string LastLineContaining(
    const std::string& text,
    const std::string& needle) {

    const std::size_t pos = text.rfind(needle);
    if (pos == std::string::npos) return {};

    std::size_t begin = text.rfind('\n', pos);
    begin = begin == std::string::npos ? 0u : begin + 1u;

    std::size_t end = text.find('\n', pos);
    if (end == std::string::npos) end = text.size();

    return text.substr(begin, end - begin);
}

std::optional<std::uint64_t> ParseUnsignedAfter(
    const std::string& line,
    const std::string& marker,
    int base = 10) {

    const std::size_t pos = line.find(marker);
    if (pos == std::string::npos) return std::nullopt;

    const std::size_t begin = pos + marker.size();
    std::size_t end = begin;

    while (end < line.size()) {
        const char ch = line[end];
        const bool ok =
            base == 16
                ? std::isxdigit(static_cast<unsigned char>(ch)) != 0
                : std::isdigit(static_cast<unsigned char>(ch)) != 0;
        if (!ok) break;
        ++end;
    }

    if (end == begin) return std::nullopt;

    try {
        return std::stoull(line.substr(begin, end - begin), nullptr, base);
    } catch (...) {
        return std::nullopt;
    }
}

struct StartupLogoRuntimeDiagnosis {
    bool present = false;
    std::uint64_t resource_hits = 0u;
    std::uint64_t totals_hits = 0u;
    std::uint64_t result_hits = 0u;
    std::uint32_t owner = 0u;
    std::uint32_t resource = 0u;
    std::uint32_t completed = 0u;
    std::uint32_t total = 0u;
    std::uint32_t result_bits = 0u;
    std::uint64_t gate_c_hits = 0u;
    std::uint64_t gate_d_hits = 0u;
    std::uint64_t after_d_hits = 0u;
    std::uint64_t patch_marker_hits = 0u;
    std::uint64_t mainmenu_marker_hits = 0u;
    std::int32_t final_state = -999;
    bool resource_present = false;
    bool qnan_7fc00000 = false;
    bool first_blocker_gate_a = false;
    std::size_t resource_pointer_occurrences = 0u;
    std::string object_correlation_line;
    std::uint32_t object_vtable = 0u;
    std::size_t resource_miss_lines = 0u;
    std::size_t wait_progress_lines = 0u;
    std::size_t http_start_lines = 0u;
    std::string text;
};

StartupLogoRuntimeDiagnosis DiagnoseStartupLogoRuntime(
    const std::string& log,
    const StartupLogoProfileValidation& static_profile,
    const Elf32Arm& elf) {

    StartupLogoRuntimeDiagnosis d;
    if (log.find("V54 STARTUPLOGO") == std::string::npos) {
        return d;
    }

    d.present = true;

    const std::string resource_line =
        LastLineContaining(log, "V54 STARTUPLOGO GateA.resource");
    const std::string totals_line =
        LastLineContaining(log, "V54 STARTUPLOGO GateA.totals");
    const std::string result_line =
        LastLineContaining(log, "V54 STARTUPLOGO GateA.result");
    const std::string summary_line =
        LastLineContaining(log, "V54 STARTUPLOGO SUMMARY:");
    const std::string final_state_line =
        LastLineContaining(log, "V53 GAMESTATE SNAPSHOT phase=final");

    if (const auto v = ParseUnsignedAfter(resource_line, "hit=")) {
        d.resource_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(resource_line, "owner=0x", 16)) {
        d.owner = static_cast<std::uint32_t>(*v);
    }
    if (const auto v = ParseUnsignedAfter(resource_line, "resource=0x", 16)) {
        d.resource = static_cast<std::uint32_t>(*v);
    }
    d.resource_present =
        !resource_line.empty() &&
        resource_line.find(" present") != std::string::npos;

    if (const auto v = ParseUnsignedAfter(totals_line, "hit=")) {
        d.totals_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(totals_line, "completed=")) {
        d.completed = static_cast<std::uint32_t>(*v);
    }
    if (const auto v = ParseUnsignedAfter(totals_line, "total=")) {
        d.total = static_cast<std::uint32_t>(*v);
    }

    if (const auto v = ParseUnsignedAfter(result_line, "hit=")) {
        d.result_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(result_line, "bits=0x", 16)) {
        d.result_bits = static_cast<std::uint32_t>(*v);
    }

    if (const auto v = ParseUnsignedAfter(summary_line, "C{hits=")) {
        d.gate_c_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(summary_line, "D{hits=")) {
        d.gate_d_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(summary_line, "afterD=")) {
        d.after_d_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(summary_line, "patchReqMarker=")) {
        d.patch_marker_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(summary_line, "mainMenuReqMarker=")) {
        d.mainmenu_marker_hits = *v;
    }
    if (const auto v = ParseUnsignedAfter(final_state_line, "current=")) {
        d.final_state = static_cast<std::int32_t>(*v);
    }

    d.qnan_7fc00000 =
        d.completed == 0u &&
        d.total == 0u &&
        d.result_bits == 0x7fc00000u;

    d.first_blocker_gate_a =
        d.result_hits != 0u &&
        d.gate_c_hits == 0u &&
        d.gate_d_hits == 0u &&
        d.after_d_hits == 0u &&
        d.patch_marker_hits == 0u &&
        d.mainmenu_marker_hits == 0u;

    if (d.resource != 0u) {
        const std::string pointer = Hex(d.resource);
        d.resource_pointer_occurrences =
            CountOccurrences(log, pointer);
        d.object_correlation_line =
            LastLineContaining(
                log,
                "V52 OBJECT node=" + pointer);
        if (const auto v =
                ParseUnsignedAfter(
                    d.object_correlation_line,
                    "vtable=0x",
                    16)) {
            d.object_vtable =
                static_cast<std::uint32_t>(*v);
        }
    }

    d.resource_miss_lines =
        CountOccurrences(
            log,
            "ResourceInfoTypes::GenericResFileRes resource not found:");
    d.wait_progress_lines =
        CountOccurrences(
            log,
            "V30 WAIT OBJECT PROGRESS");
    d.http_start_lines =
        CountOccurrences(
            log,
            "V34 HTTP Start:");

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.2 - StartupLogo runtime diagnosis\n"
        << "========================================================\n"
        << "Source evidence: supplied runtime log only.\n"
        << "Static profile: "
        << (static_profile.exact_profile()
                ? "MATCH"
                : "PARTIAL/MISMATCH")
        << " ("
        << static_profile.matched()
        << "/"
        << static_profile.checks.size()
        << " opcode checks)\n\n";

    out
        << "CONFIRMED RUNTIME PATH\n"
        << "----------------------\n"
        << "Final GameState: "
        << d.final_state
        << " ("
        << GameStateName(d.final_state)
        << ")\n"
        << "Gate A resource hits: "
        << d.resource_hits
        << "\n"
        << "Gate A owner: "
        << Hex(d.owner)
        << "\n"
        << "Gate A resource: "
        << Hex(d.resource)
        << (d.resource_present ? " PRESENT" : " NOT CONFIRMED PRESENT")
        << "\n"
        << "Gate A completed/total: "
        << d.completed
        << "/"
        << d.total
        << "\n"
        << "Gate A result bits: "
        << Hex(d.result_bits)
        << (d.qnan_7fc00000 ? " (quiet NaN)" : "")
        << "\n"
        << "Gate C hits: "
        << d.gate_c_hits
        << "\n"
        << "Gate D hits: "
        << d.gate_d_hits
        << "\n"
        << "after-A-D hits: "
        << d.after_d_hits
        << "\n"
        << "PatchScreen request marker hits: "
        << d.patch_marker_hits
        << "\n"
        << "MainMenu request marker hits: "
        << d.mainmenu_marker_hits
        << "\n\n";

    if (d.first_blocker_gate_a) {
        out
            << "FIRST OBSERVED BLOCKER\n"
            << "----------------------\n"
            << "Gate A is the first observed blocking gate. "
            << "No instrumented gate after A was reached.\n";
    } else {
        out
            << "FIRST OBSERVED BLOCKER\n"
            << "----------------------\n"
            << "The supplied log does not prove a unique first blocker.\n";
    }

    if (d.qnan_7fc00000) {
        out
            << "The observed arithmetic is 0/0 -> IEEE-754 qNaN "
            << "(0x7fc00000).\n";
        if (static_profile.exact_profile()) {
            out
                << "The verified 1.5.252752 code then executes "
                << "VCMPE.F32, VMRS APSR_nzcv,FPSCR and BLT at "
                << Hex(kGuestBase + 0x002769e0u)
                << ". An unordered NaN comparison sets ARM flags so this "
                << "BLT return path is taken.\n";
        }
    }

    out
        << "\nOBJECT CORRELATION\n"
        << "------------------\n"
        << "Resource pointer occurrences in the log: "
        << d.resource_pointer_occurrences
        << "\n";
    if (!d.object_correlation_line.empty()) {
        out
            << "The same pointer appears in the runtime object graph.\n"
            << "Object: "
            << Hex(d.resource)
            << "\n";
        if (d.object_vtable != 0u) {
            out
                << "Vtable: "
                << Resolve(d.object_vtable, elf)
                << "\n";
        }
        out
            << "The raw v52 annotation is intentionally not copied here, "
            << "because v1/v1.1 could mislabel data-section vtables as code.\n";
    } else {
        out
            << "No V52 object-graph line was found for that pointer.\n";
    }

    out
        << "\nCORRELATED EVENTS - CAUSALITY NOT ESTABLISHED\n"
        << "---------------------------------------------\n"
        << "GenericResFileRes missing-resource log lines: "
        << d.resource_miss_lines
        << "\n"
        << "wait-object progress lines: "
        << d.wait_progress_lines
        << "\n"
        << "HTTP Start lines: "
        << d.http_start_lines
        << "\n"
        << "These events coexist with the Gate A failure, but this report "
        << "does not claim that any of them caused completed=0,total=0.\n";

    out
        << "\nNEXT UNKNOWN\n"
        << "------------\n"
        << "The immediate machine-level blocker is identified. "
        << "The remaining question is why Gate A's completed and total "
        << "counters both stay at zero.\n";

    d.text = out.str();
    return d;
}

} // namespace

PvZ2InspectorResult InspectPvZ2ApkAndLog(
    const std::uint8_t* apk_data,
    std::size_t apk_size,
    const std::string& log_text) {

    PvZ2InspectorResult result;
    result.apk_size = apk_size;

    try {
        if (apk_data == nullptr || apk_size == 0) {
            throw std::runtime_error("No APK data supplied");
        }

        auto so = ExtractZipMember(
            apk_data,
            apk_size,
            "lib/armeabi-v7a/libPVZ2.so");

        result.elf_size = so.size();
        Elf32Arm elf(std::move(so));
        result.image_size = elf.image_end();
        result.sections = static_cast<std::uint32_t>(elf.sections().size());
        result.dynamic_symbols =
            static_cast<std::uint32_t>(elf.symbols().size());
        result.exidx_function_starts =
            static_cast<std::uint32_t>(elf.function_starts().size());
        result.relocations = elf.relocation_count();

        std::uint32_t loads = 0;
        for (const auto& p : elf.phdrs()) {
            if (p.type == kPtLoad) ++loads;
        }
        result.load_segments = loads;

        const auto imports = elf.undefined_symbols();
        result.undefined_symbols =
            static_cast<std::uint32_t>(imports.size());

        std::uint32_t occurrences = 0;
        const auto addresses =
            CollectHexAddresses(log_text, occurrences);
        result.log_hex_occurrences = occurrences;
        result.log_unique_addresses =
            static_cast<std::uint32_t>(addresses.size());

        const auto controls = CollectControlAddresses(log_text);

        const auto game_state_profile =
            ValidateGameStateProfile(elf);
        const auto startup_logo_profile =
            ValidateStartupLogoProfile(elf);
        const auto startup_runtime =
            DiagnoseStartupLogoRuntime(
                log_text,
                startup_logo_profile,
                elf);

        std::ostringstream summary;
        summary
            << "PvZ2 Inspector Lab v1.2\n"
            << "APK bytes: " << apk_size << "\n"
            << "libPVZ2.so bytes: " << result.elf_size << "\n"
            << "mapped image span: " << Hex(result.image_size) << "\n"
            << "PT_LOAD segments: " << result.load_segments << "\n"
            << "ELF sections: " << result.sections << "\n"
            << "dynamic symbols: " << result.dynamic_symbols << "\n"
            << "undefined/import symbols: " << result.undefined_symbols << "\n"
            << ".ARM.exidx function starts: "
            << result.exidx_function_starts << "\n"
            << "REL relocations: " << result.relocations << "\n";

        if (!log_text.empty()) {
            summary
                << "log hex occurrences: "
                << result.log_hex_occurrences << "\n"
                << "unique log addresses: "
                << result.log_unique_addresses << "\n";
        } else {
            summary << "log: not supplied (static ELF analysis only)\n";
        }

        summary
            << "GameState v53 static profile: "
            << (game_state_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << "\n"
            << "StartupLogo v54 static profile: "
            << (startup_logo_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << " ("
            << startup_logo_profile.matched()
            << "/"
            << startup_logo_profile.checks.size()
            << ")\n";

        if (startup_runtime.present) {
            summary
                << "StartupLogo runtime: "
                << (startup_runtime.first_blocker_gate_a
                        ? "Gate A is first observed blocker"
                        : "v54 evidence present; no unique blocker inferred")
                << "\n";
            if (startup_runtime.qnan_7fc00000) {
                summary
                    << "Gate A arithmetic: 0/0 -> qNaN 0x7fc00000\n";
            }
        }

        result.summary = summary.str();

        std::ostringstream report;
        report << result.summary << "\n";

        report << "ELF identity\n"
               << "============\n"
               << "guest base: " << Hex(kGuestBase) << "\n"
               << "SONAME: "
               << (elf.soname().empty() ? "(none)" : elf.soname())
               << "\n"
               << "needed libraries (" << elf.needed_libraries().size()
               << "):\n";
        for (const auto& lib : elf.needed_libraries()) {
            report << "  - " << lib << "\n";
        }

        report << "\nPT_LOAD map\n"
               << "===========\n";
        unsigned load_index = 0;
        for (const auto& p : elf.phdrs()) {
            if (p.type != kPtLoad) continue;
            report
                << "  [" << load_index++ << "] "
                << "vaddr=" << Hex(p.vaddr)
                << " fileOff=" << Hex(p.offset)
                << " fileSize=" << Hex(p.filesz)
                << " memSize=" << Hex(p.memsz)
                << " flags=" << Hex(p.flags, 1)
                << " align=" << Hex(p.align, 1)
                << "\n";
        }

        report << "\nSections\n"
               << "========\n";
        for (std::size_t i = 0; i < elf.sections().size(); ++i) {
            const auto& s = elf.sections()[i];
            report
                << "  [" << i << "] "
                << (s.name.empty() ? "(unnamed)" : s.name)
                << " type=" << Hex(s.type, 1)
                << " addr=" << Hex(s.addr)
                << " off=" << Hex(s.offset)
                << " size=" << Hex(s.size)
                << " flags=" << Hex(s.flags, 1)
                << "\n";
        }

        report << "\nRelocation histogram\n"
               << "====================\n";
        for (const auto& [type, count] : elf.relocation_types()) {
            report << "  "
                   << std::setw(8) << count << "  "
                   << RelocName(type)
                   << " (" << type << ")\n";
        }

        report << "\nUndefined/import symbols\n"
               << "========================\n";
        for (const auto& name : imports) {
            report << "  " << name << "\n";
        }

        report
            << "\nExact GameState profile (PvZ2 1.5.252752)\n"
            << "=========================================\n"
            << "profile validation: "
            << (game_state_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << "\n"
            << "GameStateMgr factory: "
            << Hex(kGuestBase + 0x00133818u)
            << " (allocates 0x460-byte object)\n"
            << "GameStateMgr ctor: "
            << Hex(kGuestBase + 0x001492bcu)
            << "\n"
            << "runtime object vtable expected: "
            << Hex(kGuestBase + 0x00cdb7d8u)
            << "\n"
            << "current GameState field: +0x374\n"
            << "GameStateMgrTransitionState field: +0x3c4\n"
            << "pending/requested GameState field: +0x41c\n"
            << "ApplyState: "
            << Hex(kGuestBase + 0x002747d0u)
            << " hook-word@+0x8="
            << (game_state_profile.apply_hook_opcode
                    ? "MATCH"
                    : "MISMATCH")
            << "\n"
            << "RequestTransition: "
            << Hex(kGuestBase + 0x00274b44u)
            << " hook-word@+0x8="
            << (game_state_profile.request_hook_opcode
                    ? "MATCH"
                    : "MISMATCH")
            << "\n"
            << "MainMenu Enter: "
            << Hex(kGuestBase + 0x002767b4u)
            << "\n"
            << "StartupLogo Update: "
            << Hex(kGuestBase + 0x00276970u)
            << "\n"
            << "GameState enum:\n";

        for (std::int32_t state = 1;
             state <= 10;
             ++state) {
            report
                << "  "
                << state
                << " = "
                << GameStateName(state)
                << "\n";
        }

        report
            << "\nThis profile is descriptive evidence from the exact 1.5.252752 ARM binary. "
            << "The inspector does not execute or mutate the state machine.\n";

        report
            << "\nExact StartupLogo v54 profile (PvZ2 1.5.252752)\n"
            << "=================================================\n"
            << "profile validation: "
            << (startup_logo_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << " ("
            << startup_logo_profile.matched()
            << "/"
            << startup_logo_profile.checks.size()
            << ")\n";

        for (const auto& check : startup_logo_profile.checks) {
            report
                << "  "
                << (check.match ? "[MATCH] " : "[MISMATCH] ")
                << check.name
                << " @ "
                << Hex(kGuestBase + check.offset)
                << " expected="
                << Hex(check.expected)
                << "\n";
        }

        report
            << "\nGate A verified sequence includes VMOV/VCMPE/VMRS/BLT. "
            << "This allows a v54 log containing 0x7fc00000 to be interpreted "
            << "as an unordered IEEE-754 comparison instead of an opaque hex value.\n";

        if (startup_runtime.present) {
            report
                << "\n"
                << startup_runtime.text
                << "\n";
        }

        report << "\nKnown port landmarks\n"
               << "====================\n";
        for (const auto& [off, label] : KnownLabels()) {
            const std::uint32_t runtime = kGuestBase + off;
            report << "  " << Resolve(runtime, elf) << "\n";
        }

        if (!log_text.empty()) {
            report << "\nControl-flow addresses from log\n"
                   << "===============================\n";

            std::set<std::uint32_t> disassembled;
            for (const auto& key :
                 std::array<std::string, 5>{
                    "PC","LR","returnPC","callerLR","SP"}) {

                const auto it = controls.find(key);
                if (it == controls.end()) continue;

                report << "\n" << key << ":\n";
                const auto ranked = SortedCounts(it->second);
                const std::size_t limit =
                    std::min<std::size_t>(ranked.size(), 80);

                for (std::size_t i = 0; i < limit; ++i) {
                    const auto [address, count] = ranked[i];
                    report << "  "
                           << std::setw(6) << count << "x  "
                           << Resolve(address, elf)
                           << "\n";

                    const auto classified =
                        Classify(address, elf);

                    if (key != "SP" &&
                        disassembled.size() < 48 &&
                        classified.region == "libPVZ2.so" &&
                        classified.executable &&
                        disassembled.insert(address).second) {

                        for (const auto& line :
                             Disassemble(elf, address)) {
                            report << "             " << line << "\n";
                        }
                    }
                }
            }

            report << "\nMost frequent executable libPVZ2 addresses in entire log\n"
                   << "=========================================================\n";
            std::vector<std::pair<std::uint32_t, std::uint32_t>> code;
            for (const auto& [address, count] : addresses) {
                const auto classified =
                    Classify(address, elf);
                if (classified.region == "libPVZ2.so" &&
                    classified.executable) {
                    code.emplace_back(address, count);
                }
            }
            std::sort(
                code.begin(),
                code.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second > b.second;
                    return a.first < b.first;
                });
            const std::size_t limit =
                std::min<std::size_t>(code.size(), 250);
            for (std::size_t i = 0; i < limit; ++i) {
                report
                    << "  " << std::setw(6) << code[i].second << "x  "
                    << Resolve(code[i].first, elf)
                    << "\n";
            }
        }

        result.report = report.str();

        std::ostringstream csv;
        csv << "address,count,region,section,executable,offset,function_start,function_delta,known_label,nearest_symbol\n";
        const auto ranked_all = SortedCounts(addresses);
        for (const auto& [address, count] : ranked_all) {
            const auto c = Classify(address, elf);
            std::string offset;
            std::string fn_start;
            std::string fn_delta;
            std::string label;
            std::string sym;

            if (c.offset) offset = Hex(*c.offset);

            if (c.region == "libPVZ2.so" &&
                c.offset &&
                c.executable) {
                const auto [start, end] = elf.FunctionRange(*c.offset);
                if (start) {
                    fn_start = Hex(*start);
                    fn_delta = Hex(*c.offset - *start, 1);
                }

                const auto known = KnownLabels().find(*c.offset);
                if (known != KnownLabels().end()) {
                    label = known->second;
                }

                const auto nearest = elf.NearestSymbol(*c.offset);
                if (nearest) {
                    sym = nearest->first.name + "+" +
                          Hex(nearest->second, 1);
                }
            }

            csv << Hex(address) << ","
                << count << ","
                << CsvEscape(c.region) << ","
                << CsvEscape(c.section) << ","
                << (c.executable ? "YES" : "NO") << ","
                << offset << ","
                << fn_start << ","
                << fn_delta << ","
                << CsvEscape(label) << ","
                << CsvEscape(sym) << "\n";
        }
        result.addresses_csv = csv.str();

        result.annotated_log = AnnotateLog(log_text, elf);
        result.startup_diagnosis =
            startup_runtime.present
                ? startup_runtime.text
                : std::string{};

        std::ostringstream json;
        json
            << "{\n"
            << "  \"tool\": \"PvZ2 Inspector Lab v1.2\",\n"
            << "  \"apkSize\": " << result.apk_size << ",\n"
            << "  \"elfSize\": " << result.elf_size << ",\n"
            << "  \"guestBase\": \"" << Hex(kGuestBase) << "\",\n"
            << "  \"imageSize\": \"" << Hex(result.image_size) << "\",\n"
            << "  \"loadSegments\": " << result.load_segments << ",\n"
            << "  \"sections\": " << result.sections << ",\n"
            << "  \"dynamicSymbols\": " << result.dynamic_symbols << ",\n"
            << "  \"undefinedSymbols\": " << result.undefined_symbols << ",\n"
            << "  \"exidxFunctionStarts\": "
            << result.exidx_function_starts << ",\n"
            << "  \"relocations\": " << result.relocations << ",\n"
            << "  \"gameStateProfileExactMatch\": "
            << (game_state_profile.exact_profile()
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"startupLogoV54ProfileExactMatch\": "
            << (startup_logo_profile.exact_profile()
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"startupLogoV54ProfileMatchedChecks\": "
            << startup_logo_profile.matched()
            << ",\n"
            << "  \"startupLogoV54ProfileTotalChecks\": "
            << startup_logo_profile.checks.size()
            << ",\n"
            << "  \"gameStateManagerVtable\": \""
            << Hex(kGuestBase + 0x00cdb7d8u)
            << "\",\n"
            << "  \"gameStateCurrentOffset\": \"0x374\",\n"
            << "  \"gameStateTransitionOffset\": \"0x3c4\",\n"
            << "  \"gameStatePendingOffset\": \"0x41c\",\n"
            << "  \"logHexOccurrences\": "
            << result.log_hex_occurrences << ",\n"
            << "  \"logUniqueAddresses\": "
            << result.log_unique_addresses << ",\n"
            << "  \"soname\": \""
            << JsonEscape(elf.soname()) << "\",\n"
            << "  \"neededLibraries\": [";

        for (std::size_t i = 0; i < elf.needed_libraries().size(); ++i) {
            if (i) json << ", ";
            json << "\"" << JsonEscape(elf.needed_libraries()[i]) << "\"";
        }

        json << "],\n"
             << "  \"startupLogoRuntime\": {\n"
             << "    \"present\": "
             << (startup_runtime.present ? "true" : "false")
             << ",\n"
             << "    \"finalGameState\": "
             << startup_runtime.final_state
             << ",\n"
             << "    \"resourceHits\": "
             << startup_runtime.resource_hits
             << ",\n"
             << "    \"resource\": \""
             << Hex(startup_runtime.resource)
             << "\",\n"
             << "    \"resourcePresent\": "
             << (startup_runtime.resource_present ? "true" : "false")
             << ",\n"
             << "    \"completed\": "
             << startup_runtime.completed
             << ",\n"
             << "    \"total\": "
             << startup_runtime.total
             << ",\n"
             << "    \"resultBits\": \""
             << Hex(startup_runtime.result_bits)
             << "\",\n"
             << "    \"quietNaN\": "
             << (startup_runtime.qnan_7fc00000 ? "true" : "false")
             << ",\n"
             << "    \"gateCHits\": "
             << startup_runtime.gate_c_hits
             << ",\n"
             << "    \"gateDHits\": "
             << startup_runtime.gate_d_hits
             << ",\n"
             << "    \"afterDHits\": "
             << startup_runtime.after_d_hits
             << ",\n"
             << "    \"patchRequestMarkerHits\": "
             << startup_runtime.patch_marker_hits
             << ",\n"
             << "    \"mainMenuRequestMarkerHits\": "
             << startup_runtime.mainmenu_marker_hits
             << ",\n"
             << "    \"firstObservedBlocker\": \""
             << (startup_runtime.first_blocker_gate_a
                    ? "GateA"
                    : "")
             << "\"\n"
             << "  }\n"
             << "}\n";
        result.summary_json = json.str();

        result.ok = true;
        result.message =
            "Analysis complete. Reports are ready for export.";
    } catch (const std::exception& e) {
        result.ok = false;
        result.message = e.what();
        result.summary = std::string("PvZ2 Inspector failed: ") + e.what();
    }

    return result;
}
