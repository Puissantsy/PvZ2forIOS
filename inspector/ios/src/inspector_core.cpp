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
constexpr std::uint32_t kRArmGlobDat = 21u;
constexpr std::uint32_t kRArmJumpSlot = 22u;
constexpr std::uint32_t kRArmRelative = 23u;

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
        {0x002c85ccu, "StartupLogo.GateA group lookup result"},
        {0x002c85f4u, "StartupLogo.GateA group contribution"},
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
        {0x00867708u, "ResourceManager registry builder"},
        {0x00867710u, "ResourceManager registry builder entry trap"},
        {0x00867860u, "ResourceManager source28 copy trap"},
        {0x00867868u, "ResourceManager post-table28 trap"},
        {0x00867b24u, "ResourceManager source30 copy trap"},
        {0x00867b2cu, "ResourceManager post-table30 trap"},
        {0x00867b68u, "ResourceManager registry builder return trap"},
        {0x00867f54u, "ResourceManager group-name-to-index"},
        {0x0086b50cu, "ResourceManager group completed-count helper"},
        {0x0086b630u, "ResourceManager group total-count helper"},
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
        {0x00a83ab0u, "ResourceManager compact-trie string lookup"},
        {0x00a83ab4u, "compact-trie root/count load trap"},
        {0x00a83ae4u, "compact-trie input-byte load"},
        {0x00a83ae8u, "compact-trie _toupper_tab_ index"},
        {0x00a83aecu, "compact-trie normalized-byte load"},
        {0x00a83af8u, "compact-trie node-byte extract"},
        {0x00a83afcu, "compact-trie normalized-byte compare"},
        {0x00a83b24u, "compact-trie miss branch"},
        {0x00a83b38u, "compact-trie found return"},
        {0x00a83b44u, "compact-trie null return"},
        {0x00d010d8u, "GOT R_ARM_GLOB_DAT _tolower_tab_"},
        {0x00d010dcu, "GOT R_ARM_GLOB_DAT _toupper_tab_"},
        {0x00d01280u, "GOT R_ARM_GLOB_DAT _ctype_"},
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

std::string RelocName(std::uint32_t type);

struct NamedRelocation {
    std::uint32_t offset = 0u;
    std::uint32_t type = 0u;
    std::uint32_t symbol_index = 0u;
    std::uint8_t symbol_type = 0u;
    std::uint16_t symbol_shndx = 0u;
    std::string symbol;
};

std::optional<NamedRelocation> FindNamedRelocation(
    const Elf32Arm& elf,
    const std::string& wanted) {

    const auto& data = elf.data();
    const auto& sections = elf.sections();

    for (const auto& relsec : sections) {
        if (relsec.type != kShtRel ||
            relsec.link >= sections.size()) {
            continue;
        }

        const auto& dynsym = sections[relsec.link];
        if (dynsym.type != kShtDynsym ||
            dynsym.link >= sections.size()) {
            continue;
        }

        const auto& strings = sections[dynsym.link];
        const std::uint32_t rel_entsize =
            relsec.entsize ? relsec.entsize : 8u;
        const std::uint32_t sym_entsize =
            dynsym.entsize ? dynsym.entsize : 16u;

        if (relsec.offset + relsec.size > data.size() ||
            dynsym.offset + dynsym.size > data.size() ||
            strings.offset + strings.size > data.size()) {
            continue;
        }

        for (std::uint32_t rel = 0u;
             rel + 8u <= relsec.size;
             rel += rel_entsize) {

            const std::size_t p =
                static_cast<std::size_t>(relsec.offset) + rel;
            const std::uint32_t offset = U32(data.data() + p);
            const std::uint32_t info = U32(data.data() + p + 4u);
            const std::uint32_t symbol_index = info >> 8u;
            const std::uint32_t type = info & 0xffu;

            const std::uint64_t sym_rel =
                static_cast<std::uint64_t>(symbol_index) *
                sym_entsize;
            if (sym_rel + 16u > dynsym.size) {
                continue;
            }

            const std::size_t sp =
                static_cast<std::size_t>(dynsym.offset + sym_rel);
            const std::uint32_t name_off =
                U32(data.data() + sp);
            if (name_off >= strings.size) {
                continue;
            }

            const std::size_t name_start =
                static_cast<std::size_t>(strings.offset) +
                name_off;
            std::size_t name_end = name_start;
            const std::size_t strings_end =
                static_cast<std::size_t>(strings.offset) +
                strings.size;
            while (name_end < strings_end &&
                   data[name_end] != 0u) {
                ++name_end;
            }
            if (name_end >= strings_end) {
                continue;
            }

            const std::string name(
                reinterpret_cast<const char*>(
                    data.data() + name_start),
                name_end - name_start);

            if (name != wanted) {
                continue;
            }

            NamedRelocation out;
            out.offset = offset;
            out.type = type;
            out.symbol_index = symbol_index;
            out.symbol_type =
                static_cast<std::uint8_t>(
                    data[sp + 12u] & 0x0fu);
            out.symbol_shndx =
                U16(data.data() + sp + 14u);
            out.symbol = name;
            return out;
        }
    }

    return std::nullopt;
}

struct V56ProfileValidation {
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

V56ProfileValidation ValidateV56Profile(
    const Elf32Arm& elf) {

    V56ProfileValidation v;

    const std::array<
        std::tuple<const char*, std::uint32_t, std::uint32_t>,
        26> expected = {{
        {"Registry builder entry",   0x00867710u, 0xe1a08000u},
        {"Registry source28",        0x00867860u, 0xe2880028u},
        {"Registry post28",          0x00867868u, 0xe5990048u},
        {"Registry source30",        0x00867b24u, 0xe2880030u},
        {"Registry post30",          0x00867b2cu, 0xe2880070u},
        {"Registry return",          0x00867b68u, 0xe1a00006u},
        {"Group lookup table30",     0x00867f64u, 0xe2840030u},
        {"Group lookup trie call30", 0x00867f68u, 0xeb086ed0u},
        {"Group lookup table28",     0x00867f80u, 0xe2840028u},
        {"Group lookup trie call28", 0x00867f84u, 0xeb086ec9u},
        {"Compact trie count/root",  0x00a83ab4u, 0xe5902004u},
        {"Compact trie GOT lit A",   0x00a83ac0u, 0xe59f2084u},
        {"Compact trie GOT lit B",   0x00a83ac4u, 0xe59f3084u},
        {"Compact trie GOT add",     0x00a83ac8u, 0xe08f2002u},
        {"Compact trie GOT load",    0x00a83accu, 0xe7932002u},
        {"Compact trie import deref",0x00a83ad4u, 0xe592c000u},
        {"Compact trie key byte",    0x00a83ae4u, 0xe5d10000u},
        {"Compact trie table index", 0x00a83ae8u, 0xe08c0080u},
        {"Compact trie norm load",   0x00a83aecu, 0xe1d0e0b2u},
        {"Compact trie node byte",   0x00a83af8u, 0xe6ef0075u},
        {"Compact trie compare",     0x00a83afcu, 0xe1500004u},
        {"Compact trie miss",        0x00a83b24u, 0xea000005u},
        {"Compact trie found",       0x00a83b38u, 0xe1a00002u},
        {"Compact trie null",        0x00a83b44u, 0xe3a00000u},
        {"Gate C field +0x98",       0x005143a4u, 0xe5901098u},
        {"Gate C compare state 4",   0x005143acu, 0xe3510004u},
    }};

    for (const auto& [name, offset, opcode] : expected) {
        v.checks.push_back(
            StartupLogoProfileCheck{
                name,
                offset,
                opcode,
                HasWordAt(elf, offset, opcode)});
    }

    return v;
}

struct CtypeImportAudit {
    std::optional<NamedRelocation> tolower_rel;
    std::optional<NamedRelocation> toupper_rel;
    std::optional<NamedRelocation> ctype_rel;
    bool trie_got_literals_match = false;
    bool trie_dependency_match = false;
    bool exact_import_profile = false;
    bool high_priority_candidate = false;
    std::string text;
};

CtypeImportAudit AuditCtypeImports(
    const Elf32Arm& elf,
    const V56ProfileValidation& v56_profile) {

    CtypeImportAudit a;
    a.tolower_rel =
        FindNamedRelocation(
            elf,
            "_tolower_tab_");
    a.toupper_rel =
        FindNamedRelocation(
            elf,
            "_toupper_tab_");
    a.ctype_rel =
        FindNamedRelocation(
            elf,
            "_ctype_");

    auto exact_object_glob =
        [](const std::optional<NamedRelocation>& r,
           std::uint32_t expected_offset) {
            return
                r.has_value() &&
                r->offset == expected_offset &&
                r->type == kRArmGlobDat &&
                r->symbol_type == 1u &&
                r->symbol_shndx == 0u;
        };

    a.exact_import_profile =
        exact_object_glob(
            a.tolower_rel,
            0x00d010d8u) &&
        exact_object_glob(
            a.toupper_rel,
            0x00d010dcu) &&
        exact_object_glob(
            a.ctype_rel,
            0x00d01280u);

    // At 0xa83ac0/0xa83ac4 the function loads two literals, combines them
    // through the GOT-base sequence at 0xa83ac8/0xa83acc, and reaches
    // 0x00d010dc: the R_ARM_GLOB_DAT cell for _toupper_tab_.
    a.trie_got_literals_match =
        HasWordAt(
            elf,
            0x00a83b4cu,
            0x0027e034u) &&
        HasWordAt(
            elf,
            0x00a83b50u,
            0xfffff5d8u);

    a.trie_dependency_match =
        v56_profile.exact_profile() &&
        a.trie_got_literals_match &&
        exact_object_glob(
            a.toupper_rel,
            0x00d010dcu);

    a.high_priority_candidate =
        a.exact_import_profile &&
        a.trie_dependency_match;

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.3 - imported ctype ABI audit\n"
        << "==================================================\n"
        << "Evidence source: original PvZ2 1.5.252752 ARM ELF.\n\n";

    auto emit =
        [&](const char* name,
            const std::optional<NamedRelocation>& r,
            std::uint32_t expected) {
            out
                << name
                << ": ";
            if (!r) {
                out << "NOT FOUND\n";
                return;
            }
            out
                << RelocName(r->type)
                << " at ELF "
                << Hex(r->offset)
                << " / runtime GOT "
                << Hex(kGuestBase + r->offset)
                << " symbolType="
                << static_cast<unsigned>(
                       r->symbol_type)
                << " shndx="
                << r->symbol_shndx
                << (r->offset == expected
                        ? " [EXPECTED OFFSET]"
                        : " [OFFSET MISMATCH]")
                << "\n";
        };

    emit(
        "_tolower_tab_",
        a.tolower_rel,
        0x00d010d8u);
    emit(
        "_toupper_tab_",
        a.toupper_rel,
        0x00d010dcu);
    emit(
        "_ctype_",
        a.ctype_rel,
        0x00d01280u);

    out
        << "\nCompact-trie dependency profile: "
        << (a.trie_dependency_match
                ? "MATCH"
                : "MISMATCH")
        << "\n"
        << "The verified lookup at "
        << Hex(kGuestBase + 0x00a83ab0u)
        << " dereferences the _toupper_tab_ imported object, then indexes "
        << "a 16-bit table using (inputByte + 1) before comparing the "
        << "normalized byte with the trie node byte.\n"
        << "Verified core sequence: "
        << "LDRB key -> ADD table,key,LSL#1 -> LDRH [table,#2] -> "
        << "UXTB -> compare.\n\n";

    out
        << "PORT-COMPATIBILITY RISK\n"
        << "-----------------------\n"
        << "PvZ2forIOS v56 source was audited when Inspector v1.3 was built: "
        << "non-function GLOB_DAT imports other than __stack_chk_guard are "
        << "backed by generic zero-filled synthetic objects. That strategy "
        << "does not provide the pointer-to-character-table ABI required by "
        << "_toupper_tab_, _tolower_tab_ or _ctype_.\n"
        << "This is a source-level compatibility mismatch. Whether it is the "
        << "runtime cause of every v56 registry miss still requires a real "
        << "iPad A/B test.\n\n"
        << "Priority: "
        << (a.high_priority_candidate
                ? "HIGH - direct v57 A/B candidate"
                : "PROFILE INCOMPLETE - do not infer causality")
        << "\n";

    a.text = out.str();
    return a;
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
    std::uint32_t gate_c_object = 0u;
    std::uint32_t gate_c_state = 0xffffffffu;
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
    if (const auto v = ParseUnsignedAfter(summary_line, "object=0x", 16)) {
        d.gate_c_object =
            static_cast<std::uint32_t>(*v);
    }
    if (const auto v = ParseUnsignedAfter(summary_line, "state=")) {
        d.gate_c_state =
            static_cast<std::uint32_t>(*v);
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

std::string TokenAfter(
    const std::string& line,
    const std::string& marker) {

    const std::size_t pos =
        line.find(marker);
    if (pos == std::string::npos) {
        return {};
    }

    const std::size_t begin =
        pos + marker.size();
    std::size_t end = begin;

    while (end < line.size()) {
        const char ch = line[end];
        if (std::isspace(
                static_cast<unsigned char>(ch)) ||
            ch == '}' ||
            ch == '|' ||
            ch == ',') {
            break;
        }
        ++end;
    }

    return line.substr(
        begin,
        end - begin);
}

struct V55RuntimeDiagnosis {
    bool present = false;
    std::uint32_t vector_count = 0u;
    std::uint64_t lookups = 0u;
    std::uint64_t contributions = 0u;
    bool all_four_miss = false;
    std::string diagnosis;
};

V55RuntimeDiagnosis DiagnoseV55Runtime(
    const std::string& log) {

    V55RuntimeDiagnosis d;
    const std::string line =
        LastLineContaining(
            log,
            "V55 STARTUP GROUP SUMMARY:");

    if (line.empty()) {
        return d;
    }

    d.present = true;

    const std::size_t gate =
        line.find("gate={");
    if (gate != std::string::npos) {
        const std::string tail =
            line.substr(gate);
        if (const auto v =
                ParseUnsignedAfter(
                    tail,
                    "count=")) {
            d.vector_count =
                static_cast<std::uint32_t>(*v);
        }
    }

    if (const auto v =
            ParseUnsignedAfter(
                line,
                " lookups=")) {
        d.lookups = *v;
    }
    if (const auto v =
            ParseUnsignedAfter(
                line,
                " contributions=")) {
        d.contributions = *v;
    }

    d.diagnosis =
        TokenAfter(
            line,
            "diagnosis=");
    d.all_four_miss =
        d.diagnosis ==
            "ALL_4_GROUPS_MISS_RESOURCE_MANAGER";

    return d;
}

struct V56TargetStat {
    std::uint64_t calls = 0u;
    std::uint64_t found = 0u;
    std::uint64_t misses = 0u;
    std::uint32_t last_table = 0u;
    std::uint32_t caller = 0u;
};

struct V56RuntimeDiagnosis {
    bool present = false;
    std::string mode;
    std::uint64_t pipeline_calls = 0u;
    std::uint64_t pipeline_returns = 0u;
    std::uint32_t pipeline_result = 0u;
    std::uint32_t src28 = 0u;
    std::uint32_t src28_bytes = 0u;
    std::uint32_t src28_count = 0u;
    std::uint32_t src30 = 0u;
    std::uint32_t src30_bytes = 0u;
    std::uint32_t src30_count = 0u;
    std::uint32_t manager = 0u;
    std::uint32_t table28_root = 0u;
    std::uint32_t table28_count = 0u;
    std::uint32_t table30_root = 0u;
    std::uint32_t table30_count = 0u;
    std::uint64_t registry_writes = 0u;
    bool scout_enabled = false;
    bool scout_activated = false;
    std::uint64_t scout_forced_hits = 0u;
    std::uint32_t scout_activation_frame = 0u;
    std::int32_t downstream_state = -999;
    std::uint64_t downstream_requests = 0u;
    std::uint64_t downstream_applies = 0u;
    std::map<std::string, V56TargetStat> targets;
    std::string diagnosis;
    bool every_target_missed = false;
    std::string text;
};

V56RuntimeDiagnosis DiagnoseV56Runtime(
    const std::string& log,
    const V55RuntimeDiagnosis& v55,
    const StartupLogoRuntimeDiagnosis& startup,
    const V56ProfileValidation& static_profile,
    const CtypeImportAudit& ctype) {

    V56RuntimeDiagnosis d;
    const std::string line =
        LastLineContaining(
            log,
            "V56 DIAGNOSTIC MATRIX SUMMARY:");

    if (line.empty()) {
        return d;
    }

    d.present = true;
    d.mode =
        TokenAfter(
            line,
            "mode=");

    auto u32 =
        [&](const std::string& marker,
            std::uint32_t& dst,
            int base = 10) {
            if (const auto v =
                    ParseUnsignedAfter(
                        line,
                        marker,
                        base)) {
                dst =
                    static_cast<std::uint32_t>(*v);
            }
        };

    auto u64 =
        [&](const std::string& marker,
            std::uint64_t& dst) {
            if (const auto v =
                    ParseUnsignedAfter(
                        line,
                        marker)) {
                dst = *v;
            }
        };

    u64(
        "pipeline{calls=",
        d.pipeline_calls);
    u64(
        "returns=",
        d.pipeline_returns);
    u32(
        "lastResult=",
        d.pipeline_result);
    u32(
        "src28=0x",
        d.src28,
        16);
    u32(
        "src28Bytes=",
        d.src28_bytes);
    u32(
        "src28Count=",
        d.src28_count);
    u32(
        "src30=0x",
        d.src30,
        16);
    u32(
        "src30Bytes=",
        d.src30_bytes);
    u32(
        "src30Count=",
        d.src30_count);
    u32(
        "registry{manager=0x",
        d.manager,
        16);
    u32(
        "table28Root=0x",
        d.table28_root,
        16);
    u32(
        "table28Count=",
        d.table28_count);
    u32(
        "table30Root=0x",
        d.table30_root,
        16);
    u32(
        "table30Count=",
        d.table30_count);
    u64(
        "writes=",
        d.registry_writes);
    d.scout_enabled =
        line.find(
            "scout{enabled=YES") !=
        std::string::npos;
    d.scout_activated =
        line.find(
            "activated=YES") !=
        std::string::npos;
    u64(
        "forcedHits=",
        d.scout_forced_hits);
    u32(
        "activationFrame=",
        d.scout_activation_frame);

    if (const auto v =
            ParseUnsignedAfter(
                line,
                "downstream{state=")) {
        d.downstream_state =
            static_cast<std::int32_t>(*v);
    }
    u64(
        "requests=",
        d.downstream_requests);
    u64(
        "applies=",
        d.downstream_applies);

    std::size_t pos = 0u;
    while ((pos = line.find(" | ", pos)) !=
           std::string::npos) {

        const std::size_t begin =
            pos + 3u;
        std::size_t end =
            line.find(
                " | ",
                begin);
        if (end == std::string::npos) {
            end = line.size();
        }

        const std::string segment =
            line.substr(
                begin,
                end - begin);

        const std::size_t brace =
            segment.find("{calls=");
        if (brace != std::string::npos) {
            const std::string key =
                segment.substr(0u, brace);
            V56TargetStat s;
            if (const auto v =
                    ParseUnsignedAfter(
                        segment,
                        "{calls=")) {
                s.calls = *v;
            }
            if (const auto v =
                    ParseUnsignedAfter(
                        segment,
                        "found=")) {
                s.found = *v;
            }
            if (const auto v =
                    ParseUnsignedAfter(
                        segment,
                        "misses=")) {
                s.misses = *v;
            }
            if (const auto v =
                    ParseUnsignedAfter(
                        segment,
                        "lastTable=0x",
                        16)) {
                s.last_table =
                    static_cast<std::uint32_t>(*v);
            }
            if (const auto v =
                    ParseUnsignedAfter(
                        segment,
                        "caller=0x",
                        16)) {
                s.caller =
                    static_cast<std::uint32_t>(*v);
            }
            d.targets[key] = s;
        }

        pos = end;
    }

    d.diagnosis =
        TokenAfter(
            line,
            "diagnosis=");

    d.every_target_missed =
        !d.targets.empty() &&
        std::all_of(
            d.targets.begin(),
            d.targets.end(),
            [](const auto& pair) {
                return
                    pair.second.calls != 0u &&
                    pair.second.found == 0u &&
                    pair.second.misses ==
                        pair.second.calls;
            });

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.3 - v55/v56 matrix diagnosis\n"
        << "====================================================\n"
        << "Source evidence: supplied iPad runtime log + verified APK static profile.\n\n"
        << "STATIC PROFILE\n"
        << "--------------\n"
        << "v56 registry/trie/Gate-C opcode profile: "
        << (static_profile.exact_profile()
                ? "MATCH"
                : "PARTIAL/MISMATCH")
        << " ("
        << static_profile.matched()
        << "/"
        << static_profile.checks.size()
        << ")\n\n";

    if (v55.present) {
        out
            << "V55 STARTUP VECTOR/GROUP EVIDENCE\n"
            << "---------------------------------\n"
            << "Gate-A vector count: "
            << v55.vector_count
            << "\n"
            << "Group lookups: "
            << v55.lookups
            << "\n"
            << "Per-group contributions: "
            << v55.contributions
            << "\n"
            << "Diagnosis: "
            << v55.diagnosis
            << "\n\n";
    }

    out
        << "V56 REGISTRY CONSTRUCTION\n"
        << "-------------------------\n"
        << "Mode: "
        << d.mode
        << "\n"
        << "Builder calls/returns/result: "
        << d.pipeline_calls
        << "/"
        << d.pipeline_returns
        << "/"
        << d.pipeline_result
        << "\n"
        << "source28: ptr="
        << Hex(d.src28)
        << " bytes="
        << d.src28_bytes
        << " count="
        << d.src28_count
        << "\n"
        << "source30: ptr="
        << Hex(d.src30)
        << " bytes="
        << d.src30_bytes
        << " count="
        << d.src30_count
        << "\n"
        << "manager: "
        << Hex(d.manager)
        << "\n"
        << "table28: root="
        << Hex(d.table28_root)
        << " count="
        << d.table28_count
        << "\n"
        << "table30: root="
        << Hex(d.table30_root)
        << " count="
        << d.table30_count
        << "\n"
        << "registry writes observed: "
        << d.registry_writes
        << "\n"
        << "Runtime diagnosis: "
        << d.diagnosis
        << "\n\n";

    out
        << "TARGET LOOKUPS\n"
        << "--------------\n";
    for (const auto& pair : d.targets) {
        out
            << pair.first
            << ": calls="
            << pair.second.calls
            << " found="
            << pair.second.found
            << " misses="
            << pair.second.misses
            << " lastTable="
            << Hex(pair.second.last_table)
            << " caller="
            << Hex(pair.second.caller)
            << "\n";
    }

    out
        << "\nSCOUT / NEXT GATE\n"
        << "-----------------\n"
        << "Gate-A scout enabled/activated: "
        << (d.scout_enabled ? "YES" : "NO")
        << "/"
        << (d.scout_activated ? "YES" : "NO")
        << "\n"
        << "Gate-A forced comparison hits after native proof: "
        << d.scout_forced_hits
        << "\n"
        << "Gate-C hits: "
        << startup.gate_c_hits
        << "\n"
        << "Gate-C object: "
        << Hex(startup.gate_c_object)
        << "\n"
        << "Gate-C object+0x98 state: "
        << startup.gate_c_state
        << " (native helper requires 4)\n"
        << "Gate-D hits: "
        << startup.gate_d_hits
        << "\n"
        << "Downstream GameState/requests/applies: "
        << d.downstream_state
        << "/"
        << d.downstream_requests
        << "/"
        << d.downstream_applies
        << "\n\n";

    out
        << "ROOT-CAUSE CANDIDATE FOR THE UNIVERSAL STRING-KEY MISS\n"
        << "------------------------------------------------------\n"
        << (ctype.high_priority_candidate
                ? "HIGH-PRIORITY STATIC CANDIDATE"
                : "STATIC PROFILE INCOMPLETE")
        << ": the compact-trie string lookup depends directly on "
        << "_toupper_tab_, while the v56 port's generic imported-data "
        << "placeholder does not implement that ABI.\n"
        << "This explains a class-wide failure pattern (many unrelated textual "
        << "keys all miss) better than an empty ResourceManager, which v56 has "
        << "now disproved. It is not considered runtime-proven until v57 A/B.\n";

    d.text = out.str();
    return d;
}

std::string BuildV57Plan(
    const V55RuntimeDiagnosis& v55,
    const V56RuntimeDiagnosis& v56,
    const StartupLogoRuntimeDiagnosis& startup,
    const CtypeImportAudit& ctype,
    const V56ProfileValidation& v56_profile) {

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.3 - v57 high-information test plan\n"
        << "========================================================\n"
        << "Goal: test the likely root cause and expose multiple downstream "
        << "blockers in one iPad build, without forcing GameState transitions.\n\n"
        << "CONFIRMED INPUT FACTS\n"
        << "---------------------\n"
        << "- v56 static registry/trie profile: "
        << (v56_profile.exact_profile()
                ? "MATCH"
                : "PARTIAL/MISMATCH")
        << "\n";

    if (v55.present) {
        out
            << "- Startup vector count="
            << v55.vector_count
            << ", lookups="
            << v55.lookups
            << ", contributions="
            << v55.contributions
            << ", diagnosis="
            << v55.diagnosis
            << "\n";
    }

    if (v56.present) {
        out
            << "- ResourceManager tables are populated: +0x28="
            << v56.table28_count
            << " entries, +0x30="
            << v56.table30_count
            << " entries; builder result="
            << v56.pipeline_result
            << ".\n"
            << "- Selected text-key lookups all-miss="
            << (v56.every_target_missed
                    ? "YES"
                    : "NO")
            << "; matrix diagnosis="
            << v56.diagnosis
            << ".\n"
            << "- Gate-A scout reached Gate C "
            << startup.gate_c_hits
            << " times; object="
            << Hex(startup.gate_c_object)
            << ", +0x98="
            << startup.gate_c_state
            << ", required=4; Gate-D hits="
            << startup.gate_d_hits
            << ".\n";
    }

    out
        << "- APK imports _toupper_tab_ at runtime GOT "
        << Hex(kGuestBase + 0x00d010dcu)
        << ", _tolower_tab_ at "
        << Hex(kGuestBase + 0x00d010d8u)
        << ", and _ctype_ at "
        << Hex(kGuestBase + 0x00d01280u)
        << ".\n"
        << "- Compact-trie lookup "
        << Hex(kGuestBase + 0x00a83ab0u)
        << " directly dereferences _toupper_tab_ and reads a 16-bit "
        << "entry at index inputByte+1.\n"
        << "- Current v56 imported-data compatibility model supplies generic "
        << "zero-filled objects for these symbols. This mismatch is confirmed "
        << "statically; its causal role must be tested on-device.\n\n";

    out
        << "RECOMMENDED v57 MATRIX - ONE IPA, MULTIPLE MODES\n"
        << "------------------------------------------------\n"
        << "MODE A: V56_BASELINE\n"
        << "  Preserve current FULL_MATRIX behavior unchanged. This is the "
        << "control run and must remain available.\n\n"
        << "MODE B: CTYPE_COMPAT_NATIVE_PATH\n"
        << "  Implement ABI-correct imported data for _toupper_tab_, "
        << "_tolower_tab_ and _ctype_. Do not patch ResourceManager tables, "
        << "group indexes, Gate A, Gate C, or GameState.\n"
        << "  For _toupper_tab_, provide the pointer variable expected by the "
        << "guest plus a 257-entry 16-bit table where guest byte c is read "
        << "from entry c+1. Verify at least A/a, D/d, I/i, R/r, U/u, '_', "
        << "'0' and '9' in the log.\n"
        << "  Before first registry lookup, log each GOT cell, imported-object "
        << "address, dereferenced backing-table pointer, and sample values.\n"
        << "  Success criterion: any previously universal text key becomes "
        << "FOUND naturally, especially AlwaysLoaded/UIImages/UI_MainMenu.\n\n"
        << "MODE C: CTYPE_COMPAT_DEEP_SCOUT\n"
        << "  Start with the same ctype fix. If Gate A still fails, retain the "
        << "existing post-proof Gate-A scout. If Gate A passes naturally, do "
        << "not force it.\n"
        << "  Add a Gate-C proof/scout: record object+0x98=1 repeatedly first; "
        << "only after proof may the scout emulate a passing Gate-C return to "
        << "discover Gate D/E/F/G/H/I/J and the natural request path. Do not "
        << "force a GameState or RequestTransition target.\n\n"
        << "HIGH-VALUE TRACE BATCH\n"
        << "----------------------\n"
        << "1. Compact-trie path tracer for the first lookup of each target "
        << "key: raw input byte, normalized _toupper_tab_ byte, trie-node "
        << "byte, node word/index, character position, and exact miss/found "
        << "reason. This distinguishes bad normalization from bad trie data.\n"
        << "2. Trace writes to Gate-C object "
        << Hex(startup.gate_c_object)
        << "+0x98 once the object is known: old/new value, PC, LR, frame, "
        << "thread and lifecycle phase. Also snapshot +0x80..+0xb0 when the "
        << "value changes.\n"
        << "3. Preserve v54-v56 gate counters so one run reports the deepest "
        << "natural/scouted gate reached.\n"
        << "4. If ctype compatibility makes group lookups succeed, log native "
        << "group index plus completed/total contribution per startup group; "
        << "this immediately tells whether loading progress becomes the next "
        << "class of blocker.\n"
        << "5. If ctype values are correct but trie still misses, inspect the "
        << "first source/root node for the same key before adding any table "
        << "fallback. Avoid mutating the 5289/3801-entry tables until the "
        << "character-by-character mismatch is known.\n\n"
        << "DECISION TREE AFTER ONE v57 BUILD\n"
        << "---------------------------------\n"
        << "- CTYPE_COMPAT -> FOUND keys: imported-data ABI was causal; continue "
        << "on natural Gate A/C progression.\n"
        << "- CTYPE_COMPAT values correct but keys still MISS: use trie path "
        << "trace to isolate source/root/index corruption.\n"
        << "- Gate A passes but Gate C remains +0x98=1: writer trace identifies "
        << "the subsystem responsible for state 1->4.\n"
        << "- Deep Scout reaches Gate D+: existing v54 probes expose the next "
        << "whole chain without another one-problem build.\n\n"
        << "DO NOT use v57 to fabricate ResourceManager entries or force "
        << "MainMenu. The highest-value experiment is repairing/testing the "
        << "ctype import ABI first, because it can explain the broad lookup "
        << "failure class at once.\n";

    return out.str();
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
        const auto v56_profile =
            ValidateV56Profile(elf);
        const auto ctype_audit =
            AuditCtypeImports(
                elf,
                v56_profile);
        const auto startup_runtime =
            DiagnoseStartupLogoRuntime(
                log_text,
                startup_logo_profile,
                elf);
        const auto v55_runtime =
            DiagnoseV55Runtime(
                log_text);
        const auto v56_runtime =
            DiagnoseV56Runtime(
                log_text,
                v55_runtime,
                startup_runtime,
                v56_profile,
                ctype_audit);
        const std::string v57_plan =
            BuildV57Plan(
                v55_runtime,
                v56_runtime,
                startup_runtime,
                ctype_audit,
                v56_profile);

        std::ostringstream summary;
        summary
            << "PvZ2 Inspector Lab v1.3\n"
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
            << ")\n"
            << "v56 registry/trie static profile: "
            << (v56_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << " ("
            << v56_profile.matched()
            << "/"
            << v56_profile.checks.size()
            << ")\n"
            << "ctype import ABI audit: "
            << (ctype_audit.high_priority_candidate
                    ? "HIGH-PRIORITY v57 CANDIDATE"
                    : "PROFILE INCOMPLETE")
            << "\n";

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

        if (v55_runtime.present) {
            summary
                << "v55 groups: "
                << v55_runtime.diagnosis
                << " vectorCount="
                << v55_runtime.vector_count
                << " lookups="
                << v55_runtime.lookups
                << "\n";
        }

        if (v56_runtime.present) {
            summary
                << "v56 matrix: "
                << v56_runtime.diagnosis
                << " tables="
                << v56_runtime.table28_count
                << "+"
                << v56_runtime.table30_count
                << " selectedKeysAllMiss="
                << (v56_runtime.every_target_missed
                        ? "YES"
                        : "NO")
                << "\n"
                << "next observed scout blocker: Gate C object="
                << Hex(startup_runtime.gate_c_object)
                << " +0x98="
                << startup_runtime.gate_c_state
                << " expected=4 hits="
                << startup_runtime.gate_c_hits
                << "\n";
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

        report
            << "\nExact v56 registry/trie/Gate-C profile\n"
            << "========================================\n"
            << "profile validation: "
            << (v56_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << " ("
            << v56_profile.matched()
            << "/"
            << v56_profile.checks.size()
            << ")\n";

        for (const auto& check : v56_profile.checks) {
            report
                << "  "
                << (check.match
                        ? "[MATCH] "
                        : "[MISMATCH] ")
                << check.name
                << " @ "
                << Hex(kGuestBase + check.offset)
                << " expected="
                << Hex(check.expected)
                << "\n";
        }

        report
            << "\n"
            << ctype_audit.text
            << "\n";

        if (v56_runtime.present) {
            report
                << "\n"
                << v56_runtime.text
                << "\n";
        }

        report
            << "\nv57 high-information plan\n"
            << "=========================\n"
            << v57_plan
            << "\n";

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
        result.matrix_diagnosis =
            v56_runtime.present
                ? v56_runtime.text +
                      "\n\n" +
                      ctype_audit.text
                : ctype_audit.text;
        result.v57_plan =
            v57_plan;

        std::ostringstream json;
        json
            << "{\n"
            << "  \"tool\": \"PvZ2 Inspector Lab v1.3\",\n"
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
            << "  \"v56ProfileExactMatch\": "
            << (v56_profile.exact_profile()
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"v56ProfileMatchedChecks\": "
            << v56_profile.matched()
            << ",\n"
            << "  \"v56ProfileTotalChecks\": "
            << v56_profile.checks.size()
            << ",\n"
            << "  \"ctypeHighPriorityCandidate\": "
            << (ctype_audit.high_priority_candidate
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"toupperGlobDat\": \""
            << (ctype_audit.toupper_rel
                    ? Hex(ctype_audit.toupper_rel->offset)
                    : std::string{})
            << "\",\n"
            << "  \"tolowerGlobDat\": \""
            << (ctype_audit.tolower_rel
                    ? Hex(ctype_audit.tolower_rel->offset)
                    : std::string{})
            << "\",\n"
            << "  \"ctypeGlobDat\": \""
            << (ctype_audit.ctype_rel
                    ? Hex(ctype_audit.ctype_rel->offset)
                    : std::string{})
            << "\",\n"
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
             << "    \"gateCObject\": \""
             << Hex(startup_runtime.gate_c_object)
             << "\",\n"
             << "    \"gateCState\": "
             << startup_runtime.gate_c_state
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
             << "  },\n"
             << "  \"v55Runtime\": {\n"
             << "    \"present\": "
             << (v55_runtime.present ? "true" : "false")
             << ",\n"
             << "    \"vectorCount\": "
             << v55_runtime.vector_count
             << ",\n"
             << "    \"lookups\": "
             << v55_runtime.lookups
             << ",\n"
             << "    \"contributions\": "
             << v55_runtime.contributions
             << ",\n"
             << "    \"diagnosis\": \""
             << JsonEscape(v55_runtime.diagnosis)
             << "\"\n"
             << "  },\n"
             << "  \"v56Runtime\": {\n"
             << "    \"present\": "
             << (v56_runtime.present ? "true" : "false")
             << ",\n"
             << "    \"mode\": \""
             << JsonEscape(v56_runtime.mode)
             << "\",\n"
             << "    \"pipelineCalls\": "
             << v56_runtime.pipeline_calls
             << ",\n"
             << "    \"pipelineReturns\": "
             << v56_runtime.pipeline_returns
             << ",\n"
             << "    \"pipelineResult\": "
             << v56_runtime.pipeline_result
             << ",\n"
             << "    \"table28Count\": "
             << v56_runtime.table28_count
             << ",\n"
             << "    \"table30Count\": "
             << v56_runtime.table30_count
             << ",\n"
             << "    \"scoutActivated\": "
             << (v56_runtime.scout_activated ? "true" : "false")
             << ",\n"
             << "    \"scoutForcedHits\": "
             << v56_runtime.scout_forced_hits
             << ",\n"
             << "    \"selectedKeysAllMiss\": "
             << (v56_runtime.every_target_missed ? "true" : "false")
             << ",\n"
             << "    \"diagnosis\": \""
             << JsonEscape(v56_runtime.diagnosis)
             << "\",\n"
             << "    \"targets\": {";

        {
            bool first = true;
            for (const auto& pair :
                 v56_runtime.targets) {
                if (!first) {
                    json << ",";
                }
                first = false;
                json
                    << "\n      \""
                    << JsonEscape(pair.first)
                    << "\": {\"calls\": "
                    << pair.second.calls
                    << ", \"found\": "
                    << pair.second.found
                    << ", \"misses\": "
                    << pair.second.misses
                    << ", \"lastTable\": \""
                    << Hex(pair.second.last_table)
                    << "\", \"caller\": \""
                    << Hex(pair.second.caller)
                    << "\"}";
            }
            if (!v56_runtime.targets.empty()) {
                json << "\n    ";
            }
        }

        json
             << "}\n"
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
