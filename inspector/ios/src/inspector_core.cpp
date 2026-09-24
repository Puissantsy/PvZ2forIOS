#include "inspector_core.hpp"
#include "v68_analyzer.hpp"
#include "v74_display_analyzer.hpp"

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
#include <string_view>
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

constexpr std::size_t kLargeLogThreshold = 24u * 1024u * 1024u;
constexpr std::size_t kLargeLogHeadBytes = 12u * 1024u * 1024u;
constexpr std::size_t kLargeLogTailBytes = 4u * 1024u * 1024u;

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

    std::optional<std::uint32_t> FileToVaddr(std::size_t file_offset) const {
        for (const auto& p : phdrs_) {
            if (p.type != kPtLoad) continue;
            const std::uint64_t begin = p.offset;
            const std::uint64_t end =
                static_cast<std::uint64_t>(p.offset) + p.filesz;
            if (file_offset >= begin && file_offset < end) {
                return p.vaddr +
                    static_cast<std::uint32_t>(file_offset - begin);
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
        {0x00868b7cu, "IResStreamsDriver resource-stream task pump"},
        {0x00868b98u, "resource-stream pump manager+0x68 mutex"},
        {0x00868ba0u, "resource-stream pump pthread_mutex_trylock call"},
        {0x00868c8cu, "resource-stream pump TaskResource vector begin (+0x50)"},
        {0x00868c94u, "resource-stream pump TaskResource vector end (+0x54)"},
        {0x00868ca8u, "resource-stream pump current TaskResource load"},
        {0x00868cacu, "resource-stream pump TaskResource vtable load"},
        {0x00868cb0u, "resource-stream pump vtable+0x14 target load"},
        {0x00868cb8u, "resource-stream pump virtual dispatch +0x14"},
        {0x00868cbcu, "resource-stream pump virtual dispatch return"},
        {0x00868cd0u, "resource-stream pump vtable+0x3c target load"},
        {0x00868cd8u, "resource-stream pump virtual dispatch +0x3c"},
        {0x00868d14u, "resource-stream pump vtable+0x18 target load"},
        {0x00868d1cu, "resource-stream pump virtual dispatch +0x18"},
        {0x00868f6cu, "resource-stream pump pthread_mutex_unlock call"},
        {0x00868f70u, "resource-stream pump verified cooperative boundary"},
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
        {0x009cb6d0u, "generic pthread wrapper ([arg], [arg+4])"},
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
        {0x00abd650u, "TaskResource constructor path A vptr store"},
        {0x00abd68cu, "TaskResource producer fast-path insert A"},
        {0x00abd700u, "TaskResource constructor path B vptr store"},
        {0x00abd73cu, "TaskResource producer fast-path insert B"},
        {0x00abd894u, "resource-stream deferred worker entry"},
        {0x00abd8f4u, "resource-stream worker -> task pump call"},
        {0x00abdf24u, "TaskResource producer virtual factory call"},
        {0x00abdf44u, "TaskResource producer fast-path insert C"},
        {0x00abe654u, "vector<IResStreamsDriver::TaskResource*>::emplace_back_aux"},
        {0x00cd0d88u, "TaskResource vtable assigned by direct producer paths"},
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


struct V61ProfileValidation {
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

V61ProfileValidation ValidateV61Profile(
    const Elf32Arm& elf) {

    V61ProfileValidation v;

    const std::array<
        std::tuple<const char*, std::uint32_t, std::uint32_t>,
        28> expected = {{
        {"Pump function start",         0x00868b7cu, 0xe92d4ff0u},
        {"Pump mutex address",          0x00868b98u, 0xe2840068u},
        {"Pump trylock call",           0x00868ba0u, 0xebe1ffcfu},
        {"Task vector begin",           0x00868c8cu, 0xe5945050u},
        {"Task vector end",             0x00868c94u, 0xe5940054u},
        {"Current task pointer",        0x00868ca8u, 0xe5967000u},
        {"Task vtable load",            0x00868cacu, 0xe5970000u},
        {"Task vfn +0x14 load",         0x00868cb0u, 0xe5901014u},
        {"Task this -> r0",             0x00868cb4u, 0xe1a00007u},
        {"Task vfn +0x14 BLX",          0x00868cb8u, 0xe12fff31u},
        {"Task vfn +0x14 result cmp",   0x00868cbcu, 0xe3500001u},
        {"Task vtable reload +0x3c",    0x00868cccu, 0xe5970000u},
        {"Task vfn +0x3c load",         0x00868cd0u, 0xe590103cu},
        {"Task vfn +0x3c BLX",          0x00868cd8u, 0xe12fff31u},
        {"Task vtable reload +0x18",    0x00868d10u, 0xe5970000u},
        {"Task vfn +0x18 load",         0x00868d14u, 0xe5901018u},
        {"Task vfn +0x18 BLX",          0x00868d1cu, 0xe12fff31u},
        {"Pump unlock call",            0x00868f6cu, 0xebe1fe55u},
        {"Pump yield epilogue",         0x00868f70u, 0xe28dd024u},
        {"Pump return",                 0x00868f74u, 0xe8bd8ff0u},
        {"pthread wrapper start",       0x009cb6d0u, 0xe92d4010u},
        {"pthread wrapper entry load",  0x009cb6d8u, 0xe5941000u},
        {"pthread wrapper this load",   0x009cb6dcu, 0xe5940004u},
        {"pthread wrapper BLX",         0x009cb6e0u, 0xe12fff31u},
        {"resource worker start",       0x00abd894u, 0xe92d48f0u},
        {"resource worker global load", 0x00abd8ecu, 0xe5970000u},
        {"resource worker +0x64c",      0x00abd8f0u, 0xe590064cu},
        {"resource worker pump call",   0x00abd8f4u, 0xebf6aca0u},
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

struct TaskResourceStaticAudit {
    bool template_symbol_present = false;
    bool producer_profile_match = false;
    bool vtable_profile_match = false;
    std::uint32_t vtable_offset = 0x00cd0d88u;
    std::uint32_t vfn14_raw = 0u;
    std::uint32_t vfn18_raw = 0u;
    std::uint32_t vfn3c_raw = 0u;
    std::string text;
};

TaskResourceStaticAudit AuditTaskResourceStatic(
    const Elf32Arm& elf) {

    TaskResourceStaticAudit a;

    static const std::string kTemplateSymbol =
        "_ZNSt6vectorIPN4Sexy17IResStreamsDriver12TaskResourceESaIS3_EE19_M_emplace_back_auxIJS3_EEEvDpOT_";

    for (const auto& sym : elf.symbols()) {
        if (sym.name == kTemplateSymbol &&
            (sym.value & ~1u) == 0x00abe654u) {
            a.template_symbol_present = true;
            break;
        }
    }

    // Two direct producer paths allocate 24-byte TaskResource objects and
    // compute the same vtable address before storing it into object+0.
    a.producer_profile_match =
        HasWordAt(elf, 0x00abd5f8u, 0xe59f01ecu) &&
        HasWordAt(elf, 0x00abd604u, 0xe08f0000u) &&
        HasWordAt(elf, 0x00abd61cu, 0xe280b008u) &&
        HasWordAt(elf, 0x00abd650u, 0xe587b000u) &&
        HasWordAt(elf, 0x00abd6acu, 0xe59f0144u) &&
        HasWordAt(elf, 0x00abd6bcu, 0xe08f0000u) &&
        HasWordAt(elf, 0x00abd6d4u, 0xe280a008u) &&
        HasWordAt(elf, 0x00abd700u, 0xe587a000u) &&
        HasWordAt(elf, 0x00abd7ecu, 0x002444f8u) &&
        HasWordAt(elf, 0x00abd7f4u, 0xfffcf27cu) &&
        HasWordAt(elf, 0x00abd7f8u, 0x00244440u);

    const auto slot14 =
        elf.Read(a.vtable_offset + 0x14u, 4u);
    const auto slot18 =
        elf.Read(a.vtable_offset + 0x18u, 4u);
    const auto slot3c =
        elf.Read(a.vtable_offset + 0x3cu, 4u);

    if (slot14.size() == 4u) {
        a.vfn14_raw = U32(slot14.data());
    }
    if (slot18.size() == 4u) {
        a.vfn18_raw = U32(slot18.data());
    }
    if (slot3c.size() == 4u) {
        a.vfn3c_raw = U32(slot3c.data());
    }

    a.vtable_profile_match =
        a.vfn14_raw == 0x00abede0u &&
        a.vfn18_raw == 0x00abf23cu &&
        a.vfn3c_raw == 0x00ac0984u;

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.4 - TaskResource static audit\n"
        << "====================================================\n"
        << "vector<TaskResource*> template symbol: "
        << (a.template_symbol_present ? "MATCH" : "NOT FOUND")
        << " @ "
        << Hex(kGuestBase + 0x00abe654u)
        << "\n"
        << "direct producer/vptr construction profile: "
        << (a.producer_profile_match ? "MATCH" : "MISMATCH")
        << "\n"
        << "assigned TaskResource vtable: "
        << Hex(kGuestBase + a.vtable_offset)
        << " section="
        << elf.SectionName(a.vtable_offset)
        << "\n"
        << "expected relocated virtual slots:\n"
        << "  +0x14 -> "
        << Hex(kGuestBase + a.vfn14_raw)
        << "\n"
        << "  +0x18 -> "
        << Hex(kGuestBase + a.vfn18_raw)
        << "\n"
        << "  +0x3c -> "
        << Hex(kGuestBase + a.vfn3c_raw)
        << "\n"
        << "vtable slot profile: "
        << (a.vtable_profile_match ? "MATCH" : "MISMATCH")
        << "\n\n"
        << "The resource-stream pump consumes pointers from manager+0x50/"
        << "+0x54 as IResStreamsDriver::TaskResource*. The v61 crash log "
        << "does not contain [r7], so the runtime object's actual vtable "
        << "pointer is still unknown. The next probe should capture it before "
        << "the BLX rather than guessing corruption.\n";

    a.text = out.str();
    return a;
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

std::optional<double> ParseDoubleAfter(
    const std::string& line,
    const std::string& marker) {

    const std::size_t pos = line.find(marker);
    if (pos == std::string::npos) return std::nullopt;
    const std::size_t begin = pos + marker.size();
    std::size_t end = begin;

    while (end < line.size()) {
        const char ch = line[end];
        const bool ok =
            std::isdigit(static_cast<unsigned char>(ch)) != 0 ||
            ch == '.' || ch == '-' || ch == '+' ||
            ch == 'e' || ch == 'E';
        if (!ok) break;
        ++end;
    }

    if (end == begin) return std::nullopt;
    try {
        return std::stod(line.substr(begin, end - begin));
    } catch (...) {
        return std::nullopt;
    }
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


struct V109FramePerf {
    std::uint64_t frame = 0u;
    double guest_ms = 0.0;
    double main_ms = 0.0;
    double wait_ms = 0.0;
    double boundary_ms = 0.0;
    double font_ms = 0.0;
    double present_ms = 0.0;
    double active_ms = 0.0;
    std::uint64_t alloc_calls = 0u;
    std::uint64_t alloc_scan_steps = 0u;
    std::uint64_t input_events = 0u;
    std::string source_line;
};

struct V109AudioPerformanceAnalysis {
    bool present = false;
    std::string summary_line;
    std::string diagnosis;
    std::string stalls_csv;
    std::string next_probe_plan;
    std::string critical_excerpt;
};

std::optional<double> ParseWorkerMs(
    const std::string& line,
    std::uint32_t tid) {

    const std::size_t workers = line.find("workers={");
    if (workers == std::string::npos) return std::nullopt;

    const std::string marker = std::to_string(tid) + ":";
    const std::size_t pos = line.find(marker, workers);
    if (pos == std::string::npos) return std::nullopt;

    const std::size_t begin = pos + marker.size();
    std::size_t end = begin;
    while (end < line.size()) {
        const char ch = line[end];
        if (!(std::isdigit(static_cast<unsigned char>(ch)) != 0 ||
              ch == '.' || ch == '-' || ch == '+' ||
              ch == 'e' || ch == 'E')) {
            break;
        }
        ++end;
    }
    if (end == begin) return std::nullopt;

    try {
        return std::stod(line.substr(begin, end - begin));
    } catch (...) {
        return std::nullopt;
    }
}

const Symbol* FindExactSymbol(
    const Elf32Arm& elf,
    const std::string& name) {

    for (const auto& symbol : elf.symbols()) {
        if (symbol.name == name &&
            symbol.shndx != 0u &&
            symbol.size != 0u) {
            return &symbol;
        }
    }
    return nullptr;
}

std::string AudioBucketForSymbol(
    const std::string& name) {

    if (name.find("Vorbis") != std::string::npos ||
        name.find("vorbis_") != std::string::npos ||
        name.find("mdct_") != std::string::npos ||
        name.find("floor1_") != std::string::npos ||
        name.find("res_inverse") != std::string::npos ||
        name.find("book_decode") != std::string::npos ||
        name.find("DecodeVorbis") != std::string::npos) {
        return "vorbis_decode";
    }
    if (name.find("Resampler") != std::string::npos ||
        name.find("VPLPitchNode") != std::string::npos) {
        return "resampler_pitch";
    }
    if (name.find("VPL") != std::string::npos ||
        name.find("LEngine") != std::string::npos) {
        return "mixer_vpl";
    }
    if (name.find("AudioMgr") != std::string::npos ||
        name.find("AudioThread") != std::string::npos) {
        return "audio_mgr_scheduler";
    }
    return "other";
}

std::vector<std::uint32_t> DirectArmBlTargets(
    const Elf32Arm& elf,
    const Symbol& symbol) {

    std::vector<std::uint32_t> out;
    const std::uint32_t start = symbol.value & ~1u;

    if ((symbol.value & 1u) != 0u || symbol.size < 4u) {
        return out;
    }

    const auto bytes = elf.Read(start, symbol.size);
    for (std::size_t i = 0u; i + 4u <= bytes.size(); i += 4u) {
        const std::uint32_t word = U32(bytes.data() + i);
        if ((word & 0x0f000000u) != 0x0b000000u) {
            continue;
        }

        const std::int32_t delta =
            SignExtend(word & 0x00ffffffu, 24) << 2;
        const std::uint32_t pc =
            start + static_cast<std::uint32_t>(i);
        const std::uint32_t target =
            static_cast<std::uint32_t>(
                static_cast<std::int64_t>(pc) +
                8ll +
                static_cast<std::int64_t>(delta)) &
            ~1u;

        if (target < elf.image_end() && elf.IsExecutable(target)) {
            out.push_back(target);
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::string BuildWwiseAudioStaticCallGraph(
    const Elf32Arm& elf) {

    const std::vector<std::pair<const char*, const char*>> focus = {
        {"CAkAudioThread::EventMgrThreadFunc", "_ZN14CAkAudioThread18EventMgrThreadFuncEPv"},
        {"CAkAudioMgr::Perform", "_ZN11CAkAudioMgr7PerformEv"},
        {"CAkLEngine::Perform", "_ZN10CAkLEngine7PerformEv"},
        {"CAkLEngine::SequencerVoiceFilling", "_ZN10CAkLEngine21SequencerVoiceFillingEv"},
        {"CAkLEngine::GetBuffer", "_ZN10CAkLEngine9GetBufferEv"},
        {"CAkLEngine::RunVPL", "_ZN10CAkLEngine6RunVPLER12AkRunningVPL"},
        {"CAkVPLSrcCbxNode::StartRun", "_ZN16CAkVPLSrcCbxNode8StartRunER10AkVPLState"},
        {"CAkVPLSrcCbxNode::ConsumeBuffer", "_ZN16CAkVPLSrcCbxNode13ConsumeBufferER10AkVPLState"},
        {"CAkVPLPitchNode::ConsumeBuffer", "_ZN15CAkVPLPitchNode13ConsumeBufferER10AkVPLState"},
        {"CAkVPLMixBusNode::ConsumeBuffer", "_ZN16CAkVPLMixBusNode13ConsumeBufferER10AkVPLStateP10AkAudioMix"},
        {"CAkResampler::Execute", "_ZN12CAkResampler7ExecuteEP13AkAudioBufferS1_"},
        {"CAkSrcBankVorbis::GetBuffer", "_ZN16CAkSrcBankVorbis9GetBufferER10AkVPLState"},
        {"CAkSrcFileVorbis::GetBuffer", "_ZN16CAkSrcFileVorbis9GetBufferER10AkVPLState"},
        {"DecodeVorbis", "_Z12DecodeVorbisP12AkTremorInfotPhPs"},
        {"vorbis_dsp_pcmout", "_Z17vorbis_dsp_pcmoutP16vorbis_dsp_statePsi"},
        {"vorbis_dsp_synthesis", "_Z20vorbis_dsp_synthesisP16vorbis_dsp_stateP10ogg_packet"},
        {"mapping_inverse", "_Z15mapping_inverseP16vorbis_dsp_stateP19vorbis_info_mapping"},
        {"res_inverse", "_Z11res_inverseP16vorbis_dsp_stateP19vorbis_info_residuePPiS3_i"},
        {"floor1_inverse1", "_Z15floor1_inverse1P16vorbis_dsp_stateP18vorbis_info_floor1Pi"},
        {"floor1_inverse2", "_Z15floor1_inverse2P16vorbis_dsp_stateP18vorbis_info_floor1PiS3_"},
        {"mdct_backward", "_Z13mdct_backwardiPf"},
        {"ak_vorbis_book_decode", "_Z21ak_vorbis_book_decodeP8codebookP14oggpack_buffer"}
    };

    std::map<std::uint32_t, std::string> names;
    std::map<std::string, const Symbol*> symbols;

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v2.4-alpha - Wwise audio static call graph\n"
        << "================================================================\n"
        << "Source: exact APK lib/armeabi-v7a/libPVZ2.so.\n"
        << "Direct ARM BL edges are static evidence; they do not measure runtime time.\n\n"
        << "FOCUS SYMBOLS\n"
        << "-------------\n";

    for (const auto& item : focus) {
        const Symbol* sym = FindExactSymbol(elf, item.second);
        if (sym == nullptr) {
            out << "[MISSING] " << item.first
                << " / " << item.second << "\n";
            continue;
        }

        const std::uint32_t off = sym->value & ~1u;
        names[off] = item.first;
        symbols[item.first] = sym;

        out
            << "[" << AudioBucketForSymbol(sym->name) << "] "
            << item.first
            << " ELF=" << Hex(off)
            << " runtime=" << Hex(kGuestBase + off)
            << " size=" << sym->size
            << " mangled=" << sym->name
            << "\n";
    }

    out
        << "\nDIRECT BL EDGES AMONG FOCUS FUNCTIONS\n"
        << "------------------------------------\n";

    std::size_t edge_count = 0u;
    for (const auto& item : focus) {
        const auto it = symbols.find(item.first);
        if (it == symbols.end()) continue;

        const auto targets = DirectArmBlTargets(elf, *it->second);
        for (const auto target : targets) {
            auto named = names.find(target);
            if (named == names.end()) continue;
            out << item.first << " -> " << named->second << "\n";
            ++edge_count;
        }
    }

    if (edge_count == 0u) {
        out << "(no direct focus-to-focus BL edges resolved)\n";
    }

    out
        << "\nKNOWN PIPELINE TO CORRELATE WITH RUNTIME tid5 PCs\n"
        << "-------------------------------------------------\n"
        << "EventMgrThreadFunc -> CAkAudioMgr::Perform -> CAkLEngine::Perform\n"
        << "  -> SequencerVoiceFilling/GetBuffer -> RunVPL\n"
        << "  -> VPL source/pitch/mix nodes\n"
        << "  -> CAkResampler::Execute (pitch/resample path)\n"
        << "  -> CAkSrcBank/FileVorbis::GetBuffer -> DecodeVorbis\n"
        << "  -> vorbis_dsp_synthesis -> mapping_inverse\n"
        << "  -> floor/residue -> mdct_backward (decode path)\n\n"
        << "v109 runtime already sampled tid5 inside mdct_backward during a severe stall.\n"
        << "The next runtime probe should TIME/BUCKET tid5 PCs rather than trap every DSP call.\n";

    return out.str();
}

V109AudioPerformanceAnalysis AnalyzeV109AudioRuntime(
    const std::string& log,
    const Elf32Arm& elf) {

    V109AudioPerformanceAnalysis a;
    a.present =
        log.find("V109_LEAN_AUDIO_PERFORMANCE") != std::string::npos ||
        log.find("PvZ2 v109 Lean Audio Performance") != std::string::npos;
    if (!a.present) return a;

    std::map<std::uint64_t, std::uint64_t> inputs_by_frame;
    std::vector<V109FramePerf> frames;
    std::vector<std::string> handshake_lines;
    std::map<std::string, std::uint64_t> handshake_pc_buckets;
    std::uint64_t handshake_total = 0u;
    std::uint64_t handshake_code = 0u;
    std::uint64_t handshake_blocked = 0u;

    std::string first_pacer;
    std::string last_pacer;
    std::string frame_summary;
    std::string mutex_summary;
    std::string input_summary;

    std::istringstream stream(log);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.find("V85 PERF input stage=UI_ProcessEvents frame=") != std::string::npos) {
            if (const auto frame = ParseUnsignedAfter(line, "frame=")) {
                ++inputs_by_frame[*frame];
            }
        }

        if (line.find("V90 FRAME frame=") != std::string::npos) {
            V109FramePerf f;
            const auto frame = ParseUnsignedAfter(line, "frame=");
            if (!frame) continue;
            f.frame = *frame;
            f.guest_ms = ParseDoubleAfter(line, "guestMs=").value_or(0.0);
            f.main_ms = ParseDoubleAfter(line, "mainApproxMs=").value_or(0.0);
            f.wait_ms = ParseDoubleAfter(line, "waitWorkerMs=").value_or(0.0);
            f.boundary_ms = ParseDoubleAfter(line, "boundaryWorkerMs=").value_or(0.0);
            f.font_ms = ParseDoubleAfter(line, "fontMs=").value_or(0.0);
            f.present_ms = ParseDoubleAfter(line, "presentMs=").value_or(0.0);
            f.active_ms = ParseDoubleAfter(line, "activeFrameMs=").value_or(0.0);
            f.alloc_calls = ParseUnsignedAfter(line, "allocCalls=").value_or(0u);
            f.alloc_scan_steps = ParseUnsignedAfter(line, "allocScanSteps=").value_or(0u);
            f.source_line = line;
            frames.push_back(std::move(f));
        }

        if (line.find("V102 AUDIO PACER") != std::string::npos) {
            if (first_pacer.empty()) first_pacer = line;
            last_pacer = line;
        }

        if (line.find("V104 AUDIO HANDSHAKE") != std::string::npos) {
            ++handshake_total;
            if (line.find("blocked=YES") != std::string::npos) {
                ++handshake_blocked;
            }
            if (handshake_lines.size() < 64u) {
                handshake_lines.push_back(line);
            }

            if (const auto pc = ParseUnsignedAfter(line, "PC=0x", 16)) {
                const auto classified =
                    Classify(static_cast<std::uint32_t>(*pc), elf);
                if (classified.region == "libPVZ2.so" &&
                    classified.offset && classified.executable) {
                    ++handshake_code;
                    const auto nearest = elf.NearestSymbol(*classified.offset);
                    const std::string key =
                        nearest
                            ? nearest->first.name
                            : ("ELF+" + Hex(*classified.offset));
                    ++handshake_pc_buckets[key];
                } else {
                    ++handshake_pc_buckets[classified.region];
                }
            }
        }

        if (line.find("V90 FRAME SUMMARY") != std::string::npos) {
            frame_summary = line;
        }
        if (line.find("V87 MUTEX SUMMARY") != std::string::npos) {
            mutex_summary = line;
        }
        if (line.find("V72 INTERACTIVE SUMMARY") != std::string::npos) {
            input_summary = line;
        }
    }

    for (auto& frame : frames) {
        frame.input_events = inputs_by_frame[frame.frame];
    }

    std::sort(frames.begin(), frames.end(),
        [](const V109FramePerf& lhs, const V109FramePerf& rhs) {
            return lhs.frame < rhs.frame;
        });

    const auto classify_frame = [](const V109FramePerf& f) {
        if (f.guest_ms <= 0.0) return std::string{"unknown"};
        const double wait_pct = 100.0 * f.wait_ms / f.guest_ms;
        const double main_pct = 100.0 * f.main_ms / f.guest_ms;
        const double font_pct = 100.0 * f.font_ms / f.guest_ms;
        if (f.font_ms >= 100.0 && font_pct >= 50.0) {
            return std::string{"font_main_load"};
        }
        if (wait_pct >= 60.0) {
            return std::string{"audio_worker_dominant"};
        }
        if (main_pct >= 70.0) {
            return std::string{"main_dominant"};
        }
        return std::string{"mixed"};
    };

    std::vector<V109FramePerf> stalls;
    for (const auto& f : frames) {
        if (f.guest_ms >= 150.0 || f.wait_ms >= 100.0) {
            stalls.push_back(f);
        }
    }

    std::ostringstream csv;
    csv << "frame,guestMs,mainApproxMs,waitWorkerMs,boundaryWorkerMs,"
        << "fontMs,presentMs,activeFrameMs,waitPct,mainPct,"
        << "allocCalls,allocScanSteps,inputEvents,classification\n";

    for (const auto& f : stalls) {
        const double wait_pct =
            f.guest_ms > 0.0 ? 100.0 * f.wait_ms / f.guest_ms : 0.0;
        const double main_pct =
            f.guest_ms > 0.0 ? 100.0 * f.main_ms / f.guest_ms : 0.0;

        csv << f.frame << ","
            << std::fixed << std::setprecision(3)
            << f.guest_ms << ","
            << f.main_ms << ","
            << f.wait_ms << ","
            << f.boundary_ms << ","
            << f.font_ms << ","
            << f.present_ms << ","
            << f.active_ms << ","
            << wait_pct << ","
            << main_pct << ","
            << f.alloc_calls << ","
            << f.alloc_scan_steps << ","
            << f.input_events << ","
            << classify_frame(f) << "\n";
    }
    a.stalls_csv = csv.str();

    struct Cluster {
        std::uint64_t first = 0u;
        std::uint64_t last = 0u;
        std::size_t count = 0u;
        double guest = 0.0;
        double main = 0.0;
        double wait = 0.0;
        double present = 0.0;
        std::uint64_t inputs = 0u;
    };

    std::vector<Cluster> clusters;
    for (const auto& f : stalls) {
        if (clusters.empty() || f.frame > clusters.back().last + 3u) {
            clusters.push_back(
                Cluster{f.frame, f.frame, 0u, 0.0, 0.0, 0.0, 0.0, 0u});
        }
        auto& c = clusters.back();
        c.last = f.frame;
        ++c.count;
        c.guest += f.guest_ms;
        c.main += f.main_ms;
        c.wait += f.wait_ms;
        c.present += f.present_ms;
        c.inputs += f.input_events;
    }

    auto slowest = stalls;
    std::sort(slowest.begin(), slowest.end(),
        [](const V109FramePerf& lhs, const V109FramePerf& rhs) {
            if (lhs.guest_ms != rhs.guest_ms) return lhs.guest_ms > rhs.guest_ms;
            return lhs.frame < rhs.frame;
        });

    const std::uint64_t total_frames =
        ParseUnsignedAfter(frame_summary, "frames=").value_or(0u);
    const double guest_total =
        ParseDoubleAfter(frame_summary, "guestTotalMs=").value_or(0.0);
    const double wait_total =
        ParseDoubleAfter(frame_summary, "waitWorkerTotalMs=").value_or(0.0);

    double present_total = 0.0;
    const std::size_t present_pos = frame_summary.find("present{");
    if (present_pos != std::string::npos) {
        present_total =
            ParseDoubleAfter(frame_summary.substr(present_pos), "totalMs=").value_or(0.0);
    }

    double worker_total = 0.0;
    for (std::uint32_t tid = 1u; tid <= 6u; ++tid) {
        worker_total += ParseWorkerMs(frame_summary, tid).value_or(0.0);
    }
    const double tid5 = ParseWorkerMs(frame_summary, 5u).value_or(0.0);
    const double tid5_share =
        worker_total > 0.0 ? 100.0 * tid5 / worker_total : 0.0;

    std::ostringstream diagnosis;
    diagnosis
        << "PvZ2 Inspector Lab v2.4-alpha - v109 audio performance diagnosis\n"
        << "==================================================================\n"
        << "Source: v109 V90/V102/V104/V85 runtime telemetry + exact Android ELF.\n\n"
        << "GLOBAL\n"
        << "------\n"
        << "frames: " << total_frames << "\n"
        << "guestTotalMs: " << std::fixed << std::setprecision(3) << guest_total << "\n"
        << "waitWorkerTotalMs: " << wait_total << "\n"
        << "waitWorker / guest total: "
        << (guest_total > 0.0 ? 100.0 * wait_total / guest_total : 0.0) << "%\n"
        << "tid5 / CAkAudioThread worker ms: " << tid5 << "\n"
        << "tid5 share of recorded worker ms: " << tid5_share << "%\n"
        << "present total ms: " << present_total << "\n"
        << "logged V90 frame samples: " << frames.size() << "\n"
        << "slow/stall samples exported: " << stalls.size() << "\n\n"
        << "STALL CLUSTERS (logged slow frames, gap <= 3)\n"
        << "--------------------------------------------\n";

    for (const auto& c : clusters) {
        if (c.count == 0u) continue;
        diagnosis << "frames " << c.first;
        if (c.last != c.first) diagnosis << "-" << c.last;
        diagnosis
            << " count=" << c.count
            << " avgGuestMs=" << (c.guest / c.count)
            << " waitPct=" << (c.guest > 0.0 ? 100.0 * c.wait / c.guest : 0.0)
            << " mainPct=" << (c.guest > 0.0 ? 100.0 * c.main / c.guest : 0.0)
            << " presentPct=" << (c.guest > 0.0 ? 100.0 * c.present / c.guest : 0.0)
            << " inputEvents=" << c.inputs << "\n";
    }

    diagnosis
        << "\nV104 HANDSHAKE SAMPLING QUALITY\n"
        << "-------------------------------\n"
        << "samples: " << handshake_total << "\n"
        << "blocked samples: " << handshake_blocked << "\n"
        << "samples whose PC resolves to libPVZ2 code: " << handshake_code << "\n";
    for (const auto& item : handshake_pc_buckets) {
        diagnosis << "  " << item.second << "x " << item.first << "\n";
    }

    diagnosis << "\nAUDIO PACER\n-----------\n";
    if (!first_pacer.empty()) diagnosis << "first: " << first_pacer << "\n";
    if (!last_pacer.empty()) diagnosis << "last:  " << last_pacer << "\n";

    diagnosis
        << "\nSCHEDULER / INPUT TERMINAL EVIDENCE\n"
        << "----------------------------------\n";
    if (!mutex_summary.empty()) diagnosis << mutex_summary << "\n";
    if (!input_summary.empty()) diagnosis << input_summary << "\n";

    diagnosis
        << "\nINTERPRETATION\n"
        << "--------------\n"
        << "1. If tid5 remains near all recorded worker time while GPU present is small, "
           "the recurring gameplay stalls are not a presentation bottleneck.\n"
        << "2. Stable 32 kHz pacer + stable underrun count during low-load periods "
           "separates callback cadence from expensive Wwise work.\n"
        << "3. A libPVZ2 code sample inside mdct_backward during a waitWorker-heavy "
           "frame proves real AkVorbis/MDCT work can sit on the frame's critical path.\n"
        << "4. The sparse V104 power-of-two handshake samples are enough for proof-of-presence, "
           "not enough to estimate where tid5 spends its time.\n";
    a.diagnosis = diagnosis.str();

    std::ostringstream excerpt;
    excerpt
        << "PvZ2 Inspector v2.4-alpha - v109 critical audio/stall excerpt\n"
        << "================================================================\n\n"
        << "FINAL FRAME SUMMARY\n"
        << frame_summary << "\n\n"
        << "TOP SLOW FRAMES\n";
    const std::size_t slow_cap = std::min<std::size_t>(slowest.size(), 30u);
    for (std::size_t i = 0u; i < slow_cap; ++i) {
        excerpt << slowest[i].source_line << "\n";
    }
    excerpt << "\nV104 HANDSHAKE SAMPLES\n";
    for (const auto& item : handshake_lines) excerpt << item << "\n";
    a.critical_excerpt = excerpt.str();

    std::ostringstream plan;
    plan
        << "PvZ2 Inspector Lab v2.4-alpha - next audio probe plan\n"
        << "=====================================================\n\n"
        << "DO NOT retune the scheduler yet. The missing datum is the time distribution "
           "inside tid5 / CAkAudioThread.\n\n"
        << "LOW-OVERHEAD RUNTIME PROBE\n"
        << "--------------------------\n"
        << "1. Instrument the host scheduler, not Wwise functions: whenever tid5 receives "
           "a cooperative execution quantum, accumulate host wall time plus start/end guest PC/LR.\n"
        << "2. Bucket PCs by the exact ELF function ranges exported in "
           "wwise-audio-static-callgraph.txt: audio manager, VPL/mixer, resampler/pitch, "
           "Vorbis/MDCT, other.\n"
        << "3. Maintain per-frame audioWorkerMs and audioQuanta counters. Emit a line only "
           "for slow frames (for example guest>=100 ms or audioWorker>=50 ms) plus one terminal histogram.\n"
        << "4. Do not reinstall v105 SVC traps and do not log every DecodeVorbis/MDCT call. "
           "The probe must be cheaper than the work being measured.\n"
        << "5. Preserve v106 32 kHz, v107 semaphore repair, v108 bank liveness and all v109 stability behavior.\n\n"
        << "DECISION RULE\n"
        << "-------------\n"
        << "- Vorbis/MDCT dominates: investigate native/offloaded decode or larger-grain audio scheduling.\n"
        << "- VPL/mixer/resampler dominates: optimize/parallelize that worker path first.\n"
        << "- large host time but PCs stay near scheduler/wait glue: fix cooperative scheduling overhead.\n"
        << "- mixed: use the per-frame histogram to target the seed-packet and animation bursts separately.\n";
    a.next_probe_plan = plan.str();

    std::ostringstream summary;
    summary
        << "v109 audio: frames=" << total_frames
        << " tid5Share=" << std::fixed << std::setprecision(1)
        << tid5_share << "%"
        << " stalls=" << stalls.size()
        << " V104CodeSamples=" << handshake_code
        << "/" << handshake_total;
    a.summary_line = summary.str();

    return a;
}



std::vector<std::uint32_t> FindExactAsciiVaddrs(
    const Elf32Arm& elf,
    const std::string& text) {

    std::vector<std::uint32_t> out;
    if (text.empty()) return out;

    const auto& bytes = elf.data();
    const auto* first =
        reinterpret_cast<const std::uint8_t*>(text.data());
    const auto* last = first + text.size();

    auto it = bytes.begin();
    while (it != bytes.end()) {
        it = std::search(it, bytes.end(), first, last);
        if (it == bytes.end()) break;

        const std::size_t off =
            static_cast<std::size_t>(
                std::distance(bytes.begin(), it));

        const bool terminates =
            off + text.size() < bytes.size() &&
            bytes[off + text.size()] == 0u;
        const bool begins =
            off == 0u ||
            bytes[off - 1u] == 0u ||
            bytes[off - 1u] < 0x20u ||
            bytes[off - 1u] > 0x7eu;

        if (terminates && begins) {
            if (const auto va = elf.FileToVaddr(off)) {
                out.push_back(*va);
            }
        }
        ++it;
    }
    return out;
}

struct UiScaleRuntimeAnalysis {
    bool present = false;
    bool ui_ipad = false;
    bool ui_android = false;
    bool mainmenu_1536 = false;
    bool can_set_false = false;

    std::uint32_t orig_width = 0u;
    std::uint32_t orig_height = 0u;
    std::uint32_t width = 0u;
    std::uint32_t height = 0u;
    double content_width = 0.0;
    double content_height = 0.0;
    std::uint64_t stop_frame = 0u;

    std::string diagnosis;
    std::string static_markers;
    std::string next_plan;
    std::string critical_excerpt;
};

UiScaleRuntimeAnalysis AnalyzeUiScaleRuntime(
    const std::string& log,
    const Elf32Arm& elf) {

    UiScaleRuntimeAnalysis a;

    const std::string orig =
        LastLineContaining(
            log,
            "LawnApp::SetWidthHeight mOrigScreenWidth");
    const std::string active =
        LastLineContaining(
            log,
            "LawnApp::SetWidthHeight mWidth");
    const std::string content =
        LastLineContaining(
            log,
            "LawnApp::SetWidthHeight m_contentResolutionWidth");

    a.present =
        !orig.empty() ||
        !active.empty() ||
        !content.empty();

    if (const auto v = ParseUnsignedAfter(orig, "mOrigScreenWidth = ")) {
        a.orig_width = static_cast<std::uint32_t>(*v);
    }
    if (const auto v = ParseUnsignedAfter(orig, "mOrigScreenHeight = ")) {
        a.orig_height = static_cast<std::uint32_t>(*v);
    }
    if (const auto v = ParseUnsignedAfter(active, "mWidth = ")) {
        a.width = static_cast<std::uint32_t>(*v);
    }
    if (const auto v = ParseUnsignedAfter(active, "mHeight = ")) {
        a.height = static_cast<std::uint32_t>(*v);
    }
    if (const auto v =
            ParseDoubleAfter(content, "m_contentResolutionWidth = ")) {
        a.content_width = *v;
    }
    if (const auto v =
            ParseDoubleAfter(content, "m_contentResolutionHeight = ")) {
        a.content_height = *v;
    }

    a.ui_ipad =
        log.find("RESFILE_PACKAGES_UI_IPAD") != std::string::npos;
    a.ui_android =
        log.find("id=\"RESFILE_PACKAGES_UI_ANDROID\"") != std::string::npos;
    a.mainmenu_1536 =
        log.find("UI_MainMenu_1536") != std::string::npos;
    a.can_set_false =
        log.find("Graphics_CanSetGLViewScaleFactor -> false") !=
        std::string::npos;

    const std::string stop =
        LastLineContaining(log, "INTERACTIVE STOP after frame ");
    if (const auto v =
            ParseUnsignedAfter(stop, "INTERACTIVE STOP after frame ")) {
        a.stop_frame = *v;
    }

    const bool canonical_2048_1536 =
        std::abs(a.content_width - 2048.0) < 0.01 &&
        std::abs(a.content_height - 1536.0) < 0.01;

    const bool active_equals_content =
        canonical_2048_1536 &&
        a.width == 2048u &&
        a.height == 1536u;

    std::ostringstream diagnosis;
    diagnosis
        << "PvZ2 Inspector Lab v2.4-alpha - UI scale / content-resolution diagnosis\n"
        << "=======================================================================\n\n"
        << "RUNTIME GEOMETRY INSIDE LawnApp\n"
        << "-------------------------------\n"
        << "mOrigScreenWidth/Height: "
        << a.orig_width << "x" << a.orig_height << "\n"
        << "mWidth/mHeight: "
        << a.width << "x" << a.height << "\n"
        << "m_contentResolutionWidth/Height: "
        << std::fixed << std::setprecision(3)
        << a.content_width << "x" << a.content_height << "\n";

    if (a.content_width > 0.0 &&
        a.content_height > 0.0 &&
        a.width != 0u &&
        a.height != 0u) {
        diagnosis
            << "active/content scale X: "
            << (static_cast<double>(a.width) / a.content_width)
            << "\n"
            << "active/content scale Y: "
            << (static_cast<double>(a.height) / a.content_height)
            << "\n";
    }

    diagnosis
        << "\nUI / RESOURCE SIGNALS\n"
        << "---------------------\n"
        << "RESFILE_PACKAGES_UI_IPAD observed: "
        << (a.ui_ipad ? "YES" : "NO") << "\n"
        << "RESFILE_PACKAGES_UI_ANDROID runtime request observed: "
        << (a.ui_android ? "YES" : "NO") << "\n"
        << "UI_MainMenu_1536 observed: "
        << (a.mainmenu_1536 ? "YES" : "NO") << "\n"
        << "CanSetGLViewScaleFactor=false observed: "
        << (a.can_set_false ? "YES" : "NO") << "\n"
        << "interactive stop frame: "
        << a.stop_frame << "\n\n"
        << "DIAGNOSIS\n"
        << "---------\n";

    if (canonical_2048_1536) {
        diagnosis
            << "1. LawnApp keeps a canonical content coordinate basis of "
            << "2048x1536 in this run. This is stronger evidence than the host "
            << "FBO alone because the value is logged from LawnApp::SetWidthHeight.\n";
    } else {
        diagnosis
            << "1. The current log does not expose the expected 2048x1536 "
            << "content-resolution basis; do not apply the v78 hypothesis blindly.\n";
    }

    if (active_equals_content) {
        diagnosis
            << "2. In the v77/v78 legacy-iPad geometry A/B, mWidth/mHeight and "
            << "m_contentResolutionWidth/Height collapse to the SAME 2048x1536 "
            << "space. Yet the user-visible UI remains oversized. Changing only "
            << "the host surface or mWidth/mHeight is therefore a low-information axis.\n";
    }

    if (a.ui_ipad && a.mainmenu_1536) {
        diagnosis
            << "3. The run combines the iPad layout package with the 1536 UI "
            << "resource tier and still reproduces the visual problem. Package "
            << "selection and texture-tier selection are not sufficient causes by themselves.\n";
    }

    diagnosis
        << "4. The next unresolved layer is the engine HotUI virtual-layout "
        << "transform: VirtualWidth/VirtualHeight, SizeFromScreen, "
        << "ScalePositionOffset, ImmuneToDeviceScaling and the effective UI_S "
        << "mapping from virtual widget coordinates into the content space.\n"
        << "5. IMPORTANT: this does NOT prove that "
        << "m_contentResolutionWidth/Height itself is wrong. It identifies the "
        << "stable coordinate basis whose consumers must be traced before mutating it.\n";

    std::ostringstream static_report;
    static_report
        << "PvZ2 Inspector Lab v2.4-alpha - Android UI-scale static anchors\n"
        << "================================================================\n"
        << "Source: original APK lib/armeabi-v7a/libPVZ2.so.\n"
        << "These are reproducible string anchors; presence does not prove execution.\n\n";

    const std::array<const char*, 12> markers = {{
        " LawnApp::SetWidthHeight mOrigScreenWidth = %d mOrigScreenHeight = %d",
        " LawnApp::SetWidthHeight mWidth = %d mHeight = %d",
        " LawnApp::SetWidthHeight m_contentResolutionWidth = %f m_contentResolutionHeight = %f",
        "UIWidgetSheet",
        "VirtualWidth",
        "BoardScaledVirtualWidth",
        "VirtualHeight",
        "SizeFromScreen",
        "PositionOffset",
        "ScalePositionOffset",
        "ImmuneToDeviceScaling",
        "RtWeakPtr<UIWidgetSheet>"
    }};

    for (const char* marker : markers) {
        const auto locations =
            FindExactAsciiVaddrs(elf, marker);

        static_report << marker << ": ";
        if (locations.empty()) {
            static_report << "NOT FOUND\n";
            continue;
        }

        for (std::size_t i = 0; i < locations.size(); ++i) {
            if (i != 0u) static_report << ", ";
            static_report
                << "ELF " << Hex(locations[i])
                << " / runtime " << Hex(kGuestBase + locations[i])
                << " section=" << elf.SectionName(locations[i]);
        }
        static_report << "\n";
    }

    static_report
        << "\nSTATIC INTERPRETATION\n"
        << "---------------------\n"
        << "The same Android binary contains both the LawnApp content-resolution "
        << "diagnostics and the HotUI virtual-layout vocabulary. The next probe "
        << "should connect these anchors through bounded runtime provenance instead "
        << "of guessing another screen size.\n";

    std::ostringstream plan;
    plan
        << "PvZ2 Inspector Lab v2.4-alpha - proposed v79 UI-scale provenance probe\n"
        << "======================================================================\n\n"
        << "GOAL\n"
        << "----\n"
        << "Find the exact virtual-widget -> content-pixel transform responsible "
        << "for the oversized first-run UI. Do not change geometry until observed.\n\n"
        << "ONE BUILD, TWO CONTROL MODES\n"
        << "----------------------------\n"
        << "A. V75 control: modern native geometry + UI_IPAD.\n"
        << "B. V77 control: 1024x768 pt / 2048x1536 px + UI_IPAD.\n"
        << "Both modes share identical UI-scale instrumentation.\n\n"
        << "TRACE BATCH\n"
        << "-----------\n"
        << "1. In the __android_log_write shim, when text begins with "
        << "LawnApp::SetWidthHeight, record guest PC/LR, r0-r12 and lifecycle "
        << "phase. This gives SetWidthHeight caller provenance without string-xref guessing.\n"
        << "2. Once SetWidthHeight/object provenance is known, snapshot bounded "
        << "reads/writes around mOrigScreenWidth/Height, mWidth/mHeight and "
        << "m_contentResolutionWidth/Height during startup and first MainMenu frames.\n"
        << "3. Correlate HotUI initialization/layout with VirtualWidth, "
        << "VirtualHeight, SizeFromScreen, ScalePositionOffset, "
        << "BoardScaledVirtualWidth and ImmuneToDeviceScaling. Log the first "
        << "bounded caller PCs and numeric operands consuming content-resolution fields.\n"
        << "4. For one concrete first-run widget/container, capture virtual "
        << "dimensions/position, effective scalar(s), and final pixel rectangle. "
        << "Target the name/Facebook/EULA screen; do not assume it belongs to "
        << "UI_MainMenu until provenance proves it.\n"
        << "5. Keep V78LIVE, touch/keyboard, scheduler, zlib and ETC1 as "
        << "regression guards; sample new UI traces to avoid hot-loop log spam.\n\n"
        << "DECISION AFTER v79\n"
        << "------------------\n"
        << "- Same virtual rect + same scalar in V75/V77: geometry is non-causal; "
        << "fix the HotUI scale source.\n"
        << "- Different scalar but same final rect: trace the downstream canonical clamp.\n"
        << "- Correct scalar but oversized virtual rect: inspect the concrete RTON layout.\n"
        << "- Only after identifying the responsible transform/value should a "
        << "corrective A/B mode alter it.\n";

    std::ostringstream excerpt;
    excerpt
        << "PvZ2 Inspector v2.3-alpha - UI-scale critical runtime evidence\n"
        << "================================================================\n";
    for (const auto& line : {orig, active, content}) {
        if (!line.empty()) excerpt << line << "\n";
    }

    const std::array<std::string, 7> evidence_needles = {{
        "V75 UI PACKAGE REMAP:",
        "V50 RESOURCE MILESTONE frame=0 id=\"RESFILE_PACKAGES_UI_IPAD\"",
        "Graphics_GetScreenSizeInPixels ->",
        "Graphics_GetScreenSizeInPoints ->",
        "V47 GLES FBO ATTACH",
        "UI_MainMenu_1536",
        "V72 INTERACTIVE SUMMARY:"
    }};

    for (const auto& needle : evidence_needles) {
        const std::string line =
            LastLineContaining(log, needle);
        if (!line.empty()) excerpt << line << "\n";
    }

    a.diagnosis = diagnosis.str();
    a.static_markers = static_report.str();
    a.next_plan = plan.str();
    a.critical_excerpt = excerpt.str();
    return a;
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


std::optional<std::uint64_t> ParseUnsignedAfterView(
    std::string_view line,
    std::string_view marker,
    int base = 10) {

    const std::size_t pos = line.find(marker);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }

    std::size_t p = pos + marker.size();
    if (p >= line.size()) {
        return std::nullopt;
    }

    std::uint64_t value = 0u;
    bool any = false;

    for (; p < line.size(); ++p) {
        const unsigned char ch =
            static_cast<unsigned char>(line[p]);

        unsigned digit = 0u;
        bool valid = false;

        if (ch >= '0' && ch <= '9') {
            digit = static_cast<unsigned>(ch - '0');
            valid = true;
        } else if (base == 16 &&
                   ch >= 'a' && ch <= 'f') {
            digit = 10u + static_cast<unsigned>(ch - 'a');
            valid = true;
        } else if (base == 16 &&
                   ch >= 'A' && ch <= 'F') {
            digit = 10u + static_cast<unsigned>(ch - 'A');
            valid = true;
        }

        if (!valid || digit >= static_cast<unsigned>(base)) {
            break;
        }

        any = true;
        value =
            value * static_cast<unsigned>(base) +
            digit;
    }

    return any
        ? std::optional<std::uint64_t>{value}
        : std::nullopt;
}

std::string ExtractQuotedAfterView(
    std::string_view line,
    std::string_view marker) {

    const std::size_t pos = line.find(marker);
    if (pos == std::string_view::npos) {
        return {};
    }

    const std::size_t begin =
        pos + marker.size();
    const std::size_t end =
        line.find('"', begin);

    if (end == std::string_view::npos) {
        return {};
    }

    return std::string(
        line.substr(
            begin,
            end - begin));
}

std::string ContextAroundNeedle(
    const std::string& log,
    const std::string& needle,
    std::size_t before_lines,
    std::size_t after_lines) {

    const std::size_t hit = log.find(needle);
    if (hit == std::string::npos) {
        return {};
    }

    std::size_t begin = hit;
    for (std::size_t i = 0u;
         i < before_lines && begin > 0u;
         ++i) {
        const std::size_t search_from =
            begin >= 2u ? begin - 2u : 0u;
        const std::size_t nl =
            log.rfind('\n', search_from);
        if (nl == std::string::npos) {
            begin = 0u;
            break;
        }
        begin = nl + 1u;
    }

    std::size_t end = hit;
    for (std::size_t i = 0u;
         i <= after_lines && end < log.size();
         ++i) {
        const std::size_t nl =
            log.find('\n', end);
        if (nl == std::string::npos) {
            end = log.size();
            break;
        }
        end = nl + 1u;
    }

    return log.substr(
        begin,
        end - begin);
}

std::string TailLines(
    const std::string& log,
    std::size_t line_count) {

    if (log.empty()) {
        return {};
    }

    std::size_t begin = log.size();
    for (std::size_t i = 0u;
         i < line_count && begin > 0u;
         ++i) {
        const std::size_t search_from =
            begin >= 2u ? begin - 2u : 0u;
        const std::size_t nl =
            log.rfind('\n', search_from);
        if (nl == std::string::npos) {
            begin = 0u;
            break;
        }
        begin = nl + 1u;
    }

    return log.substr(begin);
}

std::string BuildLargeLogAddressSample(
    const std::string& log) {

    if (log.size() <= kLargeLogThreshold) {
        return log;
    }

    const std::size_t head =
        std::min<std::size_t>(
            log.size(),
            kLargeLogHeadBytes);
    const std::size_t tail =
        std::min<std::size_t>(
            log.size() - head,
            kLargeLogTailBytes);

    std::string sample;
    sample.reserve(
        head + tail + 256u);

    sample.append(
        log.data(),
        head);

    sample +=
        "\n[Inspector v1.4: middle of very large log omitted from generic "
        "address ranking; v61 targeted scan still covers the complete log]\n";

    if (tail != 0u) {
        sample.append(
            log.data() + log.size() - tail,
            tail);
    }

    return sample;
}

struct V61WorkerRuntime {
    std::uint32_t tid = 0u;
    bool payload_present = false;
    std::uint32_t entry = 0u;
    std::uint32_t this_ptr = 0u;
    std::uint32_t wrapper_arg = 0u;
    std::uint64_t slices = 0u;
    std::uint64_t slices_after_fault = 0u;
    std::uint64_t max_total_ticks = 0u;
    std::uint32_t last_pc = 0u;
    bool failed = false;
    bool returned = false;
};

struct V61CrashRuntime {
    bool present = false;
    std::uint32_t pc = 0u;
    std::uint32_t lr = 0u;
    std::uint32_t return_pc = 0u;
    std::uint32_t sp = 0u;
    std::uint32_t pthread_id = 0u;
    std::array<std::uint32_t, 13> regs{};
    std::string phase;
    std::string last_log;
    std::uint64_t line_number = 0u;
};

struct V61RuntimeDiagnosis {
    bool present = false;
    std::size_t source_log_bytes = 0u;
    std::uint64_t source_log_lines = 0u;
    std::uint64_t pump_boundaries = 0u;
    std::uint64_t pump_boundaries_at_fault = 0u;
    std::uint64_t pump_boundaries_after_fault = 0u;
    std::uint64_t pseudo_future_boundary_lines = 0u;
    std::uint64_t worker_slice_lines = 0u;
    bool success_step_present = false;
    bool dispatch_chain_consistent = false;
    bool worker_payload_matches = false;
    bool runaway_after_fault = false;
    bool boundary_future_snapshot_invalid = false;
    V61CrashRuntime crash;
    std::map<std::uint32_t, V61WorkerRuntime> workers;
    std::string text;
    std::string critical_excerpt;
};

V61RuntimeDiagnosis DiagnoseV61Runtime(
    const std::string& log,
    const Elf32Arm& elf,
    const V61ProfileValidation& static_profile,
    const TaskResourceStaticAudit& task_audit) {

    V61RuntimeDiagnosis d;
    d.source_log_bytes = log.size();

    if (log.find("V61 RES-STREAM") == std::string::npos &&
        log.find("V61 WORKER PAYLOAD") == std::string::npos) {
        return d;
    }

    d.present = true;
    d.success_step_present =
        log.find("SUCCESS STEP 3:") !=
        std::string::npos;

    bool fault_seen = false;

    std::size_t line_begin = 0u;
    std::uint64_t line_number = 0u;

    while (line_begin < log.size()) {
        std::size_t line_end =
            log.find('\n', line_begin);
        if (line_end == std::string::npos) {
            line_end = log.size();
        }

        ++line_number;
        const std::string_view line(
            log.data() + line_begin,
            line_end - line_begin);

        if (line.find(
                "kind=res-stream-pump-boundary") !=
            std::string_view::npos) {

            ++d.pump_boundaries;

            if (line.find(
                    "wait_object{future=") !=
                std::string_view::npos) {
                ++d.pseudo_future_boundary_lines;
            }
        }

        if (line.find(
                "V61 WORKER PAYLOAD tid=") !=
            std::string_view::npos) {

            const auto tid =
                ParseUnsignedAfterView(
                    line,
                    "tid=");

            if (tid) {
                auto& w =
                    d.workers[
                        static_cast<std::uint32_t>(*tid)];
                w.tid =
                    static_cast<std::uint32_t>(*tid);
                w.payload_present = true;

                if (const auto v =
                        ParseUnsignedAfterView(
                            line,
                            "entry=0x",
                            16)) {
                    w.entry =
                        static_cast<std::uint32_t>(*v);
                }
                if (const auto v =
                        ParseUnsignedAfterView(
                            line,
                            "this=0x",
                            16)) {
                    w.this_ptr =
                        static_cast<std::uint32_t>(*v);
                }
                if (const auto v =
                        ParseUnsignedAfterView(
                            line,
                            "wrapperArg=0x",
                            16)) {
                    w.wrapper_arg =
                        static_cast<std::uint32_t>(*v);
                }
            }
        }

        if (line.find(
                "V22 WORKER SLICE tid=") !=
            std::string_view::npos) {

            const auto tid =
                ParseUnsignedAfterView(
                    line,
                    "tid=");

            if (tid) {
                auto& w =
                    d.workers[
                        static_cast<std::uint32_t>(*tid)];
                w.tid =
                    static_cast<std::uint32_t>(*tid);
                ++w.slices;
                ++d.worker_slice_lines;

                if (fault_seen) {
                    ++w.slices_after_fault;
                }

                if (const auto v =
                        ParseUnsignedAfterView(
                            line,
                            "PC=0x",
                            16)) {
                    w.last_pc =
                        static_cast<std::uint32_t>(*v);
                }

                if (const auto v =
                        ParseUnsignedAfterView(
                            line,
                            "total_ticks=")) {
                    w.max_total_ticks =
                        std::max<std::uint64_t>(
                            w.max_total_ticks,
                            *v);
                }

                if (line.find("failed=YES") !=
                    std::string_view::npos) {
                    w.failed = true;
                }
                if (line.find("returned=YES") !=
                    std::string_view::npos) {
                    w.returned = true;
                }
            }
        }

        if (!d.crash.present &&
            line.find(
                "V23 EXCEPTION: Dynarmic exception NoExecuteFault") !=
                std::string_view::npos) {

            d.crash.present = true;
            d.crash.line_number = line_number;
            d.pump_boundaries_at_fault =
                d.pump_boundaries;
            fault_seen = true;

            if (const auto v =
                    ParseUnsignedAfterView(
                        line,
                        "PC=0x",
                        16)) {
                d.crash.pc =
                    static_cast<std::uint32_t>(*v);
            }
            if (const auto v =
                    ParseUnsignedAfterView(
                        line,
                        "LR=0x",
                        16)) {
                d.crash.lr =
                    static_cast<std::uint32_t>(*v);
            }
            if (const auto v =
                    ParseUnsignedAfterView(
                        line,
                        "returnPC=0x",
                        16)) {
                d.crash.return_pc =
                    static_cast<std::uint32_t>(*v);
            }
            if (const auto v =
                    ParseUnsignedAfterView(
                        line,
                        "SP=0x",
                        16)) {
                d.crash.sp =
                    static_cast<std::uint32_t>(*v);
            }
            if (const auto v =
                    ParseUnsignedAfterView(
                        line,
                        "pthread=")) {
                d.crash.pthread_id =
                    static_cast<std::uint32_t>(*v);
            }

            const std::size_t phase_pos =
                line.find("phase=");
            if (phase_pos !=
                std::string_view::npos) {
                const std::size_t begin =
                    phase_pos + 6u;
                std::size_t end = begin;
                while (end < line.size() &&
                       !std::isspace(
                           static_cast<unsigned char>(
                               line[end]))) {
                    ++end;
                }
                d.crash.phase =
                    std::string(
                        line.substr(
                            begin,
                            end - begin));
            }

            for (std::size_t i = 0u;
                 i < d.crash.regs.size();
                 ++i) {
                const std::string marker =
                    "r" +
                    std::to_string(i) +
                    "=0x";
                if (const auto v =
                        ParseUnsignedAfterView(
                            line,
                            marker,
                            16)) {
                    d.crash.regs[i] =
                        static_cast<std::uint32_t>(*v);
                }
            }

            d.crash.last_log =
                ExtractQuotedAfterView(
                    line,
                    "lastLog=\"");
        }

        if (line_end == log.size()) {
            break;
        }
        line_begin = line_end + 1u;
    }

    d.source_log_lines = line_number;

    if (d.crash.present &&
        d.pump_boundaries >=
            d.pump_boundaries_at_fault) {
        d.pump_boundaries_after_fault =
            d.pump_boundaries -
            d.pump_boundaries_at_fault;
    }

    d.boundary_future_snapshot_invalid =
        d.pseudo_future_boundary_lines != 0u;

    if (d.crash.present) {
        const auto& r = d.crash.regs;

        d.dispatch_chain_consistent =
            static_profile.exact_profile() &&
            d.crash.pc == r[1] &&
            d.crash.lr ==
                kGuestBase + 0x00868cbcu &&
            d.crash.return_pc ==
                d.crash.lr &&
            r[0] == r[7] &&
            r[5] == r[6] + 4u &&
            r[9] == r[4] + 0x5cu;

        const auto it =
            d.workers.find(
                d.crash.pthread_id);
        if (it != d.workers.end()) {
            d.worker_payload_matches =
                it->second.payload_present &&
                it->second.entry ==
                    kGuestBase + 0x00abd894u;
        }
    }

    d.runaway_after_fault =
        d.crash.present &&
        d.pump_boundaries_after_fault >
            10000u &&
        !d.success_step_present;

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.4 - v61 crash/scheduler diagnosis\n"
        << "========================================================\n"
        << "Source: complete supplied log scan for v61-specific events.\n"
        << "Log bytes: "
        << d.source_log_bytes
        << "\n"
        << "Log lines scanned: "
        << d.source_log_lines
        << "\n"
        << "v61 static pump/worker profile: "
        << (static_profile.exact_profile()
                ? "MATCH"
                : "PARTIAL/MISMATCH")
        << " ("
        << static_profile.matched()
        << "/"
        << static_profile.checks.size()
        << ")\n\n";

    out
        << "SCHEDULER OBSERVATION\n"
        << "---------------------\n"
        << "res-stream-pump-boundary lines: "
        << d.pump_boundaries
        << "\n"
        << "boundaries already observed at first NoExecuteFault: "
        << d.pump_boundaries_at_fault
        << "\n"
        << "boundaries after that fault: "
        << d.pump_boundaries_after_fault
        << "\n"
        << "worker-slice lines: "
        << d.worker_slice_lines
        << "\n"
        << "SUCCESS STEP 3 present: "
        << (d.success_step_present ? "YES" : "NO")
        << "\n"
        << "runaway scheduling evidence after worker failure: "
        << (d.runaway_after_fault ? "YES" : "NO")
        << "\n\n";

    out
        << "WORKERS\n"
        << "-------\n";
    for (const auto& [tid, w] : d.workers) {
        out
            << "tid="
            << tid
            << " payload="
            << (w.payload_present ? "YES" : "NO");

        if (w.payload_present) {
            out
                << " entry="
                << Hex(w.entry)
                << " this="
                << Hex(w.this_ptr)
                << " wrapperArg="
                << Hex(w.wrapper_arg);
        }

        out
            << " slices="
            << w.slices
            << " slicesAfterFault="
            << w.slices_after_fault
            << " maxTotalTicks="
            << w.max_total_ticks
            << " lastPC="
            << Hex(w.last_pc)
            << " returned="
            << (w.returned ? "YES" : "NO")
            << " failed="
            << (w.failed ? "YES" : "NO")
            << "\n";
    }

    out
        << "\nFIRST NoExecuteFault\n"
        << "--------------------\n";

    if (!d.crash.present) {
        out
            << "No NoExecuteFault found in the supplied v61 log.\n";
    } else {
        const auto& r = d.crash.regs;

        out
            << "log line: "
            << d.crash.line_number
            << "\n"
            << "pthread/phase: "
            << d.crash.pthread_id
            << "/"
            << d.crash.phase
            << "\n"
            << "PC invalid target: "
            << Hex(d.crash.pc)
            << "\n"
            << "LR/returnPC: "
            << Resolve(d.crash.lr, elf)
            << " / "
            << Resolve(d.crash.return_pc, elf)
            << "\n"
            << "manager r4: "
            << Hex(r[4])
            << "\n"
            << "current vector slot r6: "
            << Hex(r[6])
            << "\n"
            << "next vector slot r5: "
            << Hex(r[5])
            << "\n"
            << "TaskResource object r7: "
            << Hex(r[7])
            << "\n"
            << "BLX target r1: "
            << Hex(r[1])
            << "\n"
            << "last guest log: "
            << (d.crash.last_log.empty()
                    ? "(not captured)"
                    : d.crash.last_log)
            << "\n"
            << "verified register/callsite chain: "
            << (d.dispatch_chain_consistent
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << "\n"
            << "worker payload matches resource worker entry "
            << Hex(kGuestBase + 0x00abd894u)
            << ": "
            << (d.worker_payload_matches
                    ? "YES"
                    : "NO")
            << "\n\n";

        if (d.dispatch_chain_consistent) {
            out
                << "CONFIRMED MACHINE-LEVEL FAILURE\n"
                << "-------------------------------\n"
                << "The exact APK sequence is:\n"
                << "  r7 = *r6                      @ "
                << Hex(kGuestBase + 0x00868ca8u)
                << "\n"
                << "  vtable = *r7                  @ "
                << Hex(kGuestBase + 0x00868cacu)
                << "\n"
                << "  r1 = *(vtable + 0x14)         @ "
                << Hex(kGuestBase + 0x00868cb0u)
                << "\n"
                << "  r0 = r7; BLX r1               @ "
                << Hex(kGuestBase + 0x00868cb8u)
                << "\n"
                << "The exception has r1=PC="
                << Hex(d.crash.pc)
                << ", so the +0x14 virtual slot used for this object "
                << "resolved to an invalid executable target.\n"
                << "The actual runtime value [r7] (the vtable pointer) is NOT "
                << "present in v61's log, so this log alone cannot distinguish "
                << "a stale/wrong object pointer from a corrupted/wrong "
                << "vtable.\n\n";
        }
    }

    out
        << "STATIC TaskResource REFERENCE\n"
        << "-----------------------------\n"
        << "The APK exports a vector<IResStreamsDriver::TaskResource*> "
        << "template helper at "
        << Hex(kGuestBase + 0x00abe654u)
        << ". Direct producer paths assign vtable "
        << Hex(kGuestBase + task_audit.vtable_offset)
        << ".\n"
        << "For that verified vtable, the three pump slots are:\n"
        << "  +0x14 -> "
        << Hex(kGuestBase + task_audit.vfn14_raw)
        << "\n"
        << "  +0x18 -> "
        << Hex(kGuestBase + task_audit.vfn18_raw)
        << "\n"
        << "  +0x3c -> "
        << Hex(kGuestBase + task_audit.vfn3c_raw)
        << "\n"
        << "Runtime [r7] remains unknown; these values are reference "
        << "expectations, not proof of the crashed object's dynamic type.\n\n";

    out
        << "DIAGNOSTIC-LABEL WARNING\n"
        << "------------------------\n"
        << "res-stream-pump-boundary lines containing a future-shaped "
        << "wait_object snapshot: "
        << d.pseudo_future_boundary_lines
        << "\n";

    if (d.boundary_future_snapshot_invalid) {
        out
            << "At this boundary r4 is the ResourceManager/pump object, not a "
            << "future. Fields such as done/failed/vfn2C from that snapshot "
            << "must not be interpreted as future state.\n";
    }

    d.text = out.str();

    std::ostringstream excerpt;
    excerpt
        << "PvZ2 Inspector Lab v1.4 - critical v61 excerpts\n"
        << "================================================\n\n"
        << "WORKER 7 CREATION CONTEXT\n"
        << "-------------------------\n"
        << ContextAroundNeedle(
               log,
               "V61 WORKER PAYLOAD tid=7",
               5u,
               8u)
        << "\n"
        << "FIRST NoExecuteFault CONTEXT\n"
        << "----------------------------\n"
        << ContextAroundNeedle(
               log,
               "V23 EXCEPTION: Dynarmic exception NoExecuteFault",
               7u,
               10u)
        << "\n"
        << "END OF SUPPLIED PARTIAL LOG\n"
        << "---------------------------\n"
        << TailLines(
               log,
               24u);

    d.critical_excerpt =
        excerpt.str();

    return d;
}

std::string BuildNextProbePlan(
    const V61RuntimeDiagnosis& v61,
    const V61ProfileValidation& profile,
    const TaskResourceStaticAudit& task) {

    std::ostringstream out;
    out
        << "PvZ2 Inspector Lab v1.4 - next high-information probe plan\n"
        << "===========================================================\n"
        << "Purpose: resolve the v61 TaskResource virtual-dispatch failure "
        << "and prevent another 75 MiB scheduling-loop log. This is a plan "
        << "only; Inspector v1.4 does not modify the main PvZ2 probe.\n\n"
        << "CONFIRMED BASIS\n"
        << "---------------\n"
        << "- v61 pump/worker static profile: "
        << (profile.exact_profile()
                ? "MATCH"
                : "PARTIAL/MISMATCH")
        << " ("
        << profile.matched()
        << "/"
        << profile.checks.size()
        << ")\n";

    if (v61.present) {
        out
            << "- observed pump boundaries: "
            << v61.pump_boundaries
            << "\n"
            << "- first NoExecuteFault: "
            << (v61.crash.present
                    ? Hex(v61.crash.pc)
                    : std::string{"none"})
            << ", worker tid="
            << v61.crash.pthread_id
            << "\n"
            << "- post-fault pump boundaries: "
            << v61.pump_boundaries_after_fault
            << "\n";
    }

    out
        << "- reference TaskResource vtable: "
        << Hex(kGuestBase + task.vtable_offset)
        << ", expected +0x14="
        << Hex(kGuestBase + task.vfn14_raw)
        << ".\n\n"
        << "ONE BUILD, BATCHED INSTRUMENTATION\n"
        << "----------------------------------\n"
        << "1. PRE-BLX TASK SNAPSHOT at "
        << Hex(kGuestBase + 0x00868cb8u)
        << "\n"
        << "   Before executing the native virtual call, log manager=r4, "
        << "vectorBegin=[r4+0x50], vectorEnd=[r4+0x54], slot=r6, "
        << "nextSlot=r5, object=r7, and index=(r6-vectorBegin)/4 when "
        << "bounds/alignment are valid.\n"
        << "   Read and classify [r7] as vtable. Dump object bytes/words "
        << "+0x00..+0x80 and vtable words +0x00..+0x60. Resolve every "
        << "vtable entry as CODE/DATA/heap/invalid. Explicitly print +0x14, "
        << "+0x18 and +0x3c.\n"
        << "   Compare [r7] with the static reference vtable "
        << Hex(kGuestBase + task.vtable_offset)
        << " and +0x14 with "
        << Hex(kGuestBase + task.vfn14_raw)
        << ". Do not replace either value.\n\n"
        << "2. TaskResource PROVENANCE REGISTRY\n"
        << "   Observe the producer vptr stores at "
        << Hex(kGuestBase + 0x00abd650u)
        << " and "
        << Hex(kGuestBase + 0x00abd700u)
        << "; record object pointer, assigned vtable, frame/thread and "
        << "nearby fields.\n"
        << "   Observe fast-path TaskResource queue inserts at "
        << Hex(kGuestBase + 0x00abd68cu)
        << ", "
        << Hex(kGuestBase + 0x00abd73cu)
        << " and "
        << Hex(kGuestBase + 0x00abdf44u)
        << ", plus the virtual producer return at "
        << Hex(kGuestBase + 0x00abdf24u)
        << " and reallocation helper "
        << Hex(kGuestBase + 0x00abe654u)
        << ".\n"
        << "   Keep a bounded pointer->provenance table so the crash report "
        << "can answer whether r7 was ever created/queued as a real "
        << "TaskResource, when, and with which original vtable.\n\n"
        << "3. WRITE WATCH FOR THE CRASH OBJECT\n"
        << "   Once the first pre-BLX snapshot identifies the object, watch "
        << "changes to object+0x00 (vptr) and, if practical, +0x00..+0x20. "
        << "Record old/new value, PC, LR, thread and lifecycle phase. This "
        << "separates bad construction from later overwrite/use-after-free.\n\n"
        << "4. SCHEDULER FAIL-FAST / LOG BOUND\n"
        << "   res-stream-pump-boundary is a scheduling opportunity, not a "
        << "future wait. Log wait_object=none and never format r4 through the "
        << "future snapshot helper for this kind.\n"
        << "   After the first worker NoExecuteFault, capture one complete "
        << "diagnostic bundle and at most a small bounded number of additional "
        << "round-robin slices, then stop with a final summary. Do not emit "
        << "100k repeated boundary lines. Throttle ordinary pump lines "
        << "aggressively (first few + periodic counters).\n\n"
        << "5. PRESERVE WORKING PROGRESS\n"
        << "   Keep the validated Bionic ctype compatibility, VFS/RSB paths, "
        << "GLES texture uploads, v57-v61 diagnostics and real worker payload "
        << "logging. Do not force a ResourceManager entry, GameState or "
        << "transition target.\n\n"
        << "DECISION TREE FROM ONE RUN\n"
        << "--------------------------\n"
        << "- [r7] != expected/known TaskResource vtable and provenance never "
        << "registered r7: stale/wrong pointer entered manager+0x50 vector.\n"
        << "- provenance registered r7 correctly, but object+0 changed later: "
        << "vptr overwrite / lifetime corruption; writer watch identifies it.\n"
        << "- [r7] is a legitimate alternative TaskResource subtype but "
        << "[vtable+0x14] is 0x50: inspect that subtype's construction/vtable "
        << "initialization rather than patching the BLX.\n"
        << "- pre-BLX target is valid and v61 fault disappears under bounded "
        << "run: compare scheduling/interleaving timing before changing "
        << "resource semantics.\n";

    return out.str();
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

        const bool large_log =
            log_text.size() >
            kLargeLogThreshold;

        std::string generic_log_storage;
        const std::string* generic_log =
            &log_text;

        if (large_log) {
            generic_log_storage =
                BuildLargeLogAddressSample(
                    log_text);
            generic_log =
                &generic_log_storage;
        }

        result.source_log_bytes =
            log_text.size();
        result.log_address_analysis_sampled =
            large_log;
        result.generic_log_bytes =
            generic_log->size();

        std::uint32_t occurrences = 0;
        const auto addresses =
            CollectHexAddresses(
                *generic_log,
                occurrences);
        result.log_hex_occurrences = occurrences;
        result.log_unique_addresses =
            static_cast<std::uint32_t>(
                addresses.size());

        const auto controls =
            CollectControlAddresses(
                *generic_log);

        const auto game_state_profile =
            ValidateGameStateProfile(elf);
        const auto startup_logo_profile =
            ValidateStartupLogoProfile(elf);
        const auto v56_profile =
            ValidateV56Profile(elf);
        const auto v61_profile =
            ValidateV61Profile(elf);
        const auto task_resource_audit =
            AuditTaskResourceStatic(elf);
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
        const auto v61_runtime =
            DiagnoseV61Runtime(
                log_text,
                elf,
                v61_profile,
                task_resource_audit);
        const std::string next_probe_plan =
            BuildNextProbePlan(
                v61_runtime,
                v61_profile,
                task_resource_audit);
        const std::string v57_plan =
            BuildV57Plan(
                v55_runtime,
                v56_runtime,
                startup_runtime,
                ctype_audit,
                v56_profile);
        const PvZ2V68RuntimeAnalysis v68_analysis =
            AnalyzeV68RuntimeLog(log_text);
        const PvZ2V74DisplayAnalysis v74_display =
            AnalyzeV74DisplayLog(log_text);
        const UiScaleRuntimeAnalysis ui_scale =
            AnalyzeUiScaleRuntime(
                log_text,
                elf);
        const V109AudioPerformanceAnalysis v109_audio =
            AnalyzeV109AudioRuntime(
                log_text,
                elf);
        const std::string wwise_audio_static_callgraph =
            BuildWwiseAudioStaticCallGraph(elf);

        std::ostringstream summary;
        summary
            << "PvZ2 Inspector Lab v2.4-alpha\n"
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
                << "source log bytes: "
                << result.source_log_bytes
                << "\n"
                << "generic address-analysis bytes: "
                << result.generic_log_bytes
                << "\n"
                << "generic address analysis sampled: "
                << (result.log_address_analysis_sampled
                        ? "YES"
                        : "NO")
                << "\n"
                << "log hex occurrences"
                << (result.log_address_analysis_sampled
                        ? " (sample)"
                        : "")
                << ": "
                << result.log_hex_occurrences << "\n"
                << "unique log addresses"
                << (result.log_address_analysis_sampled
                        ? " (sample)"
                        : "")
                << ": "
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
            << "\n"
            << "v61 resource-pump/worker static profile: "
            << (v61_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << " ("
            << v61_profile.matched()
            << "/"
            << v61_profile.checks.size()
            << ")\n"
            << "TaskResource static producer/vtable audit: "
            << ((task_resource_audit.template_symbol_present &&
                 task_resource_audit.producer_profile_match &&
                 task_resource_audit.vtable_profile_match)
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << "\n";

        if (v109_audio.present) {
            summary << v109_audio.summary_line << "\n";
        }

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

        if (v61_runtime.present) {
            summary
                << "v61 pump boundaries: "
                << v61_runtime.pump_boundaries
                << " afterFault="
                << v61_runtime.pump_boundaries_after_fault
                << " successStep="
                << (v61_runtime.success_step_present
                        ? "YES"
                        : "NO")
                << "\n"
                << "v61 first NoExecuteFault: "
                << (v61_runtime.crash.present
                        ? Hex(v61_runtime.crash.pc)
                        : std::string{"none"})
                << " pthread="
                << v61_runtime.crash.pthread_id
                << " virtualDispatchChain="
                << (v61_runtime.dispatch_chain_consistent
                        ? "CONFIRMED"
                        : "NOT CONFIRMED")
                << "\n"
                << "v61 runaway scheduling after worker fault: "
                << (v61_runtime.runaway_after_fault
                        ? "YES"
                        : "NO")
                << "\n";
        }

        if (v74_display.present) {
            summary
                << "v74 display geometry analysis: PRESENT\n";
        }

        result.summary = summary.str();

        std::ostringstream report;
        report << result.summary << "\n";
        if (v74_display.present) {
            report << v74_display.diagnosis << "\n";
        }

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
            << "\nExact v61 resource-pump/worker profile\n"
            << "=========================================\n"
            << "profile validation: "
            << (v61_profile.exact_profile()
                    ? "MATCH"
                    : "PARTIAL/MISMATCH")
            << " ("
            << v61_profile.matched()
            << "/"
            << v61_profile.checks.size()
            << ")\n";

        for (const auto& check : v61_profile.checks) {
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
            << task_resource_audit.text
            << "\n";

        if (v61_runtime.present) {
            report
                << "\n"
                << v61_runtime.text
                << "\n"
                << "\nNext high-information probe plan\n"
                << "================================\n"
                << next_probe_plan
                << "\n";
        }

        if (v68_analysis.present) {
            report
                << "\n"
                << v68_analysis.diagnosis
                << "\n"
                << "\nv69 one-build lifecycle plan\n"
                << "============================\n"
                << v68_analysis.v69_plan
                << "\n";
        }

        report
            << "\nv57 high-information plan (historical compatibility)\n"
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

            report
                << "\nMost frequent executable libPVZ2 addresses "
                << (result.log_address_analysis_sampled
                        ? "in large-log sample\n"
                        : "in entire log\n")
                << (result.log_address_analysis_sampled
                        ? "=======================================================\n"
                        : "=========================================================\n");
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

        if (!wwise_audio_static_callgraph.empty()) {
            report << "\n" << wwise_audio_static_callgraph << "\n";
        }
        if (v109_audio.present) {
            report << "\n" << v109_audio.diagnosis << "\n";
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

        result.annotated_log =
            result.log_address_analysis_sampled
                ? std::string{}
                : AnnotateLog(
                      log_text,
                      elf);
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
        result.v61_crash_diagnosis =
            v61_runtime.present
                ? v61_runtime.text
                : std::string{};
        result.next_probe_plan =
            v61_runtime.present
                ? next_probe_plan
                : std::string{};
        result.critical_log_excerpt =
            v61_runtime.present
                ? v61_runtime.critical_excerpt
                : std::string{};
        result.v68_resource_stall_diagnosis =
            v68_analysis.present
                ? v68_analysis.diagnosis
                : std::string{};
        result.v69_plan =
            v68_analysis.present
                ? v68_analysis.v69_plan
                : std::string{};
        result.v68_critical_excerpt =
            v68_analysis.present
                ? v68_analysis.critical_excerpt
                : std::string{};
        result.v74_display_diagnosis =
            v74_display.present
                ? v74_display.diagnosis
                : std::string{};
        result.v75_display_plan =
            v74_display.present
                ? v74_display.next_plan
                : std::string{};
        result.v74_display_critical_excerpt =
            v74_display.present
                ? v74_display.critical_excerpt
                : std::string{};

        result.v78_ui_scale_diagnosis =
            ui_scale.present ? ui_scale.diagnosis : std::string{};
        result.ui_scale_static_markers =
            ui_scale.static_markers;
        result.v79_ui_scale_plan =
            ui_scale.next_plan;
        result.v78_ui_scale_critical_excerpt =
            ui_scale.present ? ui_scale.critical_excerpt : std::string{};

        result.v109_audio_performance_diagnosis =
            v109_audio.present ? v109_audio.diagnosis : std::string{};
        result.v109_audio_stalls_csv =
            v109_audio.present ? v109_audio.stalls_csv : std::string{};
        result.wwise_audio_static_callgraph =
            wwise_audio_static_callgraph;
        result.next_audio_probe_plan =
            v109_audio.present ? v109_audio.next_probe_plan : std::string{};
        result.v109_audio_critical_excerpt =
            v109_audio.present ? v109_audio.critical_excerpt : std::string{};

        std::ostringstream json;
        json
            << "{\n"
            << "  \"tool\": \"PvZ2 Inspector Lab v2.4-alpha\",\n"
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
            << "  \"sourceLogBytes\": "
            << result.source_log_bytes
            << ",\n"
            << "  \"v74DisplayAnalysisPresent\": "
            << (v74_display.present ? "true" : "false")
            << ",\n"
            << "  \"v78UiScaleAnalysisPresent\": "
            << (ui_scale.present ? "true" : "false")
            << ",\n"
            << "  \"v109AudioAnalysisPresent\": "
            << (v109_audio.present ? "true" : "false")
            << ",\n"
            << "  \"genericAddressAnalysisBytes\": "
            << result.generic_log_bytes
            << ",\n"
            << "  \"logAddressAnalysisSampled\": "
            << (result.log_address_analysis_sampled
                    ? "true"
                    : "false")
            << ",\n"
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
            << "  \"v61ProfileExactMatch\": "
            << (v61_profile.exact_profile()
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"v61ProfileMatchedChecks\": "
            << v61_profile.matched()
            << ",\n"
            << "  \"v61ProfileTotalChecks\": "
            << v61_profile.checks.size()
            << ",\n"
            << "  \"taskResourceTemplateSymbol\": "
            << (task_resource_audit.template_symbol_present
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"taskResourceProducerProfileMatch\": "
            << (task_resource_audit.producer_profile_match
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"taskResourceVtableProfileMatch\": "
            << (task_resource_audit.vtable_profile_match
                    ? "true"
                    : "false")
            << ",\n"
            << "  \"taskResourceReferenceVtable\": \""
            << Hex(kGuestBase + task_resource_audit.vtable_offset)
            << "\",\n"
            << "  \"taskResourceReferenceVfn14\": \""
            << Hex(kGuestBase + task_resource_audit.vfn14_raw)
            << "\",\n"
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
             << "  },\n"
             << "  \"v61Runtime\": {\n"
             << "    \"present\": "
             << (v61_runtime.present ? "true" : "false")
             << ",\n"
             << "    \"sourceLogBytes\": "
             << v61_runtime.source_log_bytes
             << ",\n"
             << "    \"sourceLogLines\": "
             << v61_runtime.source_log_lines
             << ",\n"
             << "    \"pumpBoundaries\": "
             << v61_runtime.pump_boundaries
             << ",\n"
             << "    \"pumpBoundariesAtFault\": "
             << v61_runtime.pump_boundaries_at_fault
             << ",\n"
             << "    \"pumpBoundariesAfterFault\": "
             << v61_runtime.pump_boundaries_after_fault
             << ",\n"
             << "    \"pseudoFutureBoundaryLines\": "
             << v61_runtime.pseudo_future_boundary_lines
             << ",\n"
             << "    \"workerSliceLines\": "
             << v61_runtime.worker_slice_lines
             << ",\n"
             << "    \"successStepPresent\": "
             << (v61_runtime.success_step_present ? "true" : "false")
             << ",\n"
             << "    \"dispatchChainConsistent\": "
             << (v61_runtime.dispatch_chain_consistent ? "true" : "false")
             << ",\n"
             << "    \"workerPayloadMatches\": "
             << (v61_runtime.worker_payload_matches ? "true" : "false")
             << ",\n"
             << "    \"runawayAfterFault\": "
             << (v61_runtime.runaway_after_fault ? "true" : "false")
             << ",\n"
             << "    \"boundaryFutureSnapshotInvalid\": "
             << (v61_runtime.boundary_future_snapshot_invalid ? "true" : "false")
             << ",\n"
             << "    \"crash\": {\n"
             << "      \"present\": "
             << (v61_runtime.crash.present ? "true" : "false")
             << ",\n"
             << "      \"line\": "
             << v61_runtime.crash.line_number
             << ",\n"
             << "      \"pthread\": "
             << v61_runtime.crash.pthread_id
             << ",\n"
             << "      \"phase\": \""
             << JsonEscape(v61_runtime.crash.phase)
             << "\",\n"
             << "      \"pc\": \""
             << Hex(v61_runtime.crash.pc)
             << "\",\n"
             << "      \"lr\": \""
             << Hex(v61_runtime.crash.lr)
             << "\",\n"
             << "      \"r1Target\": \""
             << Hex(v61_runtime.crash.regs[1])
             << "\",\n"
             << "      \"managerR4\": \""
             << Hex(v61_runtime.crash.regs[4])
             << "\",\n"
             << "      \"nextSlotR5\": \""
             << Hex(v61_runtime.crash.regs[5])
             << "\",\n"
             << "      \"slotR6\": \""
             << Hex(v61_runtime.crash.regs[6])
             << "\",\n"
             << "      \"objectR7\": \""
             << Hex(v61_runtime.crash.regs[7])
             << "\",\n"
             << "      \"lastLog\": \""
             << JsonEscape(v61_runtime.crash.last_log)
             << "\"\n"
             << "    },\n"
             << "    \"workers\": {";

        {
            bool first = true;
            for (const auto& [tid, w] :
                 v61_runtime.workers) {
                if (!first) {
                    json << ",";
                }
                first = false;
                json
                    << "\n      \""
                    << tid
                    << "\": {"
                    << "\"payloadPresent\": "
                    << (w.payload_present ? "true" : "false")
                    << ", \"entry\": \""
                    << Hex(w.entry)
                    << "\", \"this\": \""
                    << Hex(w.this_ptr)
                    << "\", \"wrapperArg\": \""
                    << Hex(w.wrapper_arg)
                    << "\", \"slices\": "
                    << w.slices
                    << ", \"slicesAfterFault\": "
                    << w.slices_after_fault
                    << ", \"maxTotalTicks\": "
                    << w.max_total_ticks
                    << ", \"lastPC\": \""
                    << Hex(w.last_pc)
                    << "\", \"returned\": "
                    << (w.returned ? "true" : "false")
                    << ", \"failed\": "
                    << (w.failed ? "true" : "false")
                    << "}";
            }
            if (!v61_runtime.workers.empty()) {
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
