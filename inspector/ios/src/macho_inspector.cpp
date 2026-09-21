#include "macho_inspector.hpp"

#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

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

std::string Hex(std::uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setfill('0') << std::setw(8) << v;
    return s.str();
}

std::string FixedName(const std::uint8_t* p, std::size_t n) {
    std::size_t len = 0;
    while (len < n && p[len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(p), len);
}

std::string CsvEscape(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '\"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

struct ZipEntry {
    std::string name;
    std::uint16_t method = 0;
    std::uint32_t compressed = 0;
    std::uint32_t uncompressed = 0;
    std::uint32_t local = 0;
};

std::vector<ZipEntry> ListZip(
    const std::uint8_t* data,
    std::size_t size) {

    if (size < 22) throw std::runtime_error("IPA is too small to be a ZIP");

    const std::size_t min_pos =
        size > (0xffffu + 22u) ? size - (0xffffu + 22u) : 0u;

    std::optional<std::size_t> eocd;
    for (std::size_t p = size - 22;; --p) {
        if (p + 4 <= size && U32(data + p) == 0x06054b50u) {
            eocd = p;
            break;
        }
        if (p == min_pos) break;
    }
    if (!eocd) throw std::runtime_error("ZIP EOCD not found");

    const std::uint16_t count = U16(data + *eocd + 10);
    const std::uint32_t central_size = U32(data + *eocd + 12);
    const std::uint32_t central_off = U32(data + *eocd + 16);
    if (static_cast<std::uint64_t>(central_off) + central_size > size) {
        throw std::runtime_error("ZIP central directory outside IPA");
    }

    std::vector<ZipEntry> out;
    std::size_t pos = central_off;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (pos + 46 > size || U32(data + pos) != 0x02014b50u) {
            throw std::runtime_error("Invalid ZIP central-directory entry");
        }
        const std::uint16_t name_len = U16(data + pos + 28);
        const std::uint16_t extra_len = U16(data + pos + 30);
        const std::uint16_t comment_len = U16(data + pos + 32);
        if (pos + 46u + name_len + extra_len + comment_len > size) {
            throw std::runtime_error("Truncated ZIP central-directory entry");
        }

        ZipEntry e;
        e.method = U16(data + pos + 10);
        e.compressed = U32(data + pos + 20);
        e.uncompressed = U32(data + pos + 24);
        e.local = U32(data + pos + 42);
        e.name.assign(
            reinterpret_cast<const char*>(data + pos + 46),
            name_len);
        out.push_back(std::move(e));

        pos += 46u + name_len + extra_len + comment_len;
    }
    return out;
}

std::vector<std::uint8_t> Extract(
    const std::uint8_t* data,
    std::size_t size,
    const ZipEntry& e) {

    if (e.local + 30u > size || U32(data + e.local) != 0x04034b50u) {
        throw std::runtime_error("Invalid ZIP local header");
    }

    const std::uint16_t name_len = U16(data + e.local + 26);
    const std::uint16_t extra_len = U16(data + e.local + 28);
    const std::size_t payload =
        static_cast<std::size_t>(e.local) + 30u + name_len + extra_len;

    if (payload + e.compressed > size) {
        throw std::runtime_error("ZIP member extends outside IPA");
    }

    if (e.method == 0) {
        return {
            data + payload,
            data + payload + e.compressed
        };
    }

    if (e.method != 8) {
        throw std::runtime_error(
            "Unsupported ZIP compression method " +
            std::to_string(e.method));
    }

    std::vector<std::uint8_t> out(e.uncompressed);
    z_stream zs{};
    zs.next_in = const_cast<Bytef*>(
        reinterpret_cast<const Bytef*>(data + payload));
    zs.avail_in = e.compressed;
    zs.next_out = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());

    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
        throw std::runtime_error("zlib inflateInit2 failed");
    }
    const int rc = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);

    if (rc != Z_STREAM_END || zs.total_out != e.uncompressed) {
        throw std::runtime_error("Failed to inflate IPA member");
    }
    return out;
}

bool IsDirectAppChild(const std::string& name) {
    if (name.rfind("Payload/", 0) != 0) return false;
    const std::size_t app = name.find(".app/");
    if (app == std::string::npos) return false;
    const std::size_t child = app + 5u;
    if (child >= name.size()) return false;
    return name.find('/', child) == std::string::npos;
}

bool IsMachO32Arm(const std::vector<std::uint8_t>& b) {
    return b.size() >= 28u &&
           U32(b.data()) == 0xfeedfaceu &&
           U32(b.data() + 4) == 12u;
}

std::uint32_t DecodeVersion(std::uint32_t v, int part) {
    if (part == 0) return (v >> 16) & 0xffffu;
    if (part == 1) return (v >> 8) & 0xffu;
    return v & 0xffu;
}

std::size_t CountFunctionStarts(
    const std::vector<std::uint8_t>& b,
    std::uint32_t off,
    std::uint32_t size) {

    if (static_cast<std::uint64_t>(off) + size > b.size()) return 0u;
    std::size_t count = 0;
    std::size_t p = off;
    const std::size_t end = off + size;

    while (p < end) {
        std::uint64_t delta = 0;
        unsigned shift = 0;
        bool complete = false;
        while (p < end && shift < 64u) {
            const std::uint8_t byte = b[p++];
            delta |= static_cast<std::uint64_t>(byte & 0x7fu) << shift;
            if ((byte & 0x80u) == 0u) {
                complete = true;
                break;
            }
            shift += 7u;
        }
        if (!complete || delta == 0u) break;
        ++count;
    }
    return count;
}

std::vector<std::string> ExtractAsciiStrings(
    const std::vector<std::uint8_t>& b,
    std::size_t min_len = 8u) {

    std::set<std::string> unique;
    std::string cur;
    for (std::uint8_t c : b) {
        if (c >= 0x20u && c <= 0x7eu) {
            cur.push_back(static_cast<char>(c));
        } else {
            if (cur.size() >= min_len) unique.insert(cur);
            cur.clear();
        }
    }
    if (cur.size() >= min_len) unique.insert(cur);
    return {unique.begin(), unique.end()};
}


struct MachSegmentRecord {
    std::string name;
    std::uint32_t vmaddr = 0;
    std::uint32_t vmsize = 0;
    std::uint32_t fileoff = 0;
    std::uint32_t filesize = 0;
};

struct MachSectionRecord {
    std::string segname;
    std::string sectname;
    std::uint32_t addr = 0;
    std::uint32_t size = 0;
    std::uint32_t offset = 0;
    std::uint32_t flags = 0;
    std::uint32_t reserved1 = 0;
    std::uint32_t reserved2 = 0;
};

std::optional<std::size_t> MachVaddrToFile(
    const std::vector<MachSegmentRecord>& segments,
    const std::vector<std::uint8_t>& macho,
    std::uint32_t vaddr,
    std::size_t need = 1u) {

    for (const auto& seg : segments) {
        if (vaddr < seg.vmaddr) continue;
        const std::uint64_t delta =
            static_cast<std::uint64_t>(vaddr) - seg.vmaddr;
        if (delta + need > seg.filesize) continue;
        const std::uint64_t off =
            static_cast<std::uint64_t>(seg.fileoff) + delta;
        if (off + need <= macho.size()) {
            return static_cast<std::size_t>(off);
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> MachRead32(
    const std::vector<MachSegmentRecord>& segments,
    const std::vector<std::uint8_t>& macho,
    std::uint32_t vaddr) {

    const auto off = MachVaddrToFile(segments, macho, vaddr, 4u);
    if (!off) return std::nullopt;
    return U32(macho.data() + *off);
}

std::string MachCString(
    const std::vector<MachSegmentRecord>& segments,
    const std::vector<std::uint8_t>& macho,
    std::uint32_t vaddr,
    std::size_t max_len = 4096u) {

    const auto off = MachVaddrToFile(segments, macho, vaddr, 1u);
    if (!off) return {};

    std::string out;
    for (std::size_t i = *off;
         i < macho.size() && out.size() < max_len;
         ++i) {
        const char ch = static_cast<char>(macho[i]);
        if (ch == '\0') break;
        out.push_back(ch);
    }
    return out;
}

const MachSectionRecord* FindMachSection(
    const std::vector<MachSectionRecord>& sections,
    const std::string& segname,
    const std::string& sectname) {

    for (const auto& s : sections) {
        if (s.segname == segname && s.sectname == sectname) {
            return &s;
        }
    }
    return nullptr;
}


std::vector<std::uint32_t> DecodeFunctionStarts(
    const std::vector<std::uint8_t>& macho,
    std::uint32_t dataoff,
    std::uint32_t datasize,
    std::uint32_t text_vmaddr) {

    std::vector<std::uint32_t> out;
    if (static_cast<std::uint64_t>(dataoff) + datasize > macho.size()) {
        return out;
    }

    std::size_t p = dataoff;
    const std::size_t end =
        static_cast<std::size_t>(dataoff) + datasize;
    std::uint32_t current = text_vmaddr;

    while (p < end) {
        std::uint64_t delta = 0;
        unsigned shift = 0;
        bool complete = false;

        while (p < end && shift < 64u) {
            const std::uint8_t byte = macho[p++];
            delta |=
                static_cast<std::uint64_t>(byte & 0x7fu) << shift;
            if ((byte & 0x80u) == 0u) {
                complete = true;
                break;
            }
            shift += 7u;
        }

        if (!complete || delta == 0u) break;
        current += static_cast<std::uint32_t>(delta);
        out.push_back(current);
    }

    return out;
}

std::uint32_t NearestFunctionStart(
    const std::vector<std::uint32_t>& starts,
    std::uint32_t address) {

    const auto it =
        std::upper_bound(
            starts.begin(),
            starts.end(),
            address);

    if (it == starts.begin()) return 0u;
    return *std::prev(it);
}

std::optional<std::uint32_t> DecodeThumbCallTarget(
    std::uint32_t address,
    std::uint16_t h1,
    std::uint16_t h2) {

    if ((h1 & 0xf800u) != 0xf000u ||
        (h2 & 0xc000u) != 0xc000u) {
        return std::nullopt;
    }

    const std::uint32_t s = (h1 >> 10) & 1u;
    const std::uint32_t j1 = (h2 >> 13) & 1u;
    const std::uint32_t j2 = (h2 >> 11) & 1u;
    const std::uint32_t i1 = (~(j1 ^ s)) & 1u;
    const std::uint32_t i2 = (~(j2 ^ s)) & 1u;
    const std::uint32_t imm10h = h1 & 0x03ffu;

    std::int32_t imm = 0;
    std::uint32_t pc = address + 4u;

    if ((h2 & 0x1000u) != 0u) {
        const std::uint32_t imm11 = h2 & 0x07ffu;
        std::uint32_t raw =
            (s << 24) |
            (i1 << 23) |
            (i2 << 22) |
            (imm10h << 12) |
            (imm11 << 1);

        if (s != 0u) raw |= 0xfe000000u;
        imm = static_cast<std::int32_t>(raw);
    } else {
        if ((h2 & 1u) != 0u) return std::nullopt;

        const std::uint32_t imm10l =
            (h2 >> 1) & 0x03ffu;
        std::uint32_t raw =
            (s << 24) |
            (i1 << 23) |
            (i2 << 22) |
            (imm10h << 12) |
            (imm10l << 2);

        if (s != 0u) raw |= 0xfe000000u;
        imm = static_cast<std::int32_t>(raw);
        pc &= ~3u;
    }

    return pc + static_cast<std::uint32_t>(imm);
}

std::optional<std::uint32_t> DecodeArmCallTarget(
    std::uint32_t address,
    std::uint32_t word) {

    if ((word & 0x0f000000u) == 0x0b000000u) {
        std::int32_t imm =
            static_cast<std::int32_t>(
                (word & 0x00ffffffu) << 2);
        if ((imm & 0x02000000) != 0) {
            imm |= static_cast<std::int32_t>(0xfc000000u);
        }
        return address + 8u + static_cast<std::uint32_t>(imm);
    }

    if ((word & 0xfe000000u) == 0xfa000000u) {
        std::uint32_t raw =
            ((word & 0x00ffffffu) << 2) |
            ((word >> 23) & 0x2u);

        if ((raw & 0x02000000u) != 0u) {
            raw |= 0xfc000000u;
        }

        const auto imm =
            static_cast<std::int32_t>(raw);
        return
            (address + 8u) +
            static_cast<std::uint32_t>(imm);
    }

    return std::nullopt;
}

struct ImportCallReport {
    std::string csv;
    std::string pthread_report;
    std::size_t stub_count = 0;
    std::size_t call_count = 0;
    std::size_t pthread_call_count = 0;
};

ImportCallReport ParseImportCalls(
    const std::vector<std::uint8_t>& macho,
    const std::vector<MachSectionRecord>& sections,
    std::uint32_t symoff,
    std::uint32_t nsyms,
    std::uint32_t stroff,
    std::uint32_t strsize,
    std::uint32_t indirectsymoff,
    std::uint32_t nindirectsyms,
    const std::vector<std::uint32_t>& function_starts) {

    ImportCallReport out;

    if (symoff == 0u ||
        stroff == 0u ||
        indirectsymoff == 0u ||
        static_cast<std::uint64_t>(symoff) +
                static_cast<std::uint64_t>(nsyms) * 12u >
            macho.size() ||
        static_cast<std::uint64_t>(stroff) + strsize >
            macho.size() ||
        static_cast<std::uint64_t>(indirectsymoff) +
                static_cast<std::uint64_t>(nindirectsyms) * 4u >
            macho.size()) {
        return out;
    }

    auto symbolName =
        [&](std::uint32_t symbol_index) -> std::string {

            if (symbol_index >= nsyms) return {};

            const std::size_t nlist =
                static_cast<std::size_t>(symoff) +
                static_cast<std::size_t>(symbol_index) * 12u;

            const std::uint32_t strx =
                U32(macho.data() + nlist);
            if (strx >= strsize) return {};

            const std::size_t start =
                static_cast<std::size_t>(stroff) + strx;
            std::size_t end = start;
            while (end < macho.size() &&
                   end < static_cast<std::size_t>(stroff) + strsize &&
                   macho[end] != 0u) {
                ++end;
            }

            return std::string(
                reinterpret_cast<const char*>(
                    macho.data() + start),
                end - start);
        };

    std::map<std::uint32_t, std::string> stubs;

    for (const auto& section : sections) {
        const std::uint32_t section_type =
            section.flags & 0xffu;
        if (section_type != 0x8u ||
            section.reserved2 == 0u) {
            continue;
        }

        const std::uint32_t stub_size =
            section.reserved2;
        const std::uint32_t stub_count =
            section.size / stub_size;

        for (std::uint32_t i = 0; i < stub_count; ++i) {
            const std::uint64_t indirect_index64 =
                static_cast<std::uint64_t>(section.reserved1) + i;
            if (indirect_index64 >= nindirectsyms) break;

            const std::size_t indirect_off =
                static_cast<std::size_t>(indirectsymoff) +
                static_cast<std::size_t>(indirect_index64) * 4u;

            const std::uint32_t symbol_index =
                U32(macho.data() + indirect_off);

            if ((symbol_index & 0xc0000000u) != 0u) {
                continue;
            }

            const std::string symbol =
                symbolName(symbol_index);
            if (symbol.empty()) continue;

            stubs[
                section.addr + i * stub_size] =
                    symbol;
        }
    }

    out.stub_count = stubs.size();

    struct Call {
        std::string symbol;
        std::uint32_t stub = 0;
        std::uint32_t callsite = 0;
        std::uint32_t caller = 0;
        std::string isa;
    };

    std::vector<Call> calls;
    std::set<std::pair<std::uint32_t, std::string>> seen;

    const auto* text =
        FindMachSection(sections, "__TEXT", "__text");
    if (text != nullptr &&
        static_cast<std::uint64_t>(text->offset) + text->size <=
            macho.size()) {

        for (std::uint32_t rel = 0;
             rel + 4u <= text->size;
             rel += 2u) {

            const std::size_t file_off =
                static_cast<std::size_t>(text->offset) + rel;
            const std::uint16_t h1 =
                U16(macho.data() + file_off);
            const std::uint16_t h2 =
                U16(macho.data() + file_off + 2u);
            const std::uint32_t callsite =
                text->addr + rel;

            const auto target =
                DecodeThumbCallTarget(
                    callsite,
                    h1,
                    h2);
            if (!target) continue;

            const auto found = stubs.find(*target);
            if (found == stubs.end()) continue;

            if (!seen.insert({callsite, found->second}).second) {
                continue;
            }

            calls.push_back(
                Call{
                    found->second,
                    *target,
                    callsite,
                    NearestFunctionStart(
                        function_starts,
                        callsite),
                    "thumb"
                });
        }

        for (std::uint32_t rel = 0;
             rel + 4u <= text->size;
             rel += 4u) {

            const std::size_t file_off =
                static_cast<std::size_t>(text->offset) + rel;
            const std::uint32_t word =
                U32(macho.data() + file_off);
            const std::uint32_t callsite =
                text->addr + rel;

            const auto target =
                DecodeArmCallTarget(
                    callsite,
                    word);
            if (!target) continue;

            const auto found = stubs.find(*target);
            if (found == stubs.end()) continue;

            if (!seen.insert({callsite, found->second}).second) {
                continue;
            }

            calls.push_back(
                Call{
                    found->second,
                    *target,
                    callsite,
                    NearestFunctionStart(
                        function_starts,
                        callsite),
                    "arm"
                });
        }
    }

    std::sort(
        calls.begin(),
        calls.end(),
        [](const Call& a, const Call& b) {
            if (a.callsite != b.callsite) {
                return a.callsite < b.callsite;
            }
            return a.symbol < b.symbol;
        });

    out.call_count = calls.size();

    std::ostringstream csv;
    csv << "symbol,stub,callsite,caller_start,isa\n";

    std::ostringstream pthread;
    pthread
        << "PvZ2 iOS pthread import-call reference\n"
        << "=====================================\n\n";

    for (const auto& call : calls) {
        csv
            << CsvEscape(call.symbol) << ","
            << Hex(call.stub) << ","
            << Hex(call.callsite) << ","
            << Hex(call.caller) << ","
            << call.isa
            << "\n";

        if (call.symbol.find("_pthread_cond_") !=
                std::string::npos ||
            call.symbol.find("_pthread_mutex_") !=
                std::string::npos) {

            ++out.pthread_call_count;
            pthread
                << call.symbol
                << " stub=" << Hex(call.stub)
                << " callsite=" << Hex(call.callsite)
                << " caller=" << Hex(call.caller)
                << " isa=" << call.isa
                << "\n";
        }
    }

    out.csv = csv.str();
    out.pthread_report = pthread.str();
    return out;
}

struct ObjcMetadataReport {
    std::string classes_csv;
    std::string methods_csv;
    std::string ivars_csv;
    std::size_t class_count = 0;
    std::size_t method_count = 0;
    std::size_t ivar_count = 0;
};

ObjcMetadataReport ParseObjcMetadata(
    const std::vector<std::uint8_t>& macho,
    const std::vector<MachSegmentRecord>& segments,
    const std::vector<MachSectionRecord>& sections) {

    ObjcMetadataReport out;
    std::ostringstream classes;
    std::ostringstream methods;
    std::ostringstream ivars;

    classes
        << "class,class_ptr,superclass,superclass_ptr,instance_start,instance_size\n";
    methods
        << "class,kind,selector,types,imp\n";
    ivars
        << "class,ivar,type,offset,size,alignment\n";

    const auto* classlist =
        FindMachSection(sections, "__DATA", "__objc_classlist");
    if (classlist == nullptr || classlist->size < 4u) {
        out.classes_csv = classes.str();
        out.methods_csv = methods.str();
        out.ivars_csv = ivars.str();
        return out;
    }

    auto className = [&](std::uint32_t class_ptr) -> std::string {
        if (class_ptr == 0u) return {};
        const auto data_bits =
            MachRead32(segments, macho, class_ptr + 16u);
        if (!data_bits) return {};
        const std::uint32_t ro = *data_bits & ~3u;
        const auto name_ptr =
            MachRead32(segments, macho, ro + 16u);
        if (!name_ptr) return {};
        return MachCString(segments, macho, *name_ptr);
    };

    std::set<std::uint32_t> seen_classes;

    const std::size_t count = classlist->size / 4u;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t ptr_off =
            static_cast<std::size_t>(classlist->offset) + i * 4u;
        if (ptr_off + 4u > macho.size()) break;

        const std::uint32_t class_ptr =
            U32(macho.data() + ptr_off);
        if (class_ptr == 0u || !seen_classes.insert(class_ptr).second) {
            continue;
        }

        const auto isa =
            MachRead32(segments, macho, class_ptr + 0u);
        const auto superclass =
            MachRead32(segments, macho, class_ptr + 4u);
        const auto data_bits =
            MachRead32(segments, macho, class_ptr + 16u);
        if (!data_bits) continue;

        const std::uint32_t ro = *data_bits & ~3u;
        const auto flags = MachRead32(segments, macho, ro + 0u);
        const auto instance_start =
            MachRead32(segments, macho, ro + 4u);
        const auto instance_size =
            MachRead32(segments, macho, ro + 8u);
        const auto name_ptr =
            MachRead32(segments, macho, ro + 16u);
        if (!name_ptr) continue;

        const std::string name =
            MachCString(segments, macho, *name_ptr);
        if (name.empty()) continue;

        const std::string super_name =
            superclass ? className(*superclass) : std::string{};

        classes
            << CsvEscape(name) << ","
            << Hex(class_ptr) << ","
            << CsvEscape(super_name) << ","
            << Hex(superclass.value_or(0u)) << ","
            << instance_start.value_or(0u) << ","
            << instance_size.value_or(0u)
            << "\n";
        ++out.class_count;

        auto emitMethods =
            [&](std::uint32_t target_class_ptr,
                const char* kind) {

                if (target_class_ptr == 0u) return;

                const auto target_data =
                    MachRead32(
                        segments,
                        macho,
                        target_class_ptr + 16u);
                if (!target_data) return;

                const std::uint32_t target_ro =
                    *target_data & ~3u;
                const auto list_ptr =
                    MachRead32(
                        segments,
                        macho,
                        target_ro + 20u);
                if (!list_ptr || *list_ptr == 0u) return;

                const auto entsize_flags =
                    MachRead32(segments, macho, *list_ptr + 0u);
                const auto method_count =
                    MachRead32(segments, macho, *list_ptr + 4u);
                if (!entsize_flags || !method_count) return;

                std::uint32_t entsize =
                    *entsize_flags & 0xfffffffcU;
                if (entsize < 12u || entsize > 64u) {
                    entsize = 12u;
                }

                const std::uint32_t capped =
                    std::min<std::uint32_t>(
                        *method_count,
                        10000u);

                for (std::uint32_t m = 0; m < capped; ++m) {
                    const std::uint32_t method_va =
                        *list_ptr + 8u + m * entsize;
                    const auto selector_ptr =
                        MachRead32(
                            segments,
                            macho,
                            method_va + 0u);
                    const auto types_ptr =
                        MachRead32(
                            segments,
                            macho,
                            method_va + 4u);
                    const auto imp =
                        MachRead32(
                            segments,
                            macho,
                            method_va + 8u);
                    if (!selector_ptr || !types_ptr || !imp) continue;

                    const std::string selector =
                        MachCString(
                            segments,
                            macho,
                            *selector_ptr);
                    const std::string types =
                        MachCString(
                            segments,
                            macho,
                            *types_ptr);
                    if (selector.empty()) continue;

                    methods
                        << CsvEscape(name) << ","
                        << kind << ","
                        << CsvEscape(selector) << ","
                        << CsvEscape(types) << ","
                        << Hex(*imp)
                        << "\n";
                    ++out.method_count;
                }
            };

        emitMethods(class_ptr, "instance");
        if (isa && *isa != 0u && *isa != class_ptr) {
            emitMethods(*isa, "class");
        }

        const auto ivar_list_ptr =
            MachRead32(segments, macho, ro + 28u);
        if (ivar_list_ptr && *ivar_list_ptr != 0u) {
            const auto entsize =
                MachRead32(
                    segments,
                    macho,
                    *ivar_list_ptr + 0u);
            const auto ivar_count =
                MachRead32(
                    segments,
                    macho,
                    *ivar_list_ptr + 4u);

            if (entsize && ivar_count) {
                std::uint32_t ivar_entsize =
                    *entsize & 0xfffffffcU;
                if (ivar_entsize < 20u || ivar_entsize > 64u) {
                    ivar_entsize = 20u;
                }

                const std::uint32_t capped =
                    std::min<std::uint32_t>(
                        *ivar_count,
                        10000u);

                for (std::uint32_t v = 0; v < capped; ++v) {
                    const std::uint32_t ivar_va =
                        *ivar_list_ptr + 8u + v * ivar_entsize;

                    const auto offset_ptr =
                        MachRead32(segments, macho, ivar_va + 0u);
                    const auto ivar_name_ptr =
                        MachRead32(segments, macho, ivar_va + 4u);
                    const auto type_ptr =
                        MachRead32(segments, macho, ivar_va + 8u);
                    const auto alignment =
                        MachRead32(segments, macho, ivar_va + 12u);
                    const auto size =
                        MachRead32(segments, macho, ivar_va + 16u);

                    if (!ivar_name_ptr || !type_ptr) continue;

                    const std::string ivar_name =
                        MachCString(
                            segments,
                            macho,
                            *ivar_name_ptr);
                    const std::string type =
                        MachCString(
                            segments,
                            macho,
                            *type_ptr);
                    if (ivar_name.empty()) continue;

                    std::uint32_t offset_value = 0u;
                    if (offset_ptr && *offset_ptr != 0u) {
                        const auto stored =
                            MachRead32(
                                segments,
                                macho,
                                *offset_ptr);
                        if (stored) offset_value = *stored;
                    }

                    ivars
                        << CsvEscape(name) << ","
                        << CsvEscape(ivar_name) << ","
                        << CsvEscape(type) << ","
                        << offset_value << ","
                        << size.value_or(0u) << ","
                        << alignment.value_or(0u)
                        << "\n";
                    ++out.ivar_count;
                }
            }
        }

        (void)flags;
    }

    out.classes_csv = classes.str();
    out.methods_csv = methods.str();
    out.ivars_csv = ivars.str();
    return out;
}

} // namespace

PvZ2IpaInspectorResult InspectPvZ2IpaReference(
    const std::uint8_t* ipa_data,
    std::size_t ipa_size,
    const std::uint8_t* apk_data,
    std::size_t apk_size) {

    PvZ2IpaInspectorResult result;
    result.ipa_size = ipa_size;

    try {
        if (ipa_data == nullptr || ipa_size == 0u) {
            throw std::runtime_error("IPA data is empty");
        }

        const auto entries = ListZip(ipa_data, ipa_size);

        std::vector<std::uint8_t> macho;
        for (const auto& e : entries) {
            if (!IsDirectAppChild(e.name) ||
                e.uncompressed < 1024u * 1024u ||
                e.uncompressed > 128u * 1024u * 1024u) {
                continue;
            }

            auto candidate = Extract(ipa_data, ipa_size, e);
            if (IsMachO32Arm(candidate)) {
                result.executable_path = e.name;
                macho = std::move(candidate);
                break;
            }
        }

        if (macho.empty()) {
            throw std::runtime_error(
                "No direct Payload/*.app ARMv7 Mach-O executable found");
        }

        result.macho_size = macho.size();

        const std::uint32_t cputype = U32(macho.data() + 4);
        const std::uint32_t cpusubtype = U32(macho.data() + 8);
        const std::uint32_t filetype = U32(macho.data() + 12);
        const std::uint32_t ncmds = U32(macho.data() + 16);
        const std::uint32_t sizeofcmds = U32(macho.data() + 20);
        const std::uint32_t flags = U32(macho.data() + 24);

        std::vector<std::string> dylibs;
        std::vector<std::string> segments;
        std::vector<std::string> sections;
        std::vector<MachSegmentRecord> segment_records;
        std::vector<MachSectionRecord> section_records;
        std::set<std::string> objc_sections;
        std::uint32_t cryptid = 0xffffffffu;
        std::uint32_t minos = 0u;
        std::uint32_t sdk = 0u;
        std::uint32_t symoff = 0u;
        std::uint32_t nsyms = 0u;
        std::uint32_t stroff = 0u;
        std::uint32_t strsize = 0u;
        std::uint32_t indirectsymoff = 0u;
        std::uint32_t nindirectsyms = 0u;
        std::uint32_t function_dataoff = 0u;
        std::uint32_t function_datasize = 0u;

        std::size_t pos = 28u;
        if (pos + sizeofcmds > macho.size()) {
            throw std::runtime_error("Mach-O load commands are truncated");
        }

        for (std::uint32_t i = 0; i < ncmds; ++i) {
            if (pos + 8u > macho.size()) {
                throw std::runtime_error("Truncated Mach-O load command");
            }
            const std::uint32_t cmd = U32(macho.data() + pos);
            const std::uint32_t cmdsize = U32(macho.data() + pos + 4);
            if (cmdsize < 8u || pos + cmdsize > macho.size()) {
                throw std::runtime_error("Invalid Mach-O load command size");
            }

            const std::uint32_t base_cmd = cmd & 0x7fffffffu;

            if (base_cmd == 0x1u && cmdsize >= 56u) { // LC_SEGMENT
                const std::string seg =
                    FixedName(macho.data() + pos + 8, 16);
                segments.push_back(seg);

                MachSegmentRecord segment;
                segment.name = seg;
                segment.vmaddr = U32(macho.data() + pos + 24);
                segment.vmsize = U32(macho.data() + pos + 28);
                segment.fileoff = U32(macho.data() + pos + 32);
                segment.filesize = U32(macho.data() + pos + 36);
                segment_records.push_back(segment);

                const std::uint32_t nsects = U32(macho.data() + pos + 48);
                std::size_t sp = pos + 56u;
                for (std::uint32_t s = 0; s < nsects; ++s) {
                    if (sp + 68u > pos + cmdsize) break;
                    const std::string sect =
                        FixedName(macho.data() + sp, 16);
                    const std::string sect_seg =
                        FixedName(macho.data() + sp + 16, 16);
                    sections.push_back(sect_seg + ":" + sect);

                    MachSectionRecord section;
                    section.segname = sect_seg;
                    section.sectname = sect;
                    section.addr = U32(macho.data() + sp + 32);
                    section.size = U32(macho.data() + sp + 36);
                    section.offset = U32(macho.data() + sp + 40);
                    section.flags = U32(macho.data() + sp + 56);
                    section.reserved1 = U32(macho.data() + sp + 60);
                    section.reserved2 = U32(macho.data() + sp + 64);
                    section_records.push_back(section);

                    if (sect.rfind("__objc_", 0) == 0 ||
                        sect == "__cstring") {
                        objc_sections.insert(sect);
                    }
                    sp += 68u;
                }
            } else if (base_cmd == 0x2u && cmdsize >= 24u) { // LC_SYMTAB
                symoff = U32(macho.data() + pos + 8);
                nsyms = U32(macho.data() + pos + 12);
                stroff = U32(macho.data() + pos + 16);
                strsize = U32(macho.data() + pos + 20);
            } else if (base_cmd == 0xbu && cmdsize >= 80u) { // LC_DYSYMTAB
                indirectsymoff =
                    U32(macho.data() + pos + 56);
                nindirectsyms =
                    U32(macho.data() + pos + 60);
            } else if ((base_cmd == 0xcu ||
                        base_cmd == 0x18u ||
                        base_cmd == 0x1fu ||
                        base_cmd == 0x23u) &&
                       cmdsize >= 24u) {
                const std::uint32_t nameoff = U32(macho.data() + pos + 8);
                if (nameoff < cmdsize) {
                    const char* p = reinterpret_cast<const char*>(
                        macho.data() + pos + nameoff);
                    const std::size_t max = cmdsize - nameoff;
                    std::size_t len = 0;
                    while (len < max && p[len] != 0) ++len;
                    dylibs.emplace_back(p, len);
                }
            } else if (base_cmd == 0x21u && cmdsize >= 20u) {
                cryptid = U32(macho.data() + pos + 16);
            } else if (base_cmd == 0x25u && cmdsize >= 16u) {
                minos = U32(macho.data() + pos + 8);
                sdk = U32(macho.data() + pos + 12);
            } else if (base_cmd == 0x26u && cmdsize >= 16u) {
                function_dataoff = U32(macho.data() + pos + 8);
                function_datasize = U32(macho.data() + pos + 12);
            }

            pos += cmdsize;
        }

        const std::size_t function_starts =
            CountFunctionStarts(
                macho,
                function_dataoff,
                function_datasize);

        std::uint32_t text_vmaddr = 0u;
        for (const auto& segment : segment_records) {
            if (segment.name == "__TEXT") {
                text_vmaddr = segment.vmaddr;
                break;
            }
        }

        const auto function_start_addresses =
            DecodeFunctionStarts(
                macho,
                function_dataoff,
                function_datasize,
                text_vmaddr);

        const ImportCallReport import_calls =
            ParseImportCalls(
                macho,
                section_records,
                symoff,
                nsyms,
                stroff,
                strsize,
                indirectsymoff,
                nindirectsyms,
                function_start_addresses);

        result.ios_import_calls_csv =
            import_calls.csv;
        result.pthread_reference =
            import_calls.pthread_report;

        const ObjcMetadataReport objc =
            ParseObjcMetadata(
                macho,
                segment_records,
                section_records);
        result.objc_classes_csv = objc.classes_csv;
        result.objc_methods_csv = objc.methods_csv;
        result.objc_ivars_csv = objc.ivars_csv;
        result.objc_class_count = objc.class_count;
        result.objc_method_count = objc.method_count;
        result.objc_ivar_count = objc.ivar_count;

        const auto strings = ExtractAsciiStrings(macho);

        std::vector<std::string> shared_strings;
        if (apk_data != nullptr && apk_size > 0u) {
            const auto apk_entries = ListZip(apk_data, apk_size);
            auto it = std::find_if(
                apk_entries.begin(),
                apk_entries.end(),
                [](const ZipEntry& e) {
                    return e.name == "lib/armeabi-v7a/libPVZ2.so";
                });
            if (it != apk_entries.end()) {
                const auto android_elf =
                    Extract(apk_data, apk_size, *it);
                const auto android_strings =
                    ExtractAsciiStrings(android_elf);

                std::set_intersection(
                    strings.begin(),
                    strings.end(),
                    android_strings.begin(),
                    android_strings.end(),
                    std::back_inserter(shared_strings));

                std::ostringstream csv;
                csv << "string\n";
                for (const auto& s : shared_strings) {
                    csv << CsvEscape(s) << "\n";
                }
                result.shared_strings_csv = csv.str();
                result.shared_string_count = shared_strings.size();
            }
        }

        const std::vector<std::string> markers = {
            "RESFILE_PACKAGES_UI_IPAD",
            "RESFILE_PACKAGES_UI_IPHONE",
            "BaseResStreamsDriver::DecompressionThreadProc() exiting.",
            "ResStreamsManager::GetGroupForFile:",
            "ResourceManager::Init: RSB Initialization failed",
            "MainMenu_Background",
            "EAGLView",
            "ES2Renderer",
            "iPhoneOSAppDriver",
            "SexyApplicationDelegate",
            "CADisplayLink",
            "pthread_cond_wait"
        };

        std::set<std::string> string_set(strings.begin(), strings.end());
        std::vector<std::string> found_markers;
        for (const auto& marker : markers) {
            bool found = false;
            for (const auto& s : strings) {
                if (s.find(marker) != std::string::npos) {
                    found = true;
                    break;
                }
            }
            if (found) found_markers.push_back(marker);
        }

        std::ostringstream report;
        report
            << "PvZ2 Inspector v2 — iOS reference Mach-O report\n"
            << "================================================\n\n"
            << "IPA bytes: " << ipa_size << "\n"
            << "Executable: " << result.executable_path << "\n"
            << "Mach-O bytes: " << macho.size() << "\n"
            << "magic: 0xfeedface\n"
            << "cputype: " << cputype << " (ARM)\n"
            << "cpusubtype: " << cpusubtype << "\n"
            << "filetype: " << filetype << "\n"
            << "ncmds: " << ncmds << "\n"
            << "sizeofcmds: " << sizeofcmds << "\n"
            << "flags: " << Hex(flags) << "\n"
            << "cryptid: "
            << (cryptid == 0xffffffffu ? std::string{"not present"} : std::to_string(cryptid))
            << (cryptid == 0u ? " (decrypted)" : "") << "\n";

        if (minos != 0u) {
            report
                << "Minimum iOS: "
                << DecodeVersion(minos, 0) << "."
                << DecodeVersion(minos, 1) << "."
                << DecodeVersion(minos, 2) << "\n"
                << "SDK: "
                << DecodeVersion(sdk, 0) << "."
                << DecodeVersion(sdk, 1) << "."
                << DecodeVersion(sdk, 2) << "\n";
        }

        report
            << "symbols: " << nsyms << "\n"
            << "LC_FUNCTION_STARTS entries: " << function_starts << "\n"
            << "ASCII strings >=8 (unique): " << strings.size() << "\n"
            << "Android/iOS shared strings >=8: "
            << result.shared_string_count << "\n"
            << "Objective-C classes: " << result.objc_class_count << "\n"
            << "Objective-C methods: " << result.objc_method_count << "\n"
            << "Objective-C ivars: " << result.objc_ivar_count << "\n"
            << "Import stubs resolved: " << import_calls.stub_count << "\n"
            << "Import calls resolved: " << import_calls.call_count << "\n"
            << "pthread mutex/cond calls: " << import_calls.pthread_call_count << "\n"
            << "segments: " << segments.size() << "\n"
            << "sections: " << sections.size() << "\n"
            << "dylibs: " << dylibs.size() << "\n\n";

        report << "Loaded dylibs/frameworks\n------------------------\n";
        for (const auto& d : dylibs) report << d << "\n";

        report << "\nSegments / sections\n-------------------\n";
        for (const auto& seg : segments) report << "[SEG] " << seg << "\n";
        for (const auto& sec : sections) report << "  " << sec << "\n";

        report << "\nObjective-C/string-bearing sections\n-----------------------------------\n";
        for (const auto& sec : objc_sections) report << sec << "\n";

        report << "\nPvZ2 reference markers found\n----------------------------\n";
        for (const auto& marker : found_markers) report << marker << "\n";

        if (!shared_strings.empty()) {
            report
                << "\nRepresentative Android/iOS shared anchors\n"
                << "-----------------------------------------\n";
            const std::size_t cap = std::min<std::size_t>(80u, shared_strings.size());
            for (std::size_t i = 0; i < cap; ++i) {
                report << shared_strings[i] << "\n";
            }
        }

        report
            << "\nNext Inspector v2 stages\n------------------------\n"
            << "1. Parse Objective-C class/selector/ivar metadata and IMP addresses.\n"
            << "2. Build string/literal xrefs to ARM functions.\n"
            << "3. Match Android ELF functions to iOS Mach-O candidates.\n"
            << "4. Add pthread/ResStreams/frame-loop focused reports.\n"
            << "5. Parse/diff iOS main.rsb against the Android RSB/OBB.\n";

        std::ostringstream summary;
        summary
            << "iOS reference: ARMv7 Mach-O, "
            << macho.size() << " bytes, cryptid="
            << (cryptid == 0xffffffffu ? -1 : static_cast<int>(cryptid))
            << ", " << function_starts
            << " function starts, " << dylibs.size()
            << " dylibs, " << sections.size() << " sections, "
            << result.shared_string_count
            << " Android/iOS shared string anchors, "
            << result.objc_class_count << " ObjC classes, "
            << result.objc_method_count << " ObjC methods.";

        result.ok = true;
        result.report = report.str();
        result.summary = summary.str();
    } catch (const std::exception& e) {
        result.ok = false;
        result.message = e.what();
    }

    return result;
}
