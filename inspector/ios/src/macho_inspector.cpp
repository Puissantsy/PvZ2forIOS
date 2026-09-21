#include "macho_inspector.hpp"

#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
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
        std::set<std::string> objc_sections;
        std::uint32_t cryptid = 0xffffffffu;
        std::uint32_t minos = 0u;
        std::uint32_t sdk = 0u;
        std::uint32_t nsyms = 0u;
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
                const std::uint32_t nsects = U32(macho.data() + pos + 48);
                std::size_t sp = pos + 56u;
                for (std::uint32_t s = 0; s < nsects; ++s) {
                    if (sp + 68u > pos + cmdsize) break;
                    const std::string sect =
                        FixedName(macho.data() + sp, 16);
                    const std::string sect_seg =
                        FixedName(macho.data() + sp + 16, 16);
                    sections.push_back(sect_seg + ":" + sect);
                    if (sect.rfind("__objc_", 0) == 0 ||
                        sect == "__cstring") {
                        objc_sections.insert(sect);
                    }
                    sp += 68u;
                }
            } else if (base_cmd == 0x2u && cmdsize >= 24u) { // LC_SYMTAB
                nsyms = U32(macho.data() + pos + 12);
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
            << " Android/iOS shared string anchors.";

        result.ok = true;
        result.report = report.str();
        result.summary = summary.str();
    } catch (const std::exception& e) {
        result.ok = false;
        result.message = e.what();
    }

    return result;
}
