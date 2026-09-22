#include "v74_display_analyzer.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::optional<std::uint32_t> ParseU32(
    std::string_view text,
    std::size_t& pos) {

    while (pos < text.size() &&
           (text[pos] < '0' || text[pos] > '9')) {
        ++pos;
    }

    if (pos >= text.size()) return std::nullopt;

    std::uint64_t value = 0u;
    bool any = false;
    while (pos < text.size() &&
           text[pos] >= '0' && text[pos] <= '9') {
        any = true;
        value = value * 10u +
            static_cast<unsigned>(text[pos] - '0');
        if (value > 0xffffffffull) return std::nullopt;
        ++pos;
    }

    return any
        ? std::optional<std::uint32_t>{
              static_cast<std::uint32_t>(value)}
        : std::nullopt;
}

std::optional<std::pair<std::uint32_t, std::uint32_t>>
ParseSizeAfter(
    std::string_view line,
    std::string_view marker) {

    const std::size_t hit = line.find(marker);
    if (hit == std::string_view::npos) return std::nullopt;

    std::size_t pos = hit + marker.size();
    const auto width = ParseU32(line, pos);
    if (!width) return std::nullopt;

    const std::size_t x = line.find('x', pos);
    if (x == std::string_view::npos) return std::nullopt;
    pos = x + 1u;

    const auto height = ParseU32(line, pos);
    if (!height) return std::nullopt;

    return std::pair<std::uint32_t, std::uint32_t>{
        *width,
        *height
    };
}

std::optional<std::pair<std::uint32_t, std::uint32_t>>
ParseViewportSize(std::string_view line) {

    const std::size_t hit = line.find("guest=(");
    if (hit == std::string_view::npos) return std::nullopt;

    const std::size_t end = line.find(')', hit);
    if (end == std::string_view::npos) return std::nullopt;

    const std::string_view tuple =
        line.substr(hit + 7u, end - (hit + 7u));

    std::size_t pos = 0u;
    const auto x = ParseU32(tuple, pos);
    const auto y = ParseU32(tuple, pos);
    const auto width = ParseU32(tuple, pos);
    const auto height = ParseU32(tuple, pos);

    (void)x;
    (void)y;

    if (!width || !height) return std::nullopt;

    return std::pair<std::uint32_t, std::uint32_t>{
        *width,
        *height
    };
}

std::string SizeText(
    const std::pair<std::uint32_t, std::uint32_t>& size) {

    return
        std::to_string(size.first) +
        "x" +
        std::to_string(size.second);
}

double Aspect(
    const std::pair<std::uint32_t, std::uint32_t>& size) {

    return size.second == 0u
        ? 0.0
        : static_cast<double>(size.first) /
              static_cast<double>(size.second);
}

std::pair<std::uint32_t, std::uint32_t> MostFrequent(
    const std::map<
        std::pair<std::uint32_t, std::uint32_t>,
        std::uint64_t>& counts,
    const std::optional<
        std::pair<std::uint32_t, std::uint32_t>>& exclude =
            std::nullopt) {

    std::pair<std::uint32_t, std::uint32_t> best{};
    std::uint64_t best_count = 0u;

    for (const auto& [size, count] : counts) {
        if (exclude && size == *exclude) continue;
        if (count > best_count) {
            best = size;
            best_count = count;
        }
    }

    return best;
}

void AddExcerptLine(
    std::vector<std::string>& lines,
    std::string_view line) {

    if (line.empty()) return;

    const std::string value(line);
    if (std::find(lines.begin(), lines.end(), value) ==
        lines.end()) {
        lines.push_back(value);
    }
}

} // namespace

PvZ2V74DisplayAnalysis AnalyzeV74DisplayLog(
    const std::string& log) {

    PvZ2V74DisplayAnalysis result;

    if (log.find("V74_RETINA_INPUT_POLISH") ==
            std::string::npos &&
        log.find("V74 RETINA/INPUT POLISH") ==
            std::string::npos) {
        return result;
    }

    result.present = true;

    using Size =
        std::pair<std::uint32_t, std::uint32_t>;

    std::optional<Size> pixels;
    std::optional<Size> points;
    std::optional<Size> host_surface;

    bool point_size_2 = false;
    bool can_set_scale_false = false;
    bool get_scale_method_registered = false;
    bool set_scale_method_registered = false;
    bool ui_android = false;
    bool ui_ipad = false;

    std::uint64_t lines_seen = 0u;
    std::map<Size, std::uint64_t> viewport_counts;
    std::map<Size, std::uint64_t> fbo_attach_counts;
    std::map<Size, std::uint64_t> texture_counts;
    std::vector<std::string> excerpt;

    std::size_t begin = 0u;
    while (begin < log.size()) {
        std::size_t end = log.find('\n', begin);
        if (end == std::string::npos) end = log.size();

        ++lines_seen;
        const std::string_view line(
            log.data() + begin,
            end - begin);

        if (line.find(
                "JNI bridge: Graphics_GetScreenSizeInPixels -> ") !=
            std::string_view::npos) {

            pixels = ParseSizeAfter(line, "-> ");
            AddExcerptLine(excerpt, line);
        }

        if (line.find(
                "JNI bridge: Graphics_GetScreenSizeInPoints -> ") !=
            std::string_view::npos) {

            points = ParseSizeAfter(line, "-> ");
            AddExcerptLine(excerpt, line);
        }

        if (line.find(
                "Graphics_GetPointSizeInPixels -> 2.0") !=
            std::string_view::npos) {
            point_size_2 = true;
            AddExcerptLine(excerpt, line);
        }

        if (line.find(
                "Graphics_CanSetGLViewScaleFactor -> false") !=
            std::string_view::npos) {
            can_set_scale_false = true;
            AddExcerptLine(excerpt, line);
        }

        if (line.find(
                "name=\"Graphics_GetGLViewScaleFactor\"") !=
            std::string_view::npos) {
            get_scale_method_registered = true;
        }

        if (line.find(
                "name=\"Graphics_SetGLViewScaleFactor\"") !=
            std::string_view::npos) {
            set_scale_method_registered = true;
        }

        if (line.find("V74 SURFACE GEOMETRY:") !=
            std::string_view::npos) {
            host_surface =
                ParseSizeAfter(line, "hostFBO=");
            AddExcerptLine(excerpt, line);
        }

        if (line.find("V39 GLES VIEWPORT #") !=
            std::string_view::npos) {
            if (const auto size =
                    ParseViewportSize(line)) {
                ++viewport_counts[*size];
            }
        }

        if (line.find("V47 GLES FBO ATTACH") !=
            std::string_view::npos) {
            if (const auto size =
                    ParseSizeAfter(line, "size=")) {
                ++fbo_attach_counts[*size];
                AddExcerptLine(excerpt, line);
            }
        }

        if (line.find("V41 GLES TEXUPLOAD #") !=
            std::string_view::npos) {
            if (const auto size =
                    ParseSizeAfter(line, "size=")) {
                ++texture_counts[*size];
            }
        }

        if (line.find(
                "id=\"RESFILE_PACKAGES_UI_ANDROID\"") !=
            std::string_view::npos ||
            line.find("uiAndroid=YES") !=
            std::string_view::npos) {
            ui_android = true;
            AddExcerptLine(excerpt, line);
        }

        if (line.find(
                "id=\"RESFILE_PACKAGES_UI_IPAD\"") !=
            std::string_view::npos ||
            line.find("uiIPad=YES") !=
            std::string_view::npos) {
            ui_ipad = true;
            AddExcerptLine(excerpt, line);
        }

        if (end == log.size()) break;
        begin = end + 1u;
    }

    if (!host_surface && pixels) {
        host_surface = pixels;
    }

    const Size offscreen =
        MostFrequent(
            fbo_attach_counts,
            host_surface);

    const bool offscreen_present =
        offscreen.first != 0u &&
        offscreen.second != 0u;

    bool exact_2x_contract = false;
    if (pixels && points) {
        exact_2x_contract =
            pixels->first == points->first * 2u &&
            pixels->second == points->second * 2u;
    }

    const bool host_matches_pixels =
        host_surface &&
        pixels &&
        *host_surface == *pixels;

    const bool canonical_768 =
        offscreen_present &&
        point_size_2 &&
        (offscreen.first % 2u) == 0u &&
        (offscreen.second % 2u) == 0u &&
        (offscreen.second / 2u) == 768u;

    std::ostringstream diagnosis;
    diagnosis
        << "PvZ2 Inspector Lab v2.2-alpha - v74 display geometry / UI platform\n"
        << "===================================================================\n"
        << "source log: "
        << log.size()
        << " bytes / "
        << lines_seen
        << " lines\n\n"
        << "HOST / JNI CONTRACT\n"
        << "-------------------\n"
        << "screen pixels: "
        << (pixels ? SizeText(*pixels) : "(not observed)")
        << "\n"
        << "screen points: "
        << (points ? SizeText(*points) : "(not observed)")
        << "\n"
        << "point-size bridge reports 2.0: "
        << (point_size_2 ? "YES" : "NO")
        << "\n"
        << "exact pixels == points * 2: "
        << (exact_2x_contract ? "YES" : "NO")
        << "\n"
        << "host default surface: "
        << (host_surface
                ? SizeText(*host_surface)
                : "(not observed)")
        << "\n"
        << "host surface == advertised pixels: "
        << (host_matches_pixels ? "YES" : "NO")
        << "\n"
        << "Graphics_CanSetGLViewScaleFactor -> false: "
        << (can_set_scale_false ? "YES" : "NO")
        << "\n"
        << "Get/SetGLViewScaleFactor methods registered: "
        << (get_scale_method_registered ? "GET " : "")
        << (set_scale_method_registered ? "SET" : "")
        << ((!get_scale_method_registered &&
             !set_scale_method_registered)
                ? "(not observed)"
                : "")
        << "\n\n"
        << "GUEST RENDER PIPELINE\n"
        << "---------------------\n";

    diagnosis << "viewport sizes:\n";
    for (const auto& [size, count] : viewport_counts) {
        diagnosis
            << "  "
            << SizeText(size)
            << " : "
            << count
            << " changes/samples\n";
    }

    diagnosis << "FBO attachment sizes:\n";
    for (const auto& [size, count] : fbo_attach_counts) {
        diagnosis
            << "  "
            << SizeText(size)
            << " : "
            << count
            << "\n";
    }

    if (offscreen_present) {
        diagnosis
            << "dominant non-default guest target: "
            << SizeText(offscreen)
            << "\n";

        if (point_size_2 &&
            (offscreen.first % 2u) == 0u &&
            (offscreen.second % 2u) == 0u) {
            diagnosis
                << "same target in 2x logical units: "
                << (offscreen.first / 2u)
                << "x"
                << (offscreen.second / 2u)
                << "\n";
        }

        if (host_surface) {
            const double host_aspect = Aspect(*host_surface);
            const double offscreen_aspect = Aspect(offscreen);
            const double delta =
                std::abs(host_aspect - offscreen_aspect);

            diagnosis
                << std::fixed
                << std::setprecision(6)
                << "aspect host="
                << host_aspect
                << " guestTarget="
                << offscreen_aspect
                << " delta="
                << delta
                << "\n";
        }
    }

    diagnosis
        << "768-point-height signature: "
        << (canonical_768 ? "YES" : "NO")
        << "\n\n"
        << "UI PLATFORM SELECTION\n"
        << "---------------------\n"
        << "UI_ANDROID observed: "
        << (ui_android ? "YES" : "NO")
        << "\n"
        << "UI_IPAD observed: "
        << (ui_ipad ? "YES" : "NO")
        << "\n\n"
        << "DIAGNOSIS\n"
        << "---------\n";

    if (host_matches_pixels && exact_2x_contract) {
        diagnosis
            << "1. The v73 half-resolution host-FBO problem is NOT present in this v74 log. "
            << "The host surface and the JNI pixel/point contract are internally consistent.\n";
    } else {
        diagnosis
            << "1. Host/JNI geometry is still inconsistent; fix that before changing UI resources.\n";
    }

    if (offscreen_present) {
        diagnosis
            << "2. PvZ2 itself creates a separate "
            << SizeText(offscreen)
            << " target, then also renders/presents at the host size. "
            << "That makes the remaining visual scale issue guest-side, not a simple UIKit/live-view stretch.\n";
    }

    if (canonical_768) {
        diagnosis
            << "3. "
            << SizeText(offscreen)
            << " corresponds to "
            << (offscreen.first / 2u)
            << "x768 logical units at the reported 2x density. "
            << "This is compatible with an intentional 768-point canonical render height; it is evidence, not proof, of the engine's internal normalization path.\n";
    }

    if (ui_android && !ui_ipad) {
        diagnosis
            << "4. The run explicitly loads RESFILE_PACKAGES_UI_ANDROID and never observes UI_IPAD. "
            << "With native host geometry already correct, platform UI selection is now the highest-information axis to compare against the historical iOS build.\n";
    }

    if (can_set_scale_false) {
        diagnosis
            << "5. The Android bridge also tells the guest that GL-view scale is not settable. "
            << "Do not flip this blindly: compare it with the real iOS EAGLView/contentScaleFactor path first, then test it as a separate A/B mode.\n";
    }

    std::ostringstream plan;
    plan
        << "PvZ2 Inspector Lab v2.2-alpha - proposed v75 A/B display probe\n"
        << "=============================================================\n\n"
        << "Keep v74 rendering/input/resource scheduling untouched and batch the whole display/UI class into one build:\n\n"
        << "MODE A — V74_BASELINE\n"
        << "  Exact v74 behavior for control.\n\n"
        << "MODE B — IOS_UI_REFERENCE\n"
        << "  Remap only the UI package selection from Android to the official iPad RTON through the compatibility/VFS layer. "
        << "Do not change FBO size, GameState, readiness, touch or keyboard behavior. "
        << "Log both requested resource ID and actual served path.\n\n"
        << "MODE C — IOS_SCALE_REFERENCE\n"
        << "  Only if the historical iOS Inspector evidence confirms a real EAGL/contentScaleFactor path, emulate that scale contract without combining it with the UI remap. "
        << "Log screen pixels, points, point-size, CanSet/Get/Set scale calls, every distinct viewport and every FBO attachment size.\n\n"
        << "DECISION\n"
        << "  If B alone fixes proportions, keep the native Retina surface and reproduce iOS UI package selection.\n"
        << "  If C changes the "
        << (offscreen_present ? SizeText(offscreen) : std::string{"guest offscreen"})
        << " target while B does not, the scale-factor bridge is causal.\n"
        << "  If neither fixes it, inspect the first screen's concrete layout objects in UI_ANDROID/UI_IPAD and the iOS Mach-O callsites before touching rendering again.\n";

    std::ostringstream critical;
    critical
        << "PvZ2 Inspector v2.2-alpha - v74 display critical evidence\n"
        << "=========================================================\n";
    for (const auto& line : excerpt) {
        critical << line << "\n";
    }

    result.diagnosis = diagnosis.str();
    result.next_plan = plan.str();
    result.critical_excerpt = critical.str();
    return result;
}
