#include "v68_analyzer.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace {

std::optional<std::uint64_t> ParseUnsignedAfter(
    std::string_view line,
    std::string_view marker,
    int base = 10) {

    const std::size_t pos = line.find(marker);
    if (pos == std::string_view::npos) return std::nullopt;

    std::size_t p = pos + marker.size();
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
        } else if (base == 16 && ch >= 'a' && ch <= 'f') {
            digit = 10u + static_cast<unsigned>(ch - 'a');
            valid = true;
        } else if (base == 16 && ch >= 'A' && ch <= 'F') {
            digit = 10u + static_cast<unsigned>(ch - 'A');
            valid = true;
        }

        if (!valid || digit >= static_cast<unsigned>(base)) break;
        any = true;
        value = value * static_cast<unsigned>(base) + digit;
    }

    return any
        ? std::optional<std::uint64_t>{value}
        : std::nullopt;
}

std::string Hex(std::uint32_t value) {
    std::ostringstream out;
    out << "0x" << std::hex;
    out.width(8);
    out.fill('0');
    out << value;
    return out.str();
}

std::string ExtractBracketedAfter(
    std::string_view line,
    std::string_view marker) {

    const std::size_t pos = line.find(marker);
    if (pos == std::string_view::npos) return {};

    const std::size_t begin = pos + marker.size();
    const std::size_t end = line.find(']', begin);
    if (end == std::string_view::npos) return {};

    return std::string(line.substr(begin, end - begin));
}

std::string ContextAround(
    const std::string& log,
    const std::string& needle,
    std::size_t before_lines,
    std::size_t after_lines) {

    const std::size_t hit = log.find(needle);
    if (hit == std::string::npos) return {};

    std::size_t begin = hit;
    for (std::size_t i = 0; i < before_lines && begin > 0; ++i) {
        const std::size_t from = begin >= 2 ? begin - 2 : 0;
        const std::size_t nl = log.rfind('\n', from);
        if (nl == std::string::npos) {
            begin = 0;
            break;
        }
        begin = nl + 1;
    }

    std::size_t end = hit;
    for (std::size_t i = 0; i <= after_lines && end < log.size(); ++i) {
        const std::size_t nl = log.find('\n', end);
        if (nl == std::string::npos) {
            end = log.size();
            break;
        }
        end = nl + 1;
    }

    return log.substr(begin, end - begin);
}

std::string TailLines(
    const std::string& log,
    std::size_t count) {

    if (log.empty()) return {};

    std::size_t begin = log.size();
    for (std::size_t i = 0; i < count && begin > 0; ++i) {
        const std::size_t from = begin >= 2 ? begin - 2 : 0;
        const std::size_t nl = log.rfind('\n', from);
        if (nl == std::string::npos) {
            begin = 0;
            break;
        }
        begin = nl + 1;
    }
    return log.substr(begin);
}

} // namespace

PvZ2V68RuntimeAnalysis AnalyzeV68RuntimeLog(
    const std::string& log) {

    PvZ2V68RuntimeAnalysis result;

    if (log.find("V68_COMPLETION_TOKEN_SEMANTICS") == std::string::npos &&
        log.find("V68 COMPLETION-TOKEN SEMANTICS") == std::string::npos) {
        return result;
    }

    result.present = true;

    std::uint64_t line_count = 0;
    bool logo_screen = false;
    bool first_draw_started = false;
    bool first_draw_returned = false;
    bool watchdog = false;
    bool fail_fast = false;

    bool worker7_payload = false;
    std::uint32_t worker7_entry = 0;
    std::uint32_t worker7_this = 0;
    std::uint64_t worker7_slice_samples = 0;
    std::uint64_t worker7_max_ticks = 0;
    bool worker7_cond_wait = false;
    bool worker7_sem_wait = false;
    bool worker7_sleep = false;

    std::uint64_t max_pump_unlock = 0;
    std::uint64_t max_task_guard = 0;
    std::uint64_t max_safe_yields = 0;
    std::uint64_t texture_uploads = 0;
    std::uint64_t idle_not_stall = 0;
    bool startup_soundbank_missing = false;
    std::string last_generated_group;

    std::map<std::string, std::uint64_t> task_substates;

    std::size_t line_begin = 0;
    while (line_begin < log.size()) {
        std::size_t line_end = log.find('\n', line_begin);
        if (line_end == std::string::npos) line_end = log.size();

        ++line_count;
        const std::string_view line(
            log.data() + line_begin,
            line_end - line_begin);

        if (line.find("V53 GAMESTATE APPLY") != std::string_view::npos &&
            line.find("GAME_LogoScreen") != std::string_view::npos) {
            logo_screen = true;
        }

        if (line.find("V39 FRAME SOAK: begin frame 1/") !=
                std::string_view::npos ||
            line.find("Entering Native_onDrawFrame") !=
                std::string_view::npos) {
            first_draw_started = true;
        }

        if (line.find("Native_onDrawFrame returned") !=
                std::string_view::npos ||
            line.find("V39 FRAME SOAK: end frame 1/") !=
                std::string_view::npos) {
            first_draw_returned = true;
        }

        if (line.find("V66 TASK STAGNATION STOP") !=
            std::string_view::npos) {
            watchdog = true;
        }

        if (line.find("FAIL-FAST") != std::string_view::npos) {
            fail_fast = true;
        }

        if (line.find("V61 WORKER PAYLOAD tid=7") !=
            std::string_view::npos) {
            worker7_payload = true;

            if (const auto v =
                    ParseUnsignedAfter(line, "entry=0x", 16)) {
                worker7_entry =
                    static_cast<std::uint32_t>(*v);
            }
            if (const auto v =
                    ParseUnsignedAfter(line, "this=0x", 16)) {
                worker7_this =
                    static_cast<std::uint32_t>(*v);
            }
        }

        if (line.find("V22 WORKER SLICE tid=7") !=
            std::string_view::npos) {
            ++worker7_slice_samples;

            if (const auto v =
                    ParseUnsignedAfter(line, "total_ticks=")) {
                worker7_max_ticks =
                    std::max(worker7_max_ticks, *v);
            }
        }

        if (line.find("V65 COND WAIT") != std::string_view::npos &&
            line.find("tid=7") != std::string_view::npos) {
            worker7_cond_wait = true;
        }
        if (line.find("V66 SEM WAIT") != std::string_view::npos &&
            line.find("tid=7") != std::string_view::npos) {
            worker7_sem_wait = true;
        }
        if (line.find("V66 SLEEP") != std::string_view::npos &&
            line.find("tid=7") != std::string_view::npos) {
            worker7_sleep = true;
        }

        if (line.find("V61 RES-STREAM PUMP UNLOCK #") !=
            std::string_view::npos) {
            if (const auto v =
                    ParseUnsignedAfter(
                        line,
                        "V61 RES-STREAM PUMP UNLOCK #")) {
                max_pump_unlock =
                    std::max(max_pump_unlock, *v);
            }
        }

        if (line.find("V63 TASK GUARD #") !=
            std::string_view::npos) {
            if (const auto v =
                    ParseUnsignedAfter(
                        line,
                        "V63 TASK GUARD #")) {
                max_task_guard =
                    std::max(max_task_guard, *v);
            }
        }

        if (const auto v =
                ParseUnsignedAfter(
                    line,
                    "safeReleaseYields=")) {
            max_safe_yields =
                std::max(max_safe_yields, *v);
        }

        if (line.find("V41 GLES TEXUPLOAD #") !=
            std::string_view::npos) {
            if (const auto v =
                    ParseUnsignedAfter(
                        line,
                        "V41 GLES TEXUPLOAD #")) {
                texture_uploads =
                    std::max(texture_uploads, *v);
            }
        }

        if (line.find(
                "AttachGroupToPool : Generating textures for [") !=
            std::string_view::npos) {

            const std::string group =
                ExtractBracketedAfter(
                    line,
                    "AttachGroupToPool : Generating textures for [");

            if (!group.empty()) {
                last_generated_group = group;
            }
        }

        if (line.find("Could not load SoundBank: soundbanks") !=
                std::string_view::npos ||
            line.find("Failed to load sound bank: soundbanks") !=
                std::string_view::npos) {
            startup_soundbank_missing = true;
        }

        if (line.find("v68TokenState=IDLE_NOT_STALL") !=
            std::string_view::npos) {
            ++idle_not_stall;
        }

        const std::string_view marker =
            "V66 TASK SUBSTATE ";
        const std::size_t pos =
            line.find(marker);

        if (pos != std::string_view::npos) {
            const std::size_t kb =
                pos + marker.size();
            const std::size_t ke =
                line.find(' ', kb);

            const auto hit =
                ParseUnsignedAfter(line, "hit=");
            const auto tid =
                ParseUnsignedAfter(line, "tid=");
            const auto value =
                ParseUnsignedAfter(line, "vfnCResult=");

            if (ke != std::string_view::npos &&
                hit && tid && value && *tid == 7) {

                const std::string key =
                    std::string(
                        line.substr(
                            kb,
                            ke - kb)) +
                    "/result=" +
                    std::to_string(*value);

                task_substates[key] =
                    std::max(
                        task_substates[key],
                        *hit);
            }
        }

        if (line_end == log.size()) break;
        line_begin = line_end + 1;
    }

    const auto state_hit =
        [&](const std::string& key) -> std::uint64_t {
            const auto it = task_substates.find(key);
            return
                it == task_substates.end()
                    ? 0u
                    : it->second;
        };

    const bool stable_cycle =
        state_hit("A.dep+20/result=1") >= 1000000u &&
        state_hit("B.dep+20/result=0") >= 1000000u &&
        state_hit("B.vector78/result=1") >= 1000000u &&
        state_hit("A.vector84/result=0") >= 1000000u;

    std::ostringstream diagnosis;
    diagnosis
        << "PvZ2 Inspector Lab v2.1-alpha - v68 resource lifecycle\n"
        << "=======================================================\n"
        << "source log: "
        << log.size()
        << " bytes / "
        << line_count
        << " lines\n\n"
        << "MILESTONES\n"
        << "----------\n"
        << "GAME_LogoScreen applied: "
        << (logo_screen ? "YES" : "NO")
        << "\n"
        << "Native_onDrawFrame entered: "
        << (first_draw_started ? "YES" : "NO")
        << "\n"
        << "Native_onDrawFrame returned: "
        << (first_draw_returned ? "YES" : "NO")
        << "\n"
        << "GLES texture uploads: "
        << texture_uploads
        << "\n"
        << "last generated texture group: "
        << (last_generated_group.empty()
                ? "(none)"
                : last_generated_group)
        << "\n"
        << "startup soundbank failure: "
        << (startup_soundbank_missing ? "YES" : "NO")
        << "\n\n"
        << "RESOURCE WORKER / PUMP\n"
        << "----------------------\n"
        << "worker tid=7 payload: "
        << (worker7_payload ? "YES" : "NO")
        << " entry="
        << Hex(worker7_entry)
        << " this="
        << Hex(worker7_this)
        << "\n"
        << "worker-7 sampled slices: "
        << worker7_slice_samples
        << ", max total_ticks="
        << worker7_max_ticks
        << "\n"
        << "worker-7 waits observed: cond="
        << (worker7_cond_wait ? "YES" : "NO")
        << " sem="
        << (worker7_sem_wait ? "YES" : "NO")
        << " sleep="
        << (worker7_sleep ? "YES" : "NO")
        << "\n"
        << "max pump unlock #: "
        << max_pump_unlock
        << "\n"
        << "max TaskResource dispatch #: "
        << max_task_guard
        << "\n"
        << "max safeReleaseYields: "
        << max_safe_yields
        << "\n"
        << "IDLE_NOT_STALL samples: "
        << idle_not_stall
        << "\n"
        << "legacy watchdog/fail-fast: "
        << (watchdog ? "YES" : "NO")
        << "/"
        << (fail_fast ? "YES" : "NO")
        << "\n\n"
        << "TASKRESOURCE SUBSTATE MAXIMA (tid=7)\n"
        << "-----------------------------------\n";

    for (const auto& [key, value] : task_substates) {
        diagnosis
            << key
            << " -> "
            << value
            << "\n";
    }

    diagnosis
        << "\nDIAGNOSIS\n"
        << "---------\n";

    if (logo_screen &&
        texture_uploads >= 5 &&
        first_draw_started &&
        !first_draw_returned &&
        stable_cycle &&
        !watchdog &&
        !fail_fast) {

        diagnosis
            << "CONFIRMED CLASS: post-LogoScreen TaskResource lifecycle "
               "livelock / non-draining resource queue.\n"
            << "v68 successfully removes the false token-zero watchdog: "
               "startup advances into GAME_LogoScreen and real UI texture "
               "generation/upload, then remains alive while the resource "
               "pump and TaskResource dispatch counts keep growing.\n"
            << "The stable cycle is now more specific than v67: Task A "
               "repeatedly sees a busy dependency; Task B sees an idle "
               "dependency but busy vector candidates; another Task A path "
               "continues to observe an idle vector84 token.\n"
            << "The current log does not record the result of TaskResource "
               "vfn14 itself, the active->completed transition, vfn18 "
               "start-work, completed vfn0c/vfn1c state, or vfn24 token "
               "finalization. Those lifecycle edges are now the smallest "
               "missing evidence class.\n";
    } else {
        diagnosis
            << "The supplied log does not match the complete known v68 "
               "post-LogoScreen livelock signature.\n";
    }

    diagnosis
        << "\nSTATIC CORRELATION FOR THE NEXT PROBE\n"
        << "-------------------------------------\n"
        << "The verified Android path places the resource worker at "
           "0x10abd894, Task A readiness at 0x10abe774, Task B readiness "
           "at 0x10abebb0, and completion-token counter>0 query at "
           "0x10abedb8. Task A completion polling at 0x10abe748 reads "
           "task+0x18 and then owner=[task+0x0c], owner+0x08; owner+8==0 "
           "is therefore a high-value completion gate. Do not force token "
           "counters: observe the lifecycle that should naturally release "
           "them.\n";

    result.diagnosis = diagnosis.str();

    std::ostringstream plan;
    plan
        << "PvZ2 Inspector Lab v2.1-alpha - v69 one-build plan\n"
        << "==================================================\n"
        << "Batch the whole TaskResource lifecycle into one probe build:\n"
        << "1. Observe task vfn14 result at pump CMP 0x10868cbc; count "
           "result 0/1 by vtable and task.\n"
        << "2. Observe vfn+0x3c at 0x10868cdc and vfn+0x18 start-work "
           "at 0x10868d1c; count active->completed moves.\n"
        << "3. Observe completed-vector vfn+0x0c/vfn+0x1c/vfn+0x20 around "
           "0x10868d8c..0x10868dc8 and vfn+0x24 finalization at "
           "0x10868e14.\n"
        << "4. For Task A vtable 0x10cd0bd8, log task+0x18, "
           "owner=[task+0x0c], owner+0x08, task+0x20 and task+0x28 only "
           "when values change.\n"
        << "5. Keep verified-token inc/dec totals in memory, but do not "
           "restore v67's per-store hot logs; emit only balance summaries "
           "and anomalies.\n"
        << "6. Suppress unchanged V63/V64/TaskSubstate spam once the "
           "signature is recognized. No forced readiness, counters, "
           "GameState or resources.\n\n"
        << "Success criterion: frame 1 returns, or one exact lifecycle "
           "edge is proven non-draining.\n";

    result.v69_plan = plan.str();

    std::ostringstream excerpt;
    excerpt
        << "PvZ2 Inspector Lab v2.1-alpha - v68 critical excerpts\n"
        << "=====================================================\n\n"
        << "LOGOSCREEN / UI TEXTURE TRANSITION\n"
        << "----------------------------------\n"
        << ContextAround(log, "GAME_LogoScreen", 8, 45)
        << "\nWORKER 7 CREATION\n"
        << "-----------------\n"
        << ContextAround(log, "V61 WORKER PAYLOAD tid=7", 5, 20)
        << "\nEND OF SUPPLIED LOG\n"
        << "-------------------\n"
        << TailLines(log, 36);

    result.critical_excerpt = excerpt.str();
    return result;
}
