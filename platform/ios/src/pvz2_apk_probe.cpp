#include "pvz2_apk_probe.hpp"
#include "host_gles.hpp"
#include "host_audio.hpp"

#include <OpenGLES/ES2/gl.h>
#include <OpenGLES/ES2/glext.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <deque>
#include <cwctype>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <chrono>
#include <fnmatch.h>
#include <limits>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/exclusive_monitor.h>
#include <zlib.h>

// Test-only fresh persistence root. Both config-v1.txt (purchase ownership
// masks and the 60k grant marker) and the Android UserFS must be redirected
// together; otherwise the old global entitlements would leak to test2.
namespace {
const char* PvZ2QaPersistentEnvKey(const char* key) {
    if (key == nullptr || std::strcmp(key, "HOME") != 0) {
        return key;
    }
    static const bool qa_home_ready = [] {
        const char* original = std::getenv("HOME");
        if (original == nullptr || *original == '\0') {
            return false;
        }
        const std::string root =
            std::string{original} + "/PvZ2forIOS_QA_TestProfiles_20261001";
        return ::setenv(
            "PVZ2_QA_ISOLATED_HOME_20261001",
            root.c_str(),
            1) == 0;
    }();
    // Never silently import the old save when the QA path cannot be set up.
    return qa_home_ready
        ? "PVZ2_QA_ISOLATED_HOME_20261001"
        : "PVZ2_QA_ISOLATED_HOME_SETUP_FAILED";
}
}


// v110 source-layout refactor: the historical probe grew to ~39k lines.
// Keep one translation unit (shared private runtime state remains unchanged),
// but store the implementation in connector-sized include fragments.
#include "pvz2_apk_probe_parts/part_00.inc"
#include "pvz2_apk_probe_parts/part_01.inc"
#define getenv(key) getenv(PvZ2QaPersistentEnvKey(key))
#include "pvz2_apk_probe_parts/part_02.inc"
#undef getenv
#include "pvz2_apk_probe_parts/part_03.inc"
#include "pvz2_apk_probe_parts/part_04.inc"
#include "pvz2_apk_probe_parts/part_05.inc"
#define getenv(key) getenv(PvZ2QaPersistentEnvKey(key))
#include "pvz2_apk_probe_parts/part_06.inc"
#undef getenv
#include "pvz2_apk_probe_parts/part_07.inc"
#include "pvz2_apk_probe_parts/part_08.inc"
#include "pvz2_apk_probe_parts/part_09.inc"
