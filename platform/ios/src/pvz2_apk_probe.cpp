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


// v110 source-layout refactor: the historical probe grew to ~39k lines.
// Keep one translation unit (shared private runtime state remains unchanged),
// but store the implementation in connector-sized include fragments.
#include "pvz2_apk_probe_parts/part_00.inc"
#include "pvz2_apk_probe_parts/part_01.inc"
#include "pvz2_apk_probe_parts/part_02.inc"
#include "pvz2_apk_probe_parts/part_03.inc"
#include "pvz2_apk_probe_parts/part_04.inc"
#include "pvz2_apk_probe_parts/part_05.inc"
#include "pvz2_apk_probe_parts/part_06.inc"
#include "pvz2_apk_probe_parts/part_07.inc"
#include "pvz2_apk_probe_parts/part_08.inc"
#include "pvz2_apk_probe_parts/part_09.inc"
