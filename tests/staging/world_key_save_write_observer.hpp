#pragma once
// Bound the optional write-set trace to known original native profile files.
// No filesystem access and no writes; only used by KEYCONV research mode.
#include <string_view>
namespace pvz2_key_study {
inline bool IsObservedNativeProfileSave(std::string_view path) {
    constexpr std::string_view marker="/No_Backup/";
    const auto pos=path.rfind(marker);
    if(pos==std::string_view::npos) return false;
    const auto name=path.substr(pos+marker.size());
    return name=="pp.dat" || name=="snapshot2.dat" ||
           name=="local_profiles";
}
} // namespace pvz2_key_study
