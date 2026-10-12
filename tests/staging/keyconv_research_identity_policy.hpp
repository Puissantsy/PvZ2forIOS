#pragma once
// KEYOBS research app identity under iOS IPA re-signing.
// The compiler only includes this in a separately compiled research app.
// The Info.plist non-standard marker must survive signing; the system's
// CFBundleIdentifier is NOT immutable under sideload re-signing.
#include <string_view>
namespace pvz2_key_study::keyconv_identity {
enum class Result {
    Allowed,
    MissingResearchMarker,
    MissingRuntimeBundle,
    ProductionIdentifier
};
inline Result Evaluate(std::string_view installed_id,
                       bool research_marker) {
    if (!research_marker)
        return Result::MissingResearchMarker;
    if (installed_id.empty())
        return Result::MissingRuntimeBundle;
    // If the user accidentally signed the research IPA over a production
    // bundle ID, NEVER touch that application's saved game.
    if (installed_id=="com.puissantsy.pvz2forios" ||
        installed_id=="com.puissantsy.pvz2forios.production" ||
        installed_id=="com.ea.game.pvz2_row" ||
        installed_id.starts_with("com.ea.game.pvz2_row.")) {
        return Result::ProductionIdentifier;
    }
    // A sideload signer may append a Team ID/suffix or replace the installed
    // identifier entirely. The separately compiled research marker, backup,
    // explicit slot consent, and guest-stopped journal remain required.
    return Result::Allowed;
}
} // namespace pvz2_key_study::keyconv_identity
