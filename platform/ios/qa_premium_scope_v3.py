#!/usr/bin/env python3
"""QA v3: correct candidate native entitlement vector layout and instrument it.

Runs *after* qa_keyboard_profile_patch.py; exact anchors checked, idempotent.
Fresh v3 UserFS and V128 config isolate saves previously written by the
incorrect vector overlay. This does not remove the user's existing files.
"""
from pathlib import Path

BASE=Path(__file__).resolve().parent/"src"/"pvz2_apk_probe_parts"

def patch(file,old,new):
    file=BASE/file
    c=file.read_text(encoding="utf-8")
    if c.count(new)==1: return
    if c.count(old)!=1:
        raise RuntimeError(f"QA v3 anchor mismatch {file.name}: {c.count(old)}")
    file.write_text(c.replace(old,new,1),encoding="utf-8")

# Change both persisted paths. v2 data is potentially contaminated by the
# earlier wrong PlayerInfo offset and must not be used to validate this fix.
patch("part_02.inc",
    'config-qa-keyboard-testprofiles-v2.txt";',
    'config-qa-premium-scope-v3.txt";')
patch("part_06.inc",
    'UserData-QA-Keyboard-TestProfiles-v2" +',
    'UserData-QA-Premium-Scope-v3" +')
patch("part_06.inc",
    'PvZ2forIOS-QA-Keyboard-TestProfiles-v2" +',
    'PvZ2forIOS-QA-Premium-Scope-v3" +')

# PlayerInfo embeds GlobalSaveData at +0x30 (4-byte header). The candidate
# unlocked-plants vector begins at +0x34; the next vector of int feature IDs
# begins at +0x40. These candidates are checked at runtime before mutation.
patch("part_01.inc",
"""            if (!OfflineStoreReadTargetMask(
                    profile, 0x18u, true, plant_mask) ||
                !OfflineStoreReadTargetMask(
                    profile, 0x34u, false, feature_mask)) {
""",
"""            if (!OfflineStoreReadTargetMask(
                    profile, 0x34u, true, plant_mask) ||
                !OfflineStoreReadTargetMask(
                    profile, 0x40u, false, feature_mask)) {
""")

patch("part_01.inc",
"""        if (!OfflineStoreRewriteTargetVector(
                profile, 0x18u, true, plant_mask) ||
            !OfflineStoreRewriteTargetVector(
                profile, 0x34u, false, feature_mask)) {
            return false;
        }

        bool config_changed = false;
""",
"""        // Preflight *both* vectors before rewriting either one, and record
        // the original visible bits for comparing A -> B -> A in one log.
        std::uint32_t before_plants=0u;
        std::uint32_t before_features=0u;
        if (!OfflineStoreReadTargetMask(
                profile,0x34u,true,before_plants) ||
            !OfflineStoreReadTargetMask(
                profile,0x40u,false,before_features)) {
            AppendCritical("QA PREMIUM LAYOUT rejected: vector preflight");
            return false;
        }
        AppendDiagnostic(
            "QA PREMIUM PROFILE BEFORE id=" + std::to_string(profile_id) +
            " profile=0x" + JniProbeHex(profile) +
            " nativePlants=0x" + JniProbeHex(before_plants) +
            " nativeFeatures=0x" + JniProbeHex(before_features) +
            " ownerPlants=0x" + JniProbeHex(plant_mask) +
            " ownerFeatures=0x" + JniProbeHex(feature_mask));

        if (!OfflineStoreRewriteTargetVector(
                profile, 0x34u, true, plant_mask) ||
            !OfflineStoreRewriteTargetVector(
                profile, 0x40u, false, feature_mask)) {
            return false;
        }
        std::uint32_t after_plants=0u;
        std::uint32_t after_features=0u;
        if (!OfflineStoreReadTargetMask(
                profile,0x34u,true,after_plants) ||
            !OfflineStoreReadTargetMask(
                profile,0x40u,false,after_features) ||
            after_plants != plant_mask ||
            after_features != feature_mask) {
            AppendCritical(
                "QA PREMIUM LAYOUT post-write verification failed id=" +
                std::to_string(profile_id));
            return false;
        }
        AppendDiagnostic(
            "QA PREMIUM PROFILE APPLIED id=" + std::to_string(profile_id) +
            " plants=0x" + JniProbeHex(after_plants) +
            " features=0x" + JniProbeHex(after_features));

        bool config_changed = false;
""")

patch("part_01.inc",
"""                plants ? 0x18u : 0x34u,
                plants,
                mask)) {
""",
"""                plants ? 0x34u : 0x40u,
                plants,
                mask)) {
""")

patch("part_01.inc",
"""        Append(
            "OFFLINE STORE PROFILE PURCHASE id=" +
""",
"""        AppendDiagnostic(
            "QA PREMIUM PURCHASE owner=" + std::to_string(profile_id) +
            " kind=" + (plants ? std::string{"plant"} : std::string{"feature"}) +
            " id=" + std::to_string(entry.entitlement_id) +
            " mask=0x" + JniProbeHex(mask));
        Append(
            "OFFLINE STORE PROFILE PURCHASE id=" +
""")

# In the previous build switching profiles was arbitrarily delayed until the
# next frame divisible by 120. Detect the switch immediately; throttle only
# actual failed writes, so the store sees the new entitlement mask on open.
patch("part_01.inc",
"""    std::uint32_t offline_store_last_profile_ptr = 0u;
""",
"""    std::uint32_t offline_store_last_profile_ptr = 0u;
    std::uint32_t offline_store_next_profile_retry_frame = 0u;
""")

patch("part_09.inc",
"""                                if ((callbacks.current_frame_number < 3u ||
                                     callbacks.current_frame_number % 120u == 0u) &&
                                    (callbacks
                                        .offline_store_last_profile_ptr == 0u ||
                                     callbacks
                                        .offline_store_last_profile_id !=
                                            observed_profile_id)) {
""",
"""                                if (callbacks.current_frame_number >=
                                        callbacks.offline_store_next_profile_retry_frame &&
                                    (callbacks
                                        .offline_store_last_profile_ptr == 0u ||
                                     callbacks
                                        .offline_store_last_profile_id !=
                                            observed_profile_id)) {
""")

patch("part_09.inc",
"""                                        if (callbacks.fallback_logged.insert(
                                                "qa-profile-write-retry")
                                                .second) {
                                            callbacks.AppendCritical(
                                                "QA PROFILE: sidecar write failed; gameplay continues, purchases held until persistence works.");
                                        }
""",
"""                                        callbacks.offline_store_next_profile_retry_frame =
                                            callbacks.current_frame_number+120u;
                                        callbacks.AppendDiagnostic(
                                            "QA PREMIUM PROFILE RETRY id=" +
                                            std::to_string(active_profile_id));
                                        if (callbacks.fallback_logged.insert(
                                                "qa-profile-write-retry")
                                                .second) {
                                            callbacks.AppendCritical(
                                                "QA PROFILE: sidecar write failed; gameplay continues, purchases held until persistence works.");
                                        }
""")

# Existing failed writer retry must reset when successful and after switch.
patch("part_09.inc",
"""                                    if (active_profile != 0u &&
                                        !callbacks
                                            .OfflineStoreApplyProfileEntitlements(
                                                active_profile,
                                                active_profile_id)) {
""",
"""                                    if (active_profile != 0u &&
                                        !callbacks
                                            .OfflineStoreApplyProfileEntitlements(
                                                active_profile,
                                                active_profile_id)) {
""") # semantic no-op check, kept explicit as a stable anchor

# Make payment and catalog receipt visible without a completed probe dump.
patch("part_05.inc",
"""                        pending_offline_catalog_refresh = true;
                        regs[0] = 0u;
                        Append("OFFLINE STORE Refresh queued requestedSkus=" +
""",
"""                        pending_offline_catalog_refresh = true;
                        regs[0] = 0u;
                        AppendDiagnostic(
                            "QA PREMIUM CATALOG REFRESH profile=" +
                            std::to_string(offline_store_last_profile_id) +
                            " skus=" +
                            std::to_string(pending_offline_refresh_skus.size()));
                        Append("OFFLINE STORE Refresh queued requestedSkus=" +
""")
patch("part_05.inc",
"""                        regs[0] = 0u;
                        Append(
                            "OFFLINE STORE RequestPayment queued sku=" + sku +
""",
"""                        regs[0] = 0u;
                        AppendDiagnostic(
                            "QA PREMIUM PAYMENT REQUEST owner=" +
                            std::to_string(offline_store_last_profile_id) +
                            " sku=" + sku);
                        Append(
                            "OFFLINE STORE RequestPayment queued sku=" + sku +
""")
print("QA premium v3 prepared: fresh v3 state, vector pre/post checks, immediate switch, live billing probes.")
