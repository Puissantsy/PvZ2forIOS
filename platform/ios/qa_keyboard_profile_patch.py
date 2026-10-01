#!/usr/bin/env python3
"""QA branch build-time patch: exact Android Enter and isolated profile save.

Idempotent. Each transformation checks its exact source anchor and refuses
to build if the runtime layout has changed. No original user save is deleted.
"""
from pathlib import Path

BASE = Path(__file__).resolve().parent / "src"
PARTS = BASE / "pvz2_apk_probe_parts"


def patch(file, old, new):
    file = Path(file)
    source = file.read_text(encoding="utf-8")
    if source.count(new) == 1:
        return
    elif source.count(old) == 1:
        file.write_text(source.replace(old, new, 1), encoding="utf-8")
    else:
        raise RuntimeError(f"unsafe QA patch in {file.name}: original={source.count(old)}, patched={source.count(new)}")


main = BASE / "main.mm"

patch(main,
"""@property(nonatomic, strong)
    UITextField *keyboardField;
""",
"""@property(nonatomic, strong)
    UITextField *keyboardField;
@property(nonatomic, assign)
    BOOL keyboardSubmitQueued;
""")

patch(main,
"""    [self.view addSubview:self.keyboardField];
""",
"""    [self.view addSubview:self.keyboardField];

    // iPad's keyboard dismissal control can hide the keyboard without
    // resigning the invisible host UITextField. Reconcile both states.
    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(qaKeyboardDidHide:)
               name:UIKeyboardDidHideNotification
             object:nil];
""")

patch(main,
"""- (void)setHostKeyboardVisible:
        (BOOL)visible {
""",
"""- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)qaKeyboardDidHide:(NSNotification *)notification {
    if (self.keyboardField.isFirstResponder &&
        gPvZ2KeyboardRequested.load(std::memory_order_acquire)) {
        AppendPersistentLog(
            @"[QA KEYBOARD] system dismissed while field was still first responder");
        [self.keyboardField resignFirstResponder];
    }
}

- (void)setHostKeyboardVisible:
        (BOOL)visible {
""")

patch(main,
"""    if (visible) {
        const BOOL became =
            [self.keyboardField
                becomeFirstResponder];
""",
"""    if (visible) {
        if (!self.keyboardField.isFirstResponder) {
            self.keyboardSubmitQueued = NO;
            // Guest owns the rendered input text; this invisible field only
            // tracks the current iOS keyboard edit session.
            self.keyboardField.text = @"";
        }
        const BOOL became =
            [self.keyboardField
                becomeFirstResponder];
""")

patch(main,
"""- (void)textFieldDidEndEditing:
        (UITextField *)textField {

    gPvZ2KeyboardRequested.store(
""",
"""- (void)textFieldDidEndEditing:
        (UITextField *)textField {

    // System/manual keyboard dismissal must finalize the guest edit too.
    // Do NOT synthesize Enter for a guest-initiated HideKeyboard (e.g. Cancel).
    if (!self.keyboardSubmitQueued &&
        textField.text.length != 0u &&
        gPvZ2KeyboardRequested.load(
            std::memory_order_acquire)) {
        self.keyboardSubmitQueued = YES;
        PvZ2QueueTextInputEvent(0x100u, nullptr, 0u);
        PvZ2QueueTextInputEvent(0x101u, nullptr, 0u);
        AppendPersistentLog(
            @"[QA KEYBOARD] manual dismissal -> Android ENTER down/up");
    }

    gPvZ2KeyboardRequested.store(
""")

patch(main,
r"""- (BOOL)textFieldShouldReturn:
        (UITextField *)textField {

    static const std::uint8_t newline =
        static_cast<std::uint8_t>('\n');

    PvZ2QueueTextInputEvent(
        0u,
        &newline,
        1u);

    return YES;
}
""",
"""- (BOOL)textFieldShouldReturn:
        (UITextField *)textField {

    // Original Android EditInputConnection.sendKeyEvent(KEYCODE_ENTER=66)
    // calls AndroidUIEventManager.HandleKeyEvent, which serializes a type-1
    // UIKeyEvent. A UTF-8 newline alone does NOT end guest widget editing.
    self.keyboardSubmitQueued = YES;
    PvZ2QueueTextInputEvent(0x100u, nullptr, 0u); // ENTER down
    PvZ2QueueTextInputEvent(0x101u, nullptr, 0u); // ENTER up
    AppendPersistentLog(
        @"[QA KEYBOARD] Return -> Android ENTER down/up; resign UITextField");
    [textField resignFirstResponder];
    return NO;
}
""")

patch(PARTS / "part_08.inc",
"""    if (action != 0u &&
        action != 3u) {
""",
"""    // 0x100/0x101 are host-private queue markers: serialize them as real
    // Android UIKeyEvent records (type 1), not as UITextInputEvent text.
    if (action != 0u &&
        action != 3u &&
        action != 0x100u &&
        action != 0x101u) {
""")

patch(PARTS / "part_05.inc",
"""                                    const std::size_t padded =
                                        (event.utf8.size() + 3u) &
                                        ~std::size_t{3u};
                                    const std::size_t record_size =
                                        12u + padded;

                                    if (record_size >
                                        cleared - write_offset) {
                                        break;
                                    }

                                    std::uint8_t* record =
                                        buffer +
                                        write_offset;

                                    Write32(record + 0u, 6u);
                                    Write32(
                                        record + 4u,
                                        event.action);
                                    Write32(
                                        record + 8u,
                                        static_cast<std::uint32_t>(
                                            event.utf8.size()));

                                    if (!event.utf8.empty()) {
                                        std::memcpy(
                                            record + 12u,
                                            event.utf8.data(),
                                            event.utf8.size());
                                    }

                                    if (padded >
                                        event.utf8.size()) {
                                        std::memset(
                                            record +
                                                12u +
                                                event.utf8.size(),
                                            0,
                                            padded -
                                                event.utf8.size());
                                    }
""",
"""                                    const bool enter_key =
                                        event.action == 0x100u ||
                                        event.action == 0x101u;
                                    const std::size_t padded =
                                        (event.utf8.size() + 3u) &
                                        ~std::size_t{3u};
                                    const std::size_t record_size =
                                        enter_key ? 32u : (12u + padded);

                                    if (record_size >
                                        cleared - write_offset) {
                                        break;
                                    }

                                    std::uint8_t* record =
                                        buffer +
                                        write_offset;

                                    if (enter_key) {
                                        // classes.dex UIKeyEvent.Serialize:
                                        // type, keyCode, unicodeChar, action,
                                        // uptimeMillis(int64), repeat, DEADBEEF.
                                        const std::uint64_t ms =
                                            static_cast<std::uint64_t>(
                                                std::chrono::duration_cast<
                                                    std::chrono::milliseconds>(
                                                    std::chrono::steady_clock::now()
                                                        .time_since_epoch())
                                                    .count());
                                        Write32(record + 0u, 1u);
                                        Write32(record + 4u, 66u);
                                        Write32(record + 8u, 10u);
                                        Write32(record + 12u,
                                            event.action == 0x100u ? 0u : 1u);
                                        Write32(record + 16u,
                                            static_cast<std::uint32_t>(ms));
                                        Write32(record + 20u,
                                            static_cast<std::uint32_t>(ms >> 32u));
                                        Write32(record + 24u, 0u);
                                        Write32(record + 28u, 0xdeadbeefu);
                                        Append(
                                            "QA KEYBOARD ENTER delivered action=" +
                                            std::to_string(
                                                event.action == 0x100u ? 0u : 1u) +
                                            " frame=" +
                                            std::to_string(current_frame_number));
                                    } else {
                                        Write32(record + 0u, 6u);
                                        Write32(record + 4u, event.action);
                                        Write32(
                                            record + 8u,
                                            static_cast<std::uint32_t>(
                                                event.utf8.size()));
                                        if (!event.utf8.empty()) {
                                            std::memcpy(
                                                record + 12u,
                                                event.utf8.data(),
                                                event.utf8.size());
                                        }
                                        if (padded > event.utf8.size()) {
                                            std::memset(
                                                record + 12u + event.utf8.size(),
                                                0,
                                                padded - event.utf8.size());
                                        }
                                    }
""")

# New QA namespace below the ORIGINAL HOME/Library. The prior experimental
# HOME override is removed in the tracked pvz2_apk_probe.cpp, so both the
# configuration and UserFS land in the already-supported sandbox subtree.
patch(PARTS / "part_02.inc",
    '"/Library/Application Support/PvZ2forIOS/config-v1.txt";',
    '"/Library/Application Support/PvZ2forIOS/config-qa-keyboard-testprofiles-v2.txt";')

patch(PARTS / "part_06.inc",
    '"/Library/Application Support/PvZ2forIOS/UserData" +\n                        *suffix;',
    '"/Library/Application Support/PvZ2forIOS/UserData-QA-Keyboard-TestProfiles-v2" +\n                        *suffix;')

patch(PARTS / "part_06.inc",
    '"/Library/Caches/PvZ2forIOS" + *suffix;',
    '"/Library/Caches/PvZ2forIOS-QA-Keyboard-TestProfiles-v2" + *suffix;')

patch(PARTS / "part_02.inc",
"""        if (path.empty() || !V128EnsureHostParent(path)) {
            ++v128_config_failures;
            return false;
        }
""",
"""        if (path.empty() || !V128EnsureHostParent(path)) {
            const int reason = errno;
            ++v128_config_failures;
            AppendCritical(
                "QA PROFILE CONFIG: invalid path or mkdir failed errno=" +
                std::to_string(reason));
            return false;
        }
""")

patch(PARTS / "part_02.inc",
"""        std::FILE* file = std::fopen(temp.c_str(), "wb");
        if (file == nullptr) {
            ++v128_config_failures;
            return false;
        }
""",
"""        std::FILE* file = std::fopen(temp.c_str(), "wb");
        if (file == nullptr) {
            const int reason = errno;
            ++v128_config_failures;
            AppendCritical(
                "QA PROFILE CONFIG: fopen failed errno=" +
                std::to_string(reason) +
                " (sandbox QA config parent)");
            return false;
        }
""")

patch(PARTS / "part_02.inc",
"""        if (!ok) {
            ::unlink(temp.c_str());
            ++v128_config_failures;
            AppendDiagnostic("V128 CONFIG FLUSH FAILED");
            return false;
        }
""",
"""        if (!ok) {
            const int reason = errno;
            ::unlink(temp.c_str());
            ++v128_config_failures;
            AppendCritical(
                "QA PROFILE CONFIG: fsync/rename failed errno=" +
                std::to_string(reason));
            return false;
        }
""")

# In-memory migration keys must not claim success if they were never flushed.
patch(PARTS / "part_01.inc",
"""        const bool first_global_migration =
            v51_config_keys.count(kMigrationKey) == 0u;

        std::uint32_t plant_mask = 0u;
""",
"""        const bool first_global_migration =
            v51_config_keys.count(kMigrationKey) == 0u;
        const bool had_plant_key =
            v51_config_keys.count(plant_key) != 0u;
        const bool had_feature_key =
            v51_config_keys.count(feature_key) != 0u;

        std::uint32_t plant_mask = 0u;
""")

patch(PARTS / "part_01.inc",
"""        if (config_changed && !V128FlushConfig()) {
            AppendCritical(
                "OFFLINE STORE PROFILE failed to persist profile entitlement state.");
            return false;
        }
""",
"""        if (config_changed && !V128FlushConfig()) {
            // No false migration on a failed config write. A later frame can
            // safely retry instead of silently inheriting stale ownership.
            if (first_global_migration) {
                v51_config_keys.erase(kMigrationKey);
                v51_config_booleans.erase(kMigrationKey);
            }
            if (!had_plant_key) {
                v51_config_keys.erase(plant_key);
                v51_config_integers.erase(plant_key);
            }
            if (!had_feature_key) {
                v51_config_keys.erase(feature_key);
                v51_config_integers.erase(feature_key);
            }
            AppendCritical(
                "OFFLINE STORE PROFILE failed to persist profile entitlement state; migration will retry.");
            return false;
        }
""")

patch(PARTS / "part_09.inc",
"""                                if (callbacks.offline_store_last_profile_ptr ==
                                        0u ||
                                    callbacks.offline_store_last_profile_id !=
                                        observed_profile_id) {
""",
"""                                // Avoid hammering the save path if the
                                // sandbox refuses a write; never stop gameplay.
                                if ((callbacks.current_frame_number < 3u ||
                                     callbacks.current_frame_number % 120u == 0u) &&
                                    (callbacks
                                        .offline_store_last_profile_ptr == 0u ||
                                     callbacks
                                        .offline_store_last_profile_id !=
                                            observed_profile_id)) {
""")

patch(PARTS / "part_09.inc",
"""                                        callbacks.AppendCritical(
                                            "OFFLINE STORE PROFILE apply failed during account switch.");
                                        return false;
""",
"""                                        if (callbacks.fallback_logged.insert(
                                                "qa-profile-write-retry")
                                                .second) {
                                            callbacks.AppendCritical(
                                                "QA PROFILE: sidecar write failed; gameplay continues, purchases held until persistence works.");
                                        }
""")

# Never debit a profile while its entitlement ownership has not been
# safely persisted; otherwise a failed save might unlock globally.
patch(PARTS / "part_09.inc",
"""                        if (!run_lifecycle(
                                "OfflineStore_GetCoins",
                                kGetCoins, profile, 0u, 0u, false, true)) {
""",
"""                        if (callbacks.offline_store_last_profile_ptr !=
                                profile ||
                            callbacks.offline_store_last_profile_id !=
                                profile_id) {
                            if (callbacks.fallback_logged.insert(
                                    "qa-profile-payment-gated").second) {
                                callbacks.AppendCritical(
                                    "QA PROFILE purchase blocked: ownership save not ready");
                            }
                            if (!fire_incomplete(6)) return false;
                            callbacks.pending_offline_purchase =
                                PvZ2JniCallbacks::OfflinePurchaseRequest{};
                            return true;
                        }

                        if (!run_lifecycle(
                                "OfflineStore_GetCoins",
                                kGetCoins, profile, 0u, 0u, false, true)) {
""")

print(
    "QA keyboard/profile patches applied: Android Enter down/up, "
    "manual dismissal, isolated v2 saves, detailed config errors, "
    "retry-safe ownership migration."
)
