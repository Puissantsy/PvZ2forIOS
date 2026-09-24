            static_cast<std::uint64_t>(
                group_offset) +
                part1_offset +
                part1_zsize >
                obb_size) {
            return nullptr;
        }

        auto unpacked =
            std::make_shared<
                std::vector<std::uint8_t>>(
                    part1_size);

        const std::uint8_t* compressed =
            obb_data +
            static_cast<std::size_t>(
                group_offset) +
            part1_offset;

        if (part1_zsize ==
            part1_size) {

            std::memcpy(
                unpacked->data(),
                compressed,
                part1_size);
        } else {
            uLongf destination_size =
                static_cast<uLongf>(
                    part1_size);

            const int z_result =
                ::uncompress(
                    unpacked->data(),
                    &destination_size,
                    compressed,
                    static_cast<uLong>(
                        part1_zsize));

            if (z_result != Z_OK ||
                destination_size !=
                    part1_size) {
                Append(
                    "V31 PTX bridge: zlib inflate failed for " +
                    ptx_path +
                    " rc=" +
                    std::to_string(z_result));
                return nullptr;
            }
        }

        if (static_cast<std::uint64_t>(
                file_offset) +
                file_size >
            unpacked->size()) {
            return nullptr;
        }

        const std::uint64_t block_columns =
            (static_cast<std::uint64_t>(
                 width) +
             3u) /
            4u;
        const std::uint64_t block_rows =
            (static_cast<std::uint64_t>(
                 height) +
             3u) /
            4u;
        const std::uint64_t etc_bytes =
            block_columns *
            block_rows *
            8u;
        const std::uint64_t alpha_bytes =
            static_cast<std::uint64_t>(
                width) *
            height;
        const std::uint64_t expected =
            etc_bytes +
            alpha_bytes;

        if (expected >
                file_size ||
            file_offset + expected >
                unpacked->size()) {
            Append(
                "V31 PTX bridge: unsupported PTX payload shape " +
                ptx_path +
                " size=" +
                std::to_string(file_size) +
                " expected>=" +
                std::to_string(expected));
            return nullptr;
        }

        const std::uint8_t* texture =
            unpacked->data() +
            file_offset;
        const std::uint8_t* alpha =
            texture +
            etc_bytes;

        const std::uint64_t rgba_bytes =
            static_cast<std::uint64_t>(
                width) *
            height *
            4u;

        if (rgba_bytes >
            std::numeric_limits<
                std::size_t>::max() -
                18u) {
            return nullptr;
        }

        auto tga =
            std::make_shared<
                std::vector<std::uint8_t>>(
                    18u +
                    static_cast<std::size_t>(
                        rgba_bytes),
                    0u);

        (*tga)[2] = 2u;
        (*tga)[12] =
            static_cast<std::uint8_t>(
                width & 0xffu);
        (*tga)[13] =
            static_cast<std::uint8_t>(
                (width >> 8u) & 0xffu);
        (*tga)[14] =
            static_cast<std::uint8_t>(
                height & 0xffu);
        (*tga)[15] =
            static_cast<std::uint8_t>(
                (height >> 8u) & 0xffu);
        (*tga)[16] = 32u;
        (*tga)[17] = 0x28u;

        constexpr int modifiers[8][4] = {
            {2, 8, -2, -8},
            {5, 17, -5, -17},
            {9, 29, -9, -29},
            {13, 42, -13, -42},
            {18, 60, -18, -60},
            {24, 80, -24, -80},
            {33, 106, -33, -106},
            {47, 183, -47, -183},
        };

        auto clamp8 =
            [](int value) {
                return
                    static_cast<std::uint8_t>(
                        std::max(
                            0,
                            std::min(
                                255,
                                value)));
            };

        auto expand4 =
            [](int value) {
                return
                    (value << 4) |
                    value;
            };

        auto expand5 =
            [](int value) {
                return
                    (value << 3) |
                    (value >> 2);
            };

        auto signed3 =
            [](int value) {
                return
                    (value & 4)
                        ? value - 8
                        : value;
            };

        std::uint64_t block_index = 0;

        for (std::uint32_t by = 0;
             by < height;
             by += 4u) {

            for (std::uint32_t bx = 0;
                 bx < width;
                 bx += 4u) {

                const std::uint8_t* block =
                    texture +
                    block_index *
                    8u;
                ++block_index;

                const bool differential =
                    (block[3] & 0x02u) !=
                    0u;
                const bool flip =
                    (block[3] & 0x01u) !=
                    0u;

                const int table1 =
                    (block[3] >> 5u) &
                    7u;
                const int table2 =
                    (block[3] >> 2u) &
                    7u;

                int colors[2][3] = {};

                if (differential) {
                    const int r1 =
                        block[0] >> 3u;
                    const int g1 =
                        block[1] >> 3u;
                    const int b1 =
                        block[2] >> 3u;

                    const int r2 =
                        std::max(
                            0,
                            std::min(
                                31,
                                r1 +
                                signed3(
                                    block[0] &
                                    7u)));
                    const int g2 =
                        std::max(
                            0,
                            std::min(
                                31,
                                g1 +
                                signed3(
                                    block[1] &
                                    7u)));
                    const int b2 =
                        std::max(
                            0,
                            std::min(
                                31,
                                b1 +
                                signed3(
                                    block[2] &
                                    7u)));

                    colors[0][0] =
                        expand5(r1);
                    colors[0][1] =
                        expand5(g1);
                    colors[0][2] =
                        expand5(b1);
                    colors[1][0] =
                        expand5(r2);
                    colors[1][1] =
                        expand5(g2);
                    colors[1][2] =
                        expand5(b2);
                } else {
                    colors[0][0] =
                        expand4(
                            block[0] >> 4u);
                    colors[0][1] =
                        expand4(
                            block[1] >> 4u);
                    colors[0][2] =
                        expand4(
                            block[2] >> 4u);
                    colors[1][0] =
                        expand4(
                            block[0] & 0x0fu);
                    colors[1][1] =
                        expand4(
                            block[1] & 0x0fu);
                    colors[1][2] =
                        expand4(
                            block[2] & 0x0fu);
                }

                const std::uint32_t selector_bits =
                    (static_cast<std::uint32_t>(
                         block[4])
                     << 24u) |
                    (static_cast<std::uint32_t>(
                         block[5])
                     << 16u) |
                    (static_cast<std::uint32_t>(
                         block[6])
                     << 8u) |
                    static_cast<std::uint32_t>(
                        block[7]);

                for (std::uint32_t py = 0;
                     py < 4u;
                     ++py) {

                    for (std::uint32_t px = 0;
                         px < 4u;
                         ++px) {

                        const std::uint32_t x =
                            bx + px;
                        const std::uint32_t y =
                            by + py;

                        if (x >= width ||
                            y >= height) {
                            continue;
                        }

                        const std::uint32_t bit =
                            px * 4u + py;

                        const int selector =
                            static_cast<int>(
                                ((selector_bits >>
                                      (bit + 16u)) &
                                     1u)
                                    << 1u) |
                            static_cast<int>(
                                (selector_bits >>
                                 bit) &
                                1u);

                        const int subblock =
                            flip
                                ? (py >= 2u
                                    ? 1
                                    : 0)
                                : (px >= 2u
                                    ? 1
                                    : 0);

                        const int modifier =
                            modifiers[
                                subblock
                                    ? table2
                                    : table1][
                                selector];

                        const std::size_t pixel =
                            static_cast<std::size_t>(
                                y) *
                                width +
                            x;

                        const std::size_t out =
                            18u +
                            pixel *
                                4u;

                        const std::uint8_t r =
                            clamp8(
                                colors[subblock][0] +
                                modifier);
                        const std::uint8_t g =
                            clamp8(
                                colors[subblock][1] +
                                modifier);
                        const std::uint8_t b =
                            clamp8(
                                colors[subblock][2] +
                                modifier);

                        (*tga)[out + 0u] = b;
                        (*tga)[out + 1u] = g;
                        (*tga)[out + 2u] = r;
                        (*tga)[out + 3u] =
                            alpha[pixel];
                    }
                }
            }
        }

        SyntheticAsset asset;
        asset.bytes = tga;
        asset.source_path = ptx_path;
        asset.width = width;
        asset.height = height;

        auto inserted =
            synthetic_assets.emplace(
                asset_key,
                std::move(asset));

        Append(
            "V31 PTX->TGA bridge: \"" +
            requested +
            "\" <= " +
            ptx_path +
            " group=" +
            std::to_string(
                *group_index) +
            " " +
            std::to_string(width) +
            "x" +
            std::to_string(height) +
            " ptxBytes=" +
            std::to_string(file_size) +
            " tgaBytes=" +
            std::to_string(
                inserted.first
                    ->second
                    .bytes
                    ->size()));

        return
            &inserted.first->second;
    }

    void CallSVC(std::uint32_t swi) override {
        if (!jit) {
            return;
        }

        auto& regs = jit->Regs();

        // v95: host bridges can bypass Dynarmic scalar MemoryWrite
        // callbacks. Snapshot only while the exact external saved-LR slot is
        // armed. The local guard is allocation-free because every import uses
        // CallSVC and this path must remain cheap.
        const bool v94_svc_watch_active =
            v94_watch_armed;
        const std::uint32_t v94_svc_watch_slot =
            v94_svc_watch_active
                ? v94_watch_slot
                : 0u;
        const std::uint32_t v94_svc_before =
            v94_svc_watch_active
                ? mem.Read32Guest(v94_svc_watch_slot)
                : 0u;

        struct V94SvcExitGuard {
            PvZ2JniCallbacks* self = nullptr;
            std::uint32_t swi = 0u;
            bool active = false;
            std::uint32_t slot = 0u;
            std::uint32_t before = 0u;

            ~V94SvcExitGuard() {
                if (self != nullptr && active) {
                    self->V94FinalizeSvcWatch(
                        swi,
                        slot,
                        before);
                }
            }
        };

        V94SvcExitGuard v94_svc_guard{
            this,
            swi,
            v94_svc_watch_active,
            v94_svc_watch_slot,
            v94_svc_before};

        if (V94Enabled() &&
            swi == kJniProbeSvcV95WrapperPush) {

            // Original @0x10868978: PUSH {r4,r5,r11,lr}.
            const std::uint32_t old_sp =
                regs[13];
            const std::uint32_t new_sp =
                old_sp - 16u;
            const std::uint32_t entry_lr =
                regs[14];

            mem.Write32Guest(new_sp + 0u, regs[4]);
            mem.Write32Guest(new_sp + 4u, regs[5]);
            mem.Write32Guest(new_sp + 8u, regs[11]);
            mem.Write32Guest(new_sp + 12u, entry_lr);
            regs[13] = new_sp;

            constexpr std::uint32_t
                kExpectedOuterReturn =
                    kGuestBase + 0x0086f1fcu;

            if (entry_lr == kExpectedOuterReturn &&
                !v94_watch_armed) {
                ++v94_wrapper_entries;
                v94_watch_armed = true;
                v94_watch_slot =
                    new_sp + 12u;
                v94_entry_lr =
                    entry_lr;

                AppendDiagnostic(
                    std::string{RuntimeModeTag()} +
                    " LR-SLOT ARM #" +
                    std::to_string(
                        v94_wrapper_entries) +
                    " frame=" +
                    std::to_string(
                        current_frame_number) +
                    " slot=0x" +
                    JniProbeHex(
                        v94_watch_slot) +
                    " PC=0x" +
                    JniProbeHex(
                        kGuestBase +
                        0x00868978u) +
                    " LR=0x" +
                    JniProbeHex(entry_lr) +
                    " expected=0x" +
                    JniProbeHex(
                        kExpectedOuterReturn) +
                    " bit0=" +
                    std::to_string(
                        entry_lr & 1u) +
                    " SP=0x" +
                    JniProbeHex(new_sp));
            }

            return;
        }

        if (V94Enabled() &&
            swi == kJniProbeSvcV95WrapperPop) {

            // Original @0x108689c4: POP {r4,r5,r11,pc}.
            const std::uint32_t sp =
                regs[13];
            const std::uint32_t out_r4 =
                mem.Read32Guest(sp + 0u);
            const std::uint32_t out_r5 =
                mem.Read32Guest(sp + 4u);
            const std::uint32_t out_r11 =
                mem.Read32Guest(sp + 8u);
            const std::uint32_t raw_pc =
                mem.Read32Guest(sp + 12u);
            const std::uint32_t pop_slot =
                sp + 12u;

            const bool watched_pop =
                v94_watch_armed &&
                v94_watch_slot == pop_slot;

            if (watched_pop) {
                constexpr std::uint32_t
                    kExpectedOuterReturn =
                        kGuestBase + 0x0086f1fcu;

                AppendDiagnostic(
                    std::string{RuntimeModeTag()} +
                    " LR-SLOT POP frame=" +
                    std::to_string(
                        current_frame_number) +
                    " slot=0x" +
                    JniProbeHex(pop_slot) +
                    " value=0x" +
                    JniProbeHex(raw_pc) +
                    " expected=0x" +
                    JniProbeHex(
                        kExpectedOuterReturn) +
                    " bit0=" +
                    std::to_string(
                        raw_pc & 1u) +
                    " PC=0x" +
                    JniProbeHex(
                        kGuestBase +
                        0x008689c4u));

                v94_watch_armed = false;
            }

            regs[4] = out_r4;
            regs[5] = out_r5;
            regs[11] = out_r11;
            regs[13] = sp + 16u;
            regs[15] = raw_pc & ~1u;

            std::uint32_t cpsr =
                jit->Cpsr();
            if ((raw_pc & 1u) != 0u) {
                cpsr |= 0x20u;
            } else {
                cpsr &= ~0x20u;
            }
            jit->SetCpsr(cpsr);
            return;
        }

        // v79: exact first-run Profile provenance. Traps are installed only
        // for V75/V77, and each case below first reproduces the original ARM
        // instruction before reading anything for diagnostics.
        if (V79ProfileProbeEnabled() &&
            swi >= kJniProbeSvcV79SetWidthHeightEntry &&
            swi <= kJniProbeSvcV79GenericRect) {

            ++v79_profile_total_events;
            const std::uint64_t hit =
                ++v79_profile_hits[swi];
            const bool emit =
                hit <= 8u;

            auto f32_from_bits =
                [](std::uint32_t bits) {
                    float value = 0.0f;
                    std::memcpy(
                        &value,
                        &bits,
                        sizeof(value));
                    return value;
                };

            auto append_snapshot =
                [&](const char* site,
                    std::uint32_t object,
                    const std::string& detail) {

                    if (!emit) {
                        return;
                    }

                    const std::uint32_t app =
                        v52_last_app;
                    const std::uint32_t scale_bits =
                        app != 0u
                            ? mem.Read32Guest(
                                  app + 0x6a8u)
                            : 0u;
                    const float scale =
                        f32_from_bits(
                            scale_bits);

                    std::ostringstream line;
                    line
                        << "V79 PROFILE "
                        << site
                        << " hit="
                        << hit
                        << " frame="
                        << current_frame_number
                        << " object=0x"
                        << JniProbeHex(object)
                        << " parentWH="
                        << static_cast<std::int32_t>(
                               mem.Read32Guest(
                                   object + 0x30u))
                        << "x"
                        << static_cast<std::int32_t>(
                               mem.Read32Guest(
                                   object + 0x34u))
                        << " stateA0="
                        << static_cast<unsigned>(
                               mem.Read8(
                                   object + 0xa0u))
                        << " stateC8=0x"
                        << JniProbeHex(
                               mem.Read32Guest(
                                   object + 0xc8u))
                        << " app=0x"
                        << JniProbeHex(app)
                        << " scale6A8Bits=0x"
                        << JniProbeHex(scale_bits)
                        << " scale6A8="
                        << scale
                        << " lr="
                        << V46DescribeGuestAddress(
                               regs[14]);

                    if (!detail.empty()) {
                        line
                            << " "
                            << detail;
                    }

                    Append(
                        line.str());
                };

            switch (swi) {
            case kJniProbeSvcV79SetWidthHeightEntry: {
                // Original @0x102b8494: MOV r4,r0.
                regs[4] = regs[0];

                std::ostringstream detail;
                detail
                    << "inputR1="
                    << static_cast<std::int32_t>(
                           regs[1])
                    << " beforeWH="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               regs[0] + 0x70u))
                    << "x"
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               regs[0] + 0x74u))
                    << " baseHeight6B8="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               regs[0] + 0x6b8u));

                append_snapshot(
                    "SetWidthHeight.entry",
                    regs[0],
                    detail.str());
                return;
            }

            case kJniProbeSvcV79ProfileEntry:
                // Original @0x103095b4: MOV r11,r0.
                regs[11] = regs[0];
                if (V82Enabled()) {
                    v82_profile_object = regs[0];
                    V82ObserveProfileState("Profile.entry");
                }
                append_snapshot(
                    "Profile.entry",
                    regs[0],
                    "arg1=0x" +
                        JniProbeHex(
                            regs[1]));
                return;

            case kJniProbeSvcV79CheckboxEntry:
                // Original @0x103082d8: MOV r9,r0.
                regs[9] = regs[0];
                append_snapshot(
                    "Checkbox.entry",
                    regs[0],
                    "");
                return;

            case kJniProbeSvcV79CheckboxRect: {
                // Original @0x103083e8: MOV r2,#0.
                regs[2] = 0u;

                const std::uint32_t sp =
                    regs[13];
                std::ostringstream detail;
                detail
                    << "callArgs{r0=0x"
                    << JniProbeHex(regs[0])
                    << ",r1="
                    << static_cast<std::int32_t>(
                           regs[1])
                    << ",r2="
                    << static_cast<std::int32_t>(
                           regs[2])
                    << ",r3="
                    << static_cast<std::int32_t>(
                           regs[3])
                    << ",sp0="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(sp))
                    << "}";

                append_snapshot(
                    "Checkbox.rect",
                    regs[9],
                    detail.str());
                return;
            }

            case kJniProbeSvcV79FacebookEntry:
                // Original @0x103085f8: MOV r9,r0.
                regs[9] = regs[0];
                append_snapshot(
                    "FacebookButton.entry",
                    regs[0],
                    "");
                return;

            case kJniProbeSvcV79FacebookRect: {
                // Original @0x103087a8: MOV r0,r5.
                regs[0] = regs[5];

                const std::uint32_t sp =
                    regs[13];
                std::ostringstream detail;
                detail
                    << "callArgs{r0=0x"
                    << JniProbeHex(regs[0])
                    << ",r1="
                    << static_cast<std::int32_t>(
                           regs[1])
                    << ",r2="
                    << static_cast<std::int32_t>(
                           regs[2])
                    << ",r3="
                    << static_cast<std::int32_t>(
                           regs[3])
                    << ",sp0="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(sp))
                    << "}";

                append_snapshot(
                    "FacebookButton.rect",
                    regs[9],
                    detail.str());
                return;
            }

            case kJniProbeSvcV79ContainerEntry:
                // Original @0x10308b80: MOV r10,r0.
                regs[10] = regs[0];
                append_snapshot(
                    "FacebookContainer.entry",
                    regs[0],
                    "arg1=0x" +
                        JniProbeHex(
                            regs[1]));
                return;

            case kJniProbeSvcV79ContainerRect: {
                // Original @0x10308c5c: VSTR s2,[sp,#4].
                const std::uint32_t sp =
                    regs[13];
                mem.Write32Guest(
                    sp + 4u,
                    jit->ExtRegs()[2]);

                std::ostringstream detail;
                detail
                    << "callArgs{r0=0x"
                    << JniProbeHex(regs[0])
                    << ",r1=0x"
                    << JniProbeHex(regs[1])
                    << ",r2="
                    << static_cast<std::int32_t>(
                           regs[2])
                    << ",r3="
                    << static_cast<std::int32_t>(
                           regs[3])
                    << ",sp0="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(sp))
                    << ",sp4="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 4u))
                    << "}";

                append_snapshot(
                    "FacebookContainer.rect",
                    regs[10],
                    detail.str());
                return;
            }

            case kJniProbeSvcV79TextEntry:
                // Original @0x1030aea8: MOV r10,r0.
                regs[10] = regs[0];
                if (V82Enabled()) {
                    if (v82_profile_object == 0u) {
                        v82_profile_object = regs[0];
                    }
                    V82ObserveProfileState("TextEntry.entry");
                }
                append_snapshot(
                    "TextEntry.entry",
                    regs[0],
                    "arg1=0x" +
                        JniProbeHex(
                            regs[1]) +
                    " branchC8=" +
                        std::to_string(
                            mem.Read32Guest(
                                regs[0] +
                                0xc8u)));
                return;

            case kJniProbeSvcV79TextRectA: {
                // Original @0x1030b03c: MOV r0,r8.
                regs[0] = regs[8];

                const std::uint32_t sp =
                    regs[13];
                std::ostringstream detail;
                detail
                    << "computedTriple{x="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 40u))
                    << ",y="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 44u))
                    << ",w="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 48u))
                    << "} callR2=0x"
                    << JniProbeHex(
                           regs[2]);

                append_snapshot(
                    "TextEntry.rectA",
                    regs[10],
                    detail.str());
                return;
            }

            case kJniProbeSvcV79TextRectB: {
                // Original @0x1030b0b0: MOV r0,r8.
                regs[0] = regs[8];

                const std::uint32_t sp =
                    regs[13];
                std::ostringstream detail;
                detail
                    << "computedQuad{a="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 24u))
                    << ",b="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 28u))
                    << ",c="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 32u))
                    << ",d="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(
                               sp + 36u))
                    << "} callR2=0x"
                    << JniProbeHex(
                           regs[2]);

                append_snapshot(
                    "TextEntry.rectB",
                    regs[10],
                    detail.str());
                return;
            }

            case kJniProbeSvcV79GenericEntry:
                // Original @0x1030f930: MOV r10,r0.
                regs[10] = regs[0];
                append_snapshot(
                    "GenericProfile.entry",
                    regs[0],
                    "");
                return;

            case kJniProbeSvcV79GenericRect: {
                // Original @0x1030fa50: MOV r0,r5.
                regs[0] = regs[5];

                const std::uint32_t sp =
                    regs[13];
                std::ostringstream detail;
                detail
                    << "callArgs{r0=0x"
                    << JniProbeHex(regs[0])
                    << ",r1="
                    << static_cast<std::int32_t>(
                           regs[1])
                    << ",r2="
                    << static_cast<std::int32_t>(
                           regs[2])
                    << ",r3="
                    << static_cast<std::int32_t>(
                           regs[3])
                    << ",sp0="
                    << static_cast<std::int32_t>(
                           mem.Read32Guest(sp))
                    << "}";

                append_snapshot(
                    "GenericProfile.rect",
                    regs[10],
                    detail.str());
                return;
            }

            default:
                break;
            }
        }

        // v82: candidate widget layout radar. Each trap first emulates the
        // exact verified ARM instruction and then observes memory.
        if (V82Enabled() &&
            swi >= kJniProbeSvcV82Candidate5Post &&
            swi <= kJniProbeSvcV82Candidate6Post) {

            const std::uint32_t sp = regs[13];

            switch (swi) {
            case kJniProbeSvcV82Candidate5Post:
                // Original @0x10309f94: LDR r0,[r11,#0xa0].
                regs[0] = mem.Read32Guest(regs[11] + 0xa0u);
                v82_candidate5 = regs[0];
                ++v82_candidate5_hits;
                Append(
                    "V82 WIDGET candidate5 post#" +
                    std::to_string(v82_candidate5_hits) +
                    " frame=" + std::to_string(current_frame_number) + " " +
                    V82WidgetRaw(
                        "candidate5", v82_candidate5,
                        v82_last_touch_x, v82_last_touch_y));
                return;

            case kJniProbeSvcV82Candidate7Post:
                // Original @0x1030a558: LDR r0,[r11].
                regs[0] = mem.Read32Guest(regs[11]);
                v82_candidate7 = regs[6];
                ++v82_candidate7_hits;
                Append(
                    "V82 WIDGET candidate7 post#" +
                    std::to_string(v82_candidate7_hits) +
                    " frame=" + std::to_string(current_frame_number) + " " +
                    V82WidgetRaw(
                        "candidate7", v82_candidate7,
                        v82_last_touch_x, v82_last_touch_y));
                return;

            case kJniProbeSvcV82Candidate6Pre: {
                // Original @0x1030a68c: MOV r0,r9.
                regs[0] = regs[9];
                v82_candidate6 = regs[9];
                ++v82_candidate6_pre_hits;

                std::ostringstream line;
                line << "V82 WIDGET candidate6 pre#"
                     << v82_candidate6_pre_hits
                     << " frame=" << current_frame_number
                     << " plannedRect{"
                     << static_cast<std::int32_t>(mem.Read32Guest(sp + 0x50u))
                     << ","
                     << static_cast<std::int32_t>(mem.Read32Guest(sp + 0x54u))
                     << ","
                     << static_cast<std::int32_t>(mem.Read32Guest(sp + 0x58u))
                     << ","
                     << static_cast<std::int32_t>(mem.Read32Guest(sp + 0x5cu))
                     << "} "
                     << V82WidgetRaw(
                            "candidate6", v82_candidate6,
                            v82_last_touch_x, v82_last_touch_y);
                Append(line.str());
                return;
            }

            case kJniProbeSvcV82Candidate6Post:
                // Original @0x1030a694: ADD r8,sp,#56.
                regs[8] = sp + 56u;
                v82_candidate6 = regs[9];
                ++v82_candidate6_post_hits;
                Append(
                    "V82 WIDGET candidate6 post#" +
                    std::to_string(v82_candidate6_post_hits) +
                    " frame=" + std::to_string(current_frame_number) + " " +
                    V82WidgetRaw(
                        "candidate6", v82_candidate6,
                        v82_last_touch_x, v82_last_touch_y));
                return;

            default:
                break;
            }
        }

        if (V108Enabled() &&
            (swi == kJniProbeSvcV108KillSlotEntry ||
             swi == kJniProbeSvcV108KillBankMsg ||
             swi == kJniProbeSvcV108UsageSlotRelease ||
             swi == kJniProbeSvcV108UnloadCompletion ||
             swi == kJniProbeSvcV108DefaultBankCallback)) {
            if (swi == kJniProbeSvcV108KillSlotEntry) {
                // lib+0x00bc3fd0 MOV r0,r1.
                regs[0] = regs[1];
                v108_active_kill_slot = regs[1];
                v108_active_kill_msg_seen = false;
                v108_last_audio_liveness_pulse_ns = 0u;
                ++v108_kill_slot_calls;
                AppendDiagnostic("V108 BANK KILLSLOT #" + std::to_string(v108_kill_slot_calls) +
                                 " slot=" + V46DescribeGuestAddress(regs[1]) +
                                 " callback=" + V46DescribeGuestAddress(regs[2]) +
                                 " cookie=" + V46DescribeGuestAddress(regs[3]) + " " +
                                 V108BankCompletionSummary());
                return;
            }
            if (swi == kJniProbeSvcV108KillBankMsg) {
                // lib+0x00bbf254 LDR r10,[r4,#8].
                regs[10] = mem.Read32Guest(regs[4] + 0x8u);
                ++v108_kill_msg_calls;
                if (regs[10] == v108_active_kill_slot) v108_active_kill_msg_seen = true;
                AppendDiagnostic("V108 BANK KILLMSG #" + std::to_string(v108_kill_msg_calls) +
                                 " slot=" + V46DescribeGuestAddress(regs[10]) +
                                 " active=" + (regs[10] == v108_active_kill_slot ? "YES" : "NO") + " " +
                                 V108BankCompletionSummary());
                return;
            }
            if (swi == kJniProbeSvcV108UsageSlotRelease) {
                // lib+0x00bc5478 MOV r5,r0.
                regs[5] = regs[0];
                ++v108_slot_release_calls;
                if (regs[0] == v108_active_kill_slot || v108_slot_release_calls <= 16u ||
                    (v108_slot_release_calls & (v108_slot_release_calls - 1u)) == 0u) {
                    AppendDiagnostic("V108 BANK SLOT RELEASE #" + std::to_string(v108_slot_release_calls) +
                                     " slot=" + V46DescribeGuestAddress(regs[0]) +
                                     " destroy=" + std::to_string(regs[1]) +
                                     " caller=" + V46DescribeGuestAddress(regs[14]) + " " +
                                     V108BankCompletionSummary());
                }
                return;
            }
            if (swi == kJniProbeSvcV108UnloadCompletion) {
                // lib+0x00bc0e80 LDR r1,[r0,#0x2c].
                regs[1] = mem.Read32Guest(regs[0] + 0x2cu);
                ++v108_completion_notifications;
                AppendDiagnostic("V108 BANK COMPLETION NOTIFY #" + std::to_string(v108_completion_notifications) +
                                 " slot=" + V46DescribeGuestAddress(regs[0]) +
                                 " callback=" + V46DescribeGuestAddress(regs[1]) + " " +
                                 V108BankCompletionSummary());
                return;
            }
            // lib+0x00bb6a50 LDR r1,[sp]. DefaultBankCallbackFunc will
            // sem_post(cookie+4) immediately after the emulated load.
            regs[1] = mem.Read32Guest(regs[13]);
            ++v108_default_bank_callbacks;
            AppendDiagnostic("V108 BANK DEFAULT CALLBACK #" + std::to_string(v108_default_bank_callbacks) +
                             " cookie=" + V46DescribeGuestAddress(regs[1]) +
                             " completionSem=" + V46DescribeGuestAddress(regs[1] != 0u ? regs[1] + 4u : 0u) +
                             " result=" + std::to_string(regs[2]) + " " + V108BankCompletionSummary());
            if (v108_active_kill_slot != 0u && mem.Read32Guest(v108_active_kill_slot + 0x30u) == regs[1]) {
                v108_active_kill_slot = 0u;
                v108_active_kill_msg_seen = false;
            }
            return;
        }

        if (V105Enabled() &&
            (swi == kJniProbeSvcV105ResamplerInitState ||
             swi == kJniProbeSvcV105SetPitchState ||
             swi == kJniProbeSvcV105SwitchToState)) {

            if (swi ==
                kJniProbeSvcV105ResamplerInitState) {
                // Original @lib+0x00c141f8:
                // STRB r0,[r4,#0x34]. GetDSPFunctionIndex has returned,
                // so Init's source/target ratio, state and DSP choice are
                // all final before we log them.
                ++v105_resampler_init_calls;
                const std::uint32_t resampler =
                    regs[4];
                const std::uint32_t format =
                    regs[6];
                const std::uint32_t target =
                    regs[7];

                mem.Write8Guest(
                    resampler + 0x34u,
                    static_cast<std::uint8_t>(
                        regs[0]));

                V105LogResamplerState(
                    "INIT",
                    v105_resampler_init_calls,
                    resampler,
                    format,
                    target,
                    0xffffffffu);
                return;
            }

            if (swi ==
                kJniProbeSvcV105SetPitchState) {
                // Original @lib+0x00c14498:
                // LDR r2,[r4,#0x14]. The rate step has already been
                // calculated/stored, so this observes the final state.
                ++v105_set_pitch_calls;
                const std::uint32_t resampler =
                    regs[4];

                regs[2] =
                    mem.Read32Guest(
                        resampler + 0x14u);

                const std::uint32_t next_state =
                    regs[2] != regs[3]
                        ? 2u
                        : (regs[3] == 65536u
                               ? 0u
                               : 1u);

                V105LogResamplerState(
                    "SETPITCH",
                    v105_set_pitch_calls,
                    resampler,
                    0u,
                    0u,
                    next_state);
                return;
            }

            // Original @lib+0x00c145d8: STRB r0,[r4,#0x34].
            // SwitchTo has already updated the base ratio, run SetPitch,
            // and selected the new DSP function for r5's AkAudioFormat.
            ++v105_switch_to_calls;
            const std::uint32_t resampler =
                regs[4];
            const std::uint32_t format =
                regs[5];
            const std::uint32_t target =
                mem.Read32Guest(
                    regs[13] + 32u);

            mem.Write8Guest(
                resampler + 0x34u,
                static_cast<std::uint8_t>(
                    regs[0]));

            V105LogResamplerState(
                "SWITCHTO",
                v105_switch_to_calls,
                resampler,
                format,
                target,
                0xffffffffu);
            return;
        }

        if(V89Enabled()&&(swi==kJniProbeSvcV89BlxTarget0||swi==kJniProbeSvcV89BlxTarget1)){
            const auto obj=regs[0],vt=regs[1];
            if(swi==kJniProbeSvcV89BlxTarget0){const auto t=mem.Read32Guest(vt);regs[1]=t;V89RecordIndirectBlx(kGuestBase+0x00894b2cu,obj,vt,0u,t);}
            else{const auto t=mem.Read32Guest(vt+0x1cu);regs[2]=t;V89RecordIndirectBlx(kGuestBase+0x00894b3cu,obj,vt,0x1cu,t);}
            return;
        }

        if(V90Enabled()&&
           (swi==kJniProbeSvcV90FontScanBegin||
            swi==kJniProbeSvcV90FontScanEnd)){
            if(swi==kJniProbeSvcV90FontScanBegin){
                // Original @lib+0x00a4dc30: MOVW r6,#0xffff.
                regs[6]=0xffffu;
                V90FontScanBegin();
            } else {
                // Original @lib+0x00a4dc78: MOV r0,r4.
                regs[0]=regs[4];
                V90FontScanEnd();
            }
            return;
        }

        // v83: verified Profile button-listener dispatcher. The static switch
        // at 0x1030b8f0 uses r1 as the button ID. This trap is after the
        // prologue and emulates only the replaced MOV r9,r0.
        if (V83ButtonTrapEnabled() &&
            swi == kJniProbeSvcV83ButtonDispatchEntry) {

            const std::uint32_t button_this = regs[0];
            const std::uint32_t button_id = regs[1];
            const std::uint32_t caller_lr = regs[14];

            // Original @0x1030b8f8: MOV r9,r0.
            regs[9] = regs[0];

            ++v83_button_dispatch_calls;
            if (button_id < 21u) {
                ++v83_button_id_hits[button_id];
            }

            v83_last_button_id = button_id;
            v83_last_button_this = button_this;
            v83_last_button_lr = caller_lr;
            v83_last_button_frame = current_frame_number;

            if (V85PerformanceEnabled()) {
                V85RecordGuestAction("buttonId=" + std::to_string(button_id));
                return;
            }

            Append(
                "V83 BUTTON DISPATCH #" +
                std::to_string(v83_button_dispatch_calls) +
                " frame=" +
                std::to_string(current_frame_number) +
                " buttonId=" +
                std::to_string(button_id) +
                " staticCase=" +
                V83StaticCase(button_id) +
                " this=0x" +
                JniProbeHex(button_this) +
                " profile=0x" +
                JniProbeHex(v82_profile_object) +
                " sameProfile=" +
                ((v82_profile_object != 0u &&
                  button_this == v82_profile_object)
                    ? std::string{"YES"}
                    : std::string{"NO"}) +
                " lr=0x" +
                JniProbeHex(caller_lr) +
                " " +
                V82TouchContext() +
                " " +
                V82RadarSnapshot(
                    v82_last_touch_x,
                    v82_last_touch_y));

            V82ObserveProfileState(
                "V83.ButtonDispatch.entry");
            return;
        }

        // v31: real ARM32 printf-family formatting. Before this bridge,
        // snprintf/sprintf/vsnprintf/vsprintf returned zero without writing
        // their destination buffers. That is not just cosmetic: PvZ2 builds
        // resource identifiers and paths through libc formatting, so the
        // no-op fallback could turn valid resource names into empty strings.
        auto format_guest_printf =
            [&](const std::string& format,
                auto&& next32,
                auto&& next64) {
                std::string out;

                auto pad =
                    [](std::string value,
                       int width,
                       bool left,
                       char fill) {
                        if (width <= 0 ||
                            static_cast<int>(
                                value.size()) >= width) {
                            return value;
                        }

                        const std::size_t count =
                            static_cast<std::size_t>(
                                width -
                                static_cast<int>(
                                    value.size()));

                        if (left) {
                            value.append(
                                count,
                                ' ');
                            return value;
                        }

                        return
                            std::string(
                                count,
                                fill) +
                            value;
                    };

                for (std::size_t i = 0;
                     i < format.size();) {

                    if (format[i] != '%') {
                        out.push_back(
                            format[i++]);
                        continue;
                    }

                    ++i;

                    if (i < format.size() &&
                        format[i] == '%') {
                        out.push_back('%');
                        ++i;
                        continue;
                    }

                    bool left = false;
                    bool plus = false;
                    bool space = false;
                    bool alternate = false;
                    bool zero = false;

                    for (;;) {
                        if (i >= format.size()) {
                            break;
                        }

                        const char flag =
                            format[i];

                        if (flag == '-') {
                            left = true;
                        } else if (flag == '+') {
                            plus = true;
                        } else if (flag == ' ') {
                            space = true;
                        } else if (flag == '#') {
                            alternate = true;
                        } else if (flag == '0') {
                            zero = true;
                        } else {
                            break;
                        }

                        ++i;
                    }

                    int width = -1;

                    if (i < format.size() &&
                        format[i] == '*') {
                        width =
                            static_cast<std::int32_t>(
                                next32());
                        ++i;

                        if (width < 0) {
                            left = true;
                            width = -width;
                        }
                    } else {
                        int parsed = 0;
                        bool any = false;

                        while (i < format.size() &&
                               std::isdigit(
                                   static_cast<unsigned char>(
                                       format[i]))) {
                            any = true;
                            parsed =
                                parsed * 10 +
                                (format[i] - '0');
                            ++i;
                        }

                        if (any) {
                            width = parsed;
                        }
                    }

                    int precision = -1;

                    if (i < format.size() &&
                        format[i] == '.') {
                        ++i;
                        precision = 0;

                        if (i < format.size() &&
                            format[i] == '*') {
                            precision =
                                static_cast<std::int32_t>(
                                    next32());
                            ++i;

                            if (precision < 0) {
                                precision = -1;
                            }
                        } else {
                            while (i < format.size() &&
                                   std::isdigit(
                                       static_cast<unsigned char>(
                                           format[i]))) {
                                precision =
                                    precision * 10 +
                                    (format[i] - '0');
                                ++i;
                            }
                        }
                    }

                    enum class Length {
                        Default,
                        HH,
                        H,
                        L,
                        LL,
                        Z,
                        T,
                        J,
                        BigL,
                    };

                    Length length =
                        Length::Default;

                    if (i + 1u < format.size() &&
                        format[i] == 'h' &&
                        format[i + 1u] == 'h') {
                        length = Length::HH;
                        i += 2u;
                    } else if (
                        i < format.size() &&
                        format[i] == 'h') {
                        length = Length::H;
                        ++i;
                    } else if (
                        i + 1u < format.size() &&
                        format[i] == 'l' &&
                        format[i + 1u] == 'l') {
                        length = Length::LL;
                        i += 2u;
                    } else if (
                        i < format.size() &&
                        format[i] == 'l') {
                        length = Length::L;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 'z') {
                        length = Length::Z;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 't') {
                        length = Length::T;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 'j') {
                        length = Length::J;
                        ++i;
                    } else if (
                        i < format.size() &&
                        format[i] == 'L') {
                        length = Length::BigL;
                        ++i;
                    }

                    if (i >= format.size()) {
                        out.push_back('%');
                        break;
                    }

                    const char conversion =
                        format[i++];

                    auto configure_numeric =
                        [&](std::ostringstream& stream) {
                            if (plus) {
                                stream.setf(
                                    std::ios::showpos);
                            }

                            if (alternate) {
                                stream.setf(
                                    std::ios::showbase);
                            }

                            if (precision >= 0) {
                                stream
                                    << std::setprecision(
                                           precision);
                            }
                        };

                    std::string value;

                    switch (conversion) {
                    case 's': {
                        const std::uint32_t address =
                            next32();

                        value =
                            address != 0u
                                ? mem.ReadCStringGuest(
                                      address,
                                      1u << 20)
                                : "(null)";

                        if (precision >= 0 &&
                            static_cast<std::size_t>(
                                precision) <
                                value.size()) {
                            value.resize(
                                static_cast<std::size_t>(
                                    precision));
                        }

                        break;
                    }

                    case 'c':
                        value.push_back(
                            static_cast<char>(
                                next32() & 0xffu));
                        break;

                    case 'd':
                    case 'i': {
                        std::ostringstream stream;
                        configure_numeric(stream);

                        if (length == Length::LL ||
                            length == Length::J) {
                            stream
                                << static_cast<std::int64_t>(
                                       next64());
                        } else {
                            stream
                                << static_cast<std::int32_t>(
                                       next32());
                        }

                        value = stream.str();
                        break;
                    }

                    case 'u':
                    case 'o':
                    case 'x':
                    case 'X': {
                        std::ostringstream stream;
                        configure_numeric(stream);

                        if (conversion == 'o') {
                            stream << std::oct;
                        } else if (
                            conversion == 'x' ||
                            conversion == 'X') {
                            stream << std::hex;

                            if (conversion == 'X') {
                                stream.setf(
                                    std::ios::uppercase);
                            }
                        }

                        if (length == Length::LL ||
                            length == Length::J) {
                            stream
                                << static_cast<std::uint64_t>(
                                       next64());
                        } else {
                            stream
                                << static_cast<std::uint32_t>(
                                       next32());
                        }

                        value = stream.str();
                        break;
                    }

                    case 'p': {
                        std::ostringstream stream;
                        stream
                            << "0x"
                            << std::hex
                            << next32();
                        value = stream.str();
                        break;
                    }

                    case 'f':
                    case 'F':
                    case 'e':
                    case 'E':
                    case 'g':
                    case 'G': {
                        const std::uint64_t bits =
                            next64();
                        double number = 0.0;

                        std::memcpy(
                            &number,
                            &bits,
                            sizeof(number));

                        std::ostringstream stream;
                        configure_numeric(stream);

                        if (conversion == 'f' ||
                            conversion == 'F') {
                            stream << std::fixed;
                        } else if (
                            conversion == 'e' ||
                            conversion == 'E') {
                            stream
                                << std::scientific;
                        }

                        if (conversion == 'E' ||
                            conversion == 'F' ||
                            conversion == 'G') {
                            stream.setf(
                                std::ios::uppercase);
                        }

                        stream << number;
                        value = stream.str();
                        break;
                    }

                    case 'n': {
                        const std::uint32_t address =
                            next32();

                        if (address != 0u) {
                            mem.Write32Guest(
                                address,
                                static_cast<std::uint32_t>(
                                    out.size()));
                        }

                        continue;
                    }

                    default:
                        value.push_back('%');
                        value.push_back(
                            conversion);
                        break;
                    }

                    if (space &&
                        !value.empty() &&
                        value.front() != '-' &&
                        value.front() != '+') {
                        value.insert(
                            value.begin(),
                            ' ');
                    }

                    value =
                        pad(
                            std::move(value),
                            width,
                            left,
                            zero && !left
                                ? '0'
                                : ' ');

                    out += value;
                }

                return out;
            };

        auto format_direct =
            [&](const std::string& format,
                std::uint32_t first_register) {

                // Treat r0-r3 followed by stack words as one AAPCS argument
                // stream. 64-bit varargs are aligned to an even word slot.
                std::uint32_t cursor =
                    first_register;

                auto read_absolute_word =
                    [&](std::uint32_t absolute) {
                        if (absolute < 4u) {
                            return regs[absolute];
                        }

                        return
                            mem.Read32Guest(
                                regs[13] +
                                (absolute - 4u) *
                                    4u);
                    };

                auto next32 =
                    [&]() {
                        return
                            read_absolute_word(
                                cursor++);
                    };

                auto next64 =
                    [&]() -> std::uint64_t {
                        if ((cursor & 1u) != 0u) {
                            ++cursor;
                        }

                        const std::uint64_t lo =
                            read_absolute_word(
                                cursor++);
                        const std::uint64_t hi =
                            read_absolute_word(
                                cursor++);

                        return
                            lo |
                            (hi << 32u);
                    };

                return
                    format_guest_printf(
                        format,
                        next32,
                        next64);
            };

        auto format_va_list =
            [&](const std::string& format,
                std::uint32_t va_address) {

                // ARMv7 bionic/NDK va_list is pointer-like for this ABI.
                std::uint32_t cursor =
                    va_address;

                auto next32 =
                    [&]() {
                        const std::uint32_t value =
                            mem.Read32Guest(
                                cursor);
                        cursor += 4u;
                        return value;
                    };

                auto next64 =
                    [&]() -> std::uint64_t {
                        cursor =
                            (cursor + 7u) &
                            ~7u;

                        const std::uint64_t value =
                            mem.Read64Guest(
                                cursor);
                        cursor += 8u;
                        return value;
                    };

                return
                    format_guest_printf(
                        format,
                        next32,
                        next64);
            };

        if (swi >= kJniProbeSvcV56RegistryPipelineEntry &&
            swi <= kJniProbeSvcV56TrieMissZero) {

            switch (swi) {
            case kJniProbeSvcV56RegistryPipelineEntry: {
                // Original @ 0x10867710: MOV r8,r0.
                regs[8] = regs[0];
                v56_resource_manager =
                    regs[0];
                ++v56_registry_pipeline_calls;

                Append(
                    "V56 REGISTRY DIAGNOSIS pipeline-entry #" +
                    std::to_string(
                        v56_registry_pipeline_calls) +
                    " manager=" +
                    V46DescribeGuestAddress(
                        v56_resource_manager) +
                    " caller=" +
                    V46DescribeGuestAddress(
                        regs[14]));

                V56AppendRegistrySnapshot(
                    "pipeline-entry");
                return;
            }

            case kJniProbeSvcV56RegistrySource28: {
                // Original @ 0x10867860: ADD r0,r8,#0x28.
                v56_source28_ptr =
                    regs[1];
                v56_source28_bytes =
                    regs[2];
                regs[0] =
                    regs[8] +
                    0x28u;

                Append(
                    "V56 REGISTRY DIAGNOSIS source28 ptr=" +
                    V46DescribeGuestAddress(
                        v56_source28_ptr) +
                    " bytes=" +
                    std::to_string(
                        v56_source28_bytes) +
                    " expectedCount=" +
                    std::to_string(
                        v56_source28_bytes /
                        4u));
                return;
            }

            case kJniProbeSvcV56RegistryPost28:
                // Original @ 0x10867868: LDR r0,[r9,#0x48].
                regs[0] =
                    mem.Read32Guest(
                        regs[9] +
                        0x48u);
                V56AppendRegistrySnapshot(
                    "post-table28-copy");
                return;

            case kJniProbeSvcV56RegistrySource30:
                // Original @ 0x10867b24: ADD r0,r8,#0x30.
                v56_source30_ptr =
                    regs[1];
                v56_source30_bytes =
                    regs[2];
                regs[0] =
                    regs[8] +
                    0x30u;

                Append(
                    "V56 REGISTRY DIAGNOSIS source30 ptr=" +
                    V46DescribeGuestAddress(
                        v56_source30_ptr) +
                    " bytes=" +
                    std::to_string(
                        v56_source30_bytes) +
                    " expectedCount=" +
                    std::to_string(
                        v56_source30_bytes /
                        4u));
                return;

            case kJniProbeSvcV56RegistryPost30:
                // Original @ 0x10867b2c: ADD r0,r8,#0x70.
                regs[0] =
                    regs[8] +
                    0x70u;
                V56AppendRegistrySnapshot(
                    "post-table30-copy");
                return;

            case kJniProbeSvcV56RegistryPipelineReturn:
                // Original @ 0x10867b68: MOV r0,r6.
                regs[0] = regs[6];
                ++v56_registry_pipeline_returns;
                v56_pipeline_last_result =
                    regs[0];

                Append(
                    "V56 REGISTRY DIAGNOSIS pipeline-return #" +
                    std::to_string(
                        v56_registry_pipeline_returns) +
                    " result=" +
                    std::to_string(
                        v56_pipeline_last_result));

                V56AppendRegistrySnapshot(
                    "pipeline-return");
                return;

            case kJniProbeSvcV56TrieEntry: {
                // Original @ 0x10a83ab4: LDR r2,[r0,#4].
                const std::uint32_t table =
                    regs[0];
                const std::uint32_t key_ptr =
                    regs[1];

                regs[2] =
                    mem.Read32Guest(
                        table + 4u);

                if (!V56FullMatrixEnabled()) {
                    return;
                }

                std::string key;
                if (key_ptr != 0u &&
                    mem.Ptr(
                        key_ptr,
                        1u) != nullptr) {
                    key =
                        mem.ReadCStringGuest(
                            key_ptr,
                            256u);
                }

                const bool manager_table =
                    v56_resource_manager != 0u &&
                    (table ==
                         v56_resource_manager +
                             0x28u ||
                     table ==
                         v56_resource_manager +
                             0x30u);

                const bool target =
                    V56IsTargetLookupKey(
                        key);

                if (manager_table ||
                    target) {
                    V56TrieContext context;
                    context.table =
                        table;
                    context.caller_lr =
                        regs[14];
                    context.key_start =
                        key_ptr;
                    context.key =
                        key;
                    context.relevant = true;

                    if (V57CtypeEnabled() &&
                        V57IsPathTraceKey(key)) {
                        const std::string trace_token =
                            key +
                            "@" +
                            V57TrieTableLabel(
                                table);

                        context.trace_path =
                            v57_trie_traced_key_tables
                                .insert(
                                    trace_token)
                                .second;

                        if (context.trace_path) {
                            Append(
                                "V57 TRIE PATH BEGIN key=\"" +
                                key +
                                "\" table=" +
                                V57TrieTableLabel(
                                    table) +
                                " keyPtr=" +
                                V46DescribeGuestAddress(
                                    key_ptr) +
                                " caller=" +
                                V46DescribeGuestAddress(
                                    regs[14]));
                        }
                    }

                    v56_trie_contexts[
                        regs[13]] =
                        std::move(context);
                }

                return;
            }

            case kJniProbeSvcV56TrieMissBranch: {
                // Original @ 0x10a83b24: B 0x10a83b40.
                const auto found =
                    v56_trie_contexts.find(
                        regs[13]);

                if (found !=
                    v56_trie_contexts.end()) {
                    V56RecordTrieResult(
                        found->second,
                        false,
                        0u);
                    v56_trie_contexts.erase(
                        found);
                }

                regs[15] =
                    kGuestBase +
                    0x00a83b40u;
                return;
            }

            case kJniProbeSvcV56TrieFound: {
                // Original @ 0x10a83b38: MOV r0,r2.
                const std::uint32_t result_pointer =
                    regs[2];
                regs[0] =
                    result_pointer;

                const auto found =
                    v56_trie_contexts.find(
                        regs[13]);

                if (found !=
                    v56_trie_contexts.end()) {
                    V56RecordTrieResult(
                        found->second,
                        true,
                        result_pointer);
                    v56_trie_contexts.erase(
                        found);
                }

                return;
            }

            case kJniProbeSvcV56TrieMissZero: {
                // Original @ 0x10a83b44: MOV r0,#0.
                regs[0] = 0u;

                const auto found =
                    v56_trie_contexts.find(
                        regs[13]);

                if (found !=
                    v56_trie_contexts.end()) {
                    V56RecordTrieResult(
                        found->second,
                        false,
                        0u);
                    v56_trie_contexts.erase(
                        found);
                }

                return;
            }

            default:
                break;
            }
        }


        if (swi >= kJniProbeSvcV69WorkerPreWait &&
            swi <= kJniProbeSvcV69FinalizerReturn) {

            switch (swi) {
            case kJniProbeSvcV69WorkerPreWait: {
                // Original @ 0x10abd8c8: MOV r0,r5.
                const std::uint32_t wait_object =
                    regs[5];

                V69RecordWorkerPreWait(
                    wait_object);

                regs[0] =
                    regs[5];
                return;
            }

            case kJniProbeSvcV69ActiveReadyResult:
                // Original @ 0x10868cbc: CMP r0,#1.
                V69RecordLifecycle(
                    "active-vfn14",
                    regs[7],
                    regs[0],
                    true,
                    v69_active_ready_calls,
                    &v69_active_ready_true);
                V69EmulateCmp(
                    regs[0],
                    1u);
                V69MaybeBoundedStop();
                return;

            case kJniProbeSvcV69ActivePhaseResult:
                // Original @ 0x10868cdc: CMP r0,#1.
                V69RecordLifecycle(
                    "active-vfn3c",
                    regs[7],
                    regs[0],
                    true,
                    v69_active_phase_calls,
                    &v69_active_phase_true);
                V69EmulateCmp(
                    regs[0],
                    1u);
                return;

            case kJniProbeSvcV69StartWorkReturn:
                // Original @ 0x10868d20: STR r7,[sp,#0x14].
                V69RecordLifecycle(
                    "start-vfn18-return",
                    regs[7],
                    0u,
                    false,
                    v69_start_work_returns);
                mem.Write32Guest(
                    regs[13] + 0x14u,
                    regs[7]);
                return;

            case kJniProbeSvcV69MoveCompleted:
                // Original @ 0x10868d5c: LDR r0,[r4,#0x54].
                V69RecordLifecycle(
                    "moved-to-completed",
                    regs[7],
                    0u,
                    false,
                    v69_completed_moves);
                regs[0] =
                    mem.Read32Guest(
                        regs[4] + 0x54u);
                return;

            case kJniProbeSvcV69CompletedPollReturn:
                // Original @ 0x10868da0: LDR r0,[r8].
                // r0 still contains the just-returned vfn+0x0c value.
                V69RecordLifecycle(
                    "completed-vfn0c-return",
                    regs[8],
                    regs[0],
                    true,
                    v69_completed_poll_returns);
                regs[0] =
                    mem.Read32Guest(
                        regs[8]);
                return;

            case kJniProbeSvcV69CompletedReadyResult:
                // Original @ 0x10868db0: CMP r0,#1.
                V69RecordLifecycle(
                    "completed-vfn1c",
                    regs[8],
                    regs[0],
                    true,
                    v69_completed_ready_calls,
                    &v69_completed_ready_true);
                V69EmulateCmp(
                    regs[0],
                    1u);
                return;

            case kJniProbeSvcV69CompletedTerminalResult:
                // Original @ 0x10868dc8: CMP r0,#1.
                V69RecordLifecycle(
                    "completed-vfn20",
                    regs[8],
                    regs[0],
                    true,
                    v69_completed_terminal_calls,
                    &v69_completed_terminal_true);
                V69EmulateCmp(
                    regs[0],
                    1u);
                return;

            case kJniProbeSvcV69FinalizerReturn:
                // Original @ 0x10868e18: CMP r8,#0.
                V69RecordLifecycle(
                    "finalizer-vfn24-return",
                    regs[8],
                    0u,
                    false,
                    v69_finalizer_returns);
                V69EmulateCmp(
                    regs[8],
                    0u);
                return;

            default:
                break;
            }
        }

        if (swi == kJniProbeSvcV67TokenIncrementStore ||
            swi == kJniProbeSvcV67TokenDecrementStore) {

            V67RecordTokenStore(
                swi == kJniProbeSvcV67TokenIncrementStore
                    ? "INC"
                    : "DEC",
                regs[0],
                regs[1],
                regs[14]);
            return;
        }

        if (swi == kJniProbeSvcV66TaskADepResult ||
            swi == kJniProbeSvcV66TaskAChild78Result ||
            swi == kJniProbeSvcV66TaskAChild84Result ||
            swi == kJniProbeSvcV66TaskBDepResult ||
            swi == kJniProbeSvcV66TaskBChildResult) {

            const std::uint32_t task = regs[4];
            std::uint32_t child = 0u;
            const char* kind = "unknown";

            switch (swi) {
            case kJniProbeSvcV66TaskADepResult:
                child = mem.Read32Guest(task + 0x20u);
                kind = "A.dep+20";
                break;
            case kJniProbeSvcV66TaskAChild78Result:
                child = regs[6];
                kind = "A.vector78";
                break;
            case kJniProbeSvcV66TaskAChild84Result:
                child = regs[6];
                kind = "A.vector84";
                break;
            case kJniProbeSvcV66TaskBDepResult:
                child = mem.Read32Guest(task + 0x20u);
                kind = "B.dep+20";
                break;
            case kJniProbeSvcV66TaskBChildResult:
                child = regs[5];
                kind = "B.vector78";
                break;
            default:
                break;
            }

            V66RecordTaskSubstate(
                kind,
                task,
                child,
                regs[0]);

            // Reproduce the exact overwritten ARM instruction:
            // CMP r0,#0.
            V66EmulateCmpR0Zero();
            return;
        }

        if (swi == kJniProbeSvcV62TaskDispatch) {
            // Original @ 0x10868cb0: LDR r1,[r0,#0x14].
            const std::uint32_t slot = regs[6];
            const std::uint32_t object = regs[7];
            const std::uint32_t vtable = regs[0];
            const std::uint32_t target =
                mem.Read32Guest(vtable + 0x14u);
            regs[1] = target;

            const std::uint32_t plain_target =
                target & ~1u;
            const bool executable =
                plain_target >= kGuestBase &&
                static_cast<std::uint64_t>(
                    plain_target) <
                    static_cast<std::uint64_t>(
                        kGuestBase) +
                    mem.image.size();

            if (V63Enabled()) {
                ++v63_task_dispatch_events;

                const bool object_readable =
                    mem.Ptr(object, 4u) != nullptr;
                const bool vtable_readable =
                    mem.Ptr(vtable, 0x18u) != nullptr;
                const bool anomaly =
                    !object_readable ||
                    !vtable_readable ||
                    !executable;

                const std::uint64_t task_log_interval =
                    V69Enabled()
                        ? 1048576u
                        : (V66Enabled()
                            ? 65536u
                            : 256u);

                if (anomaly ||
                    v63_task_dispatch_events <= 8u ||
                    (v63_task_dispatch_events %
                     task_log_interval) == 0u) {

                    std::ostringstream out;
                    out
                        << "V63 TASK GUARD #"
                        << v63_task_dispatch_events
                        << (anomaly ? " ANOMALY" : "")
                        << " tid="
                        << current_probe_thread_id
                        << " slot="
                        << V46DescribeGuestAddress(slot)
                        << " object="
                        << V46DescribeGuestAddress(object)
                        << " objectClass="
                        << V62HeapPointerClass(object)
                        << " vtable="
                        << V46DescribeGuestAddress(vtable)
                        << " vfn14="
                        << V46DescribeGuestAddress(target)
                        << " executable="
                        << (executable ? "YES" : "NO")
                        << " heldMutexes="
                        << V63HeldMutexCount(
                               current_probe_thread_id)
                        << " held={"
                        << V63HeldMutexSummary(
                               current_probe_thread_id)
                        << "}";

                    if (anomaly) {
                        out
                            << " objectWords={";
                        for (std::uint32_t off = 0u;
                             off < 0x30u;
                             off += 4u) {
                            if (off != 0u) {
                                out << ",";
                            }
                            out
                                << "+0x"
                                << JniProbeHex(off)
                                << ":0x"
                                << JniProbeHex(
                                       mem.Read32Guest(
                                           object + off));
                        }

                        out
                            << "} vtableWords={";
                        for (std::uint32_t off = 0u;
                             off < 0x34u;
                             off += 4u) {
                            if (off != 0u) {
                                out << ",";
                            }
                            out
                                << "+0x"
                                << JniProbeHex(off)
                                << ":0x"
                                << JniProbeHex(
                                       mem.Read32Guest(
                                           vtable + off));
                        }
                        out << "}";
                    }

                    Append(out.str());
                }

                if (anomaly) {
                    ++v63_task_guard_failures;
                    Append(
                        "V63 TASK GUARD FAIL-FAST #" +
                        std::to_string(
                            v63_task_guard_failures) +
                        " tid=" +
                        std::to_string(
                            current_probe_thread_id) +
                        " target=" +
                        V46DescribeGuestAddress(target));

                    if (jit) {
                        jit->HaltExecution(
                            Dynarmic::HaltReason::UserDefined3);
                    }
                }

                return;
            }

            ++v62_task_dispatch_events;
            V62RefreshPumpVector();

            const std::string alias =
                V62WorkerAlias(object);
            const bool slot_in_vector =
                v62_pump_vector_begin != 0u &&
                slot >= v62_pump_vector_begin &&
                slot + 4u <=
                    v62_pump_vector_end;
            const bool anomaly =
                !executable ||
                !alias.empty();

            if (anomaly ||
                v62_task_dispatch_events <= 16u ||
                (v62_task_dispatch_events % 1000u) == 0u) {
                std::ostringstream out;
                out << "V62 TASK DISPATCH #" << v62_task_dispatch_events
                    << (anomaly ? " ANOMALY" : "")
                    << " thread=" << current_probe_thread_id
                    << " slot=" << V46DescribeGuestAddress(slot);

                if (slot_in_vector)
                    out << " slotIndex="
                        << ((slot - v62_pump_vector_begin) / 4u);

                out << " object=" << V46DescribeGuestAddress(object)
                    << " objectClass=" << V62HeapPointerClass(object);
                if (!alias.empty()) out << " alias=" << alias;

                out << " vtable=" << V46DescribeGuestAddress(vtable)
                    << " actualVptr=0x"
                    << JniProbeHex(mem.Read32Guest(object))
                    << " vfn14=" << V46DescribeGuestAddress(target)
                    << " executable=" << (executable ? "YES" : "NO")
                    << " vector={begin=0x"
                    << JniProbeHex(v62_pump_vector_begin)
                    << ",end=0x" << JniProbeHex(v62_pump_vector_end)
                    << ",cap=0x" << JniProbeHex(v62_pump_vector_cap)
                    << "}";

                if (anomaly) {
                    out << " objectWords={";
                    for (std::uint32_t off=0; off<0x40u; off+=4u) {
                        if (off) out << ",";
                        out << "+0x" << JniProbeHex(off) << ":0x"
                            << JniProbeHex(mem.Read32Guest(object + off));
                    }
                    out << "} vtableWords={";
                    for (std::uint32_t off=0; off<0x44u; off+=4u) {
                        if (off) out << ",";
                        out << "+0x" << JniProbeHex(off) << ":0x"
                            << JniProbeHex(mem.Read32Guest(vtable + off));
                    }
                    out << "}";

                    if (v62_first_bad_pointer_writer_seen) {
                        out << " firstBadWriter={dst=0x"
                            << JniProbeHex(v62_first_bad_pointer_writer_dst)
                            << ",PC="
                            << V46DescribeGuestAddress(
                                   v62_first_bad_pointer_writer_pc)
                            << ",LR="
                            << V46DescribeGuestAddress(
                                   v62_first_bad_pointer_writer_lr)
                            << "}";
                    } else {
                        out << " firstBadWriter=NOT_OBSERVED";
                    }
                }
                Append(out.str());
            }
            return;
        }

        if (swi == kJniProbeSvcV57TrieCompare) {
            // Original @ 0x10a83af8: UXTB r0,r5.
            const std::uint32_t raw =
                mem.Read8(regs[1]);
            const std::uint32_t normalized =
                regs[4] &
                0xffu;
            const std::uint32_t node_word =
                regs[5];
            const std::uint32_t node_pointer =
                regs[2];

            regs[0] =
                node_word &
                0xffu;

            const auto found =
                v56_trie_contexts.find(
                    regs[13]);

            if (found !=
                v56_trie_contexts.end()) {
                V57TraceTrieStep(
                    found->second,
                    raw,
                    normalized,
                    node_word,
                    node_pointer);
            }

            return;
        }

        if (swi == kJniProbeSvcStartupGroupsCtorSnapshot ||
            swi == kJniProbeSvcStartupGroupsLookupResult ||
            swi == kJniProbeSvcStartupGroupsContribution) {

            switch (swi) {
            case kJniProbeSvcStartupGroupsCtorSnapshot: {
                // Original @ 0x100f66e4: ADD sp,sp,#0xb0.
                regs[13] += 0xb0u;

                ++v55_ctor_snapshot_hits;
                const std::string snapshot =
                    V55StartupGroupVectorState();
                v55_ctor_vector_snapshot =
                    snapshot;

                Append(
                    "V55 STARTUP GROUPS ctor-snapshot #" +
                    std::to_string(
                        v55_ctor_snapshot_hits) +
                    " " +
                    snapshot);
                return;
            }

            case kJniProbeSvcStartupGroupsLookupResult: {
                // Original @ 0x102c85cc: MOV r4,r0.
                const std::uint32_t result_index =
                    regs[0];
                const std::uint32_t vector_object =
                    regs[7];
                const std::uint32_t byte_offset =
                    regs[8];

                regs[4] = regs[0];

                if (vector_object !=
                    kV55StartupGroupsVectorGuest) {
                    return;
                }

                const std::string group =
                    V55CurrentGateAGroup(
                        vector_object,
                        byte_offset);

                ++v55_lookup_total;

                const int slot =
                    V55StartupGroupSlot(group);

                bool should_log = false;

                if (slot >= 0) {
                    auto& stat =
                        v55_group_stats[
                            static_cast<std::size_t>(
                                slot)];

                    const std::uint32_t previous =
                        stat.last_lookup;

                    ++stat.lookup_hits;
                    if (result_index ==
                        0xffffffffu) {
                        ++stat.lookup_misses;
                    }

                    stat.last_lookup =
                        result_index;

                    should_log =
                        stat.lookup_hits <= 4u ||
                        previous !=
                            result_index ||
                        (stat.lookup_hits %
                            100u) == 0u;
                } else {
                    ++v55_lookup_unknown;
                    should_log =
                        v55_lookup_unknown <= 8u;
                }

                if (should_log) {
                    std::string source;

                    if (result_index ==
                        0xffffffffu) {
                        source = "MISS";
                    } else if (
                        (result_index &
                         0x10000000u) != 0u) {
                        source = "table+0x30";
                    } else {
                        source = "table+0x28";
                    }

                    Append(
                        "V55 STARTUP GROUPS lookup group=\"" +
                        group +
                        "\" offset=" +
                        std::to_string(
                            byte_offset) +
                        " result=0x" +
                        JniProbeHex(
                            result_index) +
                        " source=" +
                        source +
                        " totalLookup#=" +
                        std::to_string(
                            v55_lookup_total));
                }

                return;
            }

            case kJniProbeSvcStartupGroupsContribution: {
                // Original @ 0x102c85f4:
                // ADD r10,r6,r10. At this point r6 is the first
                // per-group value and r0 is the second.
                const std::uint32_t vector_object =
                    regs[7];
                const std::uint32_t byte_offset =
                    regs[8];
                const std::uint32_t completed =
                    regs[6];
                const std::uint32_t total =
                    regs[0];

                regs[10] =
                    regs[6] +
                    regs[10];

                if (vector_object !=
                    kV55StartupGroupsVectorGuest) {
                    return;
                }

                const std::string group =
                    V55CurrentGateAGroup(
                        vector_object,
                        byte_offset);

                ++v55_contribution_total;

                const int slot =
                    V55StartupGroupSlot(group);

                bool should_log = false;

                if (slot >= 0) {
                    auto& stat =
                        v55_group_stats[
                            static_cast<std::size_t>(
                                slot)];

                    const bool changed =
                        stat.last_completed !=
                            completed ||
                        stat.last_total !=
                            total;

                    ++stat.contribution_hits;
                    stat.last_completed =
                        completed;
                    stat.last_total =
                        total;

                    should_log =
                        stat.contribution_hits <=
                            4u ||
                        changed ||
                        (stat.contribution_hits %
                            100u) == 0u;
                } else {
                    should_log =
                        v55_contribution_total <=
                            8u;
                }

                if (should_log) {
                    Append(
                        "V55 STARTUP GROUPS contribution group=\"" +
                        group +
                        "\" index=0x" +
                        JniProbeHex(
                            regs[4]) +
                        " completed+=" +
                        std::to_string(
                            completed) +
                        " total+=" +
                        std::to_string(
                            total) +
                        " runningCompleted=" +
                        std::to_string(
                            regs[10]) +
                        " runningTotalBeforeAdd=" +
                        std::to_string(
                            regs[11]));
                }

                return;
            }

            default:
                break;
            }
        }

        if (swi >= kJniProbeSvcStartupGateAResource &&
            swi <= kJniProbeSvcStartupMainMenuMarker) {

            const bool logo_state =
                V53CurrentGameState() == 2;

            auto append_gate =
                [&](const std::string& text) {
                    if (logo_state) {
                        Append(
                            "V54 STARTUPLOGO " +
                            text);
                    }
                };

            switch (swi) {
            case kJniProbeSvcStartupGateAResource: {
                // Original: LDR r0,[r5,#0x64c].
                const std::uint32_t base =
                    regs[5];
                regs[0] =
                    mem.Read32Guest(
                        base + 0x64cu);
                ++v54_gate_a_resource_hits;
                v54_gate_a_resource = regs[0];

                if (logo_state) {
                    const std::string snapshot =
                        V55StartupGroupVectorState();

                    if (snapshot !=
                        v55_gate_vector_snapshot) {
                        v55_gate_vector_snapshot =
                            snapshot;

                        Append(
                            "V55 STARTUP GROUPS GateA-vector-change hit=" +
                            std::to_string(
                                v54_gate_a_resource_hits) +
                            " " +
                            snapshot);
                    }
                }

                append_gate(
                    "GateA.resource hit=" +
                    std::to_string(
                        v54_gate_a_resource_hits) +
                    " owner=" +
                    V46DescribeGuestAddress(base) +
                    " resource=0x" +
                    JniProbeHex(regs[0]) +
                    (regs[0] == 0u
                        ? " BLOCK(resource-null)"
                        : " present"));
                return;
            }

            case kJniProbeSvcStartupGateATotals: {
                // Original: VMOV s0,r11. At this exact point r10/r11 are
                // the accumulated completed/total counters used by VDIV.
                if (jit != nullptr) {
                    jit->ExtRegs()[0] =
                        regs[11];
                }

                ++v54_gate_a_totals_hits;
                v54_gate_a_completed =
                    regs[10];
                v54_gate_a_total =
                    regs[11];

                std::ostringstream line;
                line
                    << "GateA.totals hit="
                    << v54_gate_a_totals_hits
                    << " completed="
                    << v54_gate_a_completed
                    << " total="
                    << v54_gate_a_total;

                if (v54_gate_a_total != 0u) {
                    line
                        << " ratio="
                        << (static_cast<double>(
                                v54_gate_a_completed) /
                            static_cast<double>(
                                v54_gate_a_total));
                } else {
                    line << " ratio=DIV0";
                }

                append_gate(line.str());
                return;
            }

            case kJniProbeSvcStartupGateAResult: {
                ++v54_gate_a_result_hits;
                v54_gate_a_result_bits =
                    regs[0];

                float value = 0.0f;
                std::memcpy(
                    &value,
                    &v54_gate_a_result_bits,
                    sizeof(value));

                if (logo_state &&
                    value >= 1.0f) {
                    ++v57_gate_a_natural_pass_hits;
                }

                bool scout_forced = false;

                // v56 Scout rule: the first complete Gate-A evaluation is
                // always native. Only subsequent evaluations may be forced,
                // and only after v55 has proven that all four startup groups
                // were actually looked up and all four missed with no
                // contribution. We modify only S2, exactly the destination
                // of the original VMOV; R0 and all registry data stay native.
                if (jit != nullptr &&
                    logo_state &&
                    V56ScoutEnabled() &&
                    v54_gate_a_result_hits >= 2u &&
                    V56GateAProofReady() &&
                    !(value >= 1.0f)) {

                    constexpr std::uint32_t
                        kOneFloatBits =
                            0x3f800000u;

                    jit->ExtRegs()[2] =
                        kOneFloatBits;
                    scout_forced = true;
                    ++v56_gate_a_forced_hits;

                    if (!v56_gate_a_scout_activated) {
                        v56_gate_a_scout_activated =
                            true;
                        v56_gate_a_activation_frame =
                            current_frame_number;

                        Append(
                            "V56 SCOUT ACTIVATED after native proof: "
                            "GateA first cycle saw all four startup groups "
                            "MISS with zero contributions; subsequent "
                            "comparison input S2 is set to 1.0 only. "
                            "frame=" +
                            std::to_string(
                                current_frame_number) +
                            " nativeBits=0x" +
                            JniProbeHex(
                                v54_gate_a_result_bits));

                        V56AppendRegistrySnapshot(
                            "scout-activation");
                    }
                } else if (jit != nullptr) {
                    // Native instruction: VMOV s2,r0.
                    jit->ExtRegs()[2] =
                        regs[0];
                }

                std::ostringstream line;
                line
                    << "GateA.result hit="
                    << v54_gate_a_result_hits
                    << " bits=0x"
                    << JniProbeHex(
                           v54_gate_a_result_bits)
                    << " float="
                    << value
                    << " => ";

                if (scout_forced) {
                    line
                        << "V56_SCOUT_FORCE_PASS"
                        << "(native="
                        << (!(value >= 1.0f)
                                ? "BLOCK"
                                : "PASS")
                        << ")";
                } else {
                    line
                        << (value >= 1.0f
                            ? "PASS"
                            : "BLOCK(<1.0)");
                }

                append_gate(line.str());
                return;
            }

            case kJniProbeSvcStartupGateCState: {
                // Original: LDR r1,[r0,#0x98]. v57 may alter only the
                // loaded comparison operand after a delayed native proof;
                // object+0x98 itself is never modified by the Scout.
                const std::uint32_t object =
                    regs[0];
                const std::uint32_t native_state =
                    mem.Read32Guest(
                        object + 0x98u);
                regs[1] =
                    native_state;

                bool scout_forced = false;

                if (logo_state) {
                    ++v54_gate_c_hits;
                    v54_gate_c_object =
                        object;
                    v54_gate_c_state =
                        native_state;

                    ++v57_gate_c_native_hits;

                    if (native_state == 4u) {
                        ++v57_gate_c_native_pass_hits;
                    }

                    const bool object_changed =
                        v57_gate_c_last_object !=
                            object;
                    const bool state_changed =
                        v57_gate_c_last_native_state !=
                            native_state;

                    if (object_changed ||
                        state_changed ||
                        v57_gate_c_first_frame ==
                            0xffffffffu) {
                        v57_gate_c_first_frame =
                            current_frame_number;
                        v57_gate_c_window_write_base =
                            v57_gate_c_write_events;
                    }

                    v57_gate_c_last_object =
                        object;
                    v57_gate_c_last_native_state =
                        native_state;

                    const bool stable_window =
                        current_frame_number >=
                            v57_gate_c_first_frame +
                                10u &&
                        v57_gate_c_write_events ==
                            v57_gate_c_window_write_base;

                    if (V57DeepScoutEnabled() &&
                        native_state == 1u &&
                        (v57_gate_c_scout_activated ||
                         stable_window)) {

                        regs[1] = 4u;
                        scout_forced = true;
                        ++v57_gate_c_forced_hits;

                        if (!v57_gate_c_scout_activated) {
                            v57_gate_c_scout_activated =
                                true;
                            v57_gate_c_activation_frame =
                                current_frame_number;

                            Append(
                                "V57 GATEC SCOUT ACTIVATED after delayed native proof: "
                                "object+0x98 remained 1 for >=10 frames with no writes "
                                "during the stable window; only loaded r1 is set to 4 "
                                "for the native compare. object=" +
                                V46DescribeGuestAddress(
                                    object) +
                                " frame=" +
                                std::to_string(
                                    current_frame_number));
                        }
                    }
                }

                append_gate(
                    "GateC hit=" +
                    std::to_string(
                        v54_gate_c_hits) +
                    " object=" +
                    V46DescribeGuestAddress(object) +
                    " nativeState98=" +
                    std::to_string(native_state) +
                    (scout_forced
                        ? " => V57_SCOUT_COMPARE_AS_4"
                        : native_state == 4u
                            ? " => PASS"
                            : " => BLOCK(!=4)"));
                return;
            }

            case kJniProbeSvcStartupGateDCounter: {
                // Original: LDR r0,[r4,#0x430].
                const std::uint32_t manager =
                    regs[4];
                regs[0] =
                    mem.Read32Guest(
                        manager + 0x430u);

                if (logo_state) {
                    ++v54_gate_d_hits;
                    v54_gate_d_counter =
                        regs[0];
                }

                append_gate(
                    "GateD hit=" +
                    std::to_string(
                        v54_gate_d_hits) +
                    " counter430=" +
                    std::to_string(regs[0]) +
                    (regs[0] >= 3u
                        ? " => PASS"
                        : " => BLOCK(<3)"));
                return;
            }

            case kJniProbeSvcStartupAfterD:
                // Original: LDR r0,[pc,#0x3c8], literal @ +0x276e0c.
                regs[0] =
                    mem.Read32Guest(
                        kGuestBase +
                        0x00276e0cu);
                if (logo_state) {
                    ++v54_after_d_hits;
                }
                append_gate(
                    "after-A-D reached #" +
                    std::to_string(
                        v54_after_d_hits));
                return;

            case kJniProbeSvcStartupGateEByte: {
                // Original: LDRB r0,[r0,#0xb7a].
                const std::uint32_t object =
                    regs[0];
                regs[0] =
                    mem.Read8(
                        object + 0xb7au);
                if (logo_state) {
                    ++v54_gate_e_hits;
                    v54_gate_e_value =
                        regs[0];
                }
                append_gate(
                    "GateE hit=" +
                    std::to_string(
                        v54_gate_e_hits) +
                    " app.b7a=" +
                    std::to_string(regs[0]) +
                    (regs[0] != 0u
                        ? " => alternate-main-flow"
                        : " => patch-decision-flow"));
                return;
            }

            case kJniProbeSvcStartupGateFResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_gate_f_hits;
                    v54_gate_f_value =
                        regs[0];
                }
                append_gate(
                    "GateF.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_f_hits));
                return;

            case kJniProbeSvcStartupGateGResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_gate_g_hits;
                    v54_gate_g_value =
                        regs[0];
                }
                append_gate(
                    "GateG.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_g_hits));
                return;

            case kJniProbeSvcStartupGateHResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_gate_h_hits;
                    v54_gate_h_value =
                        regs[0];
                }
                append_gate(
                    "GateH.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_h_hits));
                return;

            case kJniProbeSvcStartupGateIResult:
                // Original helper epilogue: MOV r0,r5.
                regs[0] = regs[5];
                if (logo_state) {
                    ++v54_gate_i_hits;
                    v54_gate_i_value =
                        regs[0];
                }
                append_gate(
                    "GateI.result=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_gate_i_hits));
                return;

            case kJniProbeSvcStartupGateJObject: {
                // Original helper entry: MOV r1,r0. The helper returns true
                // iff byte+0x20 != 0 and byte+0x02 == 0.
                const std::uint32_t object =
                    regs[0];
                regs[1] = regs[0];

                const std::uint32_t byte20 =
                    mem.Read8(
                        object + 0x20u);
                const std::uint32_t byte02 =
                    mem.Read8(
                        object + 0x02u);

                if (logo_state) {
                    ++v54_gate_j_hits;
                    v54_gate_j_byte20 =
                        byte20;
                    v54_gate_j_byte02 =
                        byte02;
                }

                append_gate(
                    "GateJ object=" +
                    V46DescribeGuestAddress(object) +
                    " byte20=" +
                    std::to_string(byte20) +
                    " byte02=" +
                    std::to_string(byte02) +
                    " predictedResult=" +
                    ((byte20 != 0u &&
                      byte02 == 0u)
                        ? "1"
                        : "0"));
                return;
            }

            case kJniProbeSvcStartupPatchMarker:
                // Original: MOV r0,r4 immediately before target=3.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_patch_marker_hits;
                }
                append_gate(
                    "PATCH REQUEST PATH reached #" +
                    std::to_string(
                        v54_patch_marker_hits));
                return;

            case kJniProbeSvcStartupMainFlow:
                // Original: MOV r5,r0.
                regs[5] = regs[0];
                if (logo_state) {
                    ++v54_main_flow_hits;
                }
                append_gate(
                    "late/main flow entered #" +
                    std::to_string(
                        v54_main_flow_hits) +
                    " object=0x" +
                    JniProbeHex(regs[5]));
                return;

            case kJniProbeSvcStartupProgressResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_progress_result_hits;
                    v54_progress_value =
                        regs[0];
                }
                append_gate(
                    "late.progressResult=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_progress_result_hits));
                return;

            case kJniProbeSvcStartupFindResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_find_result_hits;
                    v54_find_value =
                        regs[0];
                }
                append_gate(
                    "late.findResult=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_find_result_hits));
                return;

            case kJniProbeSvcStartupLateResult:
                // Original helper epilogue: MOV r0,r4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_late_result_hits;
                    v54_late_value =
                        regs[0];
                }
                append_gate(
                    "late.booleanResult=" +
                    std::to_string(regs[0]) +
                    " hits=" +
                    std::to_string(
                        v54_late_result_hits));
                return;

            case kJniProbeSvcStartupMainMenuMarker:
                // Original: MOV r0,r4 immediately before target=4.
                regs[0] = regs[4];
                if (logo_state) {
                    ++v54_mainmenu_marker_hits;
                }
                append_gate(
                    "MAINMENU REQUEST PATH reached #" +
                    std::to_string(
                        v54_mainmenu_marker_hits));
                return;

            default:
                break;
            }
        }

        if (swi ==
                kJniProbeSvcGameStateApply ||
            swi ==
                kJniProbeSvcGameStateRequest) {

            const bool request =
                swi ==
                    kJniProbeSvcGameStateRequest;

            // Both patched instructions are MOV r4,r0.
            regs[4] = regs[0];

            const std::uint32_t manager =
                regs[0];
            const std::int32_t target =
                static_cast<std::int32_t>(
                    regs[1]);

            V53CacheGameStateManager(
                manager,
                request
                    ? "RequestTransition-hook"
                    : "ApplyState-hook");

            const std::int32_t current =
                V53IsGameStateManager(manager)
                    ? static_cast<std::int32_t>(
                          mem.Read32Guest(
                              manager +
                              0x374u))
                    : -999;

            if (request) {
                ++v53_state_request_calls;
            } else {
                ++v53_state_apply_calls;
            }

            result.game_state_manager =
                v53_game_state_manager;
            result.game_state_current =
                current;
            result.game_state_pending =
                V53PendingGameState();
            result.game_state_request_calls =
                v53_state_request_calls;
            result.game_state_apply_calls =
                v53_state_apply_calls;

            if (V82Enabled()) {
                ++v82_gamestate_correlations;
                Append(
                    "V82 ACTION GAMESTATE #" +
                    std::to_string(v82_gamestate_correlations) +
                    " frame=" + std::to_string(current_frame_number) +
                    " kind=" +
                    (request ? std::string{"REQUEST"} : std::string{"APPLY"}) +
                    " current=" + std::to_string(current) +
                    " target=" + std::to_string(target) +
                    " " + V82TouchContext() + " " +
                    V82RadarSnapshot(
                        v82_last_touch_x, v82_last_touch_y));
            }

            Append(
                std::string{
                    request
                        ? "V53 GAMESTATE REQUEST #"
                        : "V53 GAMESTATE APPLY #"} +
                std::to_string(
                    request
                        ? v53_state_request_calls
                        : v53_state_apply_calls) +
                " current=" +
                std::to_string(current) +
                "(" +
                V53GameStateName(current) +
                ") target=" +
                std::to_string(target) +
                "(" +
                V53GameStateName(target) +
                ") manager=0x" +
                JniProbeHex(manager) +
                " callerLR=" +
                V46DescribeGuestAddress(
                    regs[14]) +
                (request
                    ? " arg2=0x" +
                          JniProbeHex(regs[2]) +
                          " arg3=0x" +
                          JniProbeHex(regs[3])
                    : std::string{}));

            return;
        }

        if (swi ==
                kJniProbeSvcResourceWrapperDirectReturn ||
            swi ==
                kJniProbeSvcResourceWrapperExhausted) {

            const bool direct_return =
                swi ==
                    kJniProbeSvcResourceWrapperDirectReturn;

            const std::uint32_t manager =
                regs[5];
            const std::uint32_t group =
                direct_return
                    ? regs[8]
                    : 0u;
            const std::uint32_t id_object =
                regs[6];

            const std::string requested_id =
                RecoverGuestResfileWord(
                    id_object);

            const bool resfile =
                requested_id.rfind(
                    "RESFILE_",
                    0u) == 0u;

            if (resfile &&
                (!direct_return ||
                 regs[0] == 0u)) {

                if (direct_return) {
                    ++resource_wrapper_direct_nulls;
                } else {
                    ++resource_wrapper_exhausted_nulls;
                }

                if (resource_wrapper_direct_nulls +
                        resource_wrapper_exhausted_nulls <=
                    48u) {
                    Append(
                        "V48 WRAPPER NULL #" +
                        std::to_string(
                            resource_wrapper_direct_nulls +
                            resource_wrapper_exhausted_nulls) +
                        " kind=" +
                        (direct_return
                            ? std::string{"direct-group"}
                            : std::string{"all-groups-exhausted"}) +
                        " id=\"" +
                        requested_id +
                        "\" manager=0x" +
                        JniProbeHex(manager) +
                        " group=0x" +
                        JniProbeHex(group));
                }

                const std::uint32_t recovered =
                    ResolveResourceRegistryNativeMiss(
                        manager,
                        group,
                        id_object,
                        direct_return
                            ? "0x1087a708-wrapper-direct"
                            : "0x1087a76c-wrapper-exhausted",
                        requested_id);

                if (recovered != 0u) {
                    regs[0] = recovered;
                    ++resource_wrapper_recoveries;

                    if (resource_wrapper_recoveries <=
                        48u) {
                        Append(
                            "V48 WRAPPER RESFILE HEAL #" +
                            std::to_string(
                                resource_wrapper_recoveries) +
                            " id=\"" +
                            requested_id +
                            "\" -> ResourceInfo*=0x" +
                            JniProbeHex(recovered));
                    }
                } else if (!direct_return) {
                    regs[0] = 0u;
                }
            } else if (!direct_return) {
                // Original instruction at 0x1087a76c was MOV r0,#0.
                regs[0] = 0u;
            }

            if (direct_return) {
                // Original instruction at 0x1087a708 was B 0x1087a770.
                regs[15] =
                    kGuestBase +
                    0x0087a770u;
            }

            return;
        }

        if (swi ==
                kJniProbeSvcResourceRegistryEntry) {

            // Original instruction at guest 0x1086f674 is MOV r4,r2.
            // Preserve its semantics first.
            regs[4] = regs[2];

            const std::string entry_id =
                RecoverGuestResfileWord(
                    regs[2]);

            if (!entry_id.empty()) {
                resource_lookup_entry_ids[
                    regs[13]] =
                    entry_id;

                V50ObserveResourceId(
                    entry_id);

                if (resource_entry_id_diagnostics <
                    24u) {
                    ++resource_entry_id_diagnostics;

                    Append(
                        "V45 RES ENTRY #" +
                        std::to_string(
                            resource_entry_id_diagnostics) +
                        " sp=0x" +
                        JniProbeHex(
                            regs[13]) +
                        " r2=0x" +
                        JniProbeHex(
                            regs[2]) +
                        " id=\"" +
                        entry_id +
                        "\"");
                }
            } else {
                resource_lookup_entry_ids.erase(
                    regs[13]);
            }

            return;
        }

        if (swi ==
            kJniProbeSvcResourceRegistryGlobalValue) {

            // Original 0x1086fa84 instruction:
            //     LDR r0,[r10,#0x14]
            // r10 is the node returned by the global ResourceInfo tree.
            const std::uint32_t node =
                regs[10];

            const std::uint32_t native_value =
                node != 0u &&
                mem.Ptr(
                    node + 0x14u,
                    4u) != nullptr
                    ? mem.Read32Guest(
                          node + 0x14u)
                    : 0u;

            if (native_value != 0u) {
                // Exact emulation of the original LDR for normal native hits.
                regs[0] =
                    native_value;
                return;
            }

            std::string recovered_id;

            // Same exact per-stack-frame ID captured at 0x1086f674.
            if (const auto entry =
                    resource_lookup_entry_ids.find(
                        regs[13]);
                entry !=
                    resource_lookup_entry_ids.end()) {
                recovered_id =
                    entry->second;
            }

            if (recovered_id.empty()) {
                recovered_id =
                    RecoverGuestResfileWord(
                        regs[4]);
            }

            if (recovered_id.empty()) {
                for (std::uint32_t reg = 3u;
                     reg <= 12u &&
                     recovered_id.empty();
                     ++reg) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            regs[reg]);
                }
            }

            if (recovered_id.empty() &&
                mem.Ptr(
                    regs[13],
                    32u * 4u) != nullptr) {
                for (std::uint32_t slot = 0u;
                     slot < 32u &&
                     recovered_id.empty();
                     ++slot) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            mem.Read32Guest(
                                regs[13] +
                                slot * 4u));
                }
            }

            // In the global scan, r8 retains the original manager. r6 is the
            // selected group's std::map end sentinel after ADD r6,r6,#60, so
            // subtracting 60 recovers the group base for the narrow exact-ID
            // fallback.
            const std::uint32_t manager =
                regs[8];

            const std::uint32_t group =
                regs[6] >= 60u
                    ? regs[6] - 60u
                    : 0u;

            if (resource_global_null_node_diagnostics <
                32u) {
                ++resource_global_null_node_diagnostics;

                Append(
                    "V45 GLOBAL NULL RESOURCE NODE #" +
                    std::to_string(
                        resource_global_null_node_diagnostics) +
                    " id=\"" +
                    recovered_id +
                    "\" node=0x" +
                    JniProbeHex(
                        node) +
                    " manager=0x" +
                    JniProbeHex(
                        manager) +
                    " group=0x" +
                    JniProbeHex(
                        group) +
                    " value=0");
            }

            const std::uint32_t recovered =
                ResolveResourceRegistryNativeMiss(
                    manager,
                    group,
                    regs[4],
                    "0x1086fa84",
                    recovered_id);

            if (recovered != 0u &&
                node != 0u &&
                mem.Ptr(
                    node + 0x14u,
                    4u) != nullptr) {

                // Heal the same native node so subsequent lookups no longer
                // need the bridge. This mirrors v44's group-node repair, but
                // on the global-tree success path that v44 never trapped.
                mem.Write32Guest(
                    node + 0x14u,
                    recovered);

                ++resource_global_null_node_heals;

                if (resource_global_null_node_heals <=
                    32u) {
                    Append(
                        "V45 GLOBAL NULL NODE HEAL #" +
                        std::to_string(
                            resource_global_null_node_heals) +
                        " id=\"" +
                        recovered_id +
                        "\" node=0x" +
                        JniProbeHex(
                            node) +
                        " -> ResourceInfo*=0x" +
                        JniProbeHex(
                            recovered));
                }
            }

            // The replaced instruction was itself the return-value load.
            regs[0] =
                recovered;
            return;
        }

        if (swi ==
                kJniProbeSvcResourceRegistryMissGroup ||
            swi ==
                kJniProbeSvcResourceRegistryMissGlobal) {

            const bool group_site =
                swi ==
                kJniProbeSvcResourceRegistryMissGroup;

            bool group_null_value_node = false;

            if (group_site &&
                regs[7] != regs[8]) {

                // 0x1086f8a0 is shared by both a genuine native hit and the
                // final group-tree lookup. v43 treated every non-end node as
                // success. The v43 run shows that this is too coarse: the
                // std::map can contain the requested key while its
                // ResourceInfo* value at node+0x14 is still null. In that
                // case the very next guest LDR returns null and the caller
                // reports "resource not found" without ever entering our
                // old miss recovery.
                const std::uint32_t native_value =
                    mem.Ptr(
                        regs[7] + 0x14u,
                        4u) != nullptr
                        ? mem.Read32Guest(
                              regs[7] + 0x14u)
                        : 0u;

                if (native_value != 0u) {
                    // Preserve the original MOV r0,#0; the following guest
                    // LDR r0,[r7,#0x14] restores the real native value.
                    regs[0] = 0u;
                    return;
                }

                group_null_value_node = true;

                if (resource_null_node_diagnostics <
                    24u) {
                    ++resource_null_node_diagnostics;

                    Append(
                        "V45 GROUP NULL RESOURCE NODE #" +
                        std::to_string(
                            resource_null_node_diagnostics) +
                        " node=0x" +
                        JniProbeHex(
                            regs[7]) +
                        " end=0x" +
                        JniProbeHex(
                            regs[8]) +
                        " value=0");
                }
            }

            const std::uint32_t manager =
                group_site
                    ? regs[10]
                    : regs[8];

            const std::uint32_t group =
                group_site &&
                regs[8] >= 60u
                    ? regs[8] - 60u
                    : 0u;

            std::string recovered_id;

            // v43: use the exact lookup ID captured at 0x1086f674 for this
            // ARM stack frame. The old late-state reconstruction can miss
            // every other request after native key transformations.
            if (const auto entry =
                    resource_lookup_entry_ids.find(
                        regs[13]);
                entry !=
                    resource_lookup_entry_ids.end()) {
                recovered_id =
                    entry->second;
            }

            // Preserve the v42 late-state scan as a fallback.
            if (recovered_id.empty()) {
                recovered_id =
                    RecoverGuestResfileWord(
                        regs[4]);
            }

            if (recovered_id.empty()) {
                for (std::uint32_t reg = 3u;
                     reg <= 12u &&
                     recovered_id.empty();
                     ++reg) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            regs[reg]);
                }
            }

            if (recovered_id.empty() &&
                mem.Ptr(
                    regs[13],
                    32u * 4u) != nullptr) {
                for (std::uint32_t slot = 0u;
                     slot < 32u &&
                     recovered_id.empty();
                     ++slot) {
                    recovered_id =
                        RecoverGuestResfileWord(
                            mem.Read32Guest(
                                regs[13] +
                                slot * 4u));
                }
            }

            if (!recovered_id.empty() &&
                resource_live_id_recoveries < 16u) {
                ++resource_live_id_recoveries;

                Append(
                    "V45 LIVE RESFILE RECOVERY #" +
                    std::to_string(
                        resource_live_id_recoveries) +
                    " site=" +
                    (group_site
                        ? std::string{"0x1086f8a0"}
                        : std::string{"0x1086fa78"}) +
                    " r4=0x" +
                    JniProbeHex(
                        regs[4]) +
                    " id=\"" +
                    recovered_id +
                    "\"");
            }

            const std::uint32_t recovered =
                ResolveResourceRegistryNativeMiss(
                    manager,
                    group,
                    regs[4],
                    group_site
                        ? "0x1086f8a0"
                        : "0x1086fa78",
                    recovered_id);

            if (group_null_value_node) {
                if (recovered != 0u &&
                    mem.Ptr(
                        regs[7] + 0x14u,
                        4u) != nullptr) {

                    mem.Write32Guest(
                        regs[7] + 0x14u,
                        recovered);

                    ++resource_null_node_heals;

                    if (resource_null_node_heals <=
                        24u) {
                        Append(
                            "V45 GROUP NULL NODE HEAL #" +
                            std::to_string(
                                resource_null_node_heals) +
                            " id=\"" +
                            recovered_id +
                            "\" node=0x" +
                            JniProbeHex(
                                regs[7]) +
                            " -> ResourceInfo*=0x" +
                            JniProbeHex(
                                recovered));
                    }
                }

                // Emulate the original MOV r0,#0. Because r7!=r8, guest code
                // proceeds to LDR r0,[r7,#0x14], which now reads the healed
                // value if recovery succeeded.
                regs[0] = 0u;
            } else {
                // True end-node miss: guest branches directly to the epilogue,
                // so r0 itself carries the recovered pointer back to caller.
                regs[0] = recovered;
            }

            return;
        }

        if (swi ==
            kJniProbeSvcResourceRegistryLookup) {

            const std::uint32_t manager =
                regs[0];
            const std::uint32_t group =
                regs[1];
            const std::uint32_t id_object =
                regs[2];

            regs[0] =
                ResolveResourceRegistryLookup(
                    manager,
                    group,
                    id_object);

            return;
        }

        if (swi == kJniProbeSvcGetEnv) {
            const std::uint32_t output_address = regs[1];
            const std::uint32_t version = regs[2];

            mem.Write32Guest(output_address, env_object);
            regs[0] = 0;

            Append(
                "JavaVM.GetEnv(version=0x" +
                JniProbeHex(version) +
                ") -> JNI_OK, env=0x" +
                JniProbeHex(env_object));
            return;
        }

        if (swi == kJniProbeSvcFindClass) {
            ++result.find_class_calls;

            const std::string class_name =
                mem.ReadCStringGuest(regs[1], 256);

            const std::uint32_t class_handle =
                0x52000000u +
                result.find_class_calls * 0x100u;

            regs[0] = class_handle;

            Append(
                "JNIEnv.FindClass(\"" +
                class_name +
                "\") -> 0x" +
                JniProbeHex(class_handle));
            return;
        }

        if (swi == kJniProbeSvcNewGlobalRef) {
            regs[0] = regs[1];
            Append(
                "JNIEnv.NewGlobalRef(0x" +
                JniProbeHex(regs[1]) +
                ") -> 0x" +
                JniProbeHex(regs[0]));
            return;
        }

        if (swi == kJniProbeSvcGetObjectClass) {
            const std::uint32_t class_handle =
                0x53000000u +
                (next_synthetic_class++ * 0x100u);

            regs[0] = class_handle;

            Append(
                "JNIEnv.GetObjectClass(0x" +
                JniProbeHex(regs[1]) +
                ") -> 0x" +
                JniProbeHex(class_handle));
            return;
        }

        if (swi == kJniProbeSvcGetMethodID) {
            const std::string method_name =
                mem.ReadCStringGuest(regs[2], 256);
            const std::string signature =
                mem.ReadCStringGuest(regs[3], 512);

            const std::uint32_t method_id =
                0x54000000u +
                (next_synthetic_method++ * 0x100u);

            jni_method_names[method_id] =
                method_name;
            jni_method_signatures[method_id] =
                signature;

            regs[0] = method_id;

            Append(
                "JNIEnv.GetMethodID(clazz=0x" +
                JniProbeHex(regs[1]) +
                ", name=\"" +
                method_name +
                "\", sig=\"" +
                signature +
                "\") -> 0x" +
                JniProbeHex(method_id));
            return;
        }

        if (swi == kJniProbeSvcRegisterNatives) {
            ++result.register_natives_calls;

            const std::uint32_t class_handle = regs[1];
            const std::uint32_t methods = regs[2];
            const std::uint32_t count = regs[3];

            result.registered_native_methods += count;

            Append(
                "JNIEnv.RegisterNatives(clazz=0x" +
                JniProbeHex(class_handle) +
                ", count=" +
                std::to_string(count) +
                ")");

            const std::uint32_t visible =
                std::min<std::uint32_t>(count, 64);

            for (std::uint32_t i = 0;
                 i < visible;
                 ++i) {

                const std::uint32_t entry =
                    methods + i * 12u;

                const std::uint32_t name_ptr =
                    mem.Read32Guest(entry + 0);
                const std::uint32_t signature_ptr =
                    mem.Read32Guest(entry + 4);
