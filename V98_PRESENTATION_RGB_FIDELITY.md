# V98 Presentation RGB Fidelity

## Evidence

The real iPad v97 is playable through Day 2 and its scheduler/runtime fixes are validated. The remaining visible mismatch is graphical fidelity:
- sun halos are much more white/burned than the same level on Android/Bluestacks using the same OBB;
- antialiased edges on zombies can show bright fringe artifacts;
- lawnmower translucent shadows are much weaker or absent.

The v97 log ended by user stop after 12,665 frames with no runtime failure.

## Assets / ETC1 ruled out

PvZ2 format-147 PTX stores ETC1 RGB plus a separate 8-bit alpha plane.

The current DecodeEtc1Rgb implementation was checked against multiple original PTX + PopStudio-decoded PNG pairs from the first-frame reference pack. After skipping the 32-byte PTX header, RGB and alpha matched pixel-for-pixel. V98 therefore does not change the PTX decoder, resource mapping, SUN.PAM, or texture data.

## Root cause targeted

The offscreen gColorTexture contains the guest's final composited RGB.

The old v40 CPU/UIImage diagnostic path attempted to compensate for UIKit alpha handling by dividing RGB by framebuffer alpha and forcing alpha opaque. V90 copied that normalization into the new direct-GPU presentation shader.

That transform is not neutral:
    displayedRGB = clamp(framebufferRGB / framebufferAlpha)

For low-alpha pixels it amplifies RGB, often to white. This is consistent with the observed bright sun halo and sprite-edge fringes. It can also destroy subtle translucent shadow contrast.

## V98 correction

Direct GPU presentation now does:
    gl_FragColor = vec4(c.rgb, 1.0)

No RGB/alpha division is performed.

The host-only CPU live-copy and diagnostic PNG paths are updated to the same contract:
- preserve framebuffer RGB byte-for-byte;
- force only host/export alpha to 255;
- never modify guest framebuffer memory.

## Preserved behavior

V98 inherits the complete v97 runtime:
- v95 precise LR watcher;
- v96 real lifecycle main-thread waits;
- v97 granted-mutex wait-graph semantics;
- indexed allocator / RELRO protection;
- 128 MiB heap;
- direct GPU presentation;
- touch/keyboard/UI_IPAD bridges.

## iPad test

Compare with the Android/Bluestacks references already captured.

Expected:
- sun keeps its yellow/orange center and soft glow without excessive white clipping;
- zombie antialiased edges lose the bright fringe;
- lawnmower soft shadow becomes visible again;
- opaque terrain/UI textures remain unchanged;
- fades/transitions still look correct;
- gameplay remains stable beyond the former v97 path.

If a fade becomes incorrect, record the exact screen/frame state; do not reintroduce global RGB/alpha division.
