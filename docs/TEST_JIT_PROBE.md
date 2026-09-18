# Testing the iPadOS 26 JIT probe

This is the first device milestone for PvZ2forIOS. It does **not** contain any Plants vs. Zombies 2 files.

Its only goal is to prove that the target iPad can execute dynamically generated ARM64 code through the iPadOS 26 StikJIT universal protocol.

## What the probe does

When the test succeeds, the app:

1. confirms that the sideloaded app has `get-task-allow`;
2. confirms that the process has `CS_DEBUGGED`;
3. asks StikDebug's `universal.js` protocol to prepare an executable region;
4. creates a separate writable alias for that region;
5. writes two ARM64 instructions:
   - `mov w0, #42`
   - `ret`
6. detaches the JIT debug server;
7. executes the generated code;
8. reports success only if the generated function returns **42**.

## Requirements

- iPadOS 26 target device
- Developer Mode enabled on the iPad
- the unsigned probe IPA signed/installed with a development-style sideloading method that preserves `get-task-allow`
- StikDebug installed
- a valid device pairing file configured for StikDebug
- LocalDevVPN (or another loopback VPN supported by the installed StikDebug version)

StikDebug's current documentation supports iOS/iPadOS 26, but applications need the new iOS 26 JIT integration. This probe implements the recommended universal breakpoint protocol.

## Pairing file privacy

A pairing file is private, device-specific material.

Do **not** commit it to this repository and do **not** send it to ChatGPT, GitHub issues, or other people.

The repository's `.gitignore` excludes common pairing-file names as an additional safeguard.

## Test sequence

1. Install/sign `PvZ2forIOS-JIT-Probe-unsigned.ipa`.
2. Launch it once.
3. Check the status panel:
   - `get-task-allow: YES` is required.
4. Make sure LocalDevVPN is connected and StikDebug is already configured with the device pairing file.
5. Tap **1. Enable JIT with StikDebug**.
6. StikDebug should open and attach to this exact running process using `universal.js`.
7. Return to PvZ2forIOS.
8. The status should show `CS_DEBUGGED: YES`.
9. Tap **2. Run JIT probe**.
10. Expected result:

```text
SUCCESS: generated ARM64 code executed and returned 42.
iPadOS 26 JIT is working.
```

## Logs

The app writes:

```text
Documents/pvz2forios-jit.log
```

File sharing is enabled, so the log can be retrieved through the Files app / device file sharing.

The log contains status messages only; it deliberately does not record pairing-file contents.

## If it fails

Send only:

- a screenshot of the probe screen, or
- `pvz2forios-jit.log`

Do not send a pairing file, signing certificate, provisioning profile, Apple account credentials, or device serial number.

Once this milestone passes, the next build will replace the two-instruction probe with a minimal Dynarmic A32 guest test, then with loading/identification of the PvZ2 1.5 `libPVZ2.so`.

## iPad 10th generation / Non-TXM path

The iPad (10th generation, A14; iPad13,18/iPad13,19) is treated by StikDebug/StikJIT as **Non-TXM**.

For Non-TXM devices, StikJIT's integration guide states that attaching and detaching the debugger is enough to enable JIT. The `brk #0xf00d` executable-region protocol is only required where TXM/SPTM is present.

Therefore:

- leave **StikDebug → Settings → Behavior → Always Run Scripts** **OFF**;
- request JIT with bundle ID + current PID and **no script**;
- after `CS_DEBUGGED` becomes YES, allocate an RX mapping and create a separate RW mirror with `vm_remap`;
- do not execute `JIT26PrepareRegion` or `JIT26Detach` on this device.

Probe v6 implements this Non-TXM path.
