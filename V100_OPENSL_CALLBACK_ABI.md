# v100 — OpenSL BufferQueue callback ABI fix

## What v99 proved

The first real-iPad v99 log proves the complete forward audio path before any
callback is delivered:

- OpenSL engine object created;
- output mix created;
- Wwise requested 48,000 Hz stereo PCM16;
- AVAudioEngine started;
- Wwise registered CAkSinkOpenSL::EnqueueBufferCallback;
- play state reached PLAYING;
- four 1024-frame / 4096-byte PCM buffers were queued.

The crash occurs only when the first completed-buffer callback is entered.

## Root cause

CAkSinkOpenSL::EnqueueBufferCallback has the native OpenSL C signature:

    callback(SLAndroidSimpleBufferQueueItf queue, void* context)

ARM32 therefore requires:

    r0 = queue
    r1 = context

v99 reused the JNI lifecycle helper, whose register contract is:

    r0 = JNIEnv*
    r1 = thiz
    r2 = arg2
    r3 = arg3

So v99 delivered:

    r0 = synthetic JNIEnv*
    r1 = queue
    r2 = CAkSinkOpenSL*

Disassembly of libPVZ2.so+0x00bb02b0 immediately copies r1 to r4 and later reads
[r4+0x48] as the sink's BufferQueue interface. The iPad crash therefore showed
r4 equal to the synthetic queue handle, then loaded a null method pointer and
branched to PC=0 at callback+0x78.

## v100 fix

The existing run_lifecycle scheduler entry point now has an explicit
raw_arm_abi option. Normal Java/JNI lifecycle calls are unchanged. Only the
OpenSL completion callback opts into raw ARM ABI:

    r0 = v99_queue_itf
    r1 = v99_queue_context
    r2 = 0
    r3 = 0

The callback still runs only at the same safe pre-frame/frame boundaries. It
therefore inherits v96/v97 cooperative blocking/mutex semantics without ever
being invoked from CoreAudio's real-time thread.

## Expected first-iPad markers

    V99 AUDIO ENQUEUE #1 frames=1024 bytes=4096 ...
    V99 AUDIO CALLBACK #1 ...
    V100 AUDIO CALLBACK ABI #1 r0(queue)=... r1(context)=...
    V88 STARTUP BEGIN phase=V100_OpenSL_BufferQueueCallback
    V88 STARTUP END phase=V100_OpenSL_BufferQueueCallback ...

If callback #1 returns, Wwise should enqueue replacement buffers and the audio
ring should become a continuous producer/consumer path instead of terminating
at the first completion.
