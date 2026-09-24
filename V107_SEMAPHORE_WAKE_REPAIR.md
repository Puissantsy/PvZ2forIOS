# v107 — BankMgr semaphore wake repair

## v106 result

The 32 kHz audio correction is confirmed on the real iPad:

    V99 AUDIO PLAYER 32000 Hz
    V101 AUDIO CLOCK requested=32000 session=48000 source=32000 mixer=48000

Wwise also remains internally coherent at 32 kHz:

    sourceHz=32000
    targetHintHz=32000
    pipelineHz=32000
    ratio=1.0
    pitch=0
    stepA=stepB=65536

The former 1.5x/nightcore defect is therefore considered fixed unless a later
test disproves it.

## Frame 689/690 stall

After Play, v106 entered:

    AK::SoundEngine::UnloadBank
      -> CAkBankMgr::QueueBankCommand
      -> main completion sem_wait

The main completion semaphore stayed at zero for about 114 seconds until Hard
Stop. Prioritizing BankMgr did not help: tid 4 remained blocked at the sem_wait
import for tens of thousands of scheduler rounds.

Static ARM proof from the exact 1.5.252752 libPVZ2.so:

    CAkBankMgr::QueueBankCommand +0xc8:
        r0 = bankMgr + 0x28
        sem_post(r0)

    CAkBankMgr::BankThreadFunc:
        r5 = bankMgr + 0x28
      loop:
        sem_wait(r5)
        ExecuteCommand()

So the producer and consumer use the same dedicated BankMgr wake semaphore.
The main thread waits on a different stack-local completion semaphore.

## v107 semantic repair

The cooperative semaphore model has two pieces of state:

- v66_sem_waits: authoritative per-thread wait state
- v66_sem_waiters: FIFO acceleration index by semaphore address

v107 preserves FIFO behavior first. If a real sem_post finds no usable waiter in
the secondary FIFO but the authoritative wait map still contains a matching,
unnotified waiter, it wakes exactly one such waiter and repairs the FIFO index.
The posted counter remains real and is consumed by normal V66 resume logic.

No semaphore is forced merely because a frame is slow and no UnloadBank
completion is synthesized.

A second consistency rule is applied when guest execution physically reaches a
new sem_wait: stale previous semaphore waits and non-condition mutex-wait records
for that same executing thread are impossible states, because such a thread could
not have executed forward to the new sem_wait. v107 removes only those stale
records and logs each repair.

## Exact BankMgr telemetry

v107 stores the BankMgr object from pthread creation and derives:

    wakeSem = bankMgr + 0x28
    queueDepth = [bankMgr + 0x4c]

It recognizes exact callsites without patching guest code:

    QueueBankCommand sem_post return: lib+0x00bc1554
    BankThreadFunc sem_wait return:   lib+0x00bc7bb8

Key lines:

    V107 BANK WAKE POST
    V107 BANK WAKE WAIT
    V107 SEM INDEX REPAIR
    V107 STALE SEM WAIT REPAIR
    V107 STALE MUTEX WAIT REPAIR

The existing V106 BANK WAIT ROUND snapshots now also include bankObject,
wakeSem/wakeCount, queueDepth, authoritative BankMgr wait semaphore/notified
state, and mutex/condition blocker flags.

## Test

Use the same APK + OBB.

1. Confirm sound remains normal.
2. Press Play exactly as in v106.
3. If Play succeeds, continue far enough to exercise further SoundBank changes.
4. If a frame stalls, Hard Stop and send the complete log.

The first V107 BANK WAKE POST around the Play transition should immediately tell
whether QueueBankCommand posted the expected bankMgr+0x28 semaphore and whether
the BankMgr waiter was found/reconciled.
