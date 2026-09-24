# v108 — Bank Completion + Audio Liveness

## Root cause targeted

The long v107 iPad transition run proves the old BankMgr wake problem is no longer the final blocker. The failing synchronous `AK::SoundEngine::UnloadBank` wakes `CAkBankMgr::BankThreadFunc`, the bank queue depth goes from 1 to 0, and BankMgr returns to its own wait. The main-thread completion semaphore is nevertheless never posted.

Static analysis of the exact Android 1.5.252752 `libPVZ2.so` gives the asynchronous chain:

1. `CAkBankMgr::KillSlot` stores callback/cookie in `CAkUsageSlot`, queues `AkQueuedMsg::KillBank`, then calls `AK::SoundEngine::RenderAudio`.
2. `CAkAudioMgr::ProcessMsgQueue` handles `KillBank`, calls `CAkURenderer::StopAllPBIs(slot)`, then `CAkUsageSlot::Release(slot,false)`.
3. `CAkUsageSlot::Release` invokes `UnloadCompletionNotification` only when the slot's final references are released.
4. `UnloadCompletionNotification` invokes `DefaultBankCallbackFunc`.
5. `DefaultBankCallbackFunc` posts the synchronous `UnloadBank` semaphore.

The v107 freeze therefore occurs downstream of BankMgr command dequeue. During the same transition the Wwise audio worker dominates wait time and the user observes audio stopping. This is consistent with a circular liveness failure: live PBIs keep the bank slot referenced, while the synthetic OpenSL ring drains and stops producing further callbacks needed to drive additional `CAkAudioMgr::Perform` cycles.

## v108 changes

- Adds exact observational traps for:
  - `CAkBankMgr::KillSlot` @ lib+0x00bc3fd0
  - `CAkAudioMgr::ProcessMsgQueue` KillBank @ lib+0x00bbf254
  - `CAkUsageSlot::Release` @ lib+0x00bc5478
  - `CAkUsageSlot::UnloadCompletionNotification` @ lib+0x00bc0e80
  - `AK::SoundEngine::DefaultBankCallbackFunc` @ lib+0x00bb6a50
- Captures the real `CAkAudioThread::EventMgrThreadFunc` semaphore from its pthread argument.
- Bank-wait snapshots now include slot refcount, prepare-refcount, callback/cookie, AudioThread semaphore state, host queued PCM blocks, pending guest callbacks, consumed-block count, CoreAudio render count and underruns.
- Adds a narrowly gated audio-liveness pulse:
  - only during a synchronous v106-style `UnloadBank` wait,
  - only after the matching KillBank message has really reached the AudioThread,
  - only while the slot's real completion callback is still pending,
  - only when the host PCM block queue is empty,
  - only when no guest OpenSL callback is pending,
  - only when the real AudioThread is asleep on its own event semaphore,
  - at most once per 32 ms (1024 frames / 32 kHz).
- The pulse wakes only `CAkAudioThread`; it never posts or fabricates the main `UnloadBank` completion semaphore. Wwise must still release the slot and run its own callback chain.

## iPad validation

Expected useful lines during the transition:

- `V108 BANK KILLSLOT`
- `V108 BANK KILLMSG`
- `V108 BANK SLOT RELEASE`
- `V108 AUDIO EVENT POST/WAIT`
- `V108 AUDIO LIVENESS PULSE` if the PCM-drain circular wait is actually reached
- `V108 BANK COMPLETION NOTIFY`
- `V108 BANK DEFAULT CALLBACK`

Success is: normal 32 kHz audio remains correct, the heavy transition eventually completes, and each synchronous bank unload reaches its native Wwise completion callback. If it still stalls, the final v108 slot-ref/audio state identifies which stage owns the remaining reference.
