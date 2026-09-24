# V97 Granted Mutex Wait Graph

## Real-iPad evidence from v96

The v96 run reached 1182 completed frames and did not reproduce the historical saved-LR corruption / 0x1086fcea Thumb crash. Its real main-thread semaphore waits entered and resumed normally.

The new stop was V87's wait-for-cycle detector around g_csMain:
- tid=5 owned g_csMain;
- tid=4 blocked on it;
- unlock handed g_csMain to tid=4 and marked tid4's V87 wait record granted=true;
- before tid4 received its resume quantum, tid=5 attempted the mutex again;
- V87 followed tid4's still-present granted bookkeeping record as if it were an active dependency and reported a false cycle.

## Root cause

V87 intentionally keeps a granted wait record until V87PrepareMutexResume() consumes it. During that interval:
- the mutex state already says owner=grantedTid, depth=1;
- the thread is runnable and owns the mutex logically;
- the wait record is only a resume token.

Therefore granted=true must never be traversed as a live wait-for edge.

## V97 correction

V97 inherits the complete v96 runtime.

Deadlock traversal:
- stops when it reaches a granted wait record;
- may then queue the new waiter normally behind the granted/runnable owner.

Preferred-owner traversal:
- does not follow a granted wait as another dependency;
- returns that granted owner as the thread that should be scheduled.

A bounded diagnostic counter/log, V97 MUTEX GRAPH GRANTED TERMINAL, confirms when this exact class is encountered on iPad.

True ungranted wait-for cycles remain fatal and are still detected by V87.

## App UI cleanup

Historical diagnostic modes remain registered internally for source/history, but the app-facing selectable-mode list now contains only v97 and the segmented mode selector has been removed from the UI.

APK/OBB execution is hardwired to V97_GRANTED_MUTEX_WAIT_GRAPH, preventing accidental runs with old capability sets.

The JIT enable and Dynarmic smoke-test buttons remain because they are prerequisites/tools, not runtime-mode alternatives.

## iPad test

Expected around the previous v96 failure:
- V87 MUTEX HANDOFF ... -> tid=4
- V97 MUTEX GRAPH GRANTED TERMINAL ... ownerTid=4
- tid=5 queues normally instead of V87 MUTEX DEADLOCK
- tid=4 resumes and eventually unlocks/hands off normally

Must remain absent:
- historical LR mutation toward 0x1086f203
- UndefinedInstruction at 0x1086fcea
- false V87 cycle for the granted tid4 handoff
