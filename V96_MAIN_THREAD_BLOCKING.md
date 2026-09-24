# V96 Main Thread Blocking

## Root cause targeted

v95 proved that the recurrent saved-LR corruption was a late Wwise semaphore callback writing into a recycled main-thread stack frame.

The synchronous Wwise wrappers create a stack-local semaphore/cookie, queue an asynchronous bank command, call `sem_wait`, then destroy the semaphore and return. The compatibility bridge only performed a real semaphore wait when `current_probe_thread_id != 0`. On lifecycle main thread `tid=0`, a zero-count `sem_wait` therefore returned synthetic success. The stack frame died while the Wwise callback still held `cookie+4`; later `sem_post` calls incremented the reused saved-LR slot.

v95 observed the exact chain on iPad: the saved LR slot was armed with `0x1086f1fc`, first changed by `SVC 0x10ad = sem_post` from worker tid=4, and finally reached `0x1086f203` before the fatal Thumb return.

## V96 correction

V96 keeps the complete v95 runtime and precise LR watcher, and adds real cooperative blocking for lifecycle main thread `tid=0` for:

- `sem_wait` / `sem_timedwait`
- `pthread_cond_wait` / `pthread_cond_timedwait`
- `nanosleep` / `usleep`
- existing V87 main-thread mutex waits are folded into the same hard-wait scheduler

The compatibility no-block path is deliberately retained for constructors, `JNI_OnLoad`, and `Native_GameAppInitialize`, because those phases still execute through direct `jit.Run()` calls without a cooperative lifecycle scheduler.

## Scheduler invariant

After a blocking SVC on lifecycle main:

1. main registers, extended registers, CPSR and FPSCR are frozen;
2. no guest main instruction executes while the wait is pending;
3. only deferred workers run;
4. main resume preparation is ordered as condition wait -> semaphore/sleep -> generic mutex;
5. a condition waiter does not resume until its original mutex has been reacquired;
6. V65 condition-variable deadlines and V66 semaphore/sleep deadlines are both considered before declaring deadlock;
7. only after post/signal/timeout/reacquire is complete is the saved main context restored and `jit.Run(main)` allowed again.

The workers-only loop also handles the zero-runnable-worker timed-wait case by allowing host time to advance instead of accidentally re-running main.

## Files changed

- `platform/ios/src/pvz2_apk_probe.hpp`
  - adds V96 diagnostic mode and MainThreadBlocking capability.
- `platform/ios/src/pvz2_apk_probe.cpp`
  - lifecycle-only tid=0 wait eligibility;
  - unified main hard-wait helpers;
  - V65+V66 deadline aggregation;
  - workers-only lifecycle scheduler;
  - v95 precise saved-LR watcher retained.
- `platform/ios/src/main.mm`
  - V96 is the default diagnostic mode and UI text describes the new correction.

## iPad test

Use the ordinary APK + OBB and leave **V96 Main Waits** selected.

The log should show:

- `V96 MAIN BLOCK ENTER kind=sem-wait` (or another real blocking kind);
- worker progress while main is frozen;
- the Wwise callback / `V66 SEM POST`;
- `V96 MAIN BLOCK RESUME ...` only after the wait is truly satisfied.

For the historical Wwise failure, the v95 precise LR watcher remains the oracle: once `0x200ff914` is reused as the outer saved LR, late Wwise `sem_post` calls should no longer mutate it from `0x1086f1fc` toward `0x1086f203`.

The real iPad result must confirm whether the historical frame ~1027 crash disappears and what the next runtime boundary is.
