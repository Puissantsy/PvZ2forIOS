# v127 — Audio Worker Drain

## Root cause fixed

v126 proved that every exact audible PCM duplicate is the native Wwise
CAkSinkOpenSL starvation-replay path (LR 0x10bb0404). Around the real-iPad
crackle, a callback can consume the last host buffer while sink availableFrames
is zero. The callback therefore replays the current slot. The following tid5
handoff often runs for roughly one normal scheduler quantum and is then cut by
v87 fairness before the Wwise event cycle reaches its real sem_wait. The old
v104 handshake counter was incremented anyway.

Example from the v126 iPad run: before the exact repeat at frame 1221, tid5 ran
~12.2 ms at frame 1218 but produced zero frames. At frame 1221 the callback
replayed slot 2; only after that did tid5 run again, produce 1024 fresh frames,
change slot 2 and clear starvation.

## Functional change

On a callback-triggered v104 audio wake, v127 keeps the exact CAkAudioThread
worker running across normal scheduler quanta until it reaches a real blocking
state (normally EventMgrThreadFunc sem_wait), rather than letting the generic
v87 one-quantum fairness rule stop it mid-Perform.

A watchdog allows at most four extra continuation quanta per wake. Mutex,
condition, semaphore and fatal/return states remain authoritative and are not
fabricated.

## Telemetry retained

v126 flight recording remains enabled in frames 800-2500 and 10000-12500,
including exact-repeat provenance, FRESH vs STARVATION_REPLAY, sink state,
four-slot hashes, worker production and Inspector buckets.

v127 adds a terminal AUDIO WORKER DRAIN SUMMARY with drain rounds,
continuations, true sem_wait completions, other blocking exits and watchdog
caps.

## iPad confirmation

Run the same animation and Day-4 final-wave/input stress. Note audible crackle
apexes, Hard Stop after the late window, and inspect whether starvation/exact
repeats collapse while v127 drains normally reach sem_wait without watchdog
caps.
