#!/usr/bin/env python3
"""Static invariants for the active AddWorldKeys -> SetCoins replacement.

No game binary or save is required. Exact original ARM words remain covered by
verify_world_key_arm.py when the user's ELF is supplied separately.
"""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
svc=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_04.inc").read_text()
state=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_01.inc").read_text()
modes=(ROOT/"platform/ios/src/pvz2_apk_probe_parts/part_02.inc").read_text()
policy=(ROOT/"tests/staging/world_key_conversion_policy.hpp").read_text()

def need(ok,msg):
    if not ok: raise AssertionError(msg)

need("bool WorldKeyConversionEnabled() const" in modes,
     "missing explicit active-mode gate")
need("ResearchWorldKeyConvert" in modes and "WorldKeyResearchEnabled()" in modes,
     "active mode must inherit research/v151 runtime")
need("WorldKeyReadOnlyDecision(" in state and
     "pvz2_key_study::Evaluate(" in state,
     "runtime must use bounded tested gate policy")
need("future_enabled" not in state or "false" in state,
     "Future must remain fail-closed in historical metadata")
need("PlanCoinCredit" in policy and "kMaxSignedCoins = 0x7fffffffu" in policy,
     "wallet overflow plan missing")

# Exact AddWorldKeys prologue at hook time:
# push {r4-r11,lr}=36 bytes, sub sp,#20 => current frame 56 bytes.
for literal in (
    "kAddWorldKeysFrameBytes=56u",
    "kSavedRegsOffset=20u",
    "kSavedLrOffset=52u",
    "kGuestBase+0x0042e5acu",
):
    need(literal in svc, "tail-call ABI invariant missing: "+literal)

need("saved_lr==caller_lr" in svc and "(saved_lr&1u)==0u" in svc,
     "must verify untouched ARM return before tail-call")
need("for (std::uint32_t i=0u;i<8u;++i)" in svc and
     "regs[4u+i]=mem.Read32Guest(" in svc,
     "callee-saved r4-r11 restoration missing")
need("regs[13]=sp+kAddWorldKeysFrameBytes;" in svc,
     "AddWorldKeys stack frame not unwound")
need("regs[0]=profile;" in svc and "regs[1]=credit.after;" in svc and
     "regs[14]=saved_lr;" in svc and "regs[15]=kSetCoins;" in svc,
     "SetCoins tail-call register contract incomplete")
need("decision.convert()" in svc,
     "mutation must require complete gate policy")
need("KEYCONV FAIL_OPEN preserve original key" in svc and
     "regs[10]=regs[0];" in svc,
     "unsafe cases must preserve original AddWorldKeys path")
need("original_amount" in svc and "decision.coins" in svc,
     "per-key quantity/credit data missing")
need("regs[2]=0" not in svc,
     "do not silently mutate AddWorldKeys quantity; active replacement must tail-call or fail open")
print("PASS: eligible-only immediate SetCoins tail-call, ARM frame restore, overflow/profile/stack fail-open")
