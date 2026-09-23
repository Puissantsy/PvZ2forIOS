# PvZ2 v93 — Return Provenance

Date: 2026-09-23

## Evidence from v92

The real iPad v92 run reached frame 1305 and reproduced the historical crash:

- UndefinedInstruction at PC 0x1086fcea;
- LR 0x10868b54;
- CPSR.T set (Thumb state);
- r12 = 0x10d01c20, the free GOT slot;
- last resource log: UI_Dialog_1536 texture generation.

Unlike the earlier corruption hypothesis, v92 proved that GNU_RELRO remained
intact at the crash: the free GOT slot still contained the expected
0x40000238 trampoline, with zero RELRO write attempts and zero repairs.

Static disassembly shows that 0x1086fcea is two bytes into the ARM BL at
0x1086fce8, so it is not a valid ARM instruction boundary. The delete/free
caller at 0x108689c8 returns through:

    0x10868b2c  ADD sp,sp,#16
    0x10868b30  POP {r4,r5,r6,r7,r8,pc}

The nested delete/free call leaves LR=0x10868b54. If the saved PC popped from
the stack is odd, Dynarmic will enter Thumb state while LR still has exactly the
value seen in the crash.

## v93 probe

V93 preserves the complete v92 long-run runtime and does not patch the guest
return instruction.

Inside the existing host implementation of the imported free function, only
when LR == 0x10868b54, v93 records:

- frame;
- pointer passed to free;
- SP / LR / CPSR;
- the future saved PC at SP+36 before FreeHeap;
- the same word again after FreeHeap;
- whether bit 0 is set;
- whether the canonical target is inside libPVZ2.so;
- a 16-word stack window surrounding the saved return slot.

The SP+36 derivation follows the exact verified prologue/epilogue:
six pushed registers = 24 bytes, 16 bytes of locals, then ADD sp,#16 followed
by POP of five registers plus PC. At the free callback the saved PC therefore
remains 36 bytes above current SP.

## Diagnostic outcomes

One v93 crash should distinguish the remaining classes:

1. savedBefore is already odd/bad:
   the guest return address was corrupted before entering free.
2. savedBefore is good but savedAfter changes:
   the host FreeHeap path is corrupting guest stack state.
3. savedBefore == savedAfter and both are good, but execution still reaches
   0x1086fcea in Thumb state:
   the remaining fault is in return/interworking execution (POP/Dynarmic),
   not allocator data or the free GOT.

V93 intentionally performs no speculative return-address repair.
