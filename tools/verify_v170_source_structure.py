#!/usr/bin/env python3
"""Conservative source-integrity gate for v170 staging; NOT an iOS compile."""
from pathlib import Path
p = Path("platform/ios/src/pvz2_apk_probe_parts")
part01=(p/"part_01.inc").read_text()
part05=(p/"part_05.inc").read_text()
part09=(p/"part_09.inc").read_text()
aggregate=Path("platform/ios/src/pvz2_apk_probe.cpp").read_text()
actual=Path("platform/ios/src/offline_global_transaction.hpp").read_text()
assert '#include "offline_global_transaction.hpp"' in aggregate
assert 'bool V170ReadOriginalGlobalVectors(' in part01
assert 'V170PersistNewGlobalJournal(' in part01
assert 'V170CheckpointGlobalJournal(' in part01
assert 'V170CompactOriginalGlobalVector(' in part01
assert 'V170RollbackGlobalVector(' in part01
assert 'V170GlobalSaveFilesStamp(' in part01
assert 'V170ClearFinishedGlobalJournal(' in part01
assert 'V170CheckpointGlobalJournal(\n                                        token, true, false)' in part05
assert 'callbacks.V170CheckpointGlobalJournal(\n                                    token, false, true)' in part09
start=part09.index('auto request = callbacks.pending_offline_purchase;')
paid=part09[start:]
assert paid.index('V170PersistNewGlobalJournal(') < paid.index('"OfflineStore_SetCoins"')
assert paid.index('V170PersistNewGlobalJournal(') < paid.index('"OfflineStore_FirePaymentComplete"')
assert 'V170UnresolvedGlobalJournal()' in paid
assert 'PlanExactGlobalTransaction(' in part09
assert 'V170CheckpointGlobalJournal(\n                                                        v170.token' in part09
assert part09.index('V170CheckpointGlobalJournal(\n                                                        v170.token') < part09.index('"V170_SaveOriginalGlobal"')
assert 'kGuestBase +\n                                                                0x0043ee24u' in part09
assert 'v128_userfs_disk_failures' in part09
assert 'V170ClearFinishedGlobalJournal(' in part09
assert 'V170RollbackGlobalVector(' in part09
assert 'if (!same_live_transaction)' in actual
assert 'RecoveryMustPreserve' in actual

header=Path("platform/ios/src/pvz2_apk_probe.hpp").read_text()
parts00=(p/"part_00.inc").read_text()
parts08=(p/"part_08.inc").read_text()
ui=Path("platform/ios/src/main.mm").read_text()
assert 'void PvZ2RequestV170QaCredit();' in header
assert 'gV170QaGrantRequested{false}' in parts00
assert 'void PvZ2RequestV170QaCredit()' in parts08
assert 'Crédit PvZCoins de test (profil actif)' in ui
assert 'Je confirme : profil jetable' in ui
qa_start=part09.index('gV170QaGrantRequested.exchange(')
qa_end=part09.index('// QA-only bootstrap for the first offline store test',qa_start)
qa=part09[qa_start:qa_end]
assert 'V170UnresolvedGlobalJournal()' in qa
assert qa.index('V128FlushConfig()') < qa.index('"V170_QA_Credit_SetCoins"')
assert 'offline_store_v170_qa_credit_60000_profile_' in qa


# v2 serial must be durable before token can re-enter PurchaseBroker.
assert '#include <charconv>' in aggregate
assert 'bool OfflineStoreAllocateDurableSerial(' in part01
serial_start=part01.index('bool OfflineStoreAllocateDurableSerial(')
serial_end=part01.index('static int OfflineStorePlantBitForId(',serial_start)
serial=part01[serial_start:serial_end]
assert serial.index('V128FlushConfig()') < serial.index('offline_purchase_serial = next')
assert 'std::numeric_limits<std::uint64_t>::max()' in serial
assert 'OfflineStoreAllocateDurableSerial(' in part05
assert part05.index('OfflineStoreAllocateDurableSerial(') < part05.index('OFFLINE STORE RequestPayment queued')

print("PASS v170 native/global + QA + durable receipt source gates; no iOS build")
