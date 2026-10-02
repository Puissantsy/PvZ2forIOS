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
end=part09.index('callbacks.pending_offline_purchase =\n                            PvZ2JniCallbacks::OfflinePurchaseRequest{};\n                        return true;',start)
paid=part09[start:]
assert paid.index('V170PersistNewGlobalJournal(') < paid.index('"OfflineStore_SetCoins"')
assert paid.index('V170PersistNewGlobalJournal(') < paid.index('"OfflineStore_FirePaymentComplete"')
assert 'V170UnresolvedGlobalJournal()' in paid
assert 'PlanExactGlobalTransaction(' in paid
assert 'V170CheckpointGlobalJournal(\n                                                        v170.token' in paid
assert paid.index('V170CheckpointGlobalJournal(\n                                                        v170.token') < paid.index('"V170_SaveOriginalGlobal"')
assert 'kGuestBase +\n                                                                0x0043ee24u' in paid
assert 'v128_userfs_disk_failures' in paid
assert 'V170ClearFinishedGlobalJournal(' in paid
assert 'V170RollbackGlobalVector(' in paid
assert 'if (!same_live_transaction)' in actual
assert 'RecoveryMustPreserve' in actual
print("PASS v170 integration structural safety gate; source-only, NOT an iOS compile")
