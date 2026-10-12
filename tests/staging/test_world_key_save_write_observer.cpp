#include "world_key_save_write_observer.hpp"
#include <cassert>
#include <iostream>
using pvz2_key_study::IsObservedNativeProfileSave;
int main() {
    unsigned checked=0;
    for(auto p:{
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/pp.dat",
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/snapshot2.dat",
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/local_profiles",
        "/No_Backup/pp.dat",
        "/No_Backup/snapshot2.dat",
        "/No_Backup/local_profiles"}) {
        assert(IsObservedNativeProfileSave(p));++checked;
    }
    for(auto p:{
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/",
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/pp.dat.tmp",
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/snapshot2.dat.bak",
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/loots",
        "/data/data/com.ea.game.pvz2_row/files/No_Backup/pp.dat/child",
        "/data/data/com.ea.game.pvz2_row/files/No_Backupx/pp.dat",
        "/No_Backup/../pp.dat",
        "/no_backup/pp.dat",
        "/data/pp.dat",
        "pp.dat",
        ""}) {
        assert(!IsObservedNativeProfileSave(p));++checked;
    }
    std::cout<<"PASS: "<<checked<<" exact V128 KEYCONV profile path whitelist cases\n";
}
