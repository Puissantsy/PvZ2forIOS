#include "world_key_save_journal.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
using namespace pvz2_key_study;
namespace fs=std::filesystem;
static std::vector<std::uint8_t> Bytes(const char* s) {
    std::vector<std::uint8_t> r;
    while(*s) r.push_back(static_cast<std::uint8_t>(*s++));
    return r;
}
int main() {
    char pattern[]="/tmp/pvz2-keyjournal-XXXXXX";
    char* name=::mkdtemp(pattern);
    assert(name);
    const fs::path dir(name);
    const auto pp=dir/"pp.dat";
    const auto separate=dir/"untouched.dat";
    const auto initial=Bytes("original pp.dat world key 6 coins 7800");
    const auto target=Bytes("next pp.dat world key 0 coins 8800");
    assert(SaveWriteExclusive(separate,Bytes("other game save untouched")));
    assert(SaveWriteExclusive(pp,initial));
    unsigned checks=0;
    {
        SaveJournal tx(pp);
        assert(tx.Recover(4)==SaveOutcome::NoJournal);++checks;
        assert(!tx.Prepare({},4));++checks;
        assert(!tx.Prepare(initial,4));++checks;
        assert(tx.Prepare(target,4));++checks;
        assert(!tx.Prepare(target,4));++checks;
        assert(!tx.Commit(5));++checks;
        assert(tx.Recover(5)==SaveOutcome::Conflict);++checks;
        std::vector<std::uint8_t> current;
        assert(SaveRead(pp,current) && current==initial);++checks;
        assert(tx.Recover(4)==SaveOutcome::PreparedAborted);++checks;
        assert(tx.Recover(4)==SaveOutcome::NoJournal);++checks;
    }
    {
        SaveJournal tx(pp);
        assert(tx.Prepare(target,4));++checks;
        assert(tx.Commit(4));++checks;
        std::vector<std::uint8_t> current;
        assert(SaveRead(pp,current) && current==target);++checks;
        assert(tx.Recover(4)==SaveOutcome::NoJournal);++checks;
        assert(SaveRead(separate,current) && current==
               Bytes("other game save untouched"));++checks;
    }
    {
        assert(fs::remove(pp));
        assert(SaveWriteExclusive(pp,initial));
        SaveJournal tx(pp);
        assert(tx.Prepare(target,4));++checks;
        assert(!tx.Commit(4,CommitFault::AfterRenameBeforeDirectorySync));
        ++checks;
        std::vector<std::uint8_t> current;
        assert(SaveRead(pp,current) && current==target);++checks;
        assert(tx.Recover(4)==SaveOutcome::CommittedRecovered);++checks;
        assert(tx.Recover(4)==SaveOutcome::NoJournal);++checks;
    }
    {
        assert(fs::remove(pp));
        assert(SaveWriteExclusive(pp,initial));
        SaveJournal tx(pp);
        assert(tx.Prepare(target,4));++checks;
        assert(fs::remove(pp));
        assert(SaveWriteExclusive(pp,Bytes("diverged contents")));
        assert(!tx.Commit(4));++checks;
        assert(tx.Recover(4)==SaveOutcome::Conflict);++checks;
        std::vector<std::uint8_t> current;
        assert(SaveRead(pp,current) && current==Bytes("diverged contents"));
        ++checks;
        fs::remove_all(tx.journal);
    }
    {
        assert(fs::remove(pp));
        assert(SaveWriteExclusive(pp,initial));
        SaveJournal tx(pp);
        assert(tx.Prepare(target,4));++checks;
        assert(fs::remove(tx.journal/"next"));
        assert(SaveWriteExclusive(tx.journal/"next",Bytes("tampered")));
        assert(!tx.Commit(4));++checks;
        assert(tx.Recover(4)==SaveOutcome::Conflict);++checks;
        std::vector<std::uint8_t> current;
        assert(SaveRead(pp,current) && current==initial);++checks;
        fs::remove_all(tx.journal);
    }
    {
        SaveJournal tx(pp);
        assert(fs::create_directory(tx.journal));
        assert(tx.Recover(4)==SaveOutcome::Conflict);++checks;
        assert(!tx.Prepare(target,4));++checks;
        fs::remove_all(tx.journal);
    }
    {
        assert(fs::remove(pp));
        fs::create_symlink(separate,pp);
        SaveJournal tx(pp);
        assert(!tx.Prepare(target,4));++checks;
        fs::remove(pp);
    }
    fs::remove_all(dir);
    std::cout<<"PASS: "<<checks
             <<" one-file atomic save journal and interrupted restart checks\n";
}
