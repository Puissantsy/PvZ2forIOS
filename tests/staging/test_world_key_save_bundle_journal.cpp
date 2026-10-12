#include "world_key_save_bundle_journal.hpp"
#include <cassert>
#include <iostream>
#include <unistd.h>
using namespace pvz2_key_study;
static std::vector<std::uint8_t> B(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(),s.end());
}
static bool Eq(const fs::path& p,const std::vector<std::uint8_t>& expected) {
    std::vector<std::uint8_t> current;
    return SaveRead(p,current) && current==expected;
}
int main() {
    char templ[]="/tmp/pvz2-keybundle-XXXXXX";
    char* p=::mkdtemp(templ);assert(p);
    const fs::path root(p);
    const std::vector<std::string> paths={"pp.dat","snapshot2.dat","local_profiles"};
    const std::vector<std::string> old={"profile coins=7800 keys=1",
                                         "profile backup coins=7800 keys=1",
                                         "profiles configuration"};
    const std::vector<std::string> newer={"profile coins=8800 keys=0",
                                           "profile backup coins=8800 keys=0",
                                           "profiles configuration updated"};
    std::vector<SaveBundleChange> changes;
    for(unsigned i=0;i<3u;++i) {
        assert(SaveWriteExclusive(root/paths[i],B(old[i])));
        changes.push_back({paths[i],B(newer[i])});
    }
    auto check=[&](bool updated) {
        for(unsigned i=0;i<3u;++i)
            assert(Eq(root/paths[i],B(updated?newer[i]:old[i])));
    };
    auto reset=[&](){
        for(unsigned i=0;i<3u;++i) {
            assert(fs::remove(root/paths[i]));
            assert(SaveWriteExclusive(root/paths[i],B(old[i])));
        }
    };
    SaveBundleJournal journal(root);
    unsigned checks=0;
    assert(journal.Recover(7)==SaveOutcome::NoJournal);++checks;
    assert(!journal.Prepare({},7));++checks;
    assert(journal.Prepare(changes,7));++checks;
    assert(!journal.Prepare(changes,7));++checks;
    assert(!journal.Commit(8));++checks;
    check(false);++checks;
    assert(journal.Recover(8)==SaveOutcome::Conflict);++checks;
    assert(journal.Recover(7)==SaveOutcome::PreparedAborted);++checks;
    check(false);++checks;
    for(unsigned stop=1;stop<=3;++stop) {
        assert(journal.Prepare(changes,7));++checks;
        assert(!journal.Commit(7,stop));++checks;
        for(unsigned i=0;i<3;++i)
            assert(Eq(root/paths[i],B(i<stop?newer[i]:old[i])));
        ++checks;
        assert(journal.Recover(7)==SaveOutcome::PreparedAborted);++checks;
        check(false);++checks;
        assert(journal.Recover(7)==SaveOutcome::NoJournal);++checks;
    }
    assert(journal.Prepare(changes,7));++checks;
    assert(journal.Commit(7));++checks;
    check(true);++checks;
    assert(journal.Recover(7)==SaveOutcome::NoJournal);++checks;
    reset();
    assert(journal.Prepare(changes,7));++checks;
    // Corruption of one staged next image invalidates the entire transaction.
    assert(fs::remove(journal.journal/"new1"));
    assert(SaveWriteExclusive(journal.journal/"new1",B("tampered image")));
    assert(!journal.Commit(7));++checks;
    assert(journal.Recover(7)==SaveOutcome::Conflict);++checks;
    check(false);++checks;
    fs::remove_all(journal.journal);
    assert(journal.Prepare(changes,7));++checks;
    // Guest or external writer changes pp.dat after prepare: refuse entirely.
    assert(fs::remove(root/paths[0]));
    assert(SaveWriteExclusive(root/paths[0],B("unexpected legitimate save")));
    assert(!journal.Commit(7));++checks;
    assert(journal.Recover(7)==SaveOutcome::Conflict);++checks;
    assert(Eq(root/paths[0],B("unexpected legitimate save")));++checks;
    fs::remove_all(journal.journal);
    reset();
    std::vector<SaveBundleChange> duplicate={changes[0],changes[0]};
    assert(!journal.Prepare(duplicate,7));++checks;
    auto traversed=changes;
    traversed[0].basename="../pp.dat";
    assert(!journal.Prepare(traversed,7));++checks;
    fs::create_directory(journal.journal);
    assert(journal.Recover(7)==SaveOutcome::Conflict);++checks;
    fs::remove_all(journal.journal);
    fs::remove_all(root);
    std::cout<<"PASS: "<<checks
             <<" multi-file journal crash/rollback/conflict controls\n";
}
