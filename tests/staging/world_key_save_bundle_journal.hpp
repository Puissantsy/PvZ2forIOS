#pragma once
// KEYCONV research ONLY: crash-recoverable replacement of a bounded group
// of existing, regular save files in ONE directory. NOT connected to runtime.
// This cannot protect the game until its complete write set is confirmed and
// all competing guest/V128 writes are suspended for the whole transaction.
#include "world_key_save_journal.hpp"
#include <algorithm>
#include <cctype>
#include <set>
#include <utility>
namespace pvz2_key_study {
struct SaveBundleChange {
    std::string basename;
    std::vector<std::uint8_t> next;
};
struct SaveBundleRecord {
    std::string basename;
    std::size_t old_size, next_size;
    std::uint64_t old_hash, next_hash;
};
struct SaveBundleMetadata {
    std::uint32_t profile;
    std::vector<SaveBundleRecord> files;
};
inline bool ValidSaveBasename(const std::string& s) {
    if(s.empty()||s.size()>96u||s=="."||s=="..") return false;
    for(unsigned char c:s)
        if(!std::isalnum(c)&&c!='_'&&c!='-'&&c!='.') return false;
    return true;
}
struct SaveBundleJournal {
    fs::path directory;
    fs::path journal;
    explicit SaveBundleJournal(fs::path dir)
        :directory(std::move(dir)),
         journal(directory/".pvz2-keyconv-bundle") {}

    bool Prepare(const std::vector<SaveBundleChange>& changes,
                 std::uint32_t profile_id) const {
        std::error_code ec;
        if(changes.empty()||changes.size()>8u||
           fs::exists(journal,ec)||ec) return false;
        std::set<std::string> names;
        std::vector<std::vector<std::uint8_t>> originals;
        for(const auto& change:changes) {
            if(!ValidSaveBasename(change.basename) ||
               !names.insert(change.basename).second ||
               change.next.empty() || change.next.size()>64u*1024u*1024u)
                return false;
            std::vector<std::uint8_t> before;
            if(!SaveRead(directory/change.basename,before)) return false;
            originals.push_back(std::move(before));
        }
        if(!fs::create_directory(journal,ec)||ec) return false;
        std::ostringstream manifest;
        manifest<<"PVZ2BUNDLE1 "<<profile_id<<" "<<changes.size()<<"\n";
        for(std::size_t i=0;i<changes.size();++i) {
            const auto& change=changes[i];
            const auto& original=originals[i];
            if(!SaveWriteExclusive(journal/("old"+std::to_string(i)),original) ||
               !SaveWriteExclusive(journal/("new"+std::to_string(i)),change.next))
                return false;
            manifest<<change.basename<<" "<<original.size()<<" "
                    <<SaveFingerprint(original)<<" "<<change.next.size()
                    <<" "<<SaveFingerprint(change.next)<<"\n";
        }
        if(!SaveSyncDirectory(journal)||
           !SaveWriteExclusiveText(journal/"manifest",manifest.str())||
           !SaveSyncDirectory(journal)||
           !SaveSyncDirectory(directory)) return false;
        return true;
    }
private:
    std::optional<SaveBundleMetadata> VerifiedRecord() const {
        std::error_code ec;
        if(fs::is_symlink(journal,ec)||ec||
           !fs::is_directory(journal,ec)||ec) return std::nullopt;
        const auto record=journal/"manifest";
        if(fs::is_symlink(record,ec)||ec) return std::nullopt;
        std::ifstream in(record);
        std::string magic, trailing;
        std::size_t n=0u;
        SaveBundleMetadata m{};
        if(!(in>>magic>>m.profile>>n) ||
           magic!="PVZ2BUNDLE1" || n==0u || n>8u)
            return std::nullopt;
        std::set<std::string> names;
        for(std::size_t i=0;i<n;++i) {
            SaveBundleRecord e{};
            if(!(in>>e.basename>>e.old_size>>e.old_hash>>
                    e.next_size>>e.next_hash) ||
               !ValidSaveBasename(e.basename) ||
               !names.insert(e.basename).second ||
               e.old_size>64u*1024u*1024u ||
               e.next_size>64u*1024u*1024u) return std::nullopt;
            std::vector<std::uint8_t> old,next;
            if(!SaveRead(journal/("old"+std::to_string(i)),old)||
               !SaveRead(journal/("new"+std::to_string(i)),next)||
               old.size()!=e.old_size||next.size()!=e.next_size||
               SaveFingerprint(old)!=e.old_hash||
               SaveFingerprint(next)!=e.next_hash)
                return std::nullopt;
            m.files.push_back(std::move(e));
        }
        if(in>>trailing) return std::nullopt;
        return m;
    }
    bool Cleanup() const {
        std::error_code ec;
        fs::remove_all(journal,ec);
        return !ec && SaveSyncDirectory(directory);
    }
    bool ReplaceFromJournal(const std::string& source,
                            const std::string& staging,
                            const std::string& target) const {
        std::vector<std::uint8_t> data;
        if(!SaveRead(journal/source,data)) return false;
        std::error_code ec;
        // A previous interrupted restore may have left an incomplete temp;
        // it is never trusted, because source is always revalidated.
        const fs::path temp=journal/staging;
        if(fs::exists(temp,ec)) {
            if(ec || fs::is_symlink(temp,ec)||ec ||
               !fs::is_regular_file(temp,ec)||ec ||
               !fs::remove(temp,ec)||ec) return false;
        }
        if(!SaveWriteExclusive(temp,data) ||
           !SaveSyncDirectory(journal)) return false;
        fs::rename(temp,directory/target,ec);
        return !ec && SaveSyncDirectory(directory);
    }
public:
    bool Commit(std::uint32_t profile_id,
                std::size_t stop_after_installed=0u) const {
        const auto meta=VerifiedRecord();
        if(!meta||meta->profile!=profile_id||
           fs::exists(journal/"committed")) return false;
        // Every pre-image must still match before replacing the FIRST file.
        for(const auto& e:meta->files) {
            std::vector<std::uint8_t> current;
            if(!SaveRead(directory/e.basename,current) ||
               current.size()!=e.old_size ||
               SaveFingerprint(current)!=e.old_hash) return false;
        }
        for(std::size_t i=0;i<meta->files.size();++i) {
            if(!ReplaceFromJournal(
                "new"+std::to_string(i),"install"+std::to_string(i),
                meta->files[i].basename)) return false;
            if(stop_after_installed==i+1u) return false; // crash fixture
        }
        // Commit marker must itself be atomically published. A torn marker
        // would leave an otherwise complete transaction requiring manual
        // recovery after a sudden power loss.
        if(!SaveWriteExclusiveText(journal/"committed.tmp","COMMITTED\n")||
           !SaveSyncDirectory(journal)) return false;
        std::error_code ec;
        fs::rename(journal/"committed.tmp",journal/"committed",ec);
        if(ec || !SaveSyncDirectory(journal) ||
           !SaveSyncDirectory(directory)) return false;
        return Cleanup();
    }
    SaveOutcome Recover(std::uint32_t profile_id) const {
        std::error_code ec;
        if(!fs::exists(journal,ec)&&!ec) return SaveOutcome::NoJournal;
        const auto meta=VerifiedRecord();
        if(!meta||meta->profile!=profile_id) return SaveOutcome::Conflict;
        const auto marker=journal/"committed";
        if(fs::exists(marker,ec)) {
            std::vector<std::uint8_t> contents;
            if(!SaveRead(marker,contents) ||
               contents!=std::vector<std::uint8_t>{
                    'C','O','M','M','I','T','T','E','D','\n'})
                return SaveOutcome::Conflict;
        } else if(ec) return SaveOutcome::IOFailure;
        const bool committed=fs::exists(marker);
        // Refuse to overwrite concurrent or unrelated game/profile changes.
        for(const auto& e:meta->files) {
            std::vector<std::uint8_t> current;
            if(!SaveRead(directory/e.basename,current)) return SaveOutcome::Conflict;
            const bool old=current.size()==e.old_size &&
                           SaveFingerprint(current)==e.old_hash;
            const bool now=current.size()==e.next_size &&
                           SaveFingerprint(current)==e.next_hash;
            if((!old&&!now)||(committed&&!now)) return SaveOutcome::Conflict;
        }
        if(committed)
            return Cleanup()?SaveOutcome::CommittedRecovered:
                             SaveOutcome::IOFailure;
        // No commit marker: rollback ALL new/partial file replacements.
        // This is replayable after another crash, before guest profile load.
        for(std::size_t i=0;i<meta->files.size();++i) {
            const auto& e=meta->files[i];
            std::vector<std::uint8_t> current;
            if(!SaveRead(directory/e.basename,current)) return SaveOutcome::IOFailure;
            if(current.size()!=e.old_size ||
               SaveFingerprint(current)!=e.old_hash) {
                if(!ReplaceFromJournal(
                    "old"+std::to_string(i),"restore"+std::to_string(i),
                    e.basename)) return SaveOutcome::IOFailure;
            }
        }
        return Cleanup()?SaveOutcome::PreparedAborted:SaveOutcome::IOFailure;
    }
};
} // namespace pvz2_key_study
