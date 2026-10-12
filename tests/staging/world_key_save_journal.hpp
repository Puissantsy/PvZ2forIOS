#pragma once
// KEYCONV research ONLY: crash-aware atomic replacement of ONE already fully
// serialized native save file. Deliberately NOT installed in the live runtime.
// The actual game may write multiple files; do not use until its complete
// write set and an atomic guest mutation/serialization boundary are verified.
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace pvz2_key_study {
namespace fs = std::filesystem;

enum class SaveOutcome {
    NoJournal, PreparedAborted, CommittedRecovered, Conflict, IOFailure
};
enum class CommitFault { None, AfterRenameBeforeDirectorySync };

inline std::uint64_t SaveFingerprint(const std::vector<std::uint8_t>& b) {
    // FNV-1a is an accidental-corruption check, not a security checksum.
    std::uint64_t h=14695981039346656037ull;
    for(const auto v:b) {h^=v;h*=1099511628211ull;}
    return h;
}
inline bool SaveRead(const fs::path& p,std::vector<std::uint8_t>& out) {
    constexpr std::uintmax_t Max=64u*1024u*1024u;
    std::error_code ec;
    if (!fs::is_regular_file(p,ec) || fs::is_symlink(p,ec) ||
        ec || fs::file_size(p,ec)>Max || ec) return false;
    std::ifstream in(p,std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in),
               std::istreambuf_iterator<char>());
    return !in.bad() && out.size()<=Max;
}
inline bool SaveSyncDirectory(const fs::path& p) {
    const int fd=::open(p.c_str(),O_RDONLY);
    if (fd<0) return false;
    const bool ok=::fsync(fd)==0;
    ::close(fd);
    return ok;
}
inline bool SaveWriteExclusive(const fs::path& p,
                               const std::vector<std::uint8_t>& data) {
    const int fd=::open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd<0) return false;
    bool ok=true;
    std::size_t offset=0;
    while(offset<data.size()) {
        const ssize_t n=::write(fd,data.data()+offset,data.size()-offset);
        if(n<=0) {ok=false;break;}
        offset+=static_cast<std::size_t>(n);
    }
    if(ok && ::fsync(fd)!=0) ok=false;
    if(::close(fd)!=0) ok=false;
    return ok;
}
inline bool SaveWriteExclusiveText(const fs::path& p,const std::string& text) {
    return SaveWriteExclusive(p,
        std::vector<std::uint8_t>(text.begin(),text.end()));
}

struct SaveJournal {
    fs::path save;
    fs::path journal;
    explicit SaveJournal(fs::path path)
        :save(std::move(path)),
         journal(save.parent_path()/(save.filename().string()+".keyconv-journal")) {}

    // Safety invariants:
    // - caller guarantees guest execution and V128 UserFS writes are suspended;
    // - only this saved file is affected; no other profile root is mutated;
    // - profile identity is checked externally before invoking native calls.
    // These conditions have NOT yet been proven on iPad.
    bool Prepare(const std::vector<std::uint8_t>& expected_next,
                 std::uint32_t profile_id) const {
        if(expected_next.empty() || expected_next.size()>64u*1024u*1024u)
            return false;
        std::error_code ec;
        if(fs::exists(journal,ec) || ec) return false;
        std::vector<std::uint8_t> original;
        if(!SaveRead(save,original) || original==expected_next) return false;
        if(!fs::create_directory(journal,ec) || ec) return false;
        const auto backup=journal/"original";
        const auto next=journal/"next";
        const auto record=journal/"record";
        if(!SaveWriteExclusive(backup,original) ||
           !SaveWriteExclusive(next,expected_next) ||
           !SaveSyncDirectory(journal)) return false;
        std::ostringstream o;
        o<<"PVZ2KEYCONV1 "<<profile_id<<" "
         <<original.size()<<" "<<SaveFingerprint(original)<<" "
         <<expected_next.size()<<" "<<SaveFingerprint(expected_next)<<"\n";
        if(!SaveWriteExclusiveText(record,o.str()) ||
           !SaveSyncDirectory(journal) ||
           !SaveSyncDirectory(save.parent_path())) return false;
        return true;
    }
private:
    struct Record {
        std::uint32_t profile;
        std::size_t previous_size, next_size;
        std::uint64_t previous_hash, next_hash;
    };
    std::optional<Record> ReadVerifiedRecord() const {
        std::error_code ec;
        if(fs::is_symlink(journal,ec)||ec||
           !fs::is_directory(journal,ec)||ec) return std::nullopt;
        const auto record=journal/"record";
        if(fs::is_symlink(record,ec)||ec) return std::nullopt;
        std::ifstream in(record);
        std::string magic, extra;
        Record m{};
        if(!(in>>magic>>m.profile>>m.previous_size>>m.previous_hash
                  >>m.next_size>>m.next_hash) ||
           magic!="PVZ2KEYCONV1" || (in>>extra) ||
           m.previous_size>64u*1024u*1024u ||
           m.next_size>64u*1024u*1024u) return std::nullopt;
        std::vector<std::uint8_t> before,after;
        if(!SaveRead(journal/"original",before) ||
           !SaveRead(journal/"next",after) ||
           before.size()!=m.previous_size ||
           after.size()!=m.next_size ||
           SaveFingerprint(before)!=m.previous_hash ||
           SaveFingerprint(after)!=m.next_hash) return std::nullopt;
        return m;
    }
    bool Cleanup() const {
        std::error_code ec;
        fs::remove_all(journal,ec);
        return !ec && SaveSyncDirectory(save.parent_path());
    }
public:
    bool Commit(std::uint32_t profile_id,
                CommitFault fault=CommitFault::None) const {
        const auto rec=ReadVerifiedRecord();
        if(!rec || rec->profile!=profile_id) return false;
        std::vector<std::uint8_t> current;
        if(!SaveRead(save,current) ||
           current.size()!=rec->previous_size ||
           SaveFingerprint(current)!=rec->previous_hash) return false;
        // Atomic replacement of this ONE file. The journal remains durably
        // present until recovery confirms either old or new contents.
        std::error_code ec;
        std::vector<std::uint8_t> target;
        if(!SaveRead(journal/"next",target) ||
           !SaveWriteExclusive(journal/"install",target) ||
           !SaveSyncDirectory(journal)) return false;
        fs::rename(journal/"install",save,ec);
        if(ec) return false;
        if(fault==CommitFault::AfterRenameBeforeDirectorySync)
            return false; // simulate unexpected stop; leave journal intact
        if(!SaveSyncDirectory(save.parent_path())) return false;
        return Cleanup();
    }
    SaveOutcome Recover(std::uint32_t profile_id) const {
        std::error_code ec;
        if(!fs::exists(journal,ec) && !ec) return SaveOutcome::NoJournal;
        const auto rec=ReadVerifiedRecord();
        if(!rec || rec->profile!=profile_id)
            return SaveOutcome::Conflict;
        std::vector<std::uint8_t> current;
        if(!SaveRead(save,current)) return SaveOutcome::IOFailure;
        if(current.size()==rec->previous_size &&
           SaveFingerprint(current)==rec->previous_hash)
            return Cleanup()?SaveOutcome::PreparedAborted:SaveOutcome::IOFailure;
        if(current.size()==rec->next_size &&
           SaveFingerprint(current)==rec->next_hash)
            return Cleanup()?SaveOutcome::CommittedRecovered:SaveOutcome::IOFailure;
        // A concurrent save or corrupt state must NOT be overwritten.
        return SaveOutcome::Conflict;
    }
};
} // namespace pvz2_key_study
