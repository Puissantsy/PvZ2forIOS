#pragma once
// KEYCONV: standalone, fail-closed C++20 RTON token codec.
// RESEARCH-ONLY: not linked into iOS. Exact native {wn,kc}, c, wm/i schema.
// All unrelated RTON token bytes are preserved. No filesystem writes here.
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace pvz2_key_study::rton_native {
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };

struct Value {
    enum class Kind { Raw, String, Int, Object, Array };
    Kind kind=Kind::Raw;
    std::int64_t integer=0;
    std::string bytes;
    std::map<std::string, Value> fields;
    std::vector<Value> items;
    bool operator==(const Value&) const = default;
    static Value Int(std::int64_t n) { Value v; v.kind=Kind::Int; v.integer=n; return v; }
    static Value Str(std::string s) { Value v; v.kind=Kind::String; v.bytes=std::move(s); return v; }
    static Value Raw(std::string s) { Value v; v.bytes=std::move(s); return v; }
    const Value& Field(const char* name) const {
        if(kind!=Kind::Object) throw Error("Expected RTON object");
        const auto i=fields.find(name);
        if(i==fields.end()) throw Error("Missing RTON field");
        return i->second;
    }
    Value& Field(const char* name) {
        if(kind!=Kind::Object) throw Error("Expected RTON object");
        const auto i=fields.find(name);
        if(i==fields.end()) throw Error("Missing RTON field");
        return i->second;
    }
    const Value& At(std::size_t i) const {
        if(kind!=Kind::Array || i>=items.size()) throw Error("Invalid RTON array index");
        return items[i];
    }
    Value& At(std::size_t i) {
        if(kind!=Kind::Array || i>=items.size()) throw Error("Invalid RTON array index");
        return items[i];
    }
    std::int64_t IntValue() const {
        if(kind!=Kind::Int) throw Error("Expected RTON integer");
        return integer;
    }
    const std::string& StrValue() const {
        if(kind!=Kind::String) throw Error("Expected RTON string");
        return bytes;
    }
};

struct Span {
    std::size_t begin=0, end=0;
    std::uint8_t tag=0;
    std::int64_t value=0;
};

struct Reader {
    const std::string& bytes;
    std::size_t cursor=8, end=0, token_count=0, slot=0;
    std::vector<std::string> latin, utf8, path;
    std::optional<Span> coin;
    std::map<std::size_t,Span> key_counts;
    explicit Reader(const std::string& data,std::size_t profile_slot)
        : bytes(data),slot(profile_slot) {
        if(bytes.size()<13 || bytes.size()>64u*1024u*1024u ||
           bytes.compare(0,8,"RTON\x01\x00\x00\x00",8)!=0 ||
           bytes.compare(bytes.size()-4,4,"DONE")!=0)
            throw Error("Invalid RTON framing");
        end=bytes.size()-4;
    }
    std::uint8_t Byte() {
        if(cursor>=end) throw Error("Truncated RTON");
        return static_cast<std::uint8_t>(bytes[cursor++]);
    }
    std::string Take(std::size_t count) {
        if(count>end-cursor) throw Error("Truncated RTON payload");
        const auto start=cursor; cursor+=count;
        return bytes.substr(start,count);
    }
    std::uint64_t Varint() {
        std::uint64_t value=0;
        for(unsigned i=0;i<10;++i) {
            const auto b=Byte();
            if(i==9 && b>1) throw Error("RTON varint overflow");
            value|=(static_cast<std::uint64_t>(b&0x7fu)<<(7*i));
            if(!(b&0x80)) return value;
        }
        throw Error("RTON varint unterminated");
    }
    std::uint64_t Fixed(unsigned size) {
        if(size>8u) throw Error("Invalid integer width");
        std::uint64_t v=0;
        for(unsigned i=0;i<size;++i)
            v|=static_cast<std::uint64_t>(Byte())<<(8*i);
        return v;
    }
    std::int64_t Signed(std::uint64_t raw,unsigned width) {
        if(width==8) return std::bit_cast<std::int64_t>(raw);
        const auto bits=8*width;
        return (raw & (std::uint64_t{1}<<(bits-1)))
            ? static_cast<std::int64_t>(raw)-(std::int64_t{1}<<bits)
            : static_cast<std::int64_t>(raw);
    }
    std::int64_t Unsigned(std::uint64_t raw) {
        if(raw>static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            throw Error("RTON integer out of supported range");
        return static_cast<std::int64_t>(raw);
    }
    std::string Text(bool wide) {
        if(wide && Varint()>1024*1024) throw Error("Oversized UTF8 character count");
        const auto n=Varint();
        if(n>1024*1024) throw Error("Oversized RTON string");
        return Take(static_cast<std::size_t>(n));
    }
    void Record(std::size_t start,const Value& v) {
        if(v.kind!=Value::Kind::Int || start>=end) return;
        const auto tag=static_cast<std::uint8_t>(bytes[start]);
        const bool encodable=
            tag==8 || tag==10 || tag==16 || tag==18 || tag==32 ||
            tag==36 || tag==37 || tag==38 || tag==40 || tag==41 ||
            tag==44 || tag==45 || tag==48 || tag==49 ||
            tag==64 || tag==70;
        if(!encodable || path.size()<4 || path[0]!="objects" ||
           path[1]!=std::to_string(slot) || path[2]!="objdata") return;
        const Span span{start,cursor,tag,v.integer};
        if(path.size()==4 && path[3]=="c") {
            if(coin.has_value()) throw Error("Duplicate wallet path");
            coin=span;
        } else if(path.size()==6 && path[3]=="wsk" && path[5]=="kc") {
            const auto& index=path[4];
            if(index.empty() || index.find_first_not_of("0123456789")!=
               std::string::npos) throw Error("Invalid key index");
            const auto k=std::stoull(index);
            if(!key_counts.emplace(k,span).second) throw Error("Duplicate key span");
        }
    }
    Value Object(unsigned depth) {
        if(depth>96) throw Error("RTON depth limit");
        Value obj; obj.kind=Value::Kind::Object;
        while(true) {
            if(cursor>=end) throw Error("Missing RTON object terminator");
            if(static_cast<std::uint8_t>(bytes[cursor])==0xff) {
                ++cursor; return obj;
            }
            const auto key=Read(depth+1);
            if(key.kind!=Value::Kind::String) throw Error("Nonstring object key");
            const auto& k=key.bytes;
            if(obj.fields.find(k)!=obj.fields.end()) throw Error("Duplicate object key");
            path.push_back(k);
            const auto start=cursor;
            Value value=Read(depth+1);
            Record(start,value);
            path.pop_back();
            obj.fields.emplace(k,std::move(value));
        }
    }
    Value Read(unsigned depth) {
        if(depth>96 || ++token_count>1000000)
            throw Error("RTON depth/token limit");
        const auto start=cursor;
        const auto tag=Byte();
        if(tag==0x00 || tag==0x01 || tag==0x84) return Value::Raw(bytes.substr(start,1));
        if(tag==9 || tag==11 || tag==17 || tag==19 ||
           tag==33 || tag==35 || tag==39 || tag==65 || tag==67 || tag==71)
            return Value::Int(0);
        switch(tag) {
            case 8: return Value::Int(Signed(Fixed(1),1));
            case 10: return Value::Int(Unsigned(Fixed(1)));
            case 16: return Value::Int(Signed(Fixed(2),2));
            case 18: return Value::Int(Unsigned(Fixed(2)));
            case 32: return Value::Int(Signed(Fixed(4),4));
            case 38: return Value::Int(Unsigned(Fixed(4)));
            case 64: return Value::Int(Signed(Fixed(8),8));
            case 70: return Value::Int(Unsigned(Fixed(8)));
            case 34: { Take(4); return Value::Raw(bytes.substr(start,cursor-start)); }
            case 66: { Take(8); return Value::Raw(bytes.substr(start,cursor-start)); }
            case 36: case 40: case 44: case 48:
                return Value::Int(Unsigned(Varint()));
            case 37: case 41: case 45: case 49: {
                const auto zigzag=Varint();
                const auto decoded=(zigzag>>1) ^ (std::uint64_t{0}-(zigzag&1));
                return Value::Int(std::bit_cast<std::int64_t>(decoded));
            }
            case 0x81: case 0x82: case 0x90: case 0x92: {
                auto s=Text(tag==0x82 || tag==0x92);
                if(tag==0x90) latin.push_back(s);
                if(tag==0x92) utf8.push_back(s);
                return Value::Str(std::move(s));
            }
            case 0x91: case 0x93: {
                const auto& cache=tag==0x91?latin:utf8;
                const auto index=Varint();
                if(index>=cache.size()) throw Error("Invalid RTON string cache");
                return Value::Str(cache[static_cast<std::size_t>(index)]);
            }
            case 0x83: {
                auto subtype=Byte();
                if(subtype==2) {
                    Text(true); Varint(); Varint(); Fixed(4);
                } else if(subtype==3) {
                    Text(true); Text(true);
                } else if(subtype!=0) throw Error("Unsupported RTID");
                return Value::Raw(bytes.substr(start,cursor-start));
            }
            case 0x85: return Object(depth+1);
            case 0x86: {
                if(Byte()!=0xfd) throw Error("Bad array start");
                const auto n=Varint();
                if(n>100000) throw Error("Oversized array");
                Value a; a.kind=Value::Kind::Array;
                for(std::uint64_t i=0;i<n;++i) {
                    path.push_back(std::to_string(i));
                    a.items.push_back(Read(depth+1));
                    path.pop_back();
                }
                if(Byte()!=0xfe) throw Error("Bad array end");
                return a;
            }
            default: throw Error("Unsupported RTON token");
        }
    }
    Value Parse() {
        auto root=Object(0);
        if(cursor!=end) throw Error("Trailing RTON body");
        return root;
    }
};

inline std::string Encode(std::uint8_t tag,std::int64_t n) {
    std::string out(1,static_cast<char>(tag));
    auto fixed=[&](unsigned width,bool signed_value) {
        const auto bits=8*width;
        if(signed_value) {
            if(width!=8 && (n<-(std::int64_t{1}<<(bits-1)) ||
                            n>=(std::int64_t{1}<<(bits-1))))
                throw Error("RTON integer width overflow");
        } else if(n<0 || (width<8 && static_cast<std::uint64_t>(n)>=
                           (std::uint64_t{1}<<bits)))
            throw Error("RTON unsigned width overflow");
        const auto u=std::bit_cast<std::uint64_t>(n);
        for(unsigned i=0;i<width;++i)
            out.push_back(static_cast<char>((u>>(8*i))&0xff));
    };
    switch(tag) {
        case 8: fixed(1,true); return out;
        case 10: fixed(1,false); return out;
        case 16: fixed(2,true); return out;
        case 18: fixed(2,false); return out;
        case 32: fixed(4,true); return out;
        case 38: fixed(4,false); return out;
        case 64: fixed(8,true); return out;
        case 70: fixed(8,false); return out;
        default: break;
    }
    std::uint64_t u=0;
    if(tag==36 || tag==40 || tag==44 || tag==48) {
        if(n<0) throw Error("Negative unsigned RTON varint");
        u=static_cast<std::uint64_t>(n);
    } else if(tag==37 || tag==41 || tag==45 || tag==49) {
        const unsigned bits=(tag==45 || tag==49)?64:32;
        if(bits==32 &&
           (n<std::numeric_limits<std::int32_t>::min() ||
            n>std::numeric_limits<std::int32_t>::max()))
            throw Error("Signed RTON varint width overflow");
        u=(std::bit_cast<std::uint64_t>(n)<<1) ^
          (std::uint64_t{0}-static_cast<std::uint64_t>(n<0));
    } else throw Error("RTON target numeric token not writable");
    do {
        auto b=static_cast<std::uint8_t>(u&0x7fu);
        u>>=7;
        if(u) b|=0x80u;
        out.push_back(static_cast<char>(b));
    } while(u);
    return out;
}

struct Candidate {
    std::string data;
    bool changed=false;
    std::int64_t native_id=0, keys=0, before=0, after=0;
};
inline Candidate ConvertEgypt(const std::string& original,std::size_t slot) {
    Reader reader(original,slot);
    auto before=reader.Parse();
    const auto& player=before.Field("objects").At(slot);
    if(player.Field("objclass").StrValue()!="PlayerInfo")
        throw Error("Wrong PlayerInfo class");
    const auto& info=player.Field("objdata");
    const auto native_id=info.Field("i").IntValue();
    const auto coins=info.Field("c").IntValue();
    if(native_id<=0 || coins<0 || coins>std::numeric_limits<std::int32_t>::max())
        throw Error("Invalid native ID or wallet");
    const auto& keys=info.Field("wsk");
    const auto& events=info.Field("wm");
    if(keys.kind!=Value::Kind::Array || events.kind!=Value::Kind::Array)
        throw Error("Wrong keys/events array");
    std::map<std::string,std::int64_t> seen_worlds;
    std::optional<std::size_t> egypt_index;
    std::int64_t amount=0;
    for(std::size_t i=0;i<keys.items.size();++i) {
        const auto& k=keys.At(i);
        if(k.kind!=Value::Kind::Object || k.fields.size()!=2)
            throw Error("Unknown native world-key fields");
        const auto& world=k.Field("wn").StrValue();
        const auto count=k.Field("kc").IntValue();
        if(world!="egypt" && world!="pirate" && world!="cowboy" &&
           world!="future" && world!="dark")
            throw Error("Unknown world key");
        if(count<0 || count>99 || !seen_worlds.emplace(world,count).second)
            throw Error("Invalid or duplicate world key");
        if(world=="egypt") { amount=count; egypt_index=i; }
    }
    Candidate result{original,false,native_id,0,coins,coins};
    if(!egypt_index.has_value() || amount==0) return result;
    const std::array<std::int64_t,5> gates{13,23,33,39,41};
    for(const auto gate:gates) {
        unsigned matches=0;
        for(const auto& e:events.items) {
            if(e.Field("W").IntValue()!=2) continue;
            if(e.Field("E").IntValue()!=gate) continue;
            ++matches;
            if(e.Field("S").IntValue()<3)
                return result; // closed: leave ORIGINAL bytes untouched
        }
        if(matches!=1) return result;
    }
    const auto delta=amount*1000;
    if(coins>std::numeric_limits<std::int32_t>::max()-delta)
        throw Error("Wallet overflow");
    if(!reader.coin || !reader.key_counts.contains(*egypt_index))
        throw Error("Missing exact RTON numeric token spans");
    auto c=*reader.coin, k=reader.key_counts.at(*egypt_index);
    if(c.value!=coins || k.value!=amount)
        throw Error("Numeric token value mismatch");
    std::vector<std::pair<Span,std::string>> edits{
        {c,Encode(c.tag,coins+delta)}, {k,Encode(k.tag,0)}};
    std::sort(edits.begin(),edits.end(),[](const auto& a,const auto& b){
        return a.first.begin>b.first.begin;
    });
    for(const auto& e:edits)
        result.data.replace(e.first.begin,e.first.end-e.first.begin,e.second);
    auto expected=before;
    expected.Field("objects").At(slot).Field("objdata").Field("c").integer=coins+delta;
    expected.Field("objects").At(slot).Field("objdata").Field("wsk").At(*egypt_index)
        .Field("kc").integer=0;
    const auto reparsed=Reader(result.data,slot).Parse();
    if(!(reparsed==expected)) throw Error("Full native RTON semantic diff failed");
    result.changed=true;
    result.keys=amount;
    result.after=coins+delta;
    return result;
}
} // namespace pvz2_key_study::rton_native
