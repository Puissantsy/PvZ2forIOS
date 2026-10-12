#include "world_key_stock_view.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
using namespace pvz2_key_study;
static void Append(std::vector<std::byte>& bytes,std::uint32_t ptr,std::uint32_t count) {
    for (const auto v:{ptr,count}) for (unsigned n=0;n<4u;++n)
        bytes.push_back(std::byte{static_cast<std::uint8_t>(v>>(8u*n))});
}
static std::optional<std::string> Resolve(std::uint32_t ptr) {
    switch (ptr) {
    case 0x100cu:return "egypt";
    case 0x200cu:return "pirate";
    case 0x300cu:return "cowboy";
    case 0x400cu:return "future";
    case 0x500cu:return "dark";
    case 0x600cu:return "unexpected";
    default:return std::nullopt;
    }
}
int main() {
    unsigned checks=0u;
    std::vector<std::byte> bytes;
    auto parsed=DecodeNativeWorldKeyStock(bytes,Resolve);
    assert(parsed && parsed->empty()); ++checks;
    Append(bytes,0x100cu,6u);
    parsed=DecodeNativeWorldKeyStock(bytes,Resolve);
    assert(parsed && parsed->size()==1u &&
           parsed->at(0).world=="egypt" && parsed->at(0).count==6u);++checks;
    Append(bytes,0x200cu,0u);
    parsed=DecodeNativeWorldKeyStock(bytes,Resolve);
    assert(parsed && parsed->size()==2u &&
           parsed->at(1).world=="pirate" && parsed->at(1).count==0u);++checks;
    Append(bytes,0x100cu,1u);
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.resize(16u);
    Append(bytes,0x600cu,1u);
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.resize(16u);
    Append(bytes,0x700cu,1u);
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.resize(16u);
    Append(bytes,0x000au,1u);
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.resize(16u);
    Append(bytes,0x300cu,100u);
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.resize(16u);
    Append(bytes,0x300cu,99u);
    parsed=DecodeNativeWorldKeyStock(bytes,Resolve);
    assert(parsed && parsed->at(2).count==99u); ++checks;
    bytes.pop_back();
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.clear();
    for(unsigned n=0u;n<17u;++n)Append(bytes,0x100cu,1u);
    assert(!DecodeNativeWorldKeyStock(bytes,Resolve)); ++checks;
    bytes.clear();
    for (auto ptr:{0x100cu,0x200cu,0x300cu,0x400cu,0x500cu})
        Append(bytes,ptr,1u);
    parsed=DecodeNativeWorldKeyStock(bytes,Resolve);
    assert(parsed && parsed->size()==5u); ++checks;
    // Verify LE decoding rather than accident of host-endianness.
    bytes[4]=std::byte{99};bytes[5]=std::byte{0};
    bytes[6]=std::byte{0};bytes[7]=std::byte{0};
    parsed=DecodeNativeWorldKeyStock(bytes,Resolve);
    assert(parsed && parsed->at(0).count==99u); ++checks;
    std::cout<<"PASS: "<<checks<<" native WorldSpecificKeys decoder checks (read-only)\n";
}
