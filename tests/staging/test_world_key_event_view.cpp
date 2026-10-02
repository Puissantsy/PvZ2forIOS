#include "world_key_event_view.hpp"
#include <cassert>
#include <iostream>
#include <vector>
using namespace pvz2_key_study;
void WriteEvent(std::vector<std::byte>& bytes,unsigned w,unsigned e,unsigned s) {
    const auto start=bytes.size();
    bytes.resize(start+kNativeEventStride);
    bytes[start]=std::byte{static_cast<unsigned char>(w)};
    bytes[start+2]=std::byte{static_cast<unsigned char>(e)};
    bytes[start+3]=std::byte{static_cast<unsigned char>(e>>8)};
    for(unsigned k=0;k<4;++k)
        bytes[start+4+k]=std::byte{static_cast<unsigned char>(s>>(8*k))};
}
int main() {
    std::vector<std::byte> bytes;
    assert(!DecodeNativeEventSnapshot(bytes));
    WriteEvent(bytes,2,13,3);WriteEvent(bytes,2,23,3);
    WriteEvent(bytes,2,33,3);WriteEvent(bytes,2,39,3);
    WriteEvent(bytes,2,41,3);
    auto events=DecodeNativeEventSnapshot(bytes);
    assert(events && events->size()==5);
    assert(Evaluate(2,3,*events).coins==3000);
    bytes[4]=std::byte{2};
    events=DecodeNativeEventSnapshot(bytes);
    assert(events && Evaluate(2,3,*events).reason==Reason::GateNotOpen);
    bytes.resize(bytes.size()-1);
    assert(!DecodeNativeEventSnapshot(bytes));
    bytes.resize((kMaxNativeEvents+1)*kNativeEventStride);
    assert(!DecodeNativeEventSnapshot(bytes));
    std::cout << "PASS: 6 native event-view checks\n";
}
