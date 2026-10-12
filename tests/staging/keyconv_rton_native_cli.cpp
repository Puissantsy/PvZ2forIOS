// Research-only C++ RTON converter CLI; synthetic fixtures only, NOT for live saves.
#include "world_key_rton_native.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

int main(int argc,char** argv) {
    if(argc!=4) return 64;
    try {
        const std::filesystem::path source=argv[1], destination=argv[2];
        if(source==destination || std::filesystem::exists(destination))
            throw std::runtime_error("Must create a new disposable destination");
        const auto slot=std::stoull(argv[3]);
        std::ifstream input(source,std::ios::binary);
        if(!input) throw std::runtime_error("Missing input fixture");
        const std::string original((std::istreambuf_iterator<char>(input)),
                                    std::istreambuf_iterator<char>());
        const auto candidate=pvz2_key_study::rton_native::ConvertEgypt(
            original,static_cast<std::size_t>(slot));
        std::ofstream output(destination,std::ios::binary|std::ios::trunc);
        if(!output) throw std::runtime_error("Cannot create output");
        output.write(candidate.data.data(),
                     static_cast<std::streamsize>(candidate.data.size()));
        if(!output.good()) throw std::runtime_error("Cannot write fixture");
        std::cout<<(candidate.changed ? "CONVERTED" : "NOOP")<<"\n";
    } catch(const std::exception& e) {
        std::cerr<<"Native RTON fixture conversion refused: "<<e.what()<<"\n";
        return 2;
    }
    return 0;
}
