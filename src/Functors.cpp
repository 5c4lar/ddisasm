#include "Functors.h"

#include <fstream>
#include <iostream>

const gtirb::Module* Module = nullptr;

static const gtirb::ByteInterval* get_byte_interval(uint64_t EA)
{
    // TODO: maybe this is too slow for the functor
    for(const auto& Section : Module->sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool Loaded = Section.isFlagSet(gtirb::SectionFlag::Loaded);
        if(Loaded && (Executable || Initialized))
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
                uint64_t Size = ByteInterval.getInitializedSize();
                if(EA < Addr || EA >= Addr + Size)
                {
                    continue;
                }
                return &ByteInterval;
            }
        }
    }
    return nullptr;
}

uint8_t functor_data_exists(uint64_t EA)
{
    const gtirb::ByteInterval* ByteInterval = get_byte_interval(EA);
    return (ByteInterval != nullptr);
}

uint8_t functor_data_u8(uint64_t EA)
{
    const gtirb::ByteInterval* ByteInterval = get_byte_interval(EA);
    if(!ByteInterval)
    {
        return 0;
    }
    uint64_t Addr = static_cast<uint64_t>(*ByteInterval->getAddress());
    auto Data = ByteInterval->rawBytes<const int8_t>();
    return Data[EA - Addr];
}

/*
uint16_t data_u16(uint64_t EA);
uint32_t data_u32(uint64_t EA);
uint64_t data_u64(uint64_t EA);
int8_t data_s8(uint64_t EA);
int16_t data_s16(uint64_t EA);
int32_t data_s32(uint64_t EA);
int64_t data_s64(uint64_t EA);
*/

#ifdef __EMBEDDED_SOUFFLE__

// C++ interface allows ddisasm CPP code to instantiate functor data
void initFunctorGtirbModule(const gtirb::Module* M)
{
    // TODO: build a sorted Range => ByteInterval map. This will allow a binary
    // search to find the right range quickly.
    Module = M;
}

#else

std::unique_ptr<gtirb::Context> Context;

/*
Load the GTIRB file from the debug directory if running in the interpreter
*/
void __attribute__((constructor)) loadGtirb(void)
{
    // TODO: locate fact-dir in the command line args
    const std::string GtirbPath("debug/binary.gtirb");

    Context = std::make_unique<gtirb::Context>();

    std::ifstream Stream(GtirbPath, std::ios::in | std::ios::binary);
    gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*Context, Stream);
    if(!Result)
    {
        std::cerr << "ERROR: Failed to load GTIRB: " << GtirbPath << "\n";
        return;
    }

    // TODO: support multi-module GTIRB files (static archives)
    gtirb::IR* IR = *Result;
    Module = &(*IR->modules().begin());
}
#endif /* __EMBEDDED_SOUFFLE__ */
