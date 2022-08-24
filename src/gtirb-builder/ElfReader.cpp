//===- ElfReader.cpp --------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "ElfReader.h"

#include <algorithm>
#include <sstream>

// NOTE:
// Elf32_Sym is defined here in duplicate of LIEF::ELF::details::Elf32_Sym,
// which is an incomplete type in version 0.12.1 (not defined in a header).
namespace
{
    typedef uint32_t Elf32_Addr;
    typedef uint16_t Elf32_Half;
    typedef uint32_t Elf32_Word;

    struct Elf32_Sym
    {
        Elf32_Word st_name;
        Elf32_Addr st_value;
        Elf32_Word st_size;
        unsigned char st_info;
        unsigned char st_other;
        Elf32_Half st_shndx;
    };
} // namespace

ElfReader::ElfReader(std::string Path, std::string Name, std::shared_ptr<gtirb::Context> Context,
                     gtirb::IR *IR, std::shared_ptr<LIEF::Binary> Binary)
    : GtirbBuilder(Path, Name, Context, IR, Binary)
{
    Elf = std::dynamic_pointer_cast<LIEF::ELF::Binary>(Binary);
    assert(Elf && "Expected ELF");
};

// Collect dynamic entries
std::map<std::string, uint64_t> ElfReader::getDynamicEntries()
{
    static std::map<std::string, uint64_t> Ans;
    if(Ans.empty())
    {
        for(const auto &Entry : Elf->dynamic_entries())
        {
            std::string Ent = LIEF::ELF::to_string(Entry.tag());
            uint64_t Value = Entry.value();
            Ans[Ent] = Value;
        }
    }
    return Ans;
}

// Resurrect sections and symbols from sectionless binary
void ElfReader::resurrectSections()
{
    std::map<gtirb::UUID, uint64_t> Alignment;
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> SectionProperties;

    // Get dynamic entries
    std::map<std::string, uint64_t> DynamicEntries = getDynamicEntries();

    // Collect loaded segments ---------------------------------------
    // TODO: This assumes there is one segment for RW and one for RX.
    LIEF::ELF::Segment LoadedSegmentRW; // for .got, .data, and .bss
    LIEF::ELF::Segment LoadedSegmentRX; // for fake executable section
    for(auto &Segment : Elf->segments())
    {
        if(Segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_LOAD)
        {
            if(Segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_X))
            {
                // Check if there's multiple LoadedSegmentRX
                assert((LoadedSegmentRX.physical_size() == 0)
                       && "Developer Assert: Multiple RX segments found");
                LoadedSegmentRX = Segment;
            }
            else
            {
                // Check if there's multiple LoadedSegmentRW
                assert((LoadedSegmentRW.physical_size() == 0)
                       && "Developer Assert: Multiple RW segments found");
                LoadedSegmentRW = Segment;
            }
        }
    }

    uint64_t Index = 0;

    // Create .fake.text.segment -------------------------------------
    if(LoadedSegmentRX.physical_size() != 0)
    {
        auto Segment = LoadedSegmentRX;
        uint64_t Addr = Segment.virtual_address();
        uint64_t Size = Segment.virtual_size();

        // Add named section to GTIRB Module.
        gtirb::Section *S = Module->addSection(*Context, ".fake.text.segment");
        // Add section flags to GTIRB Section.
        S->addFlag(gtirb::SectionFlag::Loaded);
        S->addFlag(gtirb::SectionFlag::Readable);
        S->addFlag(gtirb::SectionFlag::Executable);
        S->addFlag(gtirb::SectionFlag::Writable);
        S->addFlag(gtirb::SectionFlag::Initialized);

        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(Addr, Size);
        S->addByteInterval(*Context, gtirb::Addr(Addr), Bytes.begin(), Bytes.end(), Size,
                           Bytes.size());

        uint64_t Type = static_cast<uint64_t>(Segment.type())
                        | static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS);
        uint64_t Flags = static_cast<uint64_t>(Segment.flags())
                         | static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC)
                         | static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);

        Alignment[S->getUUID()] = 16;
        SectionIndex[Index] = S->getUUID();
        SectionProperties[S->getUUID()] = {Type, Flags};
        ++Index;
    }

    // Create .fake.data.segment and .got ----------------------------
    uint64_t GotAddr = 0;
    uint64_t GotSize = 0;
    uint64_t BssDistance = 0; // offset of bss in LoadedSegmentRW
    if(LoadedSegmentRW.physical_size() != 0)
    {
        auto Segment = LoadedSegmentRW;
        uint64_t Addr = Segment.virtual_address();
        uint64_t Size = Segment.virtual_size();

        // -----------------------------------------------------------
        // Create .got -----------------------------------------------
        //
        // Add named section to GTIRB Module.
        gtirb::Section *GotS = Module->addSection(*Context, ".got");
        // Add section flags to GTIRB Section.
        GotS->addFlag(gtirb::SectionFlag::Loaded);
        GotS->addFlag(gtirb::SectionFlag::Readable);
        GotS->addFlag(gtirb::SectionFlag::Writable);
        GotS->addFlag(gtirb::SectionFlag::Initialized);

        uint64_t Type = static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS);
        uint64_t Flags = static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC
                                               | LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);

        auto It = DynamicEntries.find("PLTGOT");
        assert((It != DynamicEntries.end()) && "PLTGOT not found");
        GotAddr = It->second;
        GotSize = Size - (GotAddr - Addr);

        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(GotAddr, GotSize);
        std::vector<uint8_t> BytesCopy = Bytes;
        std::reverse(BytesCopy.begin(), BytesCopy.end());
        uint64_t BssRdistance = std::distance(
            BytesCopy.begin(),
            find_if(BytesCopy.begin(), BytesCopy.end(), [](auto x) { return x != 0; }));
        BssDistance = BytesCopy.size() - BssRdistance;

        GotS->addByteInterval(*Context, gtirb::Addr(GotAddr), Bytes.begin(), Bytes.end(),
                              BssDistance, Bytes.size() - BssRdistance);

        Alignment[GotS->getUUID()] = 16;
        SectionIndex[Index] = GotS->getUUID();
        SectionProperties[GotS->getUUID()] = {Type, Flags};
        ++Index;

        // -----------------------------------------------------------
        // Create .fake.data
        // Add named section to GTIRB Module.
        gtirb::Section *DataS = Module->addSection(*Context, ".fake.data");
        // Add section flags to GTIRB Section.
        DataS->addFlag(gtirb::SectionFlag::Loaded);
        DataS->addFlag(gtirb::SectionFlag::Readable);
        DataS->addFlag(gtirb::SectionFlag::Writable);
        DataS->addFlag(gtirb::SectionFlag::Initialized);

        uint64_t DataSize = GotAddr - Addr;

        std::vector<uint8_t> DataBytes = Elf->get_content_from_virtual_address(Addr, DataSize);
        DataS->addByteInterval(*Context, gtirb::Addr(Addr), DataBytes.begin(), DataBytes.end(),
                               DataSize, DataBytes.size());

        Alignment[DataS->getUUID()] = 16;
        SectionIndex[Index] = DataS->getUUID();
        SectionProperties[DataS->getUUID()] = {Type, Flags};
        ++Index;

        // -----------------------------------------------------------
        // Create .fake.data2 section if any at the end of the segment
        if(Segment.physical_size() < Segment.virtual_size())
        {
            uint64_t DataAddr = Segment.virtual_address() + Segment.physical_size();
            uint64_t DataSize2 = Segment.virtual_size() - Segment.physical_size();

            gtirb::Section *DataS2 = Module->addSection(*Context, ".fake.data2");
            // Add section flags to GTIRB Section.
            DataS2->addFlag(gtirb::SectionFlag::Loaded);
            DataS2->addFlag(gtirb::SectionFlag::Readable);
            DataS2->addFlag(gtirb::SectionFlag::Writable);

            std::vector<uint8_t> DataBytes2 =
                Elf->get_content_from_virtual_address(DataAddr, DataSize2);
            DataS2->addByteInterval(*Context, gtirb::Addr(DataAddr), DataBytes2.begin(),
                                    DataBytes2.end(), DataSize2, DataBytes2.size());

            Alignment[DataS2->getUUID()] = 16;
            SectionIndex[Index] = DataS2->getUUID();
            SectionProperties[DataS2->getUUID()] = {
                static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS),
                static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC
                                      | LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE)};

            ++Index;
        }
    }

    // Create .bss section if there's any in LoadedSegmentRW ---------
    // GotAddr and GotSize are used here, so make sure they are set
    // beforehand.
    if(GotAddr != 0 && GotSize != 0)
    {
        // Find the first address starting consecutive zeros,
        // which is highly likely .bss
        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(GotAddr, GotSize);
        if(BssDistance >= 0 && BssDistance < Bytes.size())
        {
            uint64_t BssAddr = GotAddr + BssDistance;
            uint64_t BssSize = Bytes.size() - BssDistance;

            gtirb::Section *Bss = Module->addSection(*Context, ".bss");
            // Add section flags to GTIRB Section.
            Bss->addFlag(gtirb::SectionFlag::Loaded);
            Bss->addFlag(gtirb::SectionFlag::Readable);
            Bss->addFlag(gtirb::SectionFlag::Writable);
            Bss->addByteInterval(*Context, gtirb::Addr(BssAddr), Bytes.begin() + BssDistance,
                                 Bytes.end(), GotSize - BssDistance, BssSize);

            Alignment[Bss->getUUID()] = 16;
            SectionIndex[Index] = Bss->getUUID();
            SectionProperties[Bss->getUUID()] = {
                static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS),
                static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC
                                      | LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE)};

            ++Index;
        }
    }

    Module->addAuxData<gtirb::schema::Alignment>(std::move(Alignment));
    Module->addAuxData<gtirb::schema::SectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::SectionProperties>(std::move(SectionProperties));
    return;
}

// MIPS: Create a symbol for _gp.
void ElfReader::createGPforMIPS(
    uint64_t SecIndex, std::map<gtirb::UUID, auxdata::ElfSymbolInfo> &SymbolInfo,
    std::map<gtirb::UUID, auxdata::ElfSymbolTabIdxInfo> &SymbolTabIdxInfo)
{
    if(!Module->findSymbols("_gp").empty()) // _gp already exists
        return;
    // Get dynamic entries
    std::map<std::string, uint64_t> DynamicEntries = getDynamicEntries();
    if(getDynamicEntries().empty())
        return; // No dynamic section, so no need for _gp symbol

    uint64_t GpAddr = 0;
    if(auto It = DynamicEntries.find("MIPS_RLD_MAP"); It != DynamicEntries.end())
    {
        const uint64_t RldMapAddr = It->second;
        GpAddr = RldMapAddr + 0x8000;
    }
    else
    {
        assert(false); // TODO: MIPS_RLD_MAP_REL? Skip _gp creation?
    }

    gtirb::Symbol *S = Module->addSymbol(*Context, gtirb::Addr(GpAddr), "_gp");
    uint64_t Size = 0;
    std::string Type = LIEF::ELF::to_string(LIEF::ELF::ELF_SYMBOL_TYPES::STT_NOTYPE);
    std::string Scope = LIEF::ELF::to_string(LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL);
    std::string Visibility = LIEF::ELF::to_string((LIEF::ELF::ELF_SYMBOL_VISIBILITY)0);
    std::vector<std::tuple<std::string, uint64_t>> Indexes;
    Indexes.push_back({".symtab", 0});

    SymbolInfo[S->getUUID()] = {Size, Type, Scope, Visibility, SecIndex};
    SymbolTabIdxInfo[S->getUUID()] = Indexes;
}

void ElfReader::resurrectSymbols()
{
    // Get dynamic entries
    std::map<std::string, uint64_t> DynamicEntries = getDynamicEntries();

    // Extract bytes from STRTAB -------------------------------------
    std::vector<uint8_t> StrTabBytes;
    auto It = DynamicEntries.find("STRTAB");
    if(It == DynamicEntries.end())
    {
        std::cerr << "\nWARNING: resurrectSymbols: STRTAB not found.";
    }
    else
    {
        uint64_t StrTabAddr = It->second;
        It = DynamicEntries.find("STRSZ");
        if(It == DynamicEntries.end())
        {
            std::cerr << "\nWARNING: resurrectSymbols: STRSZ not found.";
        }
        else
        {
            uint64_t StrTabSize = It->second;
            StrTabBytes = Elf->get_content_from_virtual_address(StrTabAddr, StrTabSize);
        }
    }

    // Extract symbols -----------------------------------------------
    // NOTE: The following code is specific to MIPS32 because it makes use of
    // MIPS-specific dynamic entries, such as MIPS_SYMTABNO, etc.
    // TODO: Generalize it if needed.
    if(Module->getISA() == gtirb::ISA::MIPS32)
    {
        auto SymTabIt = DynamicEntries.find("SYMTAB");
        if(SymTabIt == DynamicEntries.end())
        {
            std::cerr << "\nWARNING: resurrectSymbols: SYMTAB not found.";
            return;
        }
        uint64_t Addr = SymTabIt->second;

        SymTabIt = DynamicEntries.find("MIPS_SYMTABNO");
        if(SymTabIt == DynamicEntries.end())
        {
            std::cerr << "\nWARNING: resurrectSymbols: MIPS_SYMTABNO not found.";
            return;
        }
        uint64_t DynSymNum = SymTabIt->second;

        SymTabIt = DynamicEntries.find("SYMENT");
        if(SymTabIt == DynamicEntries.end())
        {
            std::cerr << "\nWARNING: resurrectSymbols: SYMENT not found.";
            return;
        }
        uint64_t SymTabEntrySize = SymTabIt->second;

        uint64_t Size = DynSymNum * SymTabEntrySize;

        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(Addr, Size);
        auto Iter = Bytes.begin();

        // Extract a string at the given Index in STRTAB
        auto getStringAt = [&StrTabBytes](uint32_t Index) {
            std::stringstream SS;
            auto It = StrTabBytes.begin() + Index;
            while(It != StrTabBytes.end())
            {
                uint8_t V = *It++;
                if(V == 0)
                    break;
                SS << V;
            }
            return SS.str();
        };

        for(uint64_t I = 0; I < DynSymNum; ++I)
        {
            // NOTE:
            // We cast a pointer to the locally defined Elf32_Sym struct to a pointer of the
            // incomplete type LIEF::ELF::details::Elf32_Sym.
            Elf32_Sym S;
            memcpy(&S, &Bytes[I * sizeof(Elf32_Sym)], sizeof(Elf32_Sym));
            LIEF::ELF::details::Elf32_Sym *P =
                reinterpret_cast<LIEF::ELF::details::Elf32_Sym *>(&S);
            if(Module->getByteOrder() == gtirb::ByteOrder::Big)
            {
                LIEF::Convert::swap_endian<LIEF::ELF::details::Elf32_Sym>(P);
            }
            LIEF::ELF::Symbol Symbol(*P);
            std::string Name = getStringAt(S.st_name);
            Symbol.name(Name);
            Elf->add_dynamic_symbol(Symbol);
        }
    }
    return;
}

// Parse .ARM.attributes to find "M" that indicates "Microcontroller".
static bool detectArm32Microcontroller(gtirb::Section *S)
{
    auto readUleb128 = [](const unsigned char *Ptr, unsigned int *len_out) {
        uint64_t Ans = 0;
        unsigned int NRead = 0;
        int Shift = 0;
        unsigned char Byte;

        do
        {
            Byte = *Ptr++;
            NRead++;

            Ans |= (Byte & 0x7f) << Shift;

            Shift += 7;
        } while(Byte & 0x80);

        if(len_out != NULL)
            *len_out = NRead;

        return Ans;
    };

    bool Found = false;
    for(const auto &ByteInterval : S->byte_intervals())
    {
        uint64_t N = ByteInterval.getSize();
        const unsigned char *RawChars = ByteInterval.rawBytes<const unsigned char>();
        const unsigned char *Ptr = RawChars;
        if(*Ptr != 'A')
            continue;

        Ptr++;
        N--;
        // Skip 4 bytes (section length)
        Ptr += 4;
        N -= 4;
        // Skip name (e.g., "aeabi")
        int NameLen = strlen((char *)Ptr) + 1;
        Ptr += NameLen;
        N -= NameLen;
        // Skip 1-bit tag
        Ptr++;
        N--;
        // Skip unrelated 4-bytes
        Ptr += 4;
        N -= 4;
        // Read pairs of (Tag,Value) until it finds (7, "M").
        while(N > 0)
        {
            unsigned int Len = 0;
            int Tag = readUleb128(Ptr, &Len);
            Ptr += Len;
            N -= Len;
            if(Tag == 7) // 7: Tag_CPU_arch_profile
            {
                int Val = readUleb128(Ptr, &Len);
                Ptr += Len;
                N -= Len;
                if(Val == 'M') // Microcontroller
                {
                    Found = true;
                }
            }
        }
    }
    return Found;
}

void ElfReader::buildSections()
{
    std::map<gtirb::UUID, uint64_t> Alignment;
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> SectionProperties;

    // For sectionless binary, call resurrectSections.
    if(Elf->sections().size() == 0)
    {
        resurrectSections();
        return;
    }

    std::optional<uint64_t> TlsBegin, TlsEnd;
    for(auto &Segment : Elf->segments())
    {
        if(Segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_TLS)
        {
            TlsBegin = Segment.virtual_address();
            TlsEnd = Segment.virtual_address() + Segment.virtual_size();
        }
    }

    // ELF object files do not have allocated address spaces.
    if(Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL)
    {
        relocateSections();
    }

    uint64_t Index = 0;
    for(auto &Section : Elf->sections())
    {
        bool Loaded = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
        bool Executable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
        bool Writable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);
        bool Initialized = Loaded && Section.type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS;
        bool Tls = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_TLS);
        bool Literal = Literals.count(Section.name()) > 0;
        bool Relocatable = Loaded && Section.virtual_address() == 0
                           && Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL;

        if(!Loaded && !Literal)
        {
            Index++;
            continue;
        }

        // Skip empty sections in relocatable ELFs (object files).
        if(Relocatable && Section.size() == 0)
        {
            Index++;
            continue;
        }

        // Add named section to GTIRB Module.
        gtirb::Section *S = Module->addSection(*Context, Section.name());

        // Add section flags to GTIRB Section.
        if(Loaded)
        {
            S->addFlag(gtirb::SectionFlag::Loaded);
            S->addFlag(gtirb::SectionFlag::Readable);
        }
        if(Executable)
        {
            S->addFlag(gtirb::SectionFlag::Executable);
        }
        if(Writable)
        {
            S->addFlag(gtirb::SectionFlag::Writable);
        }
        if(Initialized)
        {
            S->addFlag(gtirb::SectionFlag::Initialized);
        }
        if(Tls)
        {
            S->addFlag(gtirb::SectionFlag::ThreadLocal);
        }

        if(Loaded)
        {
            gtirb::Addr Addr = gtirb::Addr(Section.virtual_address());

            if(Relocatable)
            {
                Addr = gtirb::Addr(SectionRelocations[Section.name()]);
            }

            // Rebase TLS section. Thread-local data section addresses overlap other sections, as
            // they are only templates for per-thread copies of the data sections.
            if(Tls && TlsBegin && TlsEnd && !Relocatable)
            {
                if(Section.virtual_address() >= *TlsBegin && Section.virtual_address() < *TlsEnd)
                {
                    uint64_t Offset = Section.virtual_address() - *TlsBegin;
                    Addr = gtirb::Addr(tlsBaseAddress() + Offset);
                }
                else
                {
                    std::cerr << "WARNING: Failed to rebase TLS section: " << Section.name()
                              << "\n";
                }
            }

            if(Initialized)
            {
                // Add allocated section contents to a single, contiguous ByteInterval.
                LIEF::span<const uint8_t> Bytes = Section.content();
                S->addByteInterval(*Context, Addr, Bytes.begin(), Bytes.end(), Section.size(),
                                   Bytes.size());
            }
            else
            {
                // Add an uninitialized section.
                S->addByteInterval(*Context, Addr, Section.size(), 0);
            }
        }

        if(Literal)
        {
            // Transcribe unloaded, literal data to an address-less section with a single DataBlock.
            LIEF::span<const uint8_t> Bytes = Section.content();
            gtirb::ByteInterval *I = S->addByteInterval(*Context, Bytes.begin(), Bytes.end(),
                                                        Section.size(), Bytes.size());
            I->addBlock<gtirb::DataBlock>(*Context, 0, Section.size());
        }

        // Add section index and raw section properties to aux data.
        Alignment[S->getUUID()] = Section.alignment();
        SectionIndex[Index] = S->getUUID();
        SectionProperties[S->getUUID()] = {static_cast<uint64_t>(Section.type()),
                                           static_cast<uint64_t>(Section.flags())};

        // In case of ARM32, inspect .ARM.attributes section to see
        // if the binary is Microcontroller.
        if(Module->getISA() == gtirb::ISA::ARM && Section.name() == ".ARM.attributes")
        {
            if(detectArm32Microcontroller(S))
            {
                // Note that this information is used for setting up Capstone
                // mode correctly:
                // i.e., include CS_MODE_MCLASS for Microcontroller
                std::vector<std::string> ArchInfo;
                ArchInfo.emplace_back("Microcontroller");
                Module->addAuxData<gtirb::schema::ArchInfo>(std::move(ArchInfo));
            }
        }
        Index++;
    }

    Module->addAuxData<gtirb::schema::Alignment>(std::move(Alignment));
    Module->addAuxData<gtirb::schema::SectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::SectionProperties>(std::move(SectionProperties));
}

void ElfReader::buildSymbols()
{
    // If there's no existing dynamic symbols, resurrect them.
    bool Relocatable = Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL;
    if(!Relocatable && Elf->dynamic_symbols().size() == 0)
    {
        resurrectSymbols();
    }

    using SymbolVersionId = uint16_t;

    std::map<std::string, std::set<SymbolVersionId>> VersionToIds;
    auxdata::ElfSymDefs ElfSymDefinitions;
    for(LIEF::ELF::SymbolVersionDefinition &Def : Elf->symbols_version_definition())
    {
        auto &Names = ElfSymDefinitions[Def.ndx()];
        for(LIEF::ELF::SymbolVersionAux &SymAux : Def.symbols_aux())
        {
            Names.push_back(SymAux.name());
        }
        VersionToIds[*Names.begin()].insert(Def.ndx());
    }
    auxdata::ElfSymNeeded ElfSymNeededTable;
    for(LIEF::ELF::SymbolVersionRequirement &Req : Elf->symbols_version_requirement())
    {
        for(LIEF::ELF::SymbolVersionAuxRequirement &SymAux : Req.auxiliary_symbols())
        {
            ElfSymNeededTable[Req.name()][SymAux.other()] = SymAux.name();
            VersionToIds[SymAux.name()].insert(SymAux.other());
        }
    }

    using SymbolKey = std::tuple<uint64_t, uint64_t, std::string, std::string, std::string,
                                 uint64_t, std::string>;
    using TableDecl = std::tuple<std::string, uint64_t>;

    std::map<SymbolKey, std::map<SymbolVersionId, std::vector<TableDecl>>> Symbols;
    auto LoadSymbols = [&](auto SymbolIt, std::string TableName) {
        uint64_t TableIndex = 0;
        for(auto &Symbol : SymbolIt)
        {
            std::string Name = Symbol.name();
            uint64_t Value = Symbol.value();

            // Rebase symbols onto their respective relocated section address.
            bool Relocatable = Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL;
            if(Relocatable)
            {
                if(Symbol.shndx() > 0 && Symbol.shndx() < Elf->sections().size())
                {
                    const LIEF::ELF::Section &Section = Elf->sections()[Symbol.shndx()];
                    Value = SectionRelocations[Section.name()] + Value;
                }
            }

            // Rebase a TLS symbol onto the relocated TLS segment.
            bool Tls = Symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_TLS;
            if(Tls && !Relocatable)
            {
                // STT_TLS symbols are relative to PT_TLS segment base.
                Value = tlsBaseAddress() + Value;
            }

            SymbolVersionId Version = LIEF::ELF::VER_NDX_LOCAL;
            std::string VersionStr;
            // Symbols in "dynsym" table have versions.
            if(Symbol.has_version())
            {
                Version = Symbol.symbol_version()->value();
            }
            // Symbols in "symtab" table have the version attached to the name.
            // We remove the version from the name and recover the corresponding version identifier.
            else if(std::size_t I = Name.find('@'); I != std::string::npos)
            {
                VersionStr = Name.substr(I, 2) == "@@" ? Name.substr(I + 2) : Name.substr(I + 1);
                Name = Name.substr(0, I);
            }
            auto &VersionMap =
                Symbols[std::tuple(Value,                                     // Value
                                   Symbol.size(),                             // Size
                                   LIEF::ELF::to_string(Symbol.type()),       // Type
                                   LIEF::ELF::to_string(Symbol.binding()),    // Binding
                                   LIEF::ELF::to_string(Symbol.visibility()), // Scope
                                   Symbol.shndx(),                            // Section Index
                                   Name                                       // Name
                                   )];
            // If the version was part of the name,
            // select the best version already available (from dynsym).
            if(VersionStr.size() > 0)
            {
                std::set<SymbolVersionId> &PossibleVersions = VersionToIds[VersionStr];
                for(auto &[VersionId, Val] : VersionMap)
                {
                    // Ignore the 15th bit that marks whether the symbol is hidden.
                    if(PossibleVersions.find(VersionId & 0x7FFF) != PossibleVersions.end())
                    {
                        Version = VersionId;
                        break;
                    }
                }
                if(!Version)
                {
                    throw ElfReaderException("Could not find compatible symbol version for " + Name
                                             + "@" + VersionStr);
                }
            }
            else
            {
                // If there is no version but there is a global
                // instance of this symbol, we consider this one global too.
                if(VersionMap.find(LIEF::ELF::VER_NDX_GLOBAL) != VersionMap.end())
                {
                    Version = LIEF::ELF::VER_NDX_GLOBAL;
                }
            }
            VersionMap[Version].push_back({TableName, TableIndex});
            TableIndex++;
        }
    };

    LoadSymbols(Elf->dynamic_symbols(), ".dynsym");
    LoadSymbols(Elf->static_symbols(), ".symtab");

    std::map<gtirb::UUID, auxdata::ElfSymbolInfo> SymbolInfo;
    std::map<gtirb::UUID, auxdata::ElfSymbolTabIdxInfo> SymbolTabIdxInfo;
    auxdata::ElfSymbolVersionsEntries SymVerEntries;
    for(auto &[Key, VersionMap] : Symbols)
    {
        auto &[Value, Size, Type, Scope, Visibility, SecIndex, Name] = Key;
        for(auto &[Version, Indexes] : VersionMap)
        {
            std::string VersionedName = Name;
            // For datalog, we add the version id to the name.
            // This will be removed later
            if(Version > LIEF::ELF::VER_NDX_GLOBAL)
            {
                VersionedName += "@" + std::to_string(Version);
            }
            gtirb::Symbol *S;
            // Symbols with special section index do not have an address except
            // for absolute symbols (SHN_ABS).
            // See
            // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-94076.html#chapter6-tbl-16
            // FILE symbols do not have an address either.
            if((SecIndex == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
                || (SecIndex >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
                    && SecIndex <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)
                    && SecIndex != static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_ABS))
                || Type == "FILE")
               && Value == 0)
            {
                S = Module->addSymbol(*Context, VersionedName);
            }
            else
            {
                S = Module->addSymbol(*Context, gtirb::Addr(Value), VersionedName);
            }

            assert(S && "Failed to create symbol.");

            // Add additional symbol information to aux data.
            SymbolInfo[S->getUUID()] = {Size, Type, Scope, Visibility, SecIndex};
            SymbolTabIdxInfo[S->getUUID()] = Indexes;
            // 0 and 1 are used to denote local and global scope with no version.
            // anythin higher is a valid version index.
            if(Version > LIEF::ELF::VER_NDX_GLOBAL)
            {
                SymVerEntries[S->getUUID()] = Version;
            }
        }
    }

    // In case of MIPS, if _gp does not exist in Module (either sectionless or
    // stripped binaries), create a symbol for _gp.
    if(Module->getISA() == gtirb::ISA::MIPS32)
    {
        const auto &GpSymbols = Module->findSymbols("_gp");
        if(GpSymbols.empty())
        {
            createGPforMIPS(Symbols.size(), SymbolInfo, SymbolTabIdxInfo);
        }
    }

    Module->addAuxData<gtirb::schema::ElfSymbolInfo>(std::move(SymbolInfo));
    Module->addAuxData<gtirb::schema::ElfSymbolTabIdxInfo>(std::move(SymbolTabIdxInfo));
    Module->addAuxData<gtirb::schema::ElfSymbolVersions>(std::tuple(
        std::move(ElfSymDefinitions), std::move(ElfSymNeededTable), std::move(SymVerEntries)));
}

void ElfReader::addEntryBlock()
{
    gtirb::Addr Entry = gtirb::Addr(Elf->entrypoint());
    if(auto It = Module->findByteIntervalsOn(Entry); !It.empty())
    {
        if(gtirb::ByteInterval &Interval = *It.begin(); Interval.getAddress())
        {
            uint64_t Offset = Entry - *Interval.getAddress();
            gtirb::CodeBlock *Block = Interval.addBlock<gtirb::CodeBlock>(*Context, Offset, 0);
            Module->setEntryPoint(Block);
        }
    }
}

void ElfReader::addAuxData()
{
    // Add `binaryType' aux data table.
    std::vector<std::string> BinaryType;
    switch(Elf->header().file_type())
    {
        case LIEF::ELF::E_TYPE::ET_DYN:
            BinaryType.emplace_back("DYN");
            break;
        case LIEF::ELF::E_TYPE::ET_EXEC:
            BinaryType.emplace_back("EXEC");
            break;
        case LIEF::ELF::E_TYPE::ET_REL:
            BinaryType.emplace_back("REL");
            break;
        default:
            std::cerr << "ERROR: Unsupported ELF file type (e_type): "
                      << LIEF::ELF::to_string(Elf->header().file_type()) << "\n";
            std::exit(EXIT_FAILURE);
    }
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    // Add `relocations' aux data table.
    std::set<auxdata::Relocation> RelocationTuples;
    for(const auto &Relocation : Elf->relocations())
    {
        std::string SymbolName;
        std::string SectionName;
        if(Relocation.has_section())
        {
            const LIEF::ELF::Section *Section = Relocation.section();
            if(!Section->has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC))
            {
                // Ignore relocations that are applied to un-loaded sections.
                continue;
            }
            SectionName = Section->name();
        }

        if(Relocation.has_symbol())
        {
            SymbolName = Relocation.symbol()->name();
            auto SymbolVersion = Relocation.symbol()->symbol_version();
            if(SymbolVersion && SymbolVersion->value() > LIEF::ELF::VER_NDX_GLOBAL)
            {
                SymbolName += "@" + std::to_string(SymbolVersion->value());
            }
        }

        uint64_t Address = Relocation.address();
        if(Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL
           && Relocation.purpose() == LIEF::ELF::RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT)
        {
            // Rebase relocation offset for object-file relocations.
            if(Relocation.has_section())
            {
                Address = SectionRelocations[Relocation.section()->name()] + Address;
            }
        }

        // RELA relocations have an explicit addend field, and REL relocations store an
        // implicit addend in the location to be modified.
        std::string RelType = Relocation.is_rela() ? "RELA" : "REL";

        RelocationTuples.insert({Address, getRelocationType(Relocation), SymbolName,
                                 Relocation.addend(), Relocation.info(), SectionName, RelType});
    }
    Module->addAuxData<gtirb::schema::Relocations>(std::move(RelocationTuples));

    std::vector<std::string> Libraries = Elf->imported_libraries();
    Module->addAuxData<gtirb::schema::Libraries>(std::move(Libraries));

    std::vector<std::string> LibraryPaths;
    for(const auto &Entry : Elf->dynamic_entries())
    {
        if(const auto RunPath = dynamic_cast<const LIEF::ELF::DynamicEntryRunPath *>(&Entry))
        {
            std::vector<std::string> Paths = RunPath->paths();
            LibraryPaths.insert(LibraryPaths.end(), Paths.begin(), Paths.end());
        }
        if(const auto Rpath = dynamic_cast<const LIEF::ELF::DynamicEntryRpath *>(&Entry))
        {
            std::vector<std::string> Paths = Rpath->paths();
            LibraryPaths.insert(LibraryPaths.end(), Paths.begin(), Paths.end());
        }
    }
    Module->addAuxData<gtirb::schema::LibraryPaths>(std::move(LibraryPaths));

    // Get dynamic entries
    std::map<std::string, uint64_t> DynamicEntries = getDynamicEntries();
    std::set<auxdata::ElfDynamicEntry> DynamicEntryTuples;
    for(auto it = DynamicEntries.begin(); it != DynamicEntries.end(); ++it)
    {
        DynamicEntryTuples.insert({it->first, it->second});
    }
    Module->addAuxData<gtirb::schema::DynamicEntries>(std::move(DynamicEntryTuples));
}

std::string ElfReader::getRelocationType(const LIEF::ELF::Relocation &Entry)
{
    switch(Entry.architecture())
    {
        case LIEF::ELF::ARCH::EM_X86_64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_x86_64>(Entry.type()));
        case LIEF::ELF::ARCH::EM_386:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_i386>(Entry.type()));
        case LIEF::ELF::ARCH::EM_ARM:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_ARM>(Entry.type()));
        case LIEF::ELF::ARCH::EM_AARCH64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_AARCH64>(Entry.type()));
        case LIEF::ELF::ARCH::EM_PPC:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_POWERPC32>(Entry.type()));
        case LIEF::ELF::ARCH::EM_PPC64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_POWERPC64>(Entry.type()));
        default:
            return std::to_string(Entry.type());
    }
}

uint64_t ElfReader::tlsBaseAddress()
{
    if(!TlsBaseAddress)
    {
        // Find the largest virtual address.
        uint64_t VirtualEnd = 0;
        for(auto &Segment : Elf->segments())
        {
            VirtualEnd = std::max(VirtualEnd, Segment.virtual_address() + Segment.virtual_size());
        }
        // Use the next available page.
        TlsBaseAddress = (VirtualEnd & ~(0x1000 - 1)) + 0x1000;
    }
    return TlsBaseAddress;
}

void ElfReader::relocateSections()
{
    struct AddressRange
    {
        std::string Name;
        uint64_t Align;
        std::pair<uint64_t, uint64_t> Range;

        bool operator<(const AddressRange &Other) const
        {
            return Range < Other.Range;
        }
    };

    struct Disjunct
    {
        bool operator()(AddressRange Lhs, AddressRange Rhs) const
        {
            return std::get<1>(Lhs.Range) <= std::get<0>(Rhs.Range);
        };
    };

    // Begin with a sorted set of offset intervals.
    std::multiset<AddressRange> Offsets;
    for(const auto &S : Elf->sections())
    {
        if(S.virtual_address() == 0 && S.size() > 0
           && S.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC))
        {
            uint64_t Start = S.offset() - Elf->header().header_size();
            uint64_t End = Start + S.size();
            Offsets.insert({S.name(), S.alignment(), {Start, End}});
        }
    }

    // Compose a set of disjunct address ranges from the sorted offset intervals.
    std::multiset<AddressRange, Disjunct> Addresses;

    // Place non-overlapping sections.
    uint64_t NextOffset = 0;
    for(auto It = Offsets.begin(); It != Offsets.end();)
    {
        auto [Start, End] = It->Range;
        if(NextOffset <= Start)
        {
            // Allocate non-overlapping address range.
            Addresses.insert(*It);
            It = Offsets.erase(It);
            NextOffset = End;
        }
        else
        {
            // Skip overlapping section.
            It++;
        }
    }

    // Place remaining overlapping sections in allocation gaps.
    for(auto [Name, Align, Range] : Offsets)
    {
        auto [Start, End] = Range;
        uint64_t Size = End - Start;
        Align = std::max(uint64_t(8), Align);

        AddressRange Relocated = {Name, Align, Range};

        for(auto Prev = Addresses.begin(); Prev != Addresses.end(); Prev++)
        {
            // Align with previous section.
            Start = (std::get<1>(Prev->Range) + (Align - 1)) & ~(Align - 1);
            End = Start + Size;
            Relocated.Range = {Start, End};

            // Peek next element.
            auto Next = Prev;
            Next++;

            if(Next == Addresses.end() || End <= std::get<0>(Next->Range))
            {
                // Fits between previous and next section.
                Addresses.insert(Relocated);
                break;
            }
        }
    }

    for(const AddressRange &Range : Addresses)
    {
        SectionRelocations[Range.Name] = std::get<0>(Range.Range);
    }
}
