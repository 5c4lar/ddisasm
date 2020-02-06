//===- GtirbZeroBuilder.cpp -------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

#include "GtirbZeroBuilder.h"
#include "BinaryReader.h"
#include "LIEFBinaryReader.h"

bool isExeSection(const gtirb::FileFormat format, const SectionProperties &s)
{
    uint64_t flags = std::get<1>(s);
    if(format == gtirb::FileFormat::ELF)
        return flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
    else if(format == gtirb::FileFormat::PE)
        return flags & static_cast<int>(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);
    return false;
};

bool isNonZeroDataSection(const gtirb::FileFormat format, const SectionProperties &s)
{
    uint64_t type = std::get<0>(s);
    uint64_t flags = std::get<1>(s);

    if(format == gtirb::FileFormat::ELF)
    {
        bool is_allocated = flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
        bool is_not_executable =
            !(flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR));
        // SHT_NOBITS is not considered here because it is for data sections but without initial
        // data (zero initialized)
        bool is_non_zero_program_data =
            type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS)
            || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_INIT_ARRAY)
            || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_FINI_ARRAY)
            || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PREINIT_ARRAY);
        return is_allocated && is_not_executable && is_non_zero_program_data;
    }

    if(format == gtirb::FileFormat::PE)
    {
        return flags
               & static_cast<int>(
                     LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA);
    }

    return false;
};

bool isAllocatedSection(const gtirb::FileFormat format, int flags)
{
    if(format == gtirb::FileFormat::ELF)
        return (flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC));
    else if(format == gtirb::FileFormat::PE)
        return (flags & static_cast<int>(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ));
    return false;
}

std::string gtirb::auxdata_traits<ExtraSymbolInfo>::type_id()
{
    return "ExtraSymbolInfo";
}

void gtirb::auxdata_traits<ExtraSymbolInfo>::toBytes(const ExtraSymbolInfo &Object, to_iterator It)
{
    auxdata_traits<uint64_t>::toBytes(Object.size, It);
    auxdata_traits<std::string>::toBytes(Object.type, It);
    auxdata_traits<std::string>::toBytes(Object.scope, It);
    auxdata_traits<uint64_t>::toBytes(Object.sectionIndex, It);
}

gtirb::from_iterator gtirb::auxdata_traits<ExtraSymbolInfo>::fromBytes(ExtraSymbolInfo &Object,
                                                                       from_iterator It)
{
    It = auxdata_traits<uint64_t>::fromBytes(Object.size, It);
    It = auxdata_traits<std::string>::fromBytes(Object.type, It);
    It = auxdata_traits<std::string>::fromBytes(Object.scope, It);
    It = auxdata_traits<uint64_t>::fromBytes(Object.sectionIndex, It);
    return It;
}
void buildSections(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                   gtirb::Context &context)
{
    std::map<gtirb::UUID, SectionProperties> sectionProperties;
    for(auto &binSection : binary->get_sections())
    {
        if(isAllocatedSection(binary->get_binary_format(), binSection.flags))
        {
            // Create Section object and set common flags
            gtirb::Section *section = module.addSection(context, binSection.name);
            section->addFlag(gtirb::SectionFlag::Loaded);
            // TODO: Add other section flags (Readable, Writable, ...)

            /// Add allocated section contents to a single contiguous ByteInterval.
            if(isAllocatedSection(binSection.flags))
            {
                std::vector<uint8_t> &sectionBytes = std::get<0>(*sectionData);
                gtirb::ByteInterval *byteInterval = section->addByteInterval(
                    context, gtirb::Addr(binSection.address), binSection.size);
                if(auto sectionData = binary->get_section_content_and_address(binSection.name))
                {
                    std::vector<uint8_t> &sectionBytes = std::get<0>(*sectionData);
                    byteInterval->insertBytes<uint8_t>(byteInterval->bytes_begin<uint8_t>(),
                                                       sectionBytes.begin(), sectionBytes.end());
                }
            }

            void buildSections(gtirb::Module & module, std::shared_ptr<BinaryReader> binary,
                               gtirb::Context & context)
            {
                std::map<gtirb::UUID, SectionProperties> sectionProperties;
                for(auto &binSection : binary->get_sections())
                {
                    if(isAllocatedSection(binSection.flags))
                    {
                        gtirb::Section *section = gtirb::Section::Create(
                            context, binSection.name, gtirb::Addr(binSection.address),
                            binSection.size);
                        module.addSection(section);
                        // Add object specific flags to elfSectionProperties AuxData table.
                        sectionProperties[section->getUUID()] =
                            std::make_tuple(binSection.type, binSection.flags);
                    }
                }
                if(auto entryBlock =
                       module.findCodeBlocksIn(gtirb::Addr(binary->get_entry_point()));
                   !entryBlock.empty())
                {
                    module.setEntryPoint(&*entryBlock.begin());
                }
                module.addAuxData("elfSectionProperties", std::move(sectionProperties));
            }

            void buildSymbols(gtirb::Module & module, std::shared_ptr<BinaryReader> binary,
                              gtirb::Context & context)
            {
                std::map<gtirb::UUID, ExtraSymbolInfo> extraSymbolInfoTable;
                for(auto &binSymbol : binary->get_symbols())
                {
                    // Symbols with special section index do not have an address
                    gtirb::Symbol *symbol;
                    if(binSymbol.sectionIndex
                           == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
                       || (binSymbol.sectionIndex
                               >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
                           && binSymbol.sectionIndex
                                  <= static_cast<int>(
                                         LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
                    {
                        symbol = module.addSymbol(context, binSymbol.name);
                    }
                    else
                    {
                        // TODO: Add symbol type
                        symbol = module.addSymbol(context, gtirb::Addr(binSymbol.address),
                                                  binSymbol.name);
                    }
                    extraSymbolInfoTable[symbol->getUUID()] = {
                        binSymbol.size, binSymbol.type, binSymbol.scope, binSymbol.sectionIndex};
                }
                module.addAuxData("extraSymbolInfo", std::move(extraSymbolInfoTable));
            }
            void addAuxiliaryTables(gtirb::Module & module, std::shared_ptr<BinaryReader> binary)
            {
                std::vector<std::string> binaryType = {binary->get_binary_type()};
                module.addAuxData("binaryType", binaryType);
                module.addAuxData("relocations", binary->get_relocations());
                module.addAuxData("libraries", binary->get_libraries());
                module.addAuxData("libraryPaths", binary->get_library_paths());
                if(binary->get_binary_format() == gtirb::FileFormat::PE)
                {
                    module.addAuxData("dataDirectories", binary->get_data_directories());
                    module.addAuxData("importEntries", binary->get_import_entries());
                }
            }

            gtirb::IR *buildZeroIR(const std::string &filename, gtirb::Context &context)
            {
                std::shared_ptr<BinaryReader> binary(new LIEFBinaryReader(filename));
                if(!binary->is_valid())
                    return nullptr;
                auto ir = gtirb::IR::Create(context);
                gtirb::Module &module = *gtirb::Module::Create(context);
                module.setBinaryPath(filename);
                module.setFileFormat(binary->get_binary_format());
                module.setISA(gtirb::ISA::X64);
                ir->addModule(&module);
                buildSections(module, binary, context);
                buildSymbols(module, binary, context);
                addAuxiliaryTables(module, binary);

                return ir;
            }
