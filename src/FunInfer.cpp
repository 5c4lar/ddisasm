//===- FunInfer.cpp ---------------------------------------*- C++ -*-===//
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
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "AuxDataSchema.h"
#include "PrintUtils.h"
#include "Version.h"
#include "passes/FunctionInferencePass.h"
#include "passes/NoReturnPass.h"
#include "passes/SccPass.h"

// Modified version that starts with reading GTIRB instead of processing
// an ELF file through the regular disassembly Datalog system.

namespace fs = boost::filesystem;
namespace po = boost::program_options;

namespace std
{
    // program_options default values need to be printable.
    std::ostream &operator<<(std::ostream &os, const std::vector<std::string> &vec)
    {
        for(auto item : vec)
        {
            os << item << ",";
        }
        return os;
    }
} // namespace std

void registerAuxDataTypes()
{
    using namespace gtirb::schema;
    using namespace gtirb::provisional_schema;
    gtirb::AuxDataContainer::registerAuxDataType<Comments>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<Padding>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolInfo>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolVersions>();
    gtirb::AuxDataContainer::registerAuxDataType<BinaryType>();
    gtirb::AuxDataContainer::registerAuxDataType<ArchInfo>();
    gtirb::AuxDataContainer::registerAuxDataType<Sccs>();
    gtirb::AuxDataContainer::registerAuxDataType<Relocations>();
    gtirb::AuxDataContainer::registerAuxDataType<DynamicEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
    gtirb::AuxDataContainer::registerAuxDataType<SectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<SectionIndex>();
    gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
    gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolicExpressionSizes>();
    gtirb::AuxDataContainer::registerAuxDataType<DdisasmVersion>();
}

int main(int argc, char **argv)
{
    registerAuxDataTypes();

    po::options_description desc("Allowed options");
    desc.add_options()                                                  //
        ("help,h", "produce help message")                              //
        ("version", "display ddisasm version")                          //
        ("ir", po::value<std::string>(), "GTIRB output file")           //
        ("json", po::value<std::string>(), "GTIRB json output file")    //
        ("debug", "generate assembler file with debugging information") //
        ("debug-dir", po::value<std::string>(),                         //
         "location to write CSV files for debugging")                   //
        ("input-file", po::value<std::string>(), "gtirb input file")    //
        ("threads,j", po::value<unsigned int>()->default_value(std::thread::hardware_concurrency()),
         "Number of cores to use. It is set to the number of cores in the machine by default");
    po::positional_options_description pd;
    pd.add("input-file", -1);

    po::variables_map vm;
    try
    {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);

        if(vm.count("help"))
        {
            std::cout << "Usage: " << argv[0] << " [OPTIONS...] INPUT_FILE\n"
                      << "Run function analysis on gtirb INPUT_FILE and output resulting gtirb.\n\n"
                      << desc << "\n";
            return 1;
        }
        if(vm.count("version"))
        {
            std::cout << DDISASM_FULL_VERSION_STRING << "\n";
            return EXIT_SUCCESS;
        }
        po::notify(vm);
    }
    catch(std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    if(vm.count("input-file") < 1)
    {
        std::cerr << "Error: missing input file\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    std::cout << "Reading initial gtirb representation " << std::flush;
    auto StartReadBaseIR = std::chrono::high_resolution_clock::now();
    std::string filename = vm["input-file"].as<std::string>();
    std::ifstream In(filename);
    gtirb::Context Context;
    auto NewIRp = gtirb::IR::load(Context, In);
    if(!NewIRp)
    {
        std::cerr << "\nERROR: " << filename << ": " << NewIRp.getError().message() << "\n";
        return 1;
    }
    auto IR = *NewIRp;

    // Add `ddisasmVersion' aux data table.
    IR->addAuxData<gtirb::schema::DdisasmVersion>(DDISASM_FULL_VERSION_STRING);
    printElapsedTimeSince(StartReadBaseIR);
    std::cerr << "\n";

    if(!IR)
    {
        std::cerr << "There was a problem loading the GTIRB file " << filename << "\n";
        return 1;
    }

    fs::path DebugDirRoot;
    if(vm.count("debug-dir"))
    {
        DebugDirRoot = vm["debug-dir"].as<std::string>();
    }

    auto Modules = IR->modules();
    unsigned int ModuleCount = std::distance(std::begin(Modules), std::end(Modules));
    for(auto &Module : Modules)
    {
        std::cerr << "Processing module: " << Module.getName() << "\n";
        std::list<std::unique_ptr<AnalysisPass>> Pipeline;
        Pipeline.push_back(std::make_unique<SccPass>());
        Pipeline.push_back(std::make_unique<NoReturnPass>());
        Pipeline.push_back(std::make_unique<FunctionInferencePass>());

        for(auto &Pass : Pipeline)
        {
            std::cerr << std::setw(IndentWidth) << "" << std::left << std::setw(PassNameWidth)
                      << Pass->getName();

            if(!DebugDirRoot.empty())
            {
                fs::path PassDebugDir = DebugDirRoot;
                if(ModuleCount > 1)
                {
                    PassDebugDir /= Module.getName();
                }
                Pass->setDebugRoot(PassDebugDir);
            }

            if(Pass->hasLoad())
            {
                std::cerr << std::right << std::setw(PassStepWidth) << "load " << std::flush;
                if(printPassResults(Pass->load(Context, Module)))
                {
                    // warnings emitted - indent line appropriately
                    std::cerr << std::setw(IndentWidth + PassNameWidth + PassStepWidth + TimeWidth)
                              << "";
                }
            }
            else
            {
                std::cerr << std::setw(PassStepWidth + TimeWidth) << "";
            }
            std::cerr << std::flush;

            if(DatalogAnalysisPass *DatalogPass = dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
            {
                // datalog-only configuration
                DatalogPass->setThreadCount(vm["threads"].as<unsigned int>());
            }

            std::cerr << std::right << std::setw(PassStepWidth) << "compute " << std::flush;
            printPassResults(Pass->analyze(Module));

            if(Pass->hasTransform())
            {
                std::cerr << std::right << std::setw(PassStepWidth) << "transform " << std::flush;
                if(printPassResults(Pass->transform(Context, Module)))
                {
                    // warnings emitted - indent line appropriately
                    std::cerr << std::setw(IndentWidth + PassNameWidth
                                           + 2 * (PassStepWidth + TimeWidth))
                              << "";
                }
            }
            else
            {
                std::cerr << std::setw(PassStepWidth + TimeWidth) << "";
            }

            std::cerr << "\n";
        }
    }

    // Output GTIRB
    if(vm.count("ir") != 0)
    {
        std::ofstream out(vm["ir"].as<std::string>(), std::ios::out | std::ios::binary);
        IR->save(out);
    }
    // Output json GTIRB
    if(vm.count("json") != 0)
    {
        std::ofstream out(vm["json"].as<std::string>());
        IR->saveJSON(out);
    }

    return 0;
}
