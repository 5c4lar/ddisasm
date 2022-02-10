//===- StructRecoveryPass.cpp --------------------------------*- C++ -*-===//

//===----------------------------------------------------------------------===//
#include "StructRecoveryPass.h"

#include <boost/uuid/uuid_generators.hpp>

#include "../AuxDataSchema.h"
#include "../gtirb-decoder/CompositeLoader.h"
#include "../gtirb-decoder/arch/X64Loader.h"
#include "../gtirb-decoder/core/AuxDataLoader.h"
#include "../gtirb-decoder/core/EdgesLoader.h"
#include "../gtirb-decoder/core/InstructionLoader.h"
#include "../gtirb-decoder/core/SymbolicExpressionLoader.h"

void StructRecoveryPass::updateStructs(gtirb::Context& Context, gtirb::Module& Module,
                                            souffle::SouffleProgram* Program)
{
    
}

void StructRecoveryPass::computeStructs(gtirb::Context& Context, gtirb::Module& Module,
                                             unsigned int NThreads)
{
    std::cout << "Hello, struct recovery pass!" << std::endl;
    CompositeLoader Loader("souffle_struct_recovery");
    // Load GTIRB and build program.
    std::optional<DatalogProgram> StructRecovery = Loader.load(Module);
    Loader.add(BlocksLoader);
    Loader.add(CfgLoader);
    Loader.add(SymbolicExpressionLoader);

    if(Module.getISA() == gtirb::ISA::X64)
        Loader.add<CodeBlockLoader<X64Loader>>();
    if(Module.getAuxData<gtirb::schema::FunctionEntries>())
        Loader.add(FunctionEntriesLoader{&Context});
    if(!StructRecovery)
    {
        std::cerr << "Could not create souffle_function_inference program" << std::endl;
        exit(1);
    }

    // Run function inference analysis.
    StructRecovery->threads(NThreads);
    StructRecovery->run();

    if(DebugDir)
    {
        StructRecovery->writeFacts(*DebugDir);
        StructRecovery->writeRelations(*DebugDir);
    }

    updateStructs(Context, Module, StructRecovery->get());
}
