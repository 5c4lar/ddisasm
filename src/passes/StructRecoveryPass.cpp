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
    CompositeLoader Loader("souffle_struct_recovery");
    
    Loader.add(BlocksLoader);
    Loader.add(CfgLoader);
    Loader.add(SymbolicExpressionLoader);

    if(Module.getISA() == gtirb::ISA::X64)
        Loader.add<CodeBlockLoader<X64Loader>>();

    if(Module.getAuxData<gtirb::schema::Padding>())
        Loader.add(PaddingLoader{&Context});
    if(Module.getAuxData<gtirb::schema::CfiDirectives>())
        Loader.add(FdeEntriesLoader{&Context});
    if(Module.getAuxData<gtirb::schema::FunctionEntries>())
        Loader.add(FunctionEntriesLoader{&Context});

    // Load GTIRB and build program.
    std::optional<DatalogProgram> StructRecovery = Loader.load(Module);

    if(!StructRecovery)
    {
        std::cerr << "Could not create souffle_function_inference program" << std::endl;
        exit(1);
    }

    loadRelations(StructRecovery->get(), *RelationDir);
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
