//===- StructRecoveryPass.cpp --------------------------------*- C++ -*-===//

//===----------------------------------------------------------------------===//
#include "StructRecoveryPass.h"

#include <boost/uuid/uuid_generators.hpp>
#include <boost/tokenizer.hpp>
#include <boost/filesystem.hpp>
#include "../AuxDataSchema.h"
#include "../gtirb-decoder/CompositeLoader.h"
#include "../gtirb-decoder/arch/X64Loader.h"
#include "../gtirb-decoder/core/AuxDataLoader.h"
#include "../gtirb-decoder/core/EdgesLoader.h"
#include "../gtirb-decoder/core/InstructionLoader.h"
#include "../gtirb-decoder/core/SymbolicExpressionLoader.h"

static bool loadFacts(DatalogProgram &Program, const std::string &Dir) {
    typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
    for (const auto & entry: boost::filesystem::directory_iterator(Dir)) {
        if (entry.path().extension() == ".csv") {
            auto relation_name = entry.path().stem().string();
            std::ifstream file(entry.path().string());
            auto Relation = Program.get()->getRelation(relation_name);
            if (!Relation) {
                continue;
            }
            std::string line;
            std::vector<std::string> vec;
            while (getline(file, line)) {
                vec.clear();
                tokenizer tok(line, boost::char_separator<char>("\n\r\t "));
                vec.assign(tok.begin(), tok.end());
                souffle::tuple Row(Relation);
                for (size_t i = 0; i < Relation->getArity(); i++) {
                    switch (*Relation->getAttrType(i))
                    {
                    case 's':
                        Row << vec[i];
                        break;
                    case 'f':
                        Row << static_cast<souffle::RamFloat>(std::stod(vec[i]));
                        break;
                    case 'i':
                        Row << static_cast<souffle::RamSigned>(std::stoll(vec[i]));
                        break;
                    case 'u':
                        Row << static_cast<souffle::RamUnsigned>(std::stoull(vec[i]));
                        break;
                    default:
                        break;
                    }
                }
                Relation->insert(Row);
            }
        }
    }
    return true;
}

void StructRecoveryPass::computeStructs(unsigned int NThreads, souffle::SouffleProgram* Program, std::string FactsDir)
{
    auto SouffleProgram =
               std::shared_ptr<souffle::SouffleProgram>(souffle::ProgramFactory::newInstance("souffle_struct_recovery"));
    if (!SouffleProgram) {
        std::cerr << "Could not create Souffle program" << std::endl;
        return;
    }
    auto StructRecovery = DatalogProgram(SouffleProgram);
    loadFacts(StructRecovery, FactsDir);
    loadRelations(StructRecovery.get(), Program);
    if(DebugDir)
    {
        StructRecovery.writeFacts(*DebugDir);
    }
    StructRecovery.threads(NThreads);
    StructRecovery.run();
    if(DebugDir)
    {
        StructRecovery.writeRelations(*DebugDir);
    }
}
