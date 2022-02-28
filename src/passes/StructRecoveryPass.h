//===- StructRecoveryPass.h ----------------------------------*- C++ -*-===//
//===----------------------------------------------------------------------===//
#ifndef STRUCT_RECOVERY_PASS_H_
#define STRUCT_RECOVERY_PASS_H_

#include <souffle/SouffleInterface.h>

#include <gtirb/gtirb.hpp>
#include <optional>

// Refine function boundaries.
class StructRecoveryPass
{
public:
    void setDebugDir(std::string Path)
    {
        DebugDir = Path;
    };

    void setRelationDir(std::string Path)
    {
        RelationDir = Path;
    };

    void loadRelations(souffle::SouffleProgram* P, souffle::SouffleProgram* Main)
    {
        auto InputRelations = P->getInputRelations();
        for (auto Relation: InputRelations) {
            souffle::Relation *LoadedRelation;
            auto Name = Relation->getName();
            if ((LoadedRelation = Main->getRelation(Name)) ||
                (LoadedRelation = Main->getRelation(std::string("arch.") + Name)) ||
                (LoadedRelation = Main->getRelation(std::string("function_inference.") + Name))) {
                for (auto tuple: *LoadedRelation)
                {
                    souffle::tuple Row(Relation);
                    std::string str;
                    souffle::RamFloat ramFloat;
                    souffle::RamSigned ramSigned;
                    souffle::RamUnsigned ramUnsigned;
                    for (size_t i = 0; i < Relation->getArity(); i++) {
                        switch (*(Relation->getAttrType(i)))
                        {
                        case 's':
                            tuple >> str;
                            Row << str;
                            break;
                        case 'f':
                            tuple >> ramFloat;
                            Row << ramFloat;
                            break;
                        case 'i':
                            tuple >> ramSigned;
                            Row << ramSigned;
                            break;
                        case 'u':
                            tuple >> ramUnsigned;
                            Row << ramUnsigned;
                            break;
                        default:
                            break;
                        }
                    }
                    Relation->insert(Row);
                }
            } else {
                continue;
            }
        }
    }

    void computeStructs(unsigned int NThreads, souffle::SouffleProgram* Program, std::string FactsDir);

private:
    std::optional<std::string> RelationDir;
    std::optional<std::string> DebugDir;
};
#endif // STRUCT_RECOVERY_PASS_H_
