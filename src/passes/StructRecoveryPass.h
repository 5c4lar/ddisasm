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

    void loadRelations(souffle::SouffleProgram* P, std::string Path)
    {
        P->loadAll(Path);
    }

    void computeStructs(gtirb::Context& C, gtirb::Module& M, unsigned int NThreads);

private:
    std::optional<std::string> RelationDir;
    std::optional<std::string> DebugDir;
    void updateStructs(gtirb::Context& C, gtirb::Module& M, souffle::SouffleProgram* P);
};
#endif // STRUCT_RECOVERY_PASS_H_
