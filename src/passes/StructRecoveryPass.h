//===- StructRecoveryPass.h ----------------------------------*- C++ -*-===//
//===----------------------------------------------------------------------===//
#ifndef VAR_RECOVERY_PASS_H_
#define VAR_RECOVERY_PASS_H_

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

    void computeStructs(gtirb::Context& C, gtirb::Module& M, unsigned int NThreads);

private:
    std::optional<std::string> DebugDir;
    void updateStructs(gtirb::Context& C, gtirb::Module& M, souffle::SouffleProgram* P);
};
#endif // FUNCTION_INFERENCE_PASS_H_
