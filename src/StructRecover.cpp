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

#include <sleigh/libsleigh.hh>

#include "loadimage_bfd.h"
#include "AuxDataSchema.h"
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
    gtirb::AuxDataContainer::registerAuxDataType<Comments>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<Padding>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolInfo>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolVersions>();
    gtirb::AuxDataContainer::registerAuxDataType<BinaryType>();
    gtirb::AuxDataContainer::registerAuxDataType<Sccs>();
    gtirb::AuxDataContainer::registerAuxDataType<Relocations>();
    gtirb::AuxDataContainer::registerAuxDataType<DynamicEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionIndex>();
    gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
    gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolicExpressionSizes>();
    gtirb::AuxDataContainer::registerAuxDataType<DdisasmVersion>();
}

class AssemblyRaw : public AssemblyEmit
{
	public:
		void dump(const Address &addr, const string &mnem, const string &body) override
		{
			std::stringstream ss;
			addr.printRaw(ss);
			ss << ": " << mnem << ' ' << body;
			std::cerr << ss.str() << std::endl;
		}
};


static void dumpAssembly(const Translate *trans, uint64_t Start, uint64_t Size)

{ // Print disassembly of binary code
  AssemblyRaw assememit;	// Set up the disassembly dumper
  int4 length;			// Number of bytes of each machine instruction

  Address addr(trans->getDefaultCodeSpace(),Start); // First disassembly address
  Address lastaddr(trans->getDefaultCodeSpace(),Start + Size); // Last disassembly address

  while(addr < lastaddr) {
    length = trans->printAssembly(assememit,addr);
    addr = addr + length;
  }
}

class PcodeRawOut : public PcodeEmit
{
	private:
		const Translate *trans = nullptr;

		void print_vardata(ostream &s, VarnodeData &data)
		{
			AddrSpace *space = data.space;
			if(space->getName() == "register" || space->getName() == "mem")
			    s << space->getTrans()->getRegisterName(data.space, data.offset, data.size);
		    else if(space->getName() == "ram")
		    {
			    if(data.size == 1)
				    s << "byte_ptr(";
			    if(data.size == 2)
				    s << "word_ptr(";
			    if(data.size == 4)
				    s << "dword_ptr(";
			    if(data.size == 8)
				    s << "qword_ptr(";
			    space->printRaw(s, data.offset);
			    s << ')';
		    }
		    else if(space->getName() == "const")
			    static_cast<ConstantSpace *>(space)->printRaw(s, data.offset);
		    else if(space->getName() == "unique")
		    {
			    s << '(' << data.space->getName() << ',';
			    data.space->printOffset(s, data.offset);
			    s << ',' << dec << data.size << ')';
		    }
		    else if(space->getName() == "DATA")
			{
				s << '(' << data.space->getName() << ',';
				data.space->printOffset(s,data.offset);
				s << ',' << dec << data.size << ')';
			}
			else
			{
			    s << '(' << data.space->getName() << ',';
			    data.space->printOffset(s, data.offset);
			    s << ',' << dec << data.size << ')';
		    }
	    }

	public:
	    PcodeRawOut(const Translate *t): trans(t) {}

	    void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars,
	              int4 isize) override
	    {
		    std::stringstream ss;
		    // if(opc == CPUI_STORE && isize == 3)
		    // {
			//     print_vardata(ss, vars[2]);
			//     ss << " = ";
			//     isize = 2;
		    // }
		    if(outvar)
		    {
			    print_vardata(ss,*outvar);
				ss << " = ";
		    }
		    ss << get_opname(opc);
			// Possibly check for a code reference or a space reference
			ss << ' ';
			// For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
			if (isize > 1 && vars[0].size == sizeof(AddrSpace *) && vars[0].space->getName() == "const"
				&& (vars[0].offset >> 24) == ((uintb)vars[1].space >> 24) && trans == ((AddrSpace*)vars[0].offset)->getTrans())
			{
				ss << ((AddrSpace*)vars[0].offset)->getName();
			    ss << '[';
			    print_vardata(ss, vars[1]);
			    ss << ']';
			    for(int4 i = 2; i < isize; ++i)
			    {
				    ss << ", ";
				    print_vardata(ss, vars[i]);
			    }
		    }
		    else
		    {
			    print_vardata(ss, vars[0]);
			    for(int4 i = 1; i < isize; ++i)
			    {
				    ss << ", ";
					print_vardata(ss, vars[i]);
			    }
		    }
            std::cerr << ss.str() << std::endl;
			// rz_cons_printf("    %s\n", ss.str().c_str());
	    }
};

static void dumpPcode(const Translate *trans, uint64_t Start, uint64_t Size)

{ // Dump pcode translation of machine instructions
  PcodeRawOut emit(trans);		// Set up the pcode dumper
  AssemblyRaw assememit;	// Set up the disassembly dumper
  int4 length;			// Number of bytes of each machine instruction

  Address addr(trans->getDefaultCodeSpace(),Start); // First address to translate
  Address lastaddr(trans->getDefaultCodeSpace(),Start + Size); // Last address

  while(addr < lastaddr) {
    std::cerr << "--- ";
    trans->printAssembly(assememit,addr);
    length = trans->oneInstruction(emit,addr); // Translate instruction
    addr = addr + length;		// Advance to next instruction
  }
}

void print_vardata(ostream &s, Varnode &data)
{
    AddrSpace *space = data.getSpace();
    if(space->getName() == "register" || space->getName() == "mem")
        s << space->getTrans()->getRegisterName(data.getSpace(), data.getOffset(), data.getSize());
    else if(space->getName() == "ram")
    {
        if(data.getSize() == 1)
            s << "byte_ptr(";
        if(data.getSize() == 2)
            s << "word_ptr(";
        if(data.getSize() == 4)
            s << "dword_ptr(";
        if(data.getSize() == 8)
            s << "qword_ptr(";
        space->printRaw(s, data.getOffset());
        s << ')';
    }
    else if(space->getName() == "const")
        static_cast<ConstantSpace *>(space)->printRaw(s, data.getOffset());
    else if(space->getName() == "unique")
    {
        s << '(' << data.getSpace()->getName() << ',';
        data.getSpace()->printOffset(s, data.getOffset());
        s << ',' << dec << data.getSize() << ')';
    }
    else if(space->getName() == "DATA")
    {
        s << '(' << data.getSpace()->getName() << ',';
        data.getSpace()->printOffset(s,data.getOffset());
        s << ',' << dec << data.getSize() << ')';
    }
    else
    {
        s << '(' << data.getSpace()->getName() << ',';
        data.getSpace()->printOffset(s, data.getOffset());
        s << ',' << dec << data.getSize() << ')';
    }
}

void dump(PcodeOp *pcode) {
    auto opc = pcode->getOpcode()->getOpcode();
    auto outvar = pcode->getOut();
    auto isize = pcode->numInput();
    std::stringstream ss;
    // if(opc == CPUI_STORE && isize == 3)
    // {
    //     print_vardata(ss, *(pcode->getIn(2)));
    //     ss << " = ";
    //     isize = 2;
    // }
    if(outvar)
    {
        print_vardata(ss,*outvar);
        ss << " = ";
    }
    ss << get_opname(opc);
    // Possibly check for a code reference or a space reference
    ss << ' ';
    // For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
    if (isize > 1 && pcode->getIn(0)->getSize() == sizeof(AddrSpace *) && pcode->getIn(0)->getSpace()->getName() == "const"
        && (pcode->getIn(0)->getOffset() >> 24) == ((uintb)pcode->getIn(1)->getSpace() >> 24))
    {
        ss << ((AddrSpace*)pcode->getIn(0)->getOffset())->getName();
        ss << '[';
        print_vardata(ss, *(pcode->getIn(1)));
        ss << ']';
        for(int4 i = 2; i < isize; ++i)
        {
            ss << ", ";
            print_vardata(ss, *(pcode->getIn(i)));
        }
    }
    else
    {
        print_vardata(ss, *(pcode->getIn(0)));
        for(int4 i = 1; i < isize; ++i)
        {
            ss << ", ";
            print_vardata(ss, *(pcode->getIn(i)));
        }
    }
    std::cerr << ss.str() << std::endl;
}

void printElapsedTimeSince(std::chrono::time_point<std::chrono::high_resolution_clock> Start)
{
    auto End = std::chrono::high_resolution_clock::now();
    std::cout << " (";
    int secs = std::chrono::duration_cast<std::chrono::seconds>(End - Start).count();
    if(secs != 0)
        std::cout << secs << "s)" << std::endl;
    else
        std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(End - Start).count()
                  << "ms)" << std::endl;
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
        ("lang,l", po::value<std::string>()->default_value("x86:LE:64:default"), "language id")
        ("sleigh-home", po::value<std::string>()->default_value("/usr/local/share/sleigh"), "sleigh home dir")
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
                      << desc << std::endl;
            return 1;
        }
        if(vm.count("version"))
        {
            std::cout << DDISASM_FULL_VERSION_STRING << std::endl;
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

    std::cerr << "starting sleigh library" << std::endl;
    startDecompilerLibrary(vm["sleigh-home"].as<std::string>().c_str());

    std::cerr << "Reading initial gtirb representation " << std::flush;
    auto StartReadBaseIR = std::chrono::high_resolution_clock::now();
    std::string filename = vm["input-file"].as<std::string>();
    std::ifstream In(filename);
    gtirb::Context Context;
    auto NewIRp = gtirb::IR::load(Context, In);
    if(!NewIRp)
    {
        std::cerr << "\nERROR: " << filename << ": " << NewIRp.getError().message() << std::endl;
        return 1;
    }
    auto IR = *NewIRp;

    // Add `ddisasmVersion' aux data table.
    IR->addAuxData<gtirb::schema::DdisasmVersion>(DDISASM_FULL_VERSION_STRING);
    printElapsedTimeSince(StartReadBaseIR);

    if(!IR)
    {
        std::cerr << "There was a problem loading the GTIRB file " << filename << std::endl;
        return 1;
    }

    for(auto Module = IR->modules_begin(); Module != IR->modules_end(); ++Module)
    {
        auto BinaryPath = Module->getBinaryPath();
        std::cerr << "Module " << Module->getName() << ": " << BinaryPath << std::endl;
        BfdArchitecture arch(BinaryPath, "default", &std::cerr);
        try {
            DocumentStorage store;
            arch.init(store);
            arch.print->setOutputStream(&std::cerr);
            arch.setPrintLanguage("llvm-language");
        } catch (LowlevelError& e) {
            std::cerr << "Error: " << e.explain << std::endl;
            return 1;
        }
        auto *FunctionEntries = Module->getAuxData<gtirb::schema::FunctionEntries>();
        auto *FunctionBlocks = Module->getAuxData<gtirb::schema::FunctionBlocks>();
        auto *FunctionNames = Module->getAuxData<gtirb::schema::FunctionNames>();
        vector<uint64_t> FunctionEntryAddresses;
        for(const auto &[FunctionUUID, Entries] : *FunctionEntries)
        {
            std::cerr << "FunctionUUID: " << boost::uuids::to_string(FunctionUUID) << std::endl;
            auto NameUUID = (*FunctionNames)[FunctionUUID];
            auto FunctionNameUUID = gtirb::Node::getByUUID(Context, NameUUID);
            auto FunctionName = dyn_cast_or_null<gtirb::Symbol>(FunctionNameUUID);
            if(!FunctionName)
            {
                std::cerr << "There was a problem loading the FunctionName aux data table\n";
                return 1;
            }
            else
            {
                std::cerr << "FunctionName: " << FunctionName->getName() << std::endl;
            }
            for (auto &Entry: Entries) {
                auto EntryBlockNode = gtirb::Node::getByUUID(Context, Entry);
                auto EntryBlock = dyn_cast_or_null<gtirb::CodeBlock>(EntryBlockNode);
                uint64_t Addr = static_cast<uint64_t>(*(EntryBlock->getAddress()));
                std::cerr << "Entry at " << Addr << std::endl;
                arch.symboltab->getGlobalScope()->addFunction(Address(arch.getDefaultCodeSpace(), Addr), FunctionName->getName());
                FunctionEntryAddresses.push_back(Addr);
            }
            auto It = FunctionBlocks->find(FunctionUUID);
            assert(It != FunctionBlocks->end());
            auto &Blocks = It->second;
            for(auto BlockUUID : Blocks)
            {
                auto BlockNode = gtirb::Node::getByUUID(Context, BlockUUID);
                assert(BlockNode);
                auto Block = dyn_cast_or_null<gtirb::CodeBlock>(BlockNode);
                assert(Block);
                std::cerr << "    " << Block->getAddress() << std::endl;
                uint64_t Addr = static_cast<uint64_t>(*(Block->getAddress()));
                uint64_t Size = Block->getSize();
                try {
                    dumpPcode(arch.translate, Addr, Size);
                    // dumpAssembly(arch.translate, Addr, Size);
                }
                catch (LowlevelError e) {
                    std::cerr << e.explain << std::endl;
                    return -1;
                }
            }
        }
        for (auto Addr : FunctionEntryAddresses) {
            Funcdata *func = arch.symboltab->getGlobalScope()->findFunction(Address(arch.getDefaultCodeSpace(), Addr));
            if (!func) {
                std::cerr << "Function not found\n";
                continue;
            }
            std::cerr << func->getName() << std::endl;
            auto action = arch.allacts.getCurrent();
            // action->setBreakPoint(Action::breakflags::break_start, "mergerequired");
            action->reset(*func);
            action->printState(std::cerr);
            std::cerr << std::endl;
            // func->printRaw(std::cerr);
            auto res = action->perform(*func);
            action->printState(std::cerr);
            std::cerr << std::endl;
            func->printRaw(std::cerr);
            // AssemblyRaw assememit;
            
            // for (auto &fb: func->getBasicBlocks().getList()) {
            //     auto bb = reinterpret_cast<BlockBasic*>(fb);
            //     for (auto op = bb->beginOp(); op != bb->endOp(); ++op) {
            //         dump(*op);
            //     }
            // }
            // for (auto op = func->beginOpAll(); op != func->endOpAll(); ++op) {
                // std::cerr << "--- ";
                // arch.translate->printAssembly(assememit,op->first.getAddr());
            //     std::cerr << op->first.getOrder() << ": ";
            //     dump(op->second);
            // }
            arch.print->docFunction(func);
            std::cerr << "---" << std::endl;
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
