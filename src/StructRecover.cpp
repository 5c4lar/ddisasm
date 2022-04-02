#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <gtirb/gtirb.hpp>
#include <iomanip>
#include <iostream>
#include <sleigh/libsleigh.hh>
#include <string>
#include <thread>
#include <vector>

#include "AuxDataSchema.h"
#include "Version.h"
#include "llvm/Demangle/Demangle.h"
#include "loadimage_bfd.h"
#include "printLLVM.h"

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
    gtirb::AuxDataContainer::registerAuxDataType<SouffleFacts>();
    gtirb::AuxDataContainer::registerAuxDataType<SouffleOutputs>();
}

class AssemblyRaw : public AssemblyEmit
{
public:
    void dump(const Address &addr, const string &mnem, const string &body) override
    {
        std::stringstream ss;
        addr.printRaw(ss);
        ss << ": " << mnem << ' ' << body;
        std::cout << ss.str() << std::endl;
    }
};

static void dumpAssembly(const Translate *trans, uint64_t Start, uint64_t Size)

{                          // Print disassembly of binary code
    AssemblyRaw assememit; // Set up the disassembly dumper
    int4 length;           // Number of bytes of each machine instruction

    Address addr(trans->getDefaultCodeSpace(), Start);            // First disassembly address
    Address lastaddr(trans->getDefaultCodeSpace(), Start + Size); // Last disassembly address

    while(addr < lastaddr)
    {
        length = trans->printAssembly(assememit, addr);
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
            data.space->printOffset(s, data.offset);
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
    PcodeRawOut(const Translate *t) : trans(t)
    {
    }

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
            print_vardata(ss, *outvar);
            ss << " = ";
        }
        ss << get_opname(opc);
        // Possibly check for a code reference or a space reference
        ss << ' ';
        // For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
        if(isize > 1 && vars[0].size == sizeof(AddrSpace *) && vars[0].space->getName() == "const"
           && (vars[0].offset >> 24) == ((uintb)vars[1].space >> 24)
           && trans == ((AddrSpace *)vars[0].offset)->getTrans())
        {
            ss << ((AddrSpace *)vars[0].offset)->getName();
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
        std::cout << ss.str() << std::endl;
    }
};

static void dumpPcode(const Translate *trans, uint64_t Start, uint64_t Size)

{                            // Dump pcode translation of machine instructions
    PcodeRawOut emit(trans); // Set up the pcode dumper
    AssemblyRaw assememit;   // Set up the disassembly dumper
    int4 length;             // Number of bytes of each machine instruction

    Address addr(trans->getDefaultCodeSpace(), Start);            // First address to translate
    Address lastaddr(trans->getDefaultCodeSpace(), Start + Size); // Last address

    while(addr < lastaddr)
    {
        std::cout << "--- ";
        trans->printAssembly(assememit, addr);
        length = trans->oneInstruction(emit, addr); // Translate instruction
        addr = addr + length;                       // Advance to next instruction
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
        data.getSpace()->printOffset(s, data.getOffset());
        s << ',' << dec << data.getSize() << ')';
    }
    else
    {
        s << '(' << data.getSpace()->getName() << ',';
        data.getSpace()->printOffset(s, data.getOffset());
        s << ',' << dec << data.getSize() << ')';
    }
}

void dump(PcodeOp *pcode)
{
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
        print_vardata(ss, *outvar);
        ss << " = ";
    }
    ss << get_opname(opc);
    // Possibly check for a code reference or a space reference
    ss << ' ';
    // For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
    if(isize > 1 && pcode->getIn(0)->getSize() == sizeof(AddrSpace *)
       && pcode->getIn(0)->getSpace()->getName() == "const"
       && (pcode->getIn(0)->getOffset() >> 24) == ((uintb)pcode->getIn(1)->getSpace() >> 24))
    {
        ss << ((AddrSpace *)pcode->getIn(0)->getOffset())->getName();
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
    std::cout << ss.str() << std::endl;
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

template <class TupType, size_t... I>
void print(const TupType &_tup, std::index_sequence<I...>)
{
    std::cout << "(";
    (..., (std::cout << (I == 0 ? "" : ", ") << std::get<I>(_tup)));
    std::cout << ")\n";
}

template <class... T>
void print(const std::tuple<T...> &_tup)
{
    print(_tup, std::make_index_sequence<sizeof...(T)>());
}
std::map<std::string, std::string> TypedefMap = {{"size_t", "typedef uint8 size_t;"},
                                                 {"int", "typedef int4 int;"}};
std::map<std::string, std::string> FuncProtoMap = {
    {"malloc", "extern void *malloc(size_t size);"},
    {"printf", "extern int printf(char * format, ...);"},
    {"__cxa_finalize", "extern void __cxa_finalize(void * d);"},
    {"_Znwm", "extern void * _Znwm(size_t size);"},
    {"puts", "extern int puts(char * str);"}};

namespace facts
{
    struct Element
    {
        virtual void print(std::ostream &s) const = 0;
        virtual Element *create(std::string &s) = 0;
        virtual void set(std::string &s) = 0;
    };

    struct StringElement : public Element
    {
        std::string str;
        StringElement()
        {
        }
        StringElement(std::string _str) : str(_str)
        {
        }
        void set(std::string &s) override
        {
            str = s;
        }
        Element *create(std::string &s) override
        {
            return new StringElement(s);
        }
        void print(std::ostream &s) const override
        {
            s << str;
        }
    };

    struct IntElement : public Element
    {
        int64_t i;
        IntElement()
        {
        }
        IntElement(int64_t _i) : i(_i)
        {
        }
        IntElement(std::string &s) : i(std::stoll(s))
        {
        }
        void set(std::string &s) override
        {
            i = std::stoll(s);
        }
        Element *create(std::string &s) override
        {
            return new IntElement(s);
        }
        void print(std::ostream &s) const override
        {
            s << i;
        }
    };

    struct UnsignedElement : public Element
    {
        uint64_t u;
        UnsignedElement()
        {
        }
        UnsignedElement(uint64_t _u) : u(_u)
        {
        }
        UnsignedElement(std::string &s) : u(std::stoull(s))
        {
        }
        void set(std::string &s) override
        {
            u = std::stoull(s);
        }
        Element *create(std::string &s) override
        {
            return new UnsignedElement(s);
        }
        void print(std::ostream &s) const override
        {
            s << "0x" << std::hex << u;
        }
    };

    struct FloatElement : public Element
    {
        double f;
        FloatElement()
        {
        }
        FloatElement(double _f) : f(_f)
        {
        }
        FloatElement(std::string &s) : f(std::stod(s))
        {
        }
        void set(std::string &s) override
        {
            f = std::stod(s);
        }
        Element *create(std::string &s) override
        {
            return new FloatElement(s);
        }
        void print(std::ostream &s) const override
        {
            s << f;
        }
    };

    struct Relation
    {
        std::string name;
        std::vector<Element *> elements;
        std::vector<std::vector<Element *>> tuples;
        Relation(const std::string &_name, const std::string &_signature, const std::string &Csv)
            : name(_name)
        {
            std::vector<std::string> tok;
            boost::split(tok, _signature, boost::is_any_of("<,>"));
            for(auto &t : tok)
            {
                switch(t[0])
                {
                    case 's':
                        elements.push_back(new StringElement());
                        break;
                    case 'i':
                        elements.push_back(new IntElement());
                        break;
                    case 'u':
                        elements.push_back(new UnsignedElement());
                        break;
                    case 'f':
                        elements.push_back(new FloatElement());
                        break;
                    default:
                        break;
                }
            }
            load(Csv);
        }

        void load(const std::string &Csv)
        {
            std::vector<std::string> lines;
            boost::split(lines, Csv, boost::is_any_of("\n"), boost::token_compress_on);
            for(auto &line : lines)
            {
                std::vector<std::string> tokens;
                std::vector<Element *> row;
                boost::split(tokens, line, boost::is_any_of("\n\r\t "), boost::token_compress_on);
                if(tokens.size() != elements.size())
                    continue;
                for(size_t i = 0; i < tokens.size(); i++)
                {
                    row.push_back(elements[i]->create(tokens[i]));
                }
                tuples.push_back(row);
            }
        }
        void print(std::ostream &s) const
        {
            s << "Relation " << name << std::endl;
            for(size_t i = 0; i < tuples.size(); i++)
            {
                for(size_t j = 0; j < tuples[i].size(); j++)
                {
                    if(j == 0)
                    {
                        s << "(";
                    }
                    else
                    {
                        s << ", ";
                    }
                    tuples[i][j]->print(s);
                }
                s << ")\n";
            }
        }
    };

    static Relation *loadFacts(std::map<std::string, std::tuple<std::string, std::string>> *facts,
                               const std::string &name)
    {
        auto iter = facts->find(name);
        if(iter == facts->end())
        {
            return nullptr;
        }
        auto &fact = iter->second;
        std::string signature = std::get<0>(fact);
        std::string Csv = std::get<1>(fact);
        return new Relation(name, signature, Csv);
    }
} // namespace facts

int main(int argc, char **argv)
{
    registerAuxDataTypes();
    po::options_description desc("Allowed options");
    llvm::ItaniumPartialDemangler demangler;
    desc.add_options()                                                  //
        ("help,h", "produce help message")                              //
        ("version", "display ddisasm version")                          //
        ("ir", po::value<std::string>(), "GTIRB output file")           //
        ("json", po::value<std::string>(), "GTIRB json output file")    //
        ("debug", "generate assembler file with debugging information") //
        ("debug-dir", po::value<std::string>(),                         //
         "location to write CSV files for debugging")                   //
        ("input-file", po::value<std::string>(), "gtirb input file")    //
        ("lang,l", po::value<std::string>()->default_value("x86:LE:64:default"), "language id")(
            "sleigh-home", po::value<std::string>()->default_value("/usr/local/share/sleigh"),
            "sleigh home dir")(
            "threads,j",
            po::value<unsigned int>()->default_value(std::thread::hardware_concurrency()),
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
        po::notify(vm);
    }
    catch(std::exception &e)
    {
        std::cout << "Error: " << e.what() << "\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    if(vm.count("input-file") < 1)
    {
        std::cout << "Error: missing input file\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    std::cout << "starting sleigh library" << std::endl;
    startDecompilerLibrary(vm["sleigh-home"].as<std::string>().c_str());

    std::cout << "Reading initial gtirb representation " << std::flush;
    auto StartReadBaseIR = std::chrono::high_resolution_clock::now();
    std::string filename = vm["input-file"].as<std::string>();
    std::ifstream In(filename);
    gtirb::Context Context;
    auto NewIRp = gtirb::IR::load(Context, In);
    if(!NewIRp)
    {
        std::cout << "\nERROR: " << filename << ": " << NewIRp.getError().message() << std::endl;
        return 1;
    }
    auto IR = *NewIRp;

    printElapsedTimeSince(StartReadBaseIR);

    if(!IR)
    {
        std::cout << "There was a problem loading the GTIRB file " << filename << std::endl;
        return 1;
    }
    for(auto Module = IR->modules_begin(); Module != IR->modules_end(); ++Module)
    {
        auto BinaryPath = Module->getBinaryPath();
        std::cout << "Module " << Module->getName() << ": " << BinaryPath << std::endl;
        BfdArchitecture arch(BinaryPath, "default", &std::cout);
        try
        {
            DocumentStorage store;
            arch.init(store);
            arch.print->setOutputStream(&std::cout);
            arch.setPrintLanguage("llvm-language");
        }
        catch(LowlevelError &e)
        {
            std::cout << "Error: " << e.explain << std::endl;
            return 1;
        }
        auto print_llvm = dynamic_cast<PrintLLVM *>(arch.print);
        auto string_manager = arch.stringManager;
        auto type_factory = arch.types;
        auto code_space = arch.getDefaultCodeSpace();
        auto data_space = arch.getDefaultDataSpace();
        auto glb_scope = arch.symboltab->getGlobalScope();
        auto *FunctionEntries = Module->getAuxData<gtirb::schema::FunctionEntries>();
        auto *FunctionBlocks = Module->getAuxData<gtirb::schema::FunctionBlocks>();
        auto *FunctionNames = Module->getAuxData<gtirb::schema::FunctionNames>();
        auto *SymbolForwardings = Module->getAuxData<gtirb::schema::SymbolForwarding>();
        auto *ElfSymbolInfo = Module->getAuxData<gtirb::schema::ElfSymbolInfo>();
        auto *DynamicEntries = Module->getAuxData<gtirb::schema::DynamicEntries>();
        auto *Relocations = Module->getAuxData<gtirb::schema::Relocations>();
        auto *Encodings = Module->getAuxData<gtirb::schema::Encodings>();
        auto *SouffleOutputs = Module->getAuxData<gtirb::schema::SouffleOutputs>();
        auto *SouffleFacts = Module->getAuxData<gtirb::schema::SouffleFacts>();
        auto *SymbolicOperand = facts::loadFacts(SouffleOutputs, "symbolic_operand");
        auto *OperandAttribute = facts::loadFacts(SouffleOutputs, "symbolic_operand_attribute");
        auto *SymbolicExpr = facts::loadFacts(SouffleOutputs, "symbolic_expr");
        auto *String = facts::loadFacts(SouffleOutputs, "string");
        String->print(std::cout);
        std::map<uint64_t, std::string> SymbolForwardingsMap;
        std::map<uint64_t, std::string> InternalFunc;
        std::map<uint64_t, std::string> GlobalDataSymbolMap;
        std::map<uint64_t, std::set<uint64_t>> SymbolUsePointMap;
        std::map<uint64_t, std::string> OperandAttrMap;
        std::map<uint64_t, std::string> EncodingMap;
        std::set<std::string> ExternalFunc;
        std::set<uint64_t> DataSymbolCandidateSet;
        std::set<uint64_t> DataSymbolSet;
        std::set<uint64_t> CodeSymbolSet;
        OperandAttribute->print(std::cout);
        for(auto &tuple : OperandAttribute->tuples)
        {
            auto sym_addr = dynamic_cast<facts::UnsignedElement *>(tuple[0])->u;
            auto attr = dynamic_cast<facts::StringElement *>(tuple[2])->str;
            OperandAttrMap.insert(std::make_pair(sym_addr, attr));
        }
        SymbolicOperand->print(std::cout);
        for(auto &tuple : SymbolicOperand->tuples)
        {
            auto sym_addr = dynamic_cast<facts::UnsignedElement *>(tuple[2])->u;
            auto use_point = dynamic_cast<facts::UnsignedElement *>(tuple[0])->u;
            auto type = dynamic_cast<facts::StringElement *>(tuple[3])->str;
            SymbolUsePointMap[sym_addr].insert(use_point);
            if(type == "code")
            {
                CodeSymbolSet.insert(sym_addr);
            }
            else if(type == "data")
            {
                if(OperandAttrMap.count(use_point) == 0)
                {
                    DataSymbolCandidateSet.insert(sym_addr);
                }
            }
        }
        std::set_difference(DataSymbolCandidateSet.begin(), DataSymbolCandidateSet.end(),
                            CodeSymbolSet.begin(), CodeSymbolSet.end(),
                            std::inserter(DataSymbolSet, DataSymbolSet.begin()));
        std::cout << "Listing SymbolForwardings" << std::endl;
        for(const auto &[SymUUID0, SymUUID1] : *SymbolForwardings)
        {
            auto Sym0 = gtirb::Node::getByUUID(Context, SymUUID0);
            auto Sym1 = gtirb::Node::getByUUID(Context, SymUUID1);
            auto SymName0 = dyn_cast_or_null<gtirb::Symbol>(Sym0);
            auto SymName1 = dyn_cast_or_null<gtirb::Symbol>(Sym1);
            std::cout << SymName0->getAddress().value() << "==>" << SymName0->getName() << " -> "
                      << SymName1->getName() << std::endl;
            SymbolForwardingsMap.insert(std::pair<uint64_t, std::string>(
                static_cast<uint64_t>(SymName0->getAddress().value()), SymName1->getName()));
        }
        SymbolicExpr->print(std::cout);
        for(auto &tuple : SymbolicExpr->tuples)
        {
            auto sym_addr = dynamic_cast<facts::UnsignedElement *>(tuple[0])->u;
            auto expr = dynamic_cast<facts::StringElement *>(tuple[2])->str;
            if(expr.rfind("FUN_", 0) == 0)
            { // pos=0 limits the search to the prefix
                auto num = std::stoull(expr.substr(4, expr.size() - 4));
                std::stringstream s;
                s << "FUN_" << std::hex << num;
                SymbolForwardingsMap.insert(std::make_pair(sym_addr, s.str()));
            }
            else if(expr.rfind(".L_") == 0)
            {
                auto num = std::stoull(expr.substr(3, expr.size() - 3));
                std::stringstream s;
                s << ".L_" << std::hex << num;
                SymbolForwardingsMap.insert(std::make_pair(sym_addr, s.str()));
            }
            else if(expr.find("@") != std::string::npos)
            {
                continue;
            }
            else
            {
                SymbolForwardingsMap.insert(std::make_pair(sym_addr, expr));
            }
        }
        std::cout << "-----------------------" << std::endl;
        std::cout << "Listing ElfSymbolInfo" << std::endl;
        for(const auto &[SymUUID, SymbolInfo] : *ElfSymbolInfo)
        {
            auto Sym = gtirb::Node::getByUUID(Context, SymUUID);
            auto SymName = dyn_cast_or_null<gtirb::Symbol>(Sym);
            if(SymName->getAddress().has_value())
            {
                auto Addr = static_cast<uint64_t>(SymName->getAddress().value());
                std::cout << SymName->getAddress().value() << "==>" << SymName->getName() << " -> ";
                if(SymbolForwardingsMap.count(Addr) == 0 && std::get<1>(SymbolInfo) == "FUNC")
                {
                    InternalFunc.insert(std::make_pair(Addr, SymName->getName()));
                }
                else if(DataSymbolSet.count(Addr) != 0 && GlobalDataSymbolMap.count(Addr) == 0)
                {
                    GlobalDataSymbolMap.insert(std::make_pair(Addr, SymName->getName()));
                }
                else if(GlobalDataSymbolMap.count(Addr))
                {
                    auto extern_name = GlobalDataSymbolMap[Addr];
                    if(std::get<1>(SymbolInfo) != "OBJECT")
                    {
                        GlobalDataSymbolMap[Addr] = SymName->getName();
                    }
                    else
                    {
                        extern_name = SymName->getName();
                    }
                    SymbolForwardingsMap.insert(
                        std::pair<uint64_t, std::string>(Addr, extern_name));
                }
                print(SymbolInfo);
            }
            else
            {
                std::cout << "unkonwn ==>" << SymName->getName() << " -> ";
                if(std::get<1>(SymbolInfo) == "FUNC")
                {
                    ExternalFunc.insert(SymName->getName());
                }
                print(SymbolInfo);
            }
        }
        std::cout << "-----------------------" << std::endl;
        std::cout << "Listing DynamicEntries" << std::endl;
        for(const auto &Entry : *DynamicEntries)
        {
            print(Entry);
        }
        std::cout << "-----------------------" << std::endl;
        if(Relocations)
        {
            std::cout << "Listing Relocations" << std::endl;
            for(const auto Reloc : *Relocations)
            {
                print(Reloc);
            }
            std::cout << "-----------------------" << std::endl;
        }
        std::cout << "Listing Encodings" << std::endl;
        for(const auto &[UUID, Encoding] : *Encodings)
        {
            auto DataBlockNode = gtirb::Node::getByUUID(Context, UUID);
            auto DataBlock = dyn_cast_or_null<gtirb::DataBlock>(DataBlockNode);
            auto Addr = static_cast<uint64_t>(DataBlock->getAddress().value());
            std::cout << DataBlock->getAddress() << "==>" << DataBlock->getSize() << " "
                      << Encoding;
            std::string s(DataBlock->bytes_begin<char>(), DataBlock->bytes_end<char>());
            std::cout << " " << s << std::endl;
            EncodingMap.insert(std::pair<uint64_t, std::string>(Addr, Encoding));
        }
        std::cout << "-----------------------" << std::endl;
        std::cout << "Listing FunctionEntries" << std::endl;
        vector<uint64_t> FunctionEntryAddresses;
        for(const auto &[FunctionUUID, Entries] : *FunctionEntries)
        {
            std::cout << "FunctionUUID: " << boost::uuids::to_string(FunctionUUID) << std::endl;
            auto NameUUID = (*FunctionNames)[FunctionUUID];
            auto FunctionNameUUID = gtirb::Node::getByUUID(Context, NameUUID);
            auto FunctionName = dyn_cast_or_null<gtirb::Symbol>(FunctionNameUUID);
            if(!FunctionName)
            {
                std::cout << "There was a problem loading the FunctionName aux data table\n";
                return 1;
            }
            else
            {
                std::cout << "FunctionName: " << FunctionName->getName() << std::endl;
            }
            for(auto &Entry : Entries)
            {
                auto EntryBlockNode = gtirb::Node::getByUUID(Context, Entry);
                auto EntryBlock = dyn_cast_or_null<gtirb::CodeBlock>(EntryBlockNode);
                uint64_t Addr = static_cast<uint64_t>(*(EntryBlock->getAddress()));
                std::cout << "Entry at " << Addr << std::endl;
                auto iter = SymbolForwardingsMap.find(Addr);
                auto Name =
                    iter == SymbolForwardingsMap.end() ? FunctionName->getName() : iter->second;
                glb_scope->addFunction(Address(arch.getDefaultCodeSpace(), Addr), Name);
                FunctionEntryAddresses.push_back(Addr);
            }
        }
        for(auto &[Addr, Name] : GlobalDataSymbolMap)
        {
            auto biter = Module->findDataBlocksAt(gtirb::Addr(Addr));
            if(biter.empty())
            {
                continue;
            }
            auto &Datablock = biter.front();
            auto size = Datablock.getSize();
            auto iter = SymbolUsePointMap.find(Addr);
            auto content = std::vector<uint8_t>(Datablock.bytes_begin<uint8_t>(),
                                                Datablock.bytes_end<uint8_t>());
            auto forwarding =
                SymbolForwardingsMap.count(Addr) != 0 ? SymbolForwardingsMap[Addr] : "";
            auto data = std::string(content.begin(), content.end());
            auto encoding = EncodingMap.count(Addr) != 0 ? EncodingMap[Addr] : "";
            auto unkown_type = type_factory->getBase(1, type_metatype::TYPE_UNKNOWN);
            auto sym = glb_scope->addSymbol(Name, unkown_type);
            auto SymAddr = Address(data_space, Addr);
            if(iter != SymbolUsePointMap.end())
            {
                for(auto use_point : iter->second)
                {
                    std::cout << "Processing Addr " << std::hex << Addr << std::endl;
                    print_llvm->setSym(use_point, Name, Addr, size, content, encoding, forwarding);
                    std::cout << "Inserting UsePoint: " << std::hex << Addr << " " << Name << " at "
                              << std::hex << use_point << " of size " << std::hex << size << " : "
                              << data << " forwarding to " << forwarding << std::endl;
                    auto SymUsePoint = Address(code_space, use_point);
                    glb_scope->addMapPoint(sym, SymAddr, SymUsePoint);
                }
            }
        }
        std::cout << "-----------------------" << std::endl;
        std::cout << "Lifting Functions" << std::endl;
        for(auto &[Name, Def] : TypedefMap)
        {
            std::cout << "    " << Name << std::endl;
            auto s = std::istringstream(Def);
            try
            {
                parse_C(&arch, s);
            }
            catch(LowlevelError e)
            {
                std::cerr << e.explain << std::endl;
            }
        }
        for(auto Name : ExternalFunc)
        {
            auto iter = FuncProtoMap.find(Name);
            if(iter != FuncProtoMap.end())
            {
                std::cout << "    " << Name << std::endl;
                auto s = std::istringstream(iter->second);
                try
                {
                    parse_C(&arch, s);
                }
                catch(LowlevelError e)
                {
                    std::cerr << e.explain << std::endl;
                }
            }
            else
            {
                if(demangler.partialDemangle(Name.c_str()))
                {
                    std::cout << "    " << Name << " not demangled" << std::endl;
                }
                else
                {
                    std::stringstream s;
                    char *result = static_cast<char *>(malloc(0x20));
                    size_t size = 0x20;
                    result = demangler.getFunctionReturnType(result, &size);
                    std::string FunctionReturnType(result, result + strlen(result));
                    s << FunctionReturnType;
                    result = demangler.getFunctionName(result, &size);
                    std::string FunctionName(result, result + strlen(result));
                    s << FunctionName;
                    result = demangler.getFunctionParameters(result, &size);
                    std::string FunctionParameters(result, result + strlen(result));
                    s << FunctionParameters;
                    free(result);
                    std::cout << "    " << Name << "==>" << s.str() << std::endl;
                }
            }
        }
        for(auto &[Addr, Name] : InternalFunc)
        {
            std::cout << "Lifting " << Name << " at " << Addr << std::endl;
            Funcdata *func = glb_scope->findFunction(Address(arch.getDefaultCodeSpace(), Addr));
            if(!func)
            {
                std::cout << "Function not found\n";
                continue;
            }
            std::cout << func->getName() << std::endl;
            auto action = arch.allacts.getCurrent();
            action->reset(*func);
            auto res = action->perform(*func);
            func->printRaw(std::cout);
            AssemblyRaw assememit;
            for(auto &fb : func->getBasicBlocks().getList())
            {
                auto bb = dynamic_cast<BlockBasic *>(fb);
                for(auto op = bb->beginOp(); op != bb->endOp(); ++op)
                {
                    dump(*op);
                }
            }
            arch.print->docFunction(func);
            std::cout << "---" << std::endl;
        }
        for(auto &[Addr, Name] : InternalFunc)
        {
            Funcdata *func = glb_scope->findFunction(Address(arch.getDefaultCodeSpace(), Addr));
            print_llvm->buildFunction(func);
        }
        std::cout << "-----------------------" << std::endl;
        print_llvm->dumpLLVM(BinaryPath + ".ll");
        print_llvm->dumpLLVM("-");
        arch.shutdown();
        print_llvm->docAllGlobals();
    }

    return 0;
}
