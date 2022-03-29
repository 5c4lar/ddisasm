/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file printc.hh
/// \brief Classes to support the llvm-language back-end of the decompiler

#ifndef __PRINTLLVM__
#define __PRINTLLVM__

#include <sleigh/libsleigh.hh>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"

class FuncProto;
class JumpTable;

/// \brief Factory and static initializer for the "llvm-language" back-end to the decompiler
///
/// The singleton adds itself to the list of possible back-end languages for the decompiler
/// and it acts as a factory for producing the PrintLLVM object for emitting llvm-language tokens.
class PrintLLVMCapability : public PrintLanguageCapability
{
    static PrintLLVMCapability printLLVMCapability;                ///< The singleton instance
    PrintLLVMCapability(void);                                     ///< Initialize the singleton
    PrintLLVMCapability(const PrintLLVMCapability &op2);           ///< Not implemented
    PrintLLVMCapability &operator=(const PrintLLVMCapability &op); ///< Not implemented
public:
    virtual PrintLanguage *buildLanguage(Architecture *glb);
};

/// \brief A structure for pushing nested fields to the RPN stack
///
/// A helper class for unraveling a nested reference to a field. It links the
/// data-type, field name, field object, and token together
// struct PartialSymbolEntry {
//   const OpToken *token;		///< Operator used to drill-down to the field
//   const TypeField *field;	///< The component object describing the field
//   const Datatype *parent;	///< The parent data-type owning the field
//   string fieldname;		///< The name of the field
//   EmitXml::syntax_highlight hilite;	///< Highlight information for the field token
// };

/// \brief The llvm-language token emitter
///
/// The llvm-language specific rules for emitting:
///  - expressions
///  - statements
///  - function prototypes
///  - variable declarations
///  - if/else structures
///  - loop structures
///  - etc.
class PrintLLVM : public PrintLanguage
{
protected:
    static OpToken hidden;         ///< Hidden functional (that may force parentheses)
    static OpToken scope;          ///< The sub-scope/namespace operator
    static OpToken object_member;  ///< The \e member operator
    static OpToken pointer_member; ///< The \e points \e to \e member operator
    static OpToken subscript;      ///< The array subscript operator
    static OpToken function_call;  ///< The \e function \e call operator
    static OpToken bitwise_not;    ///< The \e bitwise \e negate operator
    static OpToken boolean_not;    ///< The \e boolean \e not operator
    static OpToken unary_minus;    ///< The \e unary \e minus operator
    static OpToken unary_plus;     ///< The \e unary \e plus operator
    static OpToken addressof;      ///< The \e address \e of operator
    static OpToken dereference;    ///< The \e pointer \e dereference operator
    static OpToken typecast;       ///< The \e type \e cast operator
    static OpToken multiply;       ///< The \e multiplication operator
    static OpToken divide;         ///< The \e division operator
    static OpToken modulo;         ///< The \e modulo operator
    static OpToken binary_plus;    ///< The \e binary \e addition operator
    static OpToken binary_minus;   ///< The \e binary \e subtraction operator
    static OpToken shift_left;     ///< The \e left \e shift operator
    static OpToken shift_right;    ///< The \e right \e shift operator
    static OpToken shift_sright;   ///< The signed \e right \e shift operator
    static OpToken less_than;      ///< The \e less \e than operator
    static OpToken less_equal;     ///< The \e less \e than \e or \e equal operator
    static OpToken greater_than;   ///< The \e greater \e than operator
    static OpToken greater_equal;  ///< The \e greater \e than \e or \e equal operator
    static OpToken equal;          ///< The \e equal operator
    static OpToken not_equal;      ///< The \e not \e equal operator
    static OpToken bitwise_and;    ///< The \e logical \e and operator
    static OpToken bitwise_xor;    ///< The \e logical \e xor operator
    static OpToken bitwise_or;     ///< The \e logical \e or operator
    static OpToken boolean_and;    ///< The \e boolean \e and operator
    static OpToken boolean_or;     ///< The \e boolean \e or operator
    static OpToken boolean_xor;    ///< The \e boolean \e xor operator
    static OpToken assignment;     ///< The \e assignment operator
    static OpToken comma;          ///< The \e comma operator (for parameter lists)
    static OpToken new_op;         ///< The \e new operator
    static OpToken multequal;      ///< The \e in-place \e multiplication operator
    static OpToken divequal;       ///< The \e in-place \e division operator
    static OpToken remequal;       ///< The \e in-place \e modulo operator
    static OpToken plusequal;      ///< The \e in-place \e addition operator
    static OpToken minusequal;     ///< The \e in-place \e subtraction operator
    static OpToken leftequal;      ///< The \e in-place \e left \e shift operator
    static OpToken rightequal;     ///< The \e in-place \e right \e shift operator
    static OpToken andequal;       ///< The \e in-place \e logical \e and operator
    static OpToken orequal;        ///< The \e in-place \e logical \e or operator
    static OpToken xorequal;       ///< The \e in-place \e logical \e xor operator
    static OpToken
        type_expr_space; ///< Type declaration involving a space (identifier or adornment)
    static OpToken type_expr_nospace; ///< Type declaration with no space
    static OpToken ptr_expr;          ///< Pointer adornment for a type declaration
    static OpToken array_expr;        ///< Array adornment for a type declaration
    static OpToken enum_cat;          ///< The \e concatenation operator for enumerated values
    static const string
        typePointerRelToken;  ///< The token to print indicating PTRSUB relative to a TypePointerRel
    bool option_NULL;         ///< Set to \b true if we should emit NULL keyword
    bool option_inplace_ops;  ///< Set to \b true if we should use '+=' '&=' etc.
    bool option_convention;   ///< Set to \b true if we should print calling convention
    bool option_nocasts;      ///< Don't print a cast if \b true
    bool option_unplaced;     ///< Set to \b true if we should display unplaced comments
    bool option_hide_exts;    ///< Set to \b true if we should hide implied extension operations
    string nullToken;         ///< Token to use for 'null'
    CommentSorter commsorter; ///< Container/organizer for comments in the current function

    std::unique_ptr<llvm::LLVMContext> LLVM_Context;
    std::unique_ptr<llvm::IRBuilder<>> IRBuilder;
    std::unique_ptr<llvm::Module> LLVM_Module;
    std::map<const Funcdata *, llvm::Function *> LLVM_FunctionMap;
    std::map<const Varnode *, llvm::Value *> LLVM_ValueMap;
    std::map<const BlockBasic *, llvm::BasicBlock *> LLVM_BlockMap;
    std::map<const Address, llvm::Value *> LLVM_StackVarMap;
    std::set<const PcodeOp *> PhiOps;

    // Routines that are specific to C/C++
    void buildTypeStack(const Datatype *ct,
                        vector<const Datatype *>
                            &typestack); ///< Prepare to push components of a data-type declaration
    void pushPrototypeInputs(const FuncProto *proto); ///< Push input parameters
    void pushSymbolScope(const Symbol *symbol);       ///< Push tokens resolving a symbol's scope
    void emitSymbolScope(const Symbol *symbol);       ///< Emit tokens resolving a symbol's scope
    virtual void pushTypeStart(const Datatype *ct,
                               bool noident); ///< Push part of a data-type declaration onto the RPN
                                              ///< stack, up to the identifier
    virtual void pushTypeEnd(
        const Datatype *ct); ///< Push the tail ends of a data-type declaration onto the RPN stack
    void pushBoolConstant(uintb val, const TypeBase *ct, const Varnode *vn, const PcodeOp *op);
    void pushCharConstant(uintb val, const Datatype *ct, const Varnode *vn, const PcodeOp *op);
    void pushEnumConstant(uintb val, const TypeEnum *ct, const Varnode *vn, const PcodeOp *op);
    virtual bool pushPtrCharConstant(uintb val, const TypePointer *ct, const Varnode *vn,
                                     const PcodeOp *op);
    bool pushPtrCodeConstant(uintb val, const TypePointer *ct, const Varnode *vn,
                             const PcodeOp *op);
    virtual bool doEmitWideCharPrefix(void) const;

    bool checkArrayDeref(const Varnode *vn)
        const; ///< Determine whether a LOAD/STORE expression requires pointer '*' syntax
    void emitStructDefinition(
        const TypeStruct *ct); ///< Emit the definition of a \e structure data-type
    void emitEnumDefinition(
        const TypeEnum *ct); ///< Emit the definition of an \e enumeration data-type
    void emitPrototypeOutput(
        const FuncProto *proto,
        const Funcdata *fd); ///< Emit the output data-type of a function prototype
    void emitPrototypeInputs(
        const FuncProto *proto); ///< Emit the input data-types of a function prototype
    void emitGlobalVarDeclsRecursive(
        Scope *symScope); ///< Emit variable declarations for all global symbols under given scope
    void emitLocalVarDecls(const Funcdata *fd); ///< Emit variable declarations for a function
    void emitStatement(const PcodeOp *inst);    ///< Emit a statement in the body of a function
    bool emitInplaceOp(
        const PcodeOp *op); ///< Attempt to emit an expression rooted at an \e in-place operator
    void emitGotoStatement(const FlowBlock *bl, const FlowBlock *exp_bl, uint4 type);
    void emitSwitchCase(int4 casenum,
                        const BlockSwitch *switchbl); ///< Emit labels for a \e case block
    void emitLabel(const FlowBlock *bl); ///< Emit a formal label for a given control-flow block
    void emitLabelStatement(
        const FlowBlock *bl); ///< Emit any required label statement for a given basic block
    void emitAnyLabelStatement(
        const FlowBlock *bl); ///< Emit any required label statement for a given control-flow block
    void emitCommentGroup(const PcodeOp *inst); ///< Emit comments associated with a given statement
    void emitCommentBlockTree(
        const FlowBlock *bl); ///< Emit any comments under the given control-flow subtree
    void emitCommentFuncHeader(
        const Funcdata *fd);                  ///< Emit comments in the given function's header
    void emitForLoop(const BlockWhileDo *bl); ///< Emit block as a \e for loop
    void opFunc(const PcodeOp *op); ///< Push a \e functional expression based on the given p-code
                                    ///< op to the RPN stack
    void opTypeCast(
        const PcodeOp *op); ///< Push the given p-code op using type-cast syntax to the RPN stack
    void opHiddenFunc(const PcodeOp *op); ///< Push the given p-code op as a hidden token
    static void printCharHexEscape(ostream &s,
                                   int4 val); ///< Print value as an escaped hex sequence
    bool printCharacterConstant(ostream &s, const Address &addr, Datatype *charType) const;
    int4 getHiddenThisSlot(const PcodeOp *op,
                           FuncProto *fc); ///< Get position of "this" pointer needing to be hidden
    void resetDefaultsPrintC(void);        ///< Set default values for options specific to PrintLLVM
    virtual void pushConstant(uintb val, const Datatype *ct, const Varnode *vn, const PcodeOp *op);
    virtual bool pushEquate(uintb val, int4 sz, const EquateSymbol *sym, const Varnode *vn,
                            const PcodeOp *op);
    virtual void pushAnnotation(const Varnode *vn, const PcodeOp *op);
    virtual void pushSymbol(const Symbol *sym, const Varnode *vn, const PcodeOp *op);
    virtual void pushUnnamedLocation(const Address &addr, const Varnode *vn, const PcodeOp *op);
    virtual void pushPartialSymbol(const Symbol *sym, int4 off, int4 sz, const Varnode *vn,
                                   const PcodeOp *op, Datatype *outtype);
    virtual void pushMismatchSymbol(const Symbol *sym, int4 off, int4 sz, const Varnode *vn,
                                    const PcodeOp *op);
    virtual void push_integer(uintb val, int4 sz, bool sign, const Varnode *vn, const PcodeOp *op);
    virtual void push_float(uintb val, int4 sz, const Varnode *vn, const PcodeOp *op);
    virtual void printUnicode(ostream &s, int4 onechar) const;
    virtual void pushType(const Datatype *ct);
    virtual string genericFunctionName(const Address &addr);
    virtual string genericTypeName(const Datatype *ct);

    // void buildExpression(const PcodeOp *op);
    llvm::Type *translateType(Datatype *dtype);
    void buildExpression(const PcodeOp *op);
    void buildVarDecl(const Symbol *sym);
    bool buildScopeVarDecls(const Scope *symScope, int4 cat);
    llvm::Function *buildFunctionDeclaration(const Funcdata *fd);
    llvm::BasicBlock *buildLocalVarDecls(const Funcdata *fd, llvm::Function *func);
    llvm::Type *buildPrototypeOutput(const FuncProto *proto, const Funcdata *fd);
    std::vector<llvm::Type *> buildPrototypeInputs(const FuncProto *proto);

    void buildBlockBasic(const BlockBasic *bb);
    void buildBlockGraph(const BlockGraph *bl, llvm::Function *func);
    void buildInst(const PcodeOp *op);
    // void buildBlockCopy(const BlockCopy *bl);
    // void buildBlockGoto(const BlockGoto *bl);
    // void buildBlockLs(const BlockList *bl);
    // void buildBlockCondition(const BlockCondition *bl);
    // void buildBlockIf(const BlockIf *bl);
    // void buildBlockWhileDo(const BlockWhileDo *bl);
    // void buildBlockDoWhile(const BlockDoWhile *bl);
    // void buildBlockInfLoop(const BlockInfLoop *bl);
    // void buildBlockSwitch(const BlockSwitch *bl);

    virtual void emitExpression(const PcodeOp *op);
    virtual void emitVarDecl(const Symbol *sym);
    virtual void emitVarDeclStatement(const Symbol *sym);
    virtual bool emitScopeVarDecls(const Scope *symScope, int4 cat);
    virtual void emitFunctionDeclaration(const Funcdata *fd);
    virtual void emitTypeDefinition(const Datatype *ct);
    virtual bool checkPrintNegation(const Varnode *vn);
    void pushTypePointerRel(const PcodeOp *op);

public:
    PrintLLVM(Architecture *g, const string &nm = "llvm-language"); ///< Constructor
    void setNULLPrinting(bool val)
    {
        option_NULL = val;
    } ///< Toggle the printing of a 'NULL' token
    void setInplaceOps(bool val)
    {
        option_inplace_ops = val;
    } ///< Toggle the printing of \e in-place operators
    void setConvention(bool val)
    {
        option_convention = val;
    } ///< Toggle whether calling conventions are printed
    void setNoCastPrinting(bool val)
    {
        option_nocasts = val;
    } ///< Toggle whether casts should \b not be printed
    void setCStyleComments(void)
    {
        setCommentDelimeter("/* ", " */", false);
    } ///< Set c-style "/* */" comment delimiters
    void setCPlusPlusStyleComments(void)
    {
        setCommentDelimeter("// ", "", true);
    } ///< Set c++-style "//" comment delimiters
    void setDisplayUnplaced(bool val)
    {
        option_unplaced = val;
    } ///< Toggle whether \e unplaced comments are displayed in the header
    void setHideImpliedExts(bool val)
    {
        option_hide_exts = val;
    } ///< Toggle whether implied extensions are hidden

    void buildFunction(const Funcdata *fd);
    void dumpLLVM(std::string fname)
    {
        if (fname == "-")
        {
            LLVM_Module->print(llvm::outs(), nullptr);
        }
        else
        {
            std::error_code EC;
            llvm::raw_fd_ostream out(fname, EC);
            if (EC)
            {
                throw LowlevelError("Error opening file: " + EC.message());
            }
            LLVM_Module->print(out, nullptr);
        }
    }
    virtual ~PrintLLVM(void)
    {
    }
    virtual void resetDefaults(void);
    virtual void adjustTypeOperators(void);
    virtual void setCommentStyle(const string &nm);
    virtual void docTypeDefinitions(const TypeFactory *typegrp);
    virtual void docAllGlobals(void);
    virtual void docSingleGlobal(const Symbol *sym);
    virtual void docFunction(const Funcdata *fd);

    virtual void emitBlockBasic(const BlockBasic *bb);
    virtual void emitBlockGraph(const BlockGraph *bl);
    virtual void emitBlockCopy(const BlockCopy *bl);
    virtual void emitBlockGoto(const BlockGoto *bl);
    virtual void emitBlockLs(const BlockList *bl);
    virtual void emitBlockCondition(const BlockCondition *bl);
    virtual void emitBlockIf(const BlockIf *bl);
    virtual void emitBlockWhileDo(const BlockWhileDo *bl);
    virtual void emitBlockDoWhile(const BlockDoWhile *bl);
    virtual void emitBlockInfLoop(const BlockInfLoop *bl);
    virtual void emitBlockSwitch(const BlockSwitch *bl);

    llvm::Value* getVarnodeValue(const Varnode *vn);
    void buildOpCopy(const PcodeOp *op);
    void buildOpLoad(const PcodeOp *op);
    void buildOpStore(const PcodeOp *op);
    void buildOpBranch(const PcodeOp *op);
    void buildOpCbranch(const PcodeOp *op);
    void buildOpBranchind(const PcodeOp *op);
    void buildOpCall(const PcodeOp *op);
    void buildOpCallind(const PcodeOp *op);
    void buildOpCallother(const PcodeOp *op);
    void buildOpConstructor(const PcodeOp *op);
    void buildOpReturn(const PcodeOp *op);
    void buildOpIntEqual(const PcodeOp *op);
    void buildOpIntNotEqual(const PcodeOp *op);
    void buildOpIntSless(const PcodeOp *op);
    void buildOpIntSlessEqual(const PcodeOp *op);
    void buildOpIntLess(const PcodeOp *op);
    void buildOpIntLessEqual(const PcodeOp *op);
    void buildOpIntZext(const PcodeOp *op);
    void buildOpIntSext(const PcodeOp *op);
    void buildOpIntAdd(const PcodeOp *op);
    void buildOpIntSub(const PcodeOp *op);
    void buildOpIntCarry(const PcodeOp *op);
    void buildOpIntScarry(const PcodeOp *op);
    void buildOpIntSborrow(const PcodeOp *op);
    void buildOpInt2Comp(const PcodeOp *op);
    void buildOpIntNegate(const PcodeOp *op);
    void buildOpIntXor(const PcodeOp *op);
    void buildOpIntAnd(const PcodeOp *op);
    void buildOpIntOr(const PcodeOp *op);
    void buildOpIntLeft(const PcodeOp *op);
    void buildOpIntRight(const PcodeOp *op);
    void buildOpIntSright(const PcodeOp *op);
    void buildOpIntMult(const PcodeOp *op);
    void buildOpIntDiv(const PcodeOp *op);
    void buildOpIntSdiv(const PcodeOp *op);
    void buildOpIntRem(const PcodeOp *op);
    void buildOpIntSrem(const PcodeOp *op);
    void buildOpBoolNegate(const PcodeOp *op);
    void buildOpBoolXor(const PcodeOp *op);
    void buildOpBoolAnd(const PcodeOp *op);
    void buildOpBoolOr(const PcodeOp *op);
    void buildOpFloatEqual(const PcodeOp *op);
    void buildOpFloatNotEqual(const PcodeOp *op);
    void buildOpFloatLess(const PcodeOp *op);
    void buildOpFloatLessEqual(const PcodeOp *op);
    void buildOpFloatNan(const PcodeOp *op);
    void buildOpFloatAdd(const PcodeOp *op);
    void buildOpFloatDiv(const PcodeOp *op);
    void buildOpFloatMult(const PcodeOp *op);
    void buildOpFloatSub(const PcodeOp *op);
    void buildOpFloatNeg(const PcodeOp *op);
    void buildOpFloatAbs(const PcodeOp *op);
    void buildOpFloatSqrt(const PcodeOp *op);
    void buildOpFloatInt2Float(const PcodeOp *op);
    void buildOpFloatFloat2Float(const PcodeOp *op);
    void buildOpFloatTrunc(const PcodeOp *op);
    void buildOpFloatCeil(const PcodeOp *op);
    void buildOpFloatFloor(const PcodeOp *op);
    void buildOpFloatRound(const PcodeOp *op);
    void buildOpMultiequal(const PcodeOp *op);
    void buildOpIndirect(const PcodeOp *op);
    void buildOpPiece(const PcodeOp *op);
    void buildOpSubpiece(const PcodeOp *op);
    void buildOpCast(const PcodeOp *op);
    void buildOpPtradd(const PcodeOp *op);
    void buildOpPtrsub(const PcodeOp *op);
    void buildOpSegmentOp(const PcodeOp *op);
    void buildOpCpoolRefOp(const PcodeOp *op);
    void buildOpNewOp(const PcodeOp *op);
    void buildOpInsertOp(const PcodeOp *op);
    void buildOpExtractOp(const PcodeOp *op);
    void buildOpPopcountOp(const PcodeOp *op);

    virtual void opCopy(const PcodeOp *op);
    virtual void opLoad(const PcodeOp *op);
    virtual void opStore(const PcodeOp *op);
    virtual void opBranch(const PcodeOp *op);
    virtual void opCbranch(const PcodeOp *op);
    virtual void opBranchind(const PcodeOp *op);
    virtual void opCall(const PcodeOp *op);
    virtual void opCallind(const PcodeOp *op);
    virtual void opCallother(const PcodeOp *op);
    virtual void opConstructor(const PcodeOp *op, bool withNew);
    virtual void opReturn(const PcodeOp *op);
    virtual void opIntEqual(const PcodeOp *op)
    {
        opBinary(&equal, op);
    }
    virtual void opIntNotEqual(const PcodeOp *op)
    {
        opBinary(&not_equal, op);
    }
    virtual void opIntSless(const PcodeOp *op)
    {
        opBinary(&less_than, op);
    }
    virtual void opIntSlessEqual(const PcodeOp *op)
    {
        opBinary(&less_equal, op);
    }
    virtual void opIntLess(const PcodeOp *op)
    {
        opBinary(&less_than, op);
    }
    virtual void opIntLessEqual(const PcodeOp *op)
    {
        opBinary(&less_equal, op);
    }
    virtual void opIntZext(const PcodeOp *op, const PcodeOp *readOp);
    virtual void opIntSext(const PcodeOp *op, const PcodeOp *readOp);
    virtual void opIntAdd(const PcodeOp *op)
    {
        opBinary(&binary_plus, op);
    }
    virtual void opIntSub(const PcodeOp *op)
    {
        opBinary(&binary_minus, op);
    }
    virtual void opIntCarry(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opIntScarry(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opIntSborrow(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opInt2Comp(const PcodeOp *op)
    {
        opUnary(&unary_minus, op);
    }
    virtual void opIntNegate(const PcodeOp *op)
    {
        opUnary(&bitwise_not, op);
    }
    virtual void opIntXor(const PcodeOp *op)
    {
        opBinary(&bitwise_xor, op);
    }
    virtual void opIntAnd(const PcodeOp *op)
    {
        opBinary(&bitwise_and, op);
    }
    virtual void opIntOr(const PcodeOp *op)
    {
        opBinary(&bitwise_or, op);
    }
    virtual void opIntLeft(const PcodeOp *op)
    {
        opBinary(&shift_left, op);
    }
    virtual void opIntRight(const PcodeOp *op)
    {
        opBinary(&shift_right, op);
    }
    virtual void opIntSright(const PcodeOp *op)
    {
        opBinary(&shift_sright, op);
    }
    virtual void opIntMult(const PcodeOp *op)
    {
        opBinary(&multiply, op);
    }
    virtual void opIntDiv(const PcodeOp *op)
    {
        opBinary(&divide, op);
    }
    virtual void opIntSdiv(const PcodeOp *op)
    {
        opBinary(&divide, op);
    }
    virtual void opIntRem(const PcodeOp *op)
    {
        opBinary(&modulo, op);
    }
    virtual void opIntSrem(const PcodeOp *op)
    {
        opBinary(&modulo, op);
    }
    virtual void opBoolNegate(const PcodeOp *op);
    virtual void opBoolXor(const PcodeOp *op)
    {
        opBinary(&boolean_xor, op);
    }
    virtual void opBoolAnd(const PcodeOp *op)
    {
        opBinary(&boolean_and, op);
    }
    virtual void opBoolOr(const PcodeOp *op)
    {
        opBinary(&boolean_or, op);
    }
    virtual void opFloatEqual(const PcodeOp *op)
    {
        opBinary(&equal, op);
    }
    virtual void opFloatNotEqual(const PcodeOp *op)
    {
        opBinary(&not_equal, op);
    }
    virtual void opFloatLess(const PcodeOp *op)
    {
        opBinary(&less_than, op);
    }
    virtual void opFloatLessEqual(const PcodeOp *op)
    {
        opBinary(&less_equal, op);
    }
    virtual void opFloatNan(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opFloatAdd(const PcodeOp *op)
    {
        opBinary(&binary_plus, op);
    }
    virtual void opFloatDiv(const PcodeOp *op)
    {
        opBinary(&divide, op);
    }
    virtual void opFloatMult(const PcodeOp *op)
    {
        opBinary(&multiply, op);
    }
    virtual void opFloatSub(const PcodeOp *op)
    {
        opBinary(&binary_minus, op);
    }
    virtual void opFloatNeg(const PcodeOp *op)
    {
        opUnary(&unary_minus, op);
    }
    virtual void opFloatAbs(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opFloatSqrt(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opFloatInt2Float(const PcodeOp *op)
    {
        opTypeCast(op);
    }
    virtual void opFloatFloat2Float(const PcodeOp *op)
    {
        opTypeCast(op);
    }
    virtual void opFloatTrunc(const PcodeOp *op)
    {
        opTypeCast(op);
    }
    virtual void opFloatCeil(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opFloatFloor(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opFloatRound(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opMultiequal(const PcodeOp *op)
    {
    }
    virtual void opIndirect(const PcodeOp *op)
    {
    }
    virtual void opPiece(const PcodeOp *op)
    {
        opFunc(op);
    }
    virtual void opSubpiece(const PcodeOp *op);
    virtual void opCast(const PcodeOp *op)
    {
        opTypeCast(op);
    }
    virtual void opPtradd(const PcodeOp *op);
    virtual void opPtrsub(const PcodeOp *op);
    virtual void opSegmentOp(const PcodeOp *op);
    virtual void opCpoolRefOp(const PcodeOp *op);
    virtual void opNewOp(const PcodeOp *op);
    virtual void opInsertOp(const PcodeOp *op);
    virtual void opExtractOp(const PcodeOp *op);
    virtual void opPopcountOp(const PcodeOp *op)
    {
        opFunc(op);
    }
};

/// \brief Set of print commands for displaying an open brace '{' and setting a new indent level
///
/// These are the print commands sent to the emitter prior to printing and \e else block.
/// The open brace can be canceled if the block decides it wants to use "else if" syntax.
// class PendingBrace : public PendPrint {
//   int4 indentId;		///< Id associated with the new indent level
// public:
//   PendingBrace(void) { indentId = -1; }			///< Constructor
//   int4 getIndentId(void) const { return indentId; }	///< If commands have been issued, returns
//   the new indent level id. virtual void callback(EmitXml *emit);
// };

/// \brief Push a token indicating a PTRSUB (a -> operator) is acting at an offset from the original
/// pointer
///
/// When a variable has TypePointerRel as its data-type, PTRSUB acts relative to the \e parent
/// data-type.  We print a specific token to indicate this relative shift is happening.
/// \param op is is the PTRSUB op
inline void PrintLLVM::pushTypePointerRel(const PcodeOp *op)

{
    pushOp(&function_call, op);
    pushAtom(Atom(typePointerRelToken, optoken, EmitXml::funcname_color, op));
}

#endif
