#pragma once

#include <llvm/IR/Value.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Function.h>

#include <cstdlib>
#include <set>

namespace llvm {
class AAResults;
class LoopInfo;
}

class AttackerTaintResults {
public:
    bool get(const llvm::Value *V) const;

private:
    /** Function that this analysis applies to. */
    const llvm::Function *F = nullptr;

    /** Tainted instructions .*/
    std::set<const llvm::Instruction *> insts;

    friend AttackerTaintResults compute_attacker_taint(llvm::Function& F, llvm::AAResults& AA, llvm::LoopInfo& LI);
    friend llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const AttackerTaintResults&);
};

llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const AttackerTaintResults&);

/** Compute attacker-controlled taint for function \p F.
 *  Replaces the former legacy AttackerTaintPass; the caller supplies the
 *  alias-analysis and loop-info results (obtained from the new pass manager). */
AttackerTaintResults compute_attacker_taint(llvm::Function& F, llvm::AAResults& AA, llvm::LoopInfo& LI);
