#pragma once

#include <string>
#include <ostream>
#include <optional>
#include <mutex>

#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/Module.h>

namespace llvm {

template <typename T>
std::string to_string(const T& x) {
    std::string s;
    llvm::raw_string_ostream ss {s};
    ss << x;
    return s;
}

bool getelementptr_can_zero(const llvm::GetElementPtrInst *GEP);
std::optional<int> getelementptr_const_offset(const llvm::GetElementPtrInst *GEP);
std::optional<int> getelementptr_min_offset(const llvm::GetElementPtrInst *GEP);
std::optional<int> getelementptr_max_offset(const llvm::GetElementPtrInst *GEP);

bool contains_struct(const llvm::Type *T);

/** Best-effort pointee type of a pointer-producing value under opaque pointers.
 * Returns nullptr if the pointee type cannot be determined from the value alone. */
const llvm::Type *get_pointee_type(const llvm::Value *V);

bool pointer_is_read_only(const llvm::Value *P);

  extern std::mutex errs_mutex;
struct locked_raw_ostream {
    std::unique_lock<std::mutex> lock;
    llvm::raw_ostream& os;
    
    locked_raw_ostream(llvm::raw_ostream& os, std::mutex& mutex): lock(mutex), os(os) {}
    
    operator llvm::raw_ostream&() { return os; }
};

llvm::raw_ostream& print_full_debug_info(llvm::raw_ostream& os, const llvm::DebugLoc& DL);

}

template <typename T>
std::ostream& llvm_to_cxx_os(std::ostream& os, const T& x) {
    return os << llvm::to_string(x);
}

inline std::ostream& operator<<(std::ostream& os, const llvm::Instruction& I) {
   return llvm_to_cxx_os(os, I);
}


namespace llvm {

unsigned get_min_loop_iterations(const llvm::Loop *L);

/** Parse clang annotations. Output iterator must accept pairs of llvm::Value and std::string. */
template <class OutputIt>
OutputIt parse_annotations(const llvm::Module& M, OutputIt out) {

    // Global Annotations
    //
    // Under opaque pointers (LLVM >= 15) the per-field bitcast ConstantExprs
    // that used to wrap the annotated value and the annotation-string global
    // are gone: the struct fields now point directly at the underlying values.
    // Using stripPointerCasts() handles both the typed- and opaque-pointer
    // layouts.
    if (const llvm::GlobalVariable *G = M.getNamedGlobal("llvm.global.annotations")) {
        assert(G->getNumOperands() == 1);
        const llvm::Value *V = G->getOperand(0);
        const llvm::ConstantArray *CA = llvm::cast<llvm::ConstantArray>(V);
        for (const llvm::Value *V : CA->operands()) {
            const llvm::ConstantStruct *CS = llvm::cast<llvm::ConstantStruct>(V);
            assert(CS->getNumOperands() == 5);
            const llvm::Value *annotated = CS->getOperand(0)->stripPointerCasts();
            const auto *GV_str = llvm::dyn_cast<llvm::GlobalVariable>(CS->getOperand(1)->stripPointerCasts());
            if (!GV_str || !GV_str->hasInitializer()) { continue; }
            const auto *A_str = llvm::dyn_cast<llvm::ConstantDataArray>(GV_str->getInitializer());
            if (!A_str || !A_str->isCString()) { continue; }
            const std::string str = A_str->getAsCString().str();
            *out++ = std::make_pair(annotated, str);
        }
    }
    
    return out;
}

}
