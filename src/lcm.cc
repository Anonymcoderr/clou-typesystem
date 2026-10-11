#include <optional>
#include <string>
#include <signal.h>
#include <regex>
#include <unistd.h>
#include <atomic>

#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Transforms/Utils/PromoteMemToReg.h>

#include "lcm.h"
#include "config.h"
#include "aeg/aeg.h"
#include "cfg/expanded.h"
#include "cfg/unrolled.h"
#include "cfg/calls.h"
#include "util/profiler.h"
#include "util/llvm.h"
#include "util/output.h"
#include "db.h"
#include "mon/proto.h"
#include "mon/client.h"
#include "cfg/block.h"
#include "util/exception.h"
#include "util/output.h"
#include "util/scope.h"
#include "util/timer.h"
#include "util/algorithm.h"
#include "attacker-taint.h"

Timer timer {nullptr};
std::string get_time() {
    return timer.get_str();
}

Transmitters transmitters;

template <typename Graph>
void output_(const Graph& graph, const std::string& name, const llvm::Function& F) {
    if (!output_dir.empty()) {
        std::stringstream ss;
        ss << output_dir << "/" << name << "-" << F.getName().str() << ".dot";
        graph.dump_graph(ss.str());
    }
}

void timeout_handler(int sig) {
  {
    const char *msg = "PROCESS TIMEOUT\n";
    write(2, msg, strlen(msg));
  }
  
  char path[256];
  sprintf(path, "%s/runtimes.txt", output_dir.c_str());
  int fd;
  if ((fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0664)) < 0) {
    abort();
  }

  write(2, "HERE\n", 5);

  char buf[256];
  sprintf(buf, "%f\n", cpu_time());
  write(2, buf, strlen(buf));
  write(fd, buf, strlen(buf));
  close(fd);
  _Exit(EXIT_SUCCESS);
}

namespace {
  
  void register_timeout_handler() {
    static std::atomic<int> here = 0;
    if (here++ == 0) {
      if (signal(SIGUSR2, &timeout_handler) == SIG_ERR) {
	std::perror("signal");
	std::abort();
      }
    }
  }

  int register_timeout_handler_dummy = (register_timeout_handler(), 0);
}

struct LCMPass: public llvm::PassInfoMixin<LCMPass> {

    AttackerTaintResultMap attacker_taint;
        
    std::unordered_set<const llvm::Function *> get_functions_list(const llvm::Module& M, llvm::CallGraph& CG) {
        using Set = std::unordered_set<const llvm::Function *>;
        Set out;
        for (const llvm::Function& F : M) {
            if (!should_skip(F)) {
                out.insert(&F);
            }
        }

	llvm::errs() << "initial functions list:\n";
	for (const llvm::Function *F : out) {
	  llvm::errs() << F->getName() << "\n";
	}
	
        if (analyze_callees) {
            Set cur = out;
            Set next;
            while (!cur.empty()) {
                for (const llvm::Function *caller : cur) {
		  if (caller && !caller->isDeclaration()) {
                    for (const auto& callee_pair : *CG[caller]) {
                        const auto callee_node = callee_pair.second;
                        if (const llvm::Function *callee = callee_node->getFunction()) {
			  if (out.insert(callee).second) {
                            next.insert(callee);
			  }
			}
                    }
		  }
                }
                cur = std::move(next);
            }
        }

	llvm::errs() << "final functions list:\n";
	for (const llvm::Function *F : out) {
	  llvm::errs() << F->getName() << "\n";
	}	
        
        return out;
    }
    
    std::unordered_set<const llvm::Function *> functions_list;

    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager& MAM) {
        llvm::FunctionAnalysisManager& FAM =
            MAM.getResult<llvm::FunctionAnalysisManagerModuleProxy>(M).getManager();

        /* check if filename matches regex */
        bool match = false;
        if (file_regex.empty()) {
            match = true;
        } else {
            if (std::regex_match(M.getSourceFileName(), std::regex {file_regex})) {
                match = true;
            }
        }
        if (!match) {
            std::cerr << "skipping file " << M.getSourceFileName() << "\n";
            return llvm::PreservedAnalyses::all();
        }

        // Register elimination: promote stack slots to SSA before the graph is built,
        // so -O0 spills and reloads do not become memory events. Only for the type
        // engine. Clou's SMT detector binds function arguments through their stack
        // reloads and misses leaks on promoted IR, so it always sees the original.
        // CLOU_MEM2REG=1 forces it on, CLOU_NO_MEM2REG=1 off.
        const bool axtypes_engine = [] {
            const char *p = ::getenv("CLOU_AXTYPES_ENGINE");
            return p && std::string(p) != "0";
        }();
        const bool no_mem2reg = [] {
            const char *p = ::getenv("CLOU_NO_MEM2REG");
            return p && std::string(p) != "0";
        }();
        const bool force_mem2reg = [] {
            const char *p = ::getenv("CLOU_MEM2REG");
            return p && std::string(p) != "0";
        }();
        // Not for Spectre-v4: there a spill and reload is the store forward itself.
        const bool v4 = (leakage_class == LeakageClass::SPECTRE_V4);
        if ((axtypes_engine && !no_mem2reg && !v4) || force_mem2reg) {
            for (llvm::Function& F : M) {
                if (F.isDeclaration()) { continue; }
                llvm::DominatorTree DT(F);
                std::vector<llvm::AllocaInst *> allocas;
                for (llvm::Instruction& I : F.getEntryBlock()) {
                    if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                        if (llvm::isAllocaPromotable(AI)) { allocas.push_back(AI); }
                    }
                }
                if (!allocas.empty()) {
                    llvm::PromoteMemToReg(allocas, DT);
                    FAM.invalidate(F, llvm::PreservedAnalyses::none());
                }
            }
        }

        llvm::CallGraph CG(M);

        functions_list = get_functions_list(M, CG);

        ::signal(SIGSEGV, SIG_DFL);
        ::signal(SIGABRT, SIG_DFL);

        if (use_attacker_control_analysis) {
            for (llvm::Function& F : M) {
                // TODO: Would be nice to parallelize this.
                if (!F.isDeclaration() && functions_list.contains(&F)) {
                    llvm::AAResults& AA = FAM.getResult<llvm::AAManager>(F);
                    llvm::LoopInfo& LI = FAM.getResult<llvm::LoopAnalysis>(F);
                    attacker_taint.emplace(&F, compute_attacker_taint(F, AA, LI));
                }
            }
        }

        for (llvm::scc_iterator<llvm::CallGraph *> scc_it = llvm::scc_begin(&CG);
             !scc_it.isAtEnd();
             ++scc_it) {
            runOnSCC(*scc_it, FAM);
        }

        bool changed = false;
        if (fence_insertion) {
            changed = insert_fences(transmitters);
        }

        return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
    }

    void runOnSCC(const std::vector<llvm::CallGraphNode *>& scc, llvm::FunctionAnalysisManager& FAM) {
        for (llvm::CallGraphNode *scc_node : scc) {
            if (llvm::Function *F = scc_node->getFunction()) {
                if (!F->isDeclaration()) {
                    llvm::AAResults& AA = FAM.getResult<llvm::AAManager>(*F);
                    open_log(F->getName().str());
                    timer = Timer(nullptr); // reset timer
                    runOnFunction(*F, AA, TransmitterOutputIt(transmitters, transmitters.end()));
                    close_log();
                }
            }
        }
    }
    
    bool should_skip(const llvm::Function& F) const {
        if (analyzed_functions.contains(F.getName().str())) {
            return true;
        }
        
        if (!function_names.empty()) {
            bool matched = false;
            
            for (const std::string& function_regex : function_names) {
                if (std::regex_match(static_cast<std::string>(F.getName()), std::regex {function_regex})) {
                    matched = true;
                }
            }
            
            if (!matched) {
                return true;
            }
        }
        
        /* check if should skip */
        for (const std::string& skip_function_name : skip_function_names) {
            if (std::regex_match(static_cast<std::string>(F.getName()), std::regex {skip_function_name})) {
                return true;
            }
        }
        
        return false;
    }
    
    template <typename OutputIt>
    void runOnFunction(llvm::Function& F, llvm::AliasAnalysis& AA, OutputIt out) {
        const std::string func = F.getName().str();
        
        llvm::errs() << "processing function '" << F.getName() << "'\n";
        
        if (client) {
            mon::Message msg;
            msg.mutable_func_started()->mutable_func()->set_name(F.getName().str());
            client.send(msg);
        }
        
        
        const auto profiler_stop = util::defer([] () {
            if (profile) {
                ProfilerStop();
            }
        });
        if (profile) {
            std::stringstream ss;
            ss << output_dir << "/" << func << ".prof";
            ProfilerStart(ss.str().c_str());
            const auto handler = [] (int sig) {
                ProfilerStop();
                if (sig == SIGINT) {
                    std::exit(1);
                }
            };
            signal(SIGINT, handler);
            signal(SIGUSR1, handler);
        }
        
        try {
            check_config();
            
#if 0
            if (should_skip(F)) {
#else
                if (!functions_list.contains(&F)) {
#endif
                if (client) {
                    mon::Message msg;
                    msg.mutable_func_completed()->mutable_func()->set_name(F.getName().str());
                    client.send(msg);
                }
                
                return;
            }
            
#if 0
            if (analyzed_functions.contains(F.getName().str())) {
                
                std::cerr << "skipping analyzed function " << F.getName().str() << "\n";
                if (client) {
                    mon::Message msg;
                    msg.mutable_func_completed()->mutable_func()->set_name(F.getName().str());
                    client.send(msg);
                }
                
                return;
            }
            
            if (!function_names.empty()) {
                bool match = false;
                for (const std::string& function_regex : function_names) {
                    if (std::regex_match(static_cast<std::string>(F.getName()), std::regex {function_regex})) {
                        match = true;
                        break;
                    }
                }
                if (!match) { return; }
            }
            
            /* check if should skip */
            for (const std::string& skip_function_name : skip_function_names) {
                if (std::regex_match(static_cast<std::string>(F.getName()), std::regex {skip_function_name})) {
                    return;
                }
            }
#endif
            
            const unsigned num_unrolls = 2;
            
            /* Construct AEG */
            logv(1, "Constructing AEGPO for " << F.getName() << "\n");
            client.send_step("cfg-unrolled", F.getName().str());
            CFG_Unrolled aegpo_unrolled {F, spec_depth, num_unrolls};
            aegpo_unrolled.construct();
            
            if (output_cfgs.unrolled) {
                output_(aegpo_unrolled, "cfg-unrolled", F);
            }
            
            std::cerr << "cfg-unrolled: " << aegpo_unrolled.size() << " nodes\n";
            
            client.send_step("cfg-calls", F.getName().str());
            CFG_Calls cfg_calls;
            cfg_calls.construct(aegpo_unrolled);
            cfg_calls.sort(); // EXPERIMENTAL
            
            if (output_cfgs.calls) {
                output_(cfg_calls, "cfg-calls", F);
            }
            std::cerr << "cfg-calls: " << cfg_calls.size() << " nodes\n";
            
            logv(1, "Constructing expanded AEGPO for " << F.getName() << "\n");
            client.send_step("cfg-expanded", F.getName().str());
            CFG_Expanded cfg_expanded;
            cfg_expanded.construct(cfg_calls);
            
            if (output_cfgs.expanded) {
                output_(cfg_expanded, "cfg-expanded", F);
            }
            std::cerr << "cfg-expanded: " << cfg_expanded.size() << " nodes\n";
            
            // DEBUG: show block CFG information
            {
                const BlockCFG bcfg {cfg_expanded};

                std::size_t block_size = 0.;
                for (const auto& p : bcfg.blocks) {
                    block_size += p.second.size();
                }
                std::cerr << "average block size in cfg-expanded: " << block_size / bcfg.blocks.size() << "\n";
            }
            
            client.send_property(F.getName().str(), "nodes", cfg_expanded.size());
            
            logv(1, "Constructing AEG for " << F.getName() << "\n");
            client.send_step("aeg", F.getName().str());
            aeg::AEG aeg {cfg_expanded, AA, attacker_taint};
            aeg.construct(AA, rob_size);
            
            // DEBUG INFO
            {
                unsigned i = 0;
                aeg.for_each_edge(aeg::Edge::ADDR_GEP, [&i] (NodeRef, NodeRef, const auto&) { ++i; });
                logv(1, "num ADDR_GEP edges: " << i << "\n");
            }
            
            

            client.send_step("leakage", F.getName().str());
            llvm::errs() << "Testing...\n";
            Transmitters transmitters;
            // CLOU_AXTYPES_ENGINE=1 selects the type engine instead of the SMT search.
            if (const char *e = ::getenv("CLOU_AXTYPES_ENGINE"); e && std::string(e) != "0") {
                aeg.test_axtypes(TransmitterOutputIt(transmitters, transmitters.end()));
            } else {
                aeg.test(TransmitterOutputIt(transmitters, transmitters.end()));
            }
            llvm::errs() << "done\n";
            for (const llvm::Instruction *I : transmitters) {
                llvm::errs() << "TRANSMITTER: " << F.getName() << " |";
                const llvm::DebugLoc& dl = I->getDebugLoc();
                if (dl) { llvm::errs() << " " << dl.getLine() << ":" << dl.getCol(); }
                llvm::errs() << " " << *I << "\n";
            }
            
            // find the first transmitter in topological order
            for (NodeRef ref : cfg_expanded.reverse_postorder()) {
                const auto& node = cfg_expanded.lookup(ref);
                const auto *I = std::visit(util::overloaded {
                    [&] (const llvm::Instruction *I) -> const llvm::Instruction * {
                        return I;
                    },
                    [&] (const CFG::Node::Call& call) -> const llvm::Instruction *   {
                        return call.C;
                    },
                    [&] (Entry) -> const llvm::Instruction * { return nullptr; },
                    [&] (Exit) -> const llvm::Instruction * { return nullptr; },
                }, node.v);
                if (I != nullptr) {
                    if (transmitters.contains(I)) {
                        *out++ = I;
                        break;
                    }
                }
            }
            
            // add analyzed functions
            {
                std::unordered_set<std::string> set;
                std::transform(aegpo_unrolled.nodes.begin(), aegpo_unrolled.nodes.end(), std::inserter(set, set.end()), [] (const CFG::Node& node) -> std::string {
                    if (const auto *Ip = std::get_if<const llvm::Instruction *>(&node.v)) {
                        return (**Ip).getFunction()->getName().str();
                    } else {
                        return "";
                    }
                });
                set.erase("");

                mon::Message msg;
                for (const std::string& s : set) {
                    analyzed_functions.insert(s);
                    msg.mutable_funcs_analyzed()->add_funcs()->set_name(s);
                }
                client.send(msg);
            }
            
        } catch (const util::resume& resume) {
            std::cerr << resume.what() << "\n";
        }
        
        if (client) {
            mon::Message msg;
            msg.mutable_func_completed()->mutable_func()->set_name(F.getName().str());
            client.send(msg);
        }
        
        std::cerr << "ANALYZED: " << cpu_time() << "\n";
        std::cerr << "done analyzing function " << F.getName().str() << "\n";
        
        return;
    }
    
    bool insert_fences(const Transmitters& transmitters) const {
        std::cerr << transmitters.size() << " transmitters\n";
        for (const llvm::Instruction *transmitter_ : transmitters) {
            llvm::Instruction *transmitter = const_cast<llvm::Instruction *>(transmitter_);
            llvm::IRBuilder<> builder(transmitter);
            builder.SetInsertPoint(transmitter);
            llvm::FenceInst *FI = builder.CreateFence(llvm::AtomicOrdering::Acquire);
            llvm::errs() << "INSERTED FENCE: " << *FI << "\n";
        }
        return !transmitters.empty();
    }
};

// New pass-manager plugin registration.
//
// The pass is auto-injected into clang's pipeline (including at -O0, which is
// what Clou compiles with) via the PipelineStart extension point, and can also
// be requested explicitly with `opt -passes=lcm`.
//
// Load into clang with: -fpass-plugin=/path/to/libclou.so
namespace {
llvm::PassPluginLibraryInfo getLCMPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "clou", LLVM_VERSION_STRING,
        [] (llvm::PassBuilder& PB) {
            PB.registerPipelineStartEPCallback(
                [] (llvm::ModulePassManager& MPM, llvm::OptimizationLevel) {
                    MPM.addPass(LCMPass());
                });
            PB.registerPipelineParsingCallback(
                [] (llvm::StringRef name, llvm::ModulePassManager& MPM,
                    llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) -> bool {
                    if (name == "lcm") {
                        MPM.addPass(LCMPass());
                        return true;
                    }
                    return false;
                });
        }};
}
}

extern "C" LLVM_ATTRIBUTE_WEAK llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getLCMPluginInfo();
}
