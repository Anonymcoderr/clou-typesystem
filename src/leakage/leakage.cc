#include <fstream>
#include <cctype>
#include <iomanip>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <system_error>
#include <thread>
#include <sys/stat.h>

#include <gperftools/profiler.h>

#include "aeg/aeg.h"
#include "util/timer.h"
#include "util/hash.h"
#include "util/llvm.h"
#include "cfg/expanded.h"
#include "util/output.h"
#include "util/iterator.h"
#include "leakage/leakage.h"
#include "mon/client.h"
#include "mon/proto.h"
#include "util/algorithm.h"
#include "leakage/spectre-v1.h"
#include "leakage/spectre-v4.h"
#include "util/protobuf.h"
#include "leakage/proto.h"
#include "util/sem.h"
#include "aeg/node.h"
#include "cloupy_export.h"
#include "axtypes/typecheck.h"
#include "axtypes/clou_policy.h"

extern Transmitters transmitters;


namespace aeg {

void AEG::leakage(z3::solver& solver, TransmitterOutputIt out) {
    lkg::DetectorMain detector {*this, solver};
    
#if 0
    ProfilerStart(util::to_string(function_name(), ".", ::getpid(), ".prof").c_str());
#endif
    
    switch (leakage_class) {
        case LeakageClass::SPECTRE_V4: {
            detector.run<lkg::SpectreV4_Detector>();
            break;
        }
            
        case LeakageClass::SPECTRE_V1: {
            switch (spectre_v1_mode.mode) {
                case SpectreV1Mode::Mode::CLASSIC:
                    detector.run<lkg::SpectreV1_Classic_Detector>();
                    break;
                case SpectreV1Mode::Mode::BRANCH_PREDICATE:
                    detector.run<lkg::SpectreV1_Control_Detector>();
                    break;
                default: std::abort();
            }
            break;
        }
            
        default: std::abort();
    }
    
#if 0
    ProfilerStop();
#endif
    
    util::copy(detector.get_transmitters(), out);
}

}


namespace lkg {

namespace {

std::string sanitize_component(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) {
        out = "_";
    }
    return out;
}

void json_emit_string(std::ostream& os, const std::string& s) {
    os << '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b"; break;
            case '\f': os << "\\f"; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                if (c < 0x20) {
                    os << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<unsigned>(c) << std::dec;
                } else {
                    os << static_cast<char>(c);
                }
                break;
        }
    }
    os << '"';
}

const char* cloupy_kind_for_node(const aeg::Node& node) {
    if (node.inst->is_entry()) {
        return "special";
    }
    if (node.inst->is_exit()) {
        return "receiver";
    }
    switch (node.inst->kind()) {
        case Inst::LOAD:  return "read";
        case Inst::STORE: return "write";
        default: break;
    }
    if (const llvm::Instruction* I = node.inst->get_inst()) {
        if (llvm::isa<llvm::BranchInst>(I) || llvm::isa<llvm::SwitchInst>(I)) {
            return "branch";
        }
    }
    return "other";
}

const char* cloupy_exec_mode_for_node(const aeg::Node& node, const z3::eval& eval) {
    // In Clou, `arch` models committed (architectural) execution; `trans` models
    // speculative fetch/execution (tfo). Nodes that are in `trans` but not
    // `arch` are transient-only.
    if (eval(node.arch)) {
        return "arch";
    }
    if (eval(node.trans)) {
        return "spec";
    }
    // Shouldn't happen for nodes on a witness trace; fall back to arch.
    return "arch";
}

bool cloupy_struct_unsafe_for_node(const aeg::Node& node, const z3::eval& eval) {
    return (!eval(node.arch)) && (bool) eval(node.trans);
}

// Map Clou edge kinds to cloupy EdgeKind strings.
std::optional<const char*> cloupy_edge_kind(aeg::Edge::Kind kind) {
    switch (kind) {
        case aeg::Edge::RF:  return "rf";
        case aeg::Edge::RFX: return "rfx";
        case aeg::Edge::DATA: return "data";
        case aeg::Edge::ADDR:
        case aeg::Edge::ADDR_GEP:
            return "addr";
        case aeg::Edge::CTRL: return "ctrl";
        case aeg::Edge::PO:   return "po";
        case aeg::Edge::TFO:  return "tfo";
        default:
            return std::nullopt;
    }
}

} // namespace

DetectorMain::DetectorMain(aeg::AEG& aeg, z3::solver& solver): aeg(aeg), solver(solver) {}

z3::context& DetectorJob::ctx() { return aeg.context; }

z3::context& DetectorMain::ctx() const { return aeg.context; }
std::mutex& DetectorMain::mutex() const { return aeg.context.mutex; }

template <class Job>
void DetectorMain::get_candidate_transmitters(NodeRefSet& candidate_transmitters) const {
    DetectorJob::DepVec deps = Job::get_deps();
    if (!custom_deps.empty()) {
        deps = custom_deps;
    }
    const auto& dep = deps.back();
    const auto kind = dep.first;
    const auto exec_mode = dep.second;
    z3::solver candidate_solver {ctx()};
    
    aeg.for_each_edge(kind, [&] (NodeRef, NodeRef ref, const aeg::Edge&) {
        const aeg::Node& node = aeg.lookup(ref);
        
        z3::expr_vector vec {ctx()};
        vec.push_back(node.exec(exec_mode));
        vec.push_back(node.access());
        if (candidate_solver.check(vec) != z3::unsat) {
            candidate_transmitters.insert(ref);
        }
    });
    
    // filter out any already-seen transmitters
    {
        std::erase_if(candidate_transmitters, [&] (NodeRef ref) -> bool {
            const auto& node = aeg.lookup(ref);
            if (const llvm::Instruction *I = node.inst->get_inst()) {
                if (::transmitters.contains(I)) {
                    llvm::errs() << "filtered transmitter: " << *I << "\n";
                    return true;
                }
            }
            return false;
        });
    }
    
    logv(2, "Number of candidate transmitters: " << candidate_transmitters.size() << "\n");
}

template <class Job>
void DetectorMain::run() {
    std::vector<std::thread> threads;
    
    NodeRefSet candidate_transmitters;
    get_candidate_transmitters<Job>(candidate_transmitters);
    NodeRefVec candidate_transmitter_vec (candidate_transmitters.begin(), candidate_transmitters.end());
    
    // spawn threads
    const unsigned total_tasks = candidate_transmitters.size();
    std::atomic<unsigned> completed_tasks = 0;
    std::atomic<unsigned> next_task = 0;
    
    // create contexts & solvers
    ParallelContextVec solvers = create_solvers(solver, std::min<unsigned>(max_parallel, candidate_transmitters.size()));
    
    {
        mutex().lock();
        
        for (unsigned i = 0; i < solvers.size(); ++i) {
            const auto func = [&, total_tasks] (ParallelContext *pctx) {
                while (true) {
                    // get next task
                    const auto task = next_task++;
                    if (task >= total_tasks) { break; }
                    
                    // run task
                    {
                        semutil::acquire(semid);
                        Job job {aeg, pctx->ctx, pctx->solver, candidate_transmitter_vec.at(task), leaks};
                        static_cast<DetectorJob&>(job).run();
                        semutil::release(semid);
                    }
                    
                    ++completed_tasks;
                    
                    if (client) {
                        std::unique_lock<std::mutex> lock {mutex()};
                        mon::Message msg;
                        auto *progress = msg.mutable_func_progress();
                        progress->mutable_func()->set_name(aeg.po.function_name());
                        const float frac = static_cast<float>(completed_tasks) / static_cast<float>(total_tasks);
                        std::cerr << "FLOAT: " << frac << "\n";
                        progress->set_frac(frac);
                        client.send(msg);
                    }
                }
            };
            threads.emplace_back(func, &solvers.at(i));
        }
        mutex().unlock();
    }
    
    /* join threads */
    for (std::thread& thread : threads) {
        thread.join();
    }
    
    /* dump information */
    dump();
}

void DetectorMain::dump() {
    const std::ios::openmode openmode = batch_mode ? (std::ios::out | std::ios::app) : (std::ios::out);
    
    {
        // open file
        const std::string path = util::to_string(output_dir, "/leakage.txt");
        std::ofstream ofs {
            path,
            openmode,
        };
        
        // dump leakage
        if (batch_mode) {
            ofs << "\n" << aeg.function_name() << ": \n";
        }
        for (const auto& leak : leaks) {
            leak.first.print_short(ofs);
            ofs << " : " << leak.second << " --";
            leak.first.print_long(ofs, aeg);
            ofs << "\n";
        }
    }
    
    {
        const std::string path = util::to_string(output_dir, "/transmitters.txt");
        std::ofstream ofs {
            path,
            openmode,
        };
        
        // print out set of transmitters
        for (const auto& leak : leaks) {
            transmitters.insert(aeg.lookup(leak.first.transmitter).inst->get_inst());
        }
        llvm::errs() << "transmitters:\n";
        for (const auto transmitter : transmitters) {
            llvm::errs() << *transmitter << "\n";
            using ::operator<<;
            ofs << *transmitter << "\n";
        }
    }
}

void DetectorJob::run() {
    for_one_transmitter(candidate_transmitter, [&] (NodeRef ref, CheckMode check_mode) {
        entry(ref, check_mode);
    }, true);
}


void DetectorJob::output_execution(const Leakage& leak) {
    assert(lookahead_tmp);
    
    assert(solver.check() == z3::sat);
    z3::model model = solver.get_model();
    const z3::eval eval {z3::model(model, ctx(), z3::model::translate())};
    
    // get actions description
    std::stringstream actions_ss;
    for (const Action& action : actions) {
        actions_ss << action << " ";
    }
    
    leaks.emplace_back(leak, actions_ss.str());
    
    // DEBUG: print out debug locations of vec
    {
        std::stringstream ss;
        ss << output_dir << "/lkg/" << aeg.function_name() << "/";
        if (::mkdir(ss.str().c_str(), 0775) < 0 && errno != EEXIST) {
            throw std::system_error(errno, std::generic_category(), "mkdir");
        }
        for (NodeRef ref : leak.vec) {
            ss << ref << "-";
        }
        ss << ".txt";
        
        std::ofstream ofs {ss.str()};
        
        std::string s;
        llvm::raw_string_ostream os {s};
        
        std::unordered_set<const llvm::Function *> functions;
        
        const auto print_ref = [&] (NodeRef ref) {
            os << ref << ": ";

            const aeg::Node& node = aeg.lookup(ref);
            os << util::to_string(*node.inst) << ": ";
            if (const llvm::Instruction *I = node.inst->get_inst()) {
                functions.insert(I->getFunction());
                const llvm::DebugLoc& DL = I->getDebugLoc();
                if (DL) {
                    llvm::print_full_debug_info(os, DL);
                }
            }
            
            os << "\n";
        };
        
        std::optional<NodeRef> src;
        for (auto it = actions.rbegin(); it != actions.rend(); ++it) {
            const Action& action = *it;
            if (!src) {
                print_ref(action.src);
            } else {
                assert(*src == action.src);
            }
            os << aeg::Edge::kind_tostr(action.edge) << "\n";
            print_ref(action.dst);
            src = action.dst;
        }
        
        // also dump relevant functions
        os << "\nFunctions:\n";
        for (const llvm::Function *F : functions) {
            os << *F << "\n";
        }
        
        ofs << s;
        
        ofs << "\n";
        for (NodeRef ref : leak.vec) {
            const auto& node = aeg.lookup(ref);
            const bool taint = node.attacker_taint;
            ofs << ref << " " << taint << "\n";
        }
    }
    // print short debug locations
    {
        std::stringstream ss;
        ss << output_dir << "/test.out";
        std::ofstream ofs {ss.str(), std::ofstream::app};
        for (auto it = actions.rbegin(); it != actions.rend(); ++it) {
            const Action& action = *it;
            const auto print_node = [&] (NodeRef ref) {
                const aeg::Node& node = aeg.lookup(ref);
                if (node.is_special()) {
                    if (ref == aeg.entry) {
                        ofs << "ENTRY";
                    } else if (aeg.exits.contains(ref)) {
                        ofs << "EXIT";
                    } else {
                        std::abort();
                    }
                } else {
                    const llvm::Instruction *I = node.inst->get_inst();
                    const llvm::DebugLoc& DL = I->getDebugLoc();
                    if (DL) {
                        ofs << DL.getLine() << ":" << DL.getCol();
                    } else {
                        ofs << "(none)";
                    }
                }
                ofs << ";";
            };
            if (it == actions.rbegin()) {
                print_node(action.src);
            }
            ofs << action.edge << ";";
            print_node(action.dst);
        }
        ofs << "\n";
    }
    
    std::stringstream ss;
    ss << output_dir << "/" << name();
    for (const NodeRef ref : leak.vec) {
        ss << "-" << ref;
    }
    ss << ".dot";
    const std::string path = ss.str();
    const auto edge = push_edge(EdgeRef {
        .src = leak.transmitter,
        .dst = aeg.exit_con(eval),
        .kind = aeg::Edge::RFX,
    });
    
    // TODO: shouldn't need to do this
    std::vector<std::tuple<NodeRef, NodeRef, aeg::Edge::Kind>> flag_edges_;
    std::transform(flag_edges.begin(), flag_edges.end(), std::back_inserter(flag_edges_), [] (const EdgeRef& e) {
        return std::make_tuple(e.src, e.dst, e.kind);
    });
    
    // add to detector's transmitters list
    {
        const aeg::Node& transmitter_node = aeg.lookup(leak.transmitter);
        transmitters.insert(transmitter_node.inst->get_inst());
    }

    // Export the witness graph as JSON (cloupy-graph-v1).
    if (cloupy_json) {
        const std::string fn = sanitize_component(aeg.function_name());

        const std::string cloupy_dir = util::to_string(output_dir, "/cloupy/", fn);
        if (::mkdir(cloupy_dir.c_str(), 0775) < 0 && errno != EEXIST) {
            throw std::system_error(errno, std::generic_category(), "mkdir");
        }

        std::stringstream jss;
        jss << cloupy_dir << "/" << name();
        for (const NodeRef ref : leak.vec) {
            jss << "-" << ref;
        }
        jss << ".json";

        // Nodes: mirror AEG::output_execution (executed nodes only), but keep
        // ENTRY/EXIT even if they end up being pruned by the model.
        std::vector<NodeRef> nodes;
        nodes.reserve(aeg.size());
        for (const NodeRef ref : aeg.node_range()) {
            const aeg::Node& node = aeg.lookup(ref);
            if (node.is_special() || eval(node.exec())) {
                nodes.push_back(ref);
            }
        }
        std::sort(nodes.begin(), nodes.end());

        NodeRefSet node_set;
        node_set.reserve(nodes.size());
        for (const NodeRef r : nodes) {
            node_set.insert(r);
        }

        // Edges: explicit information-flow edges (ADDR/DATA/CTRL) + (optionally)
        // ordering edges (PO/TFO), plus pseudo relations (RF/RFX).
        using EdgeT = std::tuple<std::string, NodeRef, NodeRef>;
        std::vector<EdgeT> edges;

        const auto add_edge = [&] (aeg::Edge::Kind kind, NodeRef src, NodeRef dst) {
            const auto mk = cloupy_edge_kind(kind);
            if (!mk) {
                return;
            }
            if (!node_set.contains(src) || !node_set.contains(dst)) {
                return;
            }
            edges.emplace_back(std::string(*mk), src, dst);
        };

        // Explicit edges.
        const aeg::Edge::Kind explicit_kinds[] = {
            aeg::Edge::PO,
            aeg::Edge::TFO,
            aeg::Edge::ADDR,
            aeg::Edge::ADDR_GEP,
            aeg::Edge::DATA,
            aeg::Edge::CTRL,
        };

        for (const auto kind : explicit_kinds) {
            aeg.for_each_edge(kind, [&] (NodeRef src, NodeRef dst, const aeg::Edge& e) {
                if (eval(e.exists)) {
                    add_edge(kind, src, dst);
                }
            });
        }

        // Pseudo edges (RF/RFX): computed by enumerating executed nodes and
        // evaluating the corresponding existence predicate under the model.
        const aeg::Edge::Kind pseudo_kinds[] = {aeg::Edge::RF, aeg::Edge::RFX};
        for (const auto kind : pseudo_kinds) {
            for (const NodeRef src : nodes) {
                if (!eval(aeg.exists_src(kind, src))) {
                    continue;
                }
                for (const NodeRef dst : nodes) {
                    if (!eval(aeg.exists_dst(kind, dst))) {
                        continue;
                    }
                    if (eval(aeg.exists(kind, src, dst))) {
                        add_edge(kind, src, dst);
                    }
                }
            }
        }

        std::sort(edges.begin(), edges.end());
        edges.erase(std::unique(edges.begin(), edges.end()), edges.end());

        // Type the witness graph as well and log whether the checker flags the
        // transmitter the SMT search found.
        {
            axtypes::Graph tg;
            for (const NodeRef ref : nodes) {
                const aeg::Node& node = aeg.lookup(ref);
                tg.add_event(static_cast<int>(ref),
                             axtypes::kind_from_cloupy(cloupy_kind_for_node(node)),
                             std::string(cloupy_exec_mode_for_node(node, eval)) == "spec",
                             axtypes::PUBLIC, axtypes::PUBLIC,
                             util::to_string(*node.inst),
                             node.inst->is_exit());
            }
            for (const auto& [k, s, d] : edges) {
                const int si = static_cast<int>(s), di = static_cast<int>(d);
                if (k == "addr") tg.add(tg.addr, si, di);
                else if (k == "data") tg.add(tg.data, si, di);
                else if (k == "ctrl") tg.add(tg.ctrl, si, di);
                else if (k == "rf") tg.add(tg.rf, si, di);
                else if (k == "rfx") tg.add(tg.rfx, si, di);
            }
            axtypes::apply_clou_secret_policy(tg);
            const auto cr = axtypes::check_containment(tg);
            bool tx_flagged = false;
            for (const auto& v : cr.violations)
                if (v.obs_name == "AddrObs" && v.eid == static_cast<int>(leak.transmitter))
                    tx_flagged = true;
            llvm::errs() << "AXTYPES: " << (cr.ok ? "CONTAINED" : "LEAK")
                         << " agree=" << ((!cr.ok && tx_flagged) ? "yes" : "no")
                         << " smt_transmitter=" << leak.transmitter
                         << " axtypes_flagged=" << cr.violations.size() << "\n";
        }

        // Emit JSON in cloupy-graph-v1 format.
        std::ofstream jofs {jss.str()};
        jofs << "{\n";
        jofs << "  \"version\": \"cloupy-graph-v1\",\n";
        jofs << "  \"events\": [\n";

        for (std::size_t i = 0; i < nodes.size(); ++i) {
            const NodeRef ref = nodes[i];
            const aeg::Node& node = aeg.lookup(ref);

            std::string nm = util::to_string(*node.inst);
            if (const llvm::Instruction* I = node.inst->get_inst()) {
                const llvm::DebugLoc& DL = I->getDebugLoc();
                if (DL) {
                    nm += util::to_string(" @", DL.getLine(), ":", DL.getCol());
                }
            }

            jofs << "    {\"id\": " << ref << ", \"name\": ";
            json_emit_string(jofs, nm);
            jofs << ", \"kind\": \"" << cloupy_kind_for_node(node) << "\"";
            jofs << ", \"base\": \"L\"";
            jofs << ", \"struct_unsafe\": " << (cloupy_struct_unsafe_for_node(node, eval) ? "true" : "false");
            jofs << ", \"is_receiver\": " << (node.inst->is_exit() ? "true" : "false");
            jofs << ", \"exec_mode\": \"" << cloupy_exec_mode_for_node(node, eval) << "\"";
            jofs << ", \"guard\": null}";

            if (i + 1 != nodes.size()) {
                jofs << ",";
            }
            jofs << "\n";
        }

        jofs << "  ],\n";
        jofs << "  \"edges\": [\n";

        for (std::size_t i = 0; i < edges.size(); ++i) {
            const auto& e = edges[i];
            jofs << "    {\"kind\": ";
            json_emit_string(jofs, std::get<0>(e));
            jofs << ", \"src\": " << std::get<1>(e) << ", \"dst\": " << std::get<2>(e) << "}";
            if (i + 1 != edges.size()) {
                jofs << ",";
            }
            jofs << "\n";
        }

        jofs << "  ]\n";
        jofs << "}\n";
    }
    
    if (witness_executions) {
        aeg.output_execution(path, eval, flag_edges_);
    }
    
    if (fast_mode) {
        throw next_transmitter {};
    }
    // Export to ClouPy JSON format
    if (! output_dir.empty()) {
        std::stringstream ss;
        ss << output_dir << "/cloupy_graph";
        for (NodeRef ref : leak.vec) {
            ss << "_" << ref;
        }
        ss << ".json";
	std::cerr << "DEBUG: Attempting to export ClouPy JSON to: " << ss.str() << "\n";
        cloupy::export_graph_to_json(aeg, eval, ss.str(), exec_window);
    }
}


void Leakage::print_long(std::ostream& os, const aeg::AEG& aeg) const {
    for (auto it = vec.begin(); it != vec.end(); ++it) {
        if (it != vec.begin()) {
            os << "; ";
        }
        os << *aeg.lookup(*it).inst;
    }
}

void Leakage::print_short(std::ostream& os) const {
    for (auto it = vec.begin(); it != vec.end(); ++it) {
        if (it != vec.begin()) {
            os << " ";
        }
        os << *it;
    }
}


/* LEAKAGE DETECTOR METHODS */

DetectorJob::DetectorJob(aeg::AEG& aeg, z3::context& local_ctx, z3::solver& solver, NodeRef candidate_transmitter, std::vector<std::pair<Leakage, std::string>>& leaks):
lock(aeg.context.mutex),
candidate_transmitter(candidate_transmitter),
aeg(aeg),
local_ctx(local_ctx),
solver(solver),
alias_solver(ctx()),
init_mem(z3::const_array(ctx().int_sort(), ctx().int_val(static_cast<unsigned>(aeg.entry)))),
leaks(leaks)
{}

DetectorJob::Mems DetectorJob::get_mems(const NodeRefSet& set) {
    Mems ins;
    Mems outs;
    z3::expr mem = init_mem;
    for (const NodeRef ref : aeg.po.reverse_postorder()) {
        if (ref == aeg.entry || set.find(ref) == set.end()) { continue; }
        const aeg::Node& node = aeg.lookup(ref);
        
        ins.emplace(ref, mem);
        
        if (node.may_write()) {
            mem = z3::conditional_store(mem, aeg.get_memory_address(ref), ctx().int_val(static_cast<unsigned>(ref)), node.exec() && node.write);
        }
        
        outs.emplace(ref, mem);
    }
    
    return ins;
}

bool DetectorJob::lookahead(std::function<void ()> thunk) {
    if (!use_lookahead) {
        return true;
    }
    try {
        thunk();
        lookahead_tmp = false;
        return false;
    } catch (const lookahead_found&) {
        lookahead_tmp = true;
        return true;
    }
}

void DetectorJob::traceback_rf(NodeRef load, aeg::ExecMode exec_mode, std::function<void (NodeRef, CheckMode)> func, CheckMode mode) {
    // Sources new_sources;
    const auto& stores = rf_sources(load);
    if (mode == CheckMode::SLOW) {
        logv(1, __FUNCTION__ << ": tracing back " << stores.size() << " stores\n");
    }
    for (const auto& store_pair : stores) {
        const NodeRef store = store_pair.first;
        
        assert(exec_window.contains(load));
        
        switch (exec_mode) {
            case aeg::ExecMode::ARCH:
            case aeg::ExecMode::EXEC:
                if (!exec_window.contains(store)) { continue; }
                break;
            case aeg::ExecMode::TRANS:
                if (!trans_window.contains(store)) { continue; }
                break;
            default: std::abort();
        }
        
        if (mode == CheckMode::SLOW && use_lookahead && !lookahead([&] () {
            func(store, CheckMode::FAST);
        })) {
            if (mode == CheckMode::SLOW) {
                logv(1, __FUNCTION__ << ": skipping: failed lookahead\n");
            }
            continue;
        }
        z3_cond_scope;
        const std::string desc = util::to_string(store, " -rf-> ", load);
        if (mode == CheckMode::SLOW) {
            const z3::expr& cond = store_pair.second;
            solver_add(translate(cond), desc.c_str());
            solver_add(translate(aeg.lookup(store).exec(exec_mode)));
        }

        const auto action = util::push(actions, {.src = store, .edge = aeg::Edge::Kind::RF, .dst = load});
        
        // new_sources.insert(store_pair);
        // TODO: need to separately check if this is due to something else
        func(store, mode);
    }
}

void DetectorJob::traceback_edge(aeg::Edge::Kind kind, NodeRef ref, std::function<void (NodeRef, CheckMode)> func, CheckMode mode) {
    const auto edges = aeg.get_nodes(Direction::IN, ref, kind);
    for (const auto& edge : edges) {
        if (!check_edge(edge.first, ref)) { continue; }
        z3_cond_scope;
        if (mode == CheckMode::SLOW) {
            assert_edge(edge.first, ref, edge.second, kind);
        }
        const auto action = util::push(actions, {.src = edge.first, .edge = kind, .dst = ref});
        
        if (mode == CheckMode::SLOW && use_lookahead && !lookahead([&] () {
            func(edge.first, CheckMode::FAST);
        })) {
            continue;
        }
        
        func(edge.first, mode);
    }
}

void DetectorJob::traceback(NodeRef load, aeg::ExecMode exec_mode, std::function<void (NodeRef, CheckMode)> func, CheckMode mode) {
    const aeg::Node& load_node = aeg.lookup(load);
    
    if (traceback_depth == max_traceback) {
        if (mode == CheckMode::SLOW) {
            std::cerr << "backtracking: max traceback depth (" << max_traceback << ")\n";
        }
        return;
    }
    
    // TODO: POSSIBLY UNNECESSARY SCOPE: there is no forking here
    z3_cond_scope;
    if (mode == CheckMode::SLOW) {
        solver.add(translate(load_node.exec() && load_node.read), util::to_string(load, ".read").c_str());
        if (solver_check() == z3::unsat) { return; }
    }
    
    const auto inc_depth = util::inc_scope(traceback_depth);
    
    // traceback via rf.data
    // TODO: This shouldn't necessarily always be TRANS.
    traceback_rf(load, exec_mode, [&] (const NodeRef store, CheckMode mode) {
        traceback_edge(aeg::Edge::DATA, store, func, mode);
    }, mode);
    
    // traceback via addr
    traceback_edge(aeg::Edge::ADDR, load, func, mode);
}

void DetectorJob::for_one_transmitter(NodeRef transmitter, std::function<void (NodeRef, CheckMode)> func, bool priv) {
    rf.clear();
    
    {
        logv(1, "windows ");
        Timer timer;
        // MAKE EXEC WINDOW
        {
            std::vector<CFG::FuncID> func_id_pfx; // function ID prefix
            exec_window.clear();
            exec_notwindow.clear();
            aeg.for_each_pred_in_window(transmitter, window_size, [&] (NodeRef ref) {
                exec_window.insert(ref);
                const auto& po_node = aeg.po.lookup(ref);
                {
                    std::vector<CFG::FuncID> new_func_id_pfx;
                    util::shared_prefix(func_id_pfx, po_node.id->func, std::back_inserter(new_func_id_pfx));
                    func_id_pfx = std::move(new_func_id_pfx);
                }
            }, [&] (NodeRef ref) {
                exec_notwindow.insert(ref);
            });
            
            // TODO: This should be removed, since the 'pruning paths' step will result in an empty window anyway.
            const bool reaches_main_function = func_id_pfx.empty();
            if (!reaches_main_function) {
                logv(2, "skipping transmitter " << transmitter << " because it doesn't reach main function\n");
                return;
            }
            
            /* pruning paths */
            auto new_exec_window = aeg.po.prune_exec_window(exec_window);
            logv(2, "pruned " << (exec_window.size() - new_exec_window.size()) << " transmitters that don't reach main function\n");
            exec_window = std::move(new_exec_window);
            for (NodeRef ref : aeg.po.reverse_postorder()) {
                if (!exec_window.contains(ref)) {
                    exec_notwindow.insert(ref);
                }
            }
            
            mems = get_mems(exec_window);
        }
        
        // MAKE TRANS WINDOW
        {
            trans_window.clear();
            trans_notwindow.clear();
            aeg.for_each_pred_in_window(transmitter, spec_depth, [&] (NodeRef ref) {
                trans_window.insert(ref);
            }, [&] (NodeRef ref) {
                trans_notwindow.insert(ref);
            });
        }
    }
    
    if (use_lookahead && !lookahead([&] () {
        func(transmitter, CheckMode::FAST);
    })) {
        logv(1, __FUNCTION__ << "skipping transmitter: failed lookahead\n");
        return;
    }
    
    Timer timer;
    
    if (transmitters.find(aeg.lookup(transmitter).inst->get_inst()) != transmitters.end()) {
        return;
    }

#if 0
    const auto action = util::push(actions, util::to_string("transmitter ", transmitter));
#endif
    
    const aeg::Node& transmitter_node = aeg.lookup(transmitter);
    
    if (aeg.exits.find(transmitter) != aeg.exits.end()) {
        return;
    }
    
    z3::expr_vector vec {ctx()};
    
    // require transmitter is access
    vec.push_back(transmitter_node.access());
    
    // require transmitter.trans
    vec.push_back(transmitter_node.trans);
    
    // window size
    {
        z3::expr window_expr {local_ctx};
        z3::model window_model {local_ctx};
        z3::expr F = ctx().bool_val(false);
        z3::expr zero = ctx().int_val(0);
        const auto nullify = [&] (const z3::expr& e, z3::expr& repl) {
            if (e.is_const()) {
                z3::func_decl decl = e.decl();
                window_model.add_const_interp(decl, repl);
            }
        };
        const auto nullify_bool = [&] (const z3::expr& e) {
            nullify(e, F);
        };
        const auto nullify_int = [&] (const z3::expr& e) {
            nullify(e, zero);
        };
        
        for (NodeRef ref : exec_notwindow) {
            assert(!aeg.exits.contains(ref));
            const auto& node = aeg.lookup(ref);
            vec.push_back(!node.exec());
            nullify_bool(node.arch);
            nullify_bool(node.trans);
            nullify_bool(node.read);
            nullify_bool(node.write);
            nullify_bool(node.xsread);
            nullify_bool(node.xswrite);
            if (node.xsaccess_order) {
                nullify_int(*node.xsaccess_order);
            }
        }
        for (NodeRef ref : trans_notwindow) {
            if (!exec_notwindow.contains(ref)) {
                const auto& node = aeg.lookup(ref);
                vec.push_back(!node.trans);
                nullify_bool(node.trans);
            }
        }
        
        /* invalidate edges too */
        {
            aeg.for_each_edge([&] (NodeRef src, NodeRef dst, const aeg::Edge& e) {
                if (!(exec_window.contains(src) && exec_window.contains(dst))) {
                    // invalidate edge
                    nullify_bool(e.exists);
                }
            });
        }
        
        if (priv) {
            Timer timer;
            logv(1, "translating to window...\n");
            z3::solver new_solver {local_ctx};
            for (z3::expr old_assertion : solver.assertions()) {
                z3::expr new_assertion = window_model.eval(old_assertion);
                new_assertion = new_assertion.simplify();
                assert(!new_assertion.is_false());
                if (!new_assertion.is_true()) {
                    new_solver.add(new_assertion);
                }
            }
            logv(1, "translated to window in " << timer.get_str() << "\n");
            solver = new_solver;
            
            const auto solver_add = [&] (const z3::expr& e, const std::string& s) {
#if 0
                static unsigned i = 0;
                solver.add(translate(e), util::to_string(s, "-", i++).c_str());
#else
                solver.add(translate(e));
#endif
            };
            aeg.constrain_arch(exec_window, solver_add);
            aeg.constrain_exec(exec_window, solver_add);
            aeg.constrain_tfo(exec_window,  solver_add);
            aeg.constrain_comx(exec_window, solver_add);
            aeg.constrain_aliases(exec_window, solver_add);
            
            aeg.for_each_edge([&] (NodeRef src, NodeRef dst, const aeg::Edge& edge) {
                edge.constraints.add_to(solver_add);
            });
            
            aeg.constraints.add_to(solver_add);

        }
        
    }
    
    logv(0, __FUNCTION__ << ": adding window constraints\n");
    std::optional<Timer> timer_opt = Timer();
    
    std::optional<z3::scope> scope;
    if (!priv) {
        scope.emplace(solver);
    }
    
    for (const z3::expr& e : vec) { solver.add(translate(e)); }
    logv(0, __FUNCTION__ << ": added window constraints in " << timer_opt->get_str() << "\n");
    timer_opt = std::nullopt;
    
    if (solver_check() != z3::unsat) {
        for (const auto& assertion : aeg.assert_xsaccess_order(exec_window)) {
            solver.add(translate(assertion.first), assertion.second.c_str());
        }
        
        try {
            func(transmitter, CheckMode::SLOW);
        } catch (const next_transmitter& e) {
            // continue
        }
    } else {
        logv(1, "skipping transmitter\n");
        logv(1, "access: " << util::to_string(transmitter_node.access()) << "\n");
        logv(1, "trans: " << util::to_string(transmitter_node.trans) << "\n");
        dbg::append_core(solver, "skipped transmitter");
    }
}

#if 0
template <class OutputIt>
OutputIt DetectorJob::for_new_transmitter(NodeRef transmitter, std::function<void (NodeRef, CheckMode)> func, OutputIt out) {
    
    char *path;
    if (::asprintf(&path, "%s/tmp/lkg.XXXXXX", output_dir.c_str()) < 0) {
        throw std::system_error(errno, std::generic_category(), "asprintf");
    }
    int fd = ::mkstemp(path);
    std::free(path);
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(), "mkstemp");
    }
    
    ::signal(SIGSEGV, SIG_DFL);
    ::signal(SIGABRT, SIG_DFL);
    
    const pid_t pid = ::fork();
    if (pid < 0) {
        std::perror("fork");
        std::abort();
    } else if (pid == 0) {
        
        leaks.clear();
        transmitters.clear();
        
        if (semid >= 0) {
            logv(1, "waiting on semaphore...\n");
            semutil::acquire(semid);
            logv(1, "starting\n");
        }
        
        Timer timer;
        
        for_one_transmitter(transmitter, func, true);
        
        if (fast_mode && leaks.size() > 1) {
            std::cerr << "ERROR: num leaks: " << leaks.size() << "\n";
            std::abort();
        }
        
        // write leakage to parent
        for (const auto& leakage_pair : leaks) {
            lkg::LeakageMsg msg;
            for (NodeRef ref : leakage_pair.first.vec) {
                msg.mutable_vec()->Add(ref);
            }
            assert(msg.vec().size() > 1);
            msg.set_transmitter(leakage_pair.first.transmitter);
            msg.set_desc(leakage_pair.second);
            
            if (!proto::write(fd, msg)) {
                std::cerr << "failed to write leakage\n";
                std::abort();
            }
        }
        
        logv(0, "RUNTIME: " << ::getppid() << " " << ::getpid() << " " << cpu_time() << "\n");
        
        std::_Exit(0); // quick exit
    } else {
        *out++ = std::make_pair(pid, Child {.ref = transmitter, .fd = fd});
        return out;
    }
}
#endif

#if 0
void DetectorJob::for_each_transmitter(std::function<void (NodeRef, CheckMode)> func) {
    const aeg::Edge::Kind kind = deps().back().first;
    NodeRefSet candidate_transmitters;
    {
        z3::solver solver {ctx()};
        aeg.for_each_edge(kind, [&] (NodeRef, NodeRef ref, const aeg::Edge&) {
            const aeg::Node& node = aeg.lookup(ref);
            
            z3::expr_vector vec(ctx());
            vec.push_back(node.trans);
            vec.push_back(node.access());
            if (solver.check(vec) != z3::unsat) {
                candidate_transmitters.insert(ref);
            }
        });
    }
    
    // filter out any already-seen transmitters
    {
        std::erase_if(candidate_transmitters, [&] (NodeRef ref) -> bool {
            const auto& node = aeg.lookup(ref);
            if (const llvm::Instruction *I = node.inst->get_inst()) {
                if (::transmitters.contains(I)) {
                    llvm::errs() << "filtered transmitter: " << *I << "\n";
                    return true;
                }
            }
            return false;
        });
    }
    
    
    /* make sure that the AEG constraints are satisfiable.
     * NOTE: I should probably move this to AEG::leakage(). */
#ifndef NDEBUG
    {
        const auto check_res = solver.check();
        if (check_res != z3::sat) {
            std::cerr << __FUNCTION__ << ": AEG constraints unsat!\n";
            std::cerr << solver.unsat_core() << "\n";
            std::abort();
        }
    }
#endif
    
    if (max_parallel > 1) {
        
        for_each_transmitter_parallel_private(candidate_transmitters, func);
        
    } else {
        std::cerr << "using 1 thread\n";
        std::size_t i = 0;
        for (NodeRef transmitter : candidate_transmitters) {
            ++i;
            logv(1, i << "/" << candidate_transmitters.size() << "       " << aeg.po.lookup(transmitter) << "\n");
            if (client) {
                mon::Message msg;
                auto *progress = msg.mutable_func_progress();
                progress->mutable_func()->set_name(aeg.po.function_name());
                const float frac = static_cast<float>(i) / static_cast<float>(candidate_transmitters.size());
                progress->set_frac(frac);
                client.send(msg);
            }
            
            for_one_transmitter(transmitter, func, false);
        }
    }
}
#endif

NodeRefSet DetectorJob::reachable_r(const NodeRefSet& window, NodeRef init) const {
    NodeRefVec todo = {init};
    NodeRefSet seen;
    while (!todo.empty()) {
        const NodeRef ref = todo.back();
        todo.pop_back();
        if (!window.contains(ref)) { continue; }
        if (!seen.insert(ref).second) { continue; }
        util::copy(aeg.po.po.rev.at(ref), std::back_inserter(todo));
    }
    return seen;
}

std::unordered_map<NodeRef, z3::expr> DetectorJob::precompute_rf_one(NodeRef load, const NodeRefSet& window) {
    z3::expr no = ctx().bool_val(true);
    std::unordered_map<NodeRef, z3::expr> yesses;
    for (NodeRef store : aeg.po.postorder()) {
        if (!window.contains(store)) { continue; }
        const auto& store_node = aeg.lookup(store);
        if (!store_node.may_write()) { continue; }
        
        const z3::expr write = store_node.exec() && store_node.write && aeg.same_addr(store, load);
        yesses.emplace(store, no && write);
        
        no = no && !write;
    }
    
    return yesses;
}

void DetectorJob::precompute_rf(NodeRef load) {
    logv(1, "precomputing rf " << load << "\n");
    Timer timer;
    
    auto& out = rf[load];
    
    if (aeg.exits.contains(load)) { return; }
    const aeg::Node& node = aeg.lookup(load);
    if (!node.may_read()) { return; }
    
    assert(alias_mode.transient);
    
    const NodeRefSet window = reachable_r(exec_window, load);
    const auto mem = precompute_rf_one(load, window);
    
    for (const NodeRef ref : window) {
        const auto& store_node = aeg.lookup(ref);
        if (!store_node.may_write()) { continue; }
        
#if 0
        /* make sure that types agree */
        {
            /* either both pointers or neither pointers */
            const auto& load_node = aeg.lookup(load);
            const auto *load_op = load_node.get_memory_address_pair().first;
            if (const auto *store_inst = dynamic_cast<const MemoryInst *>(store_node.inst.get())) {
                const auto *store_op = store_inst->get_memory_operand();

                if (llvm::to_string(*load_op->getType()) == "type opaque") {
                    goto label;
                }
                
                auto *load_type = load_op->getType()->getPointerElementType();
                if (load_type != load_node.inst->get_inst()->getType()) {
                    llvm::errs() << "load_type = " << *load_type << "\n";
                    llvm::errs() << "load_node->inst.get_inst()->getType() = " << *load_node.inst->get_inst()->getType() << "\n";
                }
                assert(load_type == load_node.inst->get_inst()->getType());
                auto *store_type = store_op->getType()->getPointerElementType();
                
                if (load_type->isPointerTy() != store_type->isPointerTy()) {
                    continue;
                }
                
                /* check if type sizes differ */
                llvm::DataLayout DL(store_inst->get_inst()->getModule());
                if (DL.getTypeSizeInBits(load_type) != DL.getTypeSizeInBits(store_type)) {
                    continue;
                }
            }
        }
        
        label:
#endif
        
        
        /* check if this store occurs before AllocaInst is allocated */
        {
            const auto& load_node = aeg.po.lookup(load);
            if (const auto *AI = llvm::dyn_cast<llvm::AllocaInst>(aeg.lookup(load).get_memory_address_pair().first)) {
                const auto ai_refs = load_node.refs.at(AI);
                if (ai_refs.size() == 1) {
                    const auto ai_ref = *ai_refs.begin();
                    if (ref < ai_ref) {
                        continue; // can't possibly alias
                    }
                }
            }
        }
        
        if (aeg.lookup(ref).may_write()) {
            switch (aeg.compute_alias(load, ref)) {
                case llvm::AliasResult::NoAlias:
#if 0
                    break;
#endif
                    
                case llvm::AliasResult::MayAlias:
                case llvm::AliasResult::MustAlias:
                    /* necessary condition: the two pointers must alias */
                    //out.emplace(ref, mems.at(load)[node.get_memory_address()] == ctx().int_val((unsigned) ref));
                    // out.emplace(ref, mem(load)[node.get_memory_address()] == ctx().int_val((unsigned) ref));
                    out.emplace(ref, mem.at(ref));
                    break;
                    
                default: std::abort();
            }
        }
    }
    
    // filter by satisfiable aliases
    unsigned filtered = 0;
    for (auto it = out.begin(); it != out.end(); ) {
        bool keep = true;
        
        // check if alias expression is always false
        if (it->first != aeg.entry) {
            const z3::expr alias = aeg.get_memory_address(it->first) == aeg.get_memory_address(load);
            if (alias.simplify().is_false()) {
                keep = false;
            } else {
                z3::expr_vector vec(ctx());
                vec.push_back(alias);
                if (alias_solver.check(vec) == z3::unsat) {
                    keep = false;
                }
            }
        }
        
        if (keep) {
            ++it;
        } else {
            it = out.erase(it);
            ++filtered;
        }
    }
    {
        std::stringstream ss;
        for (const auto& pair : out) {
            ss << " " << pair.first;
        }
        logv(1, __FUNCTION__ << ": filtered " << filtered << " {" << ss.str() << "}\n");
    }
}

const DetectorJob::Sources& DetectorJob::rf_sources(NodeRef load) {
    auto it = rf.find(load);
    if (it == rf.end()) {
        precompute_rf(load);
        it = rf.find(load);
    }
    assert(it != rf.end());
    return it->second;
}

void DetectorJob::rf_sources(NodeRef load, Sources&& sources) {
    rf[load] = sources;
}


void DetectorJob::assert_edge(NodeRef src, NodeRef dst, const z3::expr& edge, aeg::Edge::Kind kind) {
    const auto desc = [src, dst] (const std::string& name) -> std::string {
        return util::to_string(name, "-", src, "-", dst);
    };
    
    solver.add(translate(edge), desc(util::to_string(kind)).c_str());
    
    const auto& src_node = aeg.lookup(src);
    const auto& dst_node = aeg.lookup(dst);
    solver.add(translate(z3::implies(src_node.trans, dst_node.trans)), desc("trans->trans").c_str());
    solver.add(translate(z3::implies(dst_node.arch, src_node.arch)), desc("arch<-arch").c_str());
    
    if (aeg.po.same_basic_block(src, dst)) {
        NodeRef ref = src;
        while (ref != dst) {
            solver.add(translate(aeg.lookup(ref).exec()));
            ref = *aeg.po.po.fwd.at(ref).begin();
        }
    }
}




void DetectorJob::traceback_deps(NodeRef from_ref, std::function<void (const NodeRefVec&, CheckMode)> func, CheckMode mode) {
    NodeRefVec vec;
    DepVec deps;
    if (custom_deps.empty()) {
        deps = this->default_deps();
    } else {
        deps = custom_deps;
    }
    traceback_deps_rec(deps.rbegin(), deps.rend(), vec, from_ref, func, mode);
}

DetectorJob::DepVec DetectorJob::deps() const {
    if (custom_deps.empty()) {
        return default_deps();
    } else {
        return custom_deps;
    }
}


void DetectorJob::traceback_deps_rec(DepIt it, DepIt end, NodeRefVec& vec, NodeRef from_ref, std::function<void (const NodeRefVec&, CheckMode)> func, CheckMode mode) {
    const auto push_ref = util::push(vec, from_ref);
    
    if (mode == CheckMode::SLOW) {
        using output::operator<<;
        logv(1, __FUNCTION__ << ": " << vec << "\n");
        
        // lookahead
        if (use_lookahead && !lookahead([&] () {
            traceback_deps_rec(it, end, vec, from_ref, func, CheckMode::FAST);
        })) {
            return;
        }
    }
    
    // check if done (all dependencies found)
    if (it == end) {
        if (mode == CheckMode::SLOW) {
            logv(1, __FUNCTION__ << ": all dependencies found\n");
            if (solver_check() == z3::unsat) {
                logv(1, __FUNCTION__ << ":" << __LINE__ << ": backtrack: unsat\n");
                dbg::append_core(solver, "all dependencies found");
                return;
            }
        }
        func(vec, mode);
        goto label;
    }
    
    // try committing load
    {
        const aeg::Edge::Kind dep_kind = it->first;
        const aeg::ExecMode dep_src_mode = it->second;
        const auto deps = aeg.get_nodes(Direction::IN, from_ref, dep_kind);
        
        if (deps.empty()) {
            goto label;
        }
        
        if (mode == CheckMode::SLOW) {
            if (solver_check() == z3::unsat) {
                logv(1, __FUNCTION__ << ":" << __LINE__ << ": backtrack: unsat\n");
                dbg::append_core(solver, "committing load");
                return;
            }
            logv(1, "trying to commit " << from_ref << " (" << deps.size() << " deps)\n");
        }
        
        for (const auto& dep : deps) {
            const NodeRef to_ref = dep.first;
            if (!check_edge(to_ref, from_ref)) {
                continue;
            }
            
            z3_cond_scope;
            
            if (mode == CheckMode::SLOW) {
                assert_edge(to_ref, from_ref, dep.second, dep_kind);
                solver.add(translate(aeg.lookup(to_ref).exec(dep_src_mode)), util::to_string(to_ref, " ", dep_kind, " ", from_ref, " ", dep_src_mode).c_str());
            }
            
            const auto push_edge = util::push(flag_edges, EdgeRef {
                .src = to_ref,
                .dst = from_ref,
                .kind = dep_kind
            });
            
            const std::string desc = util::to_string(to_ref, "-", dep_kind, "->", from_ref);
#if 0
            const auto push_action = util::push(actions, desc);
#else
            const auto push = util::push(actions, {.src = to_ref, .edge = dep_kind, .dst = from_ref});
#endif
            
            if (mode == CheckMode::SLOW) {
                logv(1, __FUNCTION__ << ": committed " << desc << "\n");
            }
            
            traceback_deps_rec(std::next(it), end, vec, to_ref, func, mode);
        }
    }
    
label:
    
    /* traceback
     * NOTE: only if it's not the universal transmitter.
     */
    assert(!vec.empty());
    if (from_ref != vec.front()) {
        std::cerr << "checking TB " << from_ref << "\n";
        traceback(from_ref, aeg::ExecMode::EXEC, [&] (NodeRef to_ref, CheckMode mode) {
            if (mode == CheckMode::SLOW) {
                logv(1, "traceback " << to_ref << "-TB->" << from_ref << "\n");
            }
            traceback_deps_rec(it, end, vec, to_ref, func, mode);
        }, mode);
    }
}


z3::check_result DetectorJob::solver_check(bool allow_unknown) {
    lock.unlock();
    
    z3::check_result res;
    Stopwatch timer;
    timer.start();
    
    const auto timeout = get_timeout();
    if (allow_unknown && timeout) {
        const unsigned timeout2 = static_cast<unsigned>(std::ceil(*timeout * 1000));
        logv(2, __FUNCTION__ << ": checking with time limit " << timeout2 << "ms\n");
        res = z3::check_timeout(solver, timeout2);
    } else {
        do {
            logv(2, __FUNCTION__ << ": checking with no time limit\n");
            res = solver.check();
        } while (res == z3::unknown && solver.reason_unknown() == "canceled");
    }
    
    timer.stop();
    const auto duration = timer.get();
    if (res != z3::unknown) {
        set_timeout(res, duration);
    }
    logv(2, __FUNCTION__ << ": got " << util::to_string(res) << " in " << static_cast<unsigned>(duration * 1000) << "ms\n");
    switch (res) {
        case z3::sat:
            ++check_stats.sat;
            break;
        case z3::unsat:
            ++check_stats.unsat;
            // logv(2, "unsat core: " << util::to_string(solver.unsat_core()) << "\n");
            break;
        case z3::unknown:
            ++check_stats.unknown;
            break;
    }
    
    lock.lock();
    
    return res;
}

template <typename OS>
inline OS& operator<<(OS& os, const DetectorJob::CheckStats& stats) {
    const auto frac = [&] (unsigned n) -> std::string {
        if (stats.total() == 0) { return "0%"; }
        std::stringstream ss;
        ss << n * 100 / stats.total() << "%";
        return ss.str();
    };
    os << "sat: " << frac(stats.sat) << ", unsat: " << frac(stats.unsat) << ", unknown: " << frac(stats.unknown);
    return os;
}

DetectorJob::~DetectorJob() {
    logv(1, "stats: " << check_stats << "\n");
}


DetectorMain::ParallelContextVec DetectorMain::create_solvers(z3::solver &from_solver, unsigned int N) const {
    ParallelContextVec to_solvers (N);
    
    if (N == 0) { return to_solvers; }

    const auto translate = [] (const z3::solver *from_solver, z3::solver& to_solver) {
        to_solver = z3::translate(*from_solver, to_solver.ctx());
    };
    
    translate(&from_solver, to_solvers.front().solver);

    for (std::size_t idx = 1; idx < N; idx *= 2) {
        std::vector<std::thread> threads;
        for (std::size_t i = 0; i < idx; ++i) {
            const std::size_t j = idx + i;
            if (j < N) {
                threads.emplace_back([] (const z3::solver *from_solver, z3::solver *to_solver) {
                    *to_solver = z3::translate(*from_solver, to_solver->ctx());
                }, &to_solvers.at(i).solver, &to_solvers.at(j).solver);
            }
        }
        
        for (std::thread& thread : threads) {
            thread.join();
        }
    }
    
    return to_solvers;
}

std::ostream& operator<<(std::ostream& os, const DetectorJob::Action& action) {
    os << action.src << "-" << action.edge << "->" << action.dst;
    return os;
}


}

