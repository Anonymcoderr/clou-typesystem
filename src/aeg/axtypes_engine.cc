// Containment check as the detection engine: build an over-approximated graph
// from the AEG, type it, and report every unstable checked observation.

#include "aeg.h"
#include "aeg/node.h"
#include "aeg/edge.h"
#include "inst.h"
#include "util/llvm.h"
#include "config.h"

#include "axtypes/typecheck.h"
#include "axtypes/clou_policy.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Support/KnownBits.h>

#include "axtypes/refine.h"

#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aeg {

namespace {

// Not provably false.
bool possibly(const z3::expr& e) {
    return e.simplify().bool_value() != Z3_L_FALSE;
}

axtypes::Kind node_kind(const Node& node) {
    if (node.inst->is_entry() || node.inst->is_exit()) {
        return axtypes::Kind::Special;
    }
    // Library calls modelled as memory accesses (memcmp) count as well.
    if (node.may_read())  { return axtypes::Kind::Read; }
    if (node.may_write()) { return axtypes::Kind::Write; }
    if (const llvm::Instruction *I = node.inst->get_inst()) {
        if (llvm::isa<llvm::BranchInst>(I) || llvm::isa<llvm::SwitchInst>(I)) {
            return axtypes::Kind::Branch;
        }
    }
    return axtypes::Kind::Other;
}

}

void AEG::test_axtypes(TransmitterOutputIt out) {
    axtypes::Graph g;

    std::vector<NodeRef> refs;
    for (const NodeRef ref : node_range()) {
        const Node& node = lookup(ref);
        const bool transient = possibly(node.trans);
        g.add_event(static_cast<int>(ref), node_kind(node), transient,
                    axtypes::PUBLIC, axtypes::PUBLIC,
                    util::to_string(*node.inst), node.inst->is_exit(),
                    static_cast<bool>(node.attacker_taint));
        refs.push_back(ref);
    }

    const auto collect = [&] (Edge::Kind kind, axtypes::Rel& rel) {
        for_each_edge(kind, [&] (NodeRef src, NodeRef dst, const Edge& e) {
            if (possibly(e.exists)) {
                g.add(rel, static_cast<int>(src), static_cast<int>(dst));
            }
        });
    };
    collect(Edge::ADDR, g.addr);
    collect(Edge::ADDR_GEP, g.addr);
    collect(Edge::DATA, g.data);
    collect(Edge::CTRL, g.ctrl);

    // Index-to-access edges, kept apart for the gated seed policy.
    axtypes::Rel addr_gep;
    for_each_edge(Edge::ADDR_GEP, [&] (NodeRef src, NodeRef dst, const Edge& e) {
        if (possibly(e.exists)) { addr_gep.insert({static_cast<int>(src), static_cast<int>(dst)}); }
    });

    // rf and rfx are not stored in the AEG. Deciding one exactly walks all other
    // writes, so by default every same-location pair in admissible order is kept:
    // a superset, at constant cost per pair. CLOU_AXTYPES_EXACT_COM=1 selects the
    // exact check. The pruning switches are for comparison only; the two
    // alias-based ones drop feasible edges.
    const bool alias_prune = [] {
        const char *p = ::getenv("CLOU_AXTYPES_ALIAS_PRUNE");
        return p && std::string(p) != "0";
    }();
    const bool smt_prune = [] {
        const char *p = ::getenv("CLOU_AXTYPES_SMT_PRUNE");
        return p && std::string(p) != "0";
    }();

    std::optional<z3::solver> feas;
    if (smt_prune) {
        feas.emplace(make_solver());
        NodeRefSet all;
        for (const NodeRef ref : node_range()) { all.insert(ref); }
        const AssertFunc add = [&] (const z3::expr& e, const std::string&) { feas->add(e); };
        constrain_arch(all, add);
        constrain_exec(all, add);
        constrain_tfo(all, add);
        constrain_comx(all, add);
        constrain_aliases(all, add);
        for_each_edge([&] (NodeRef, NodeRef, const Edge& e) { e.constraints.add_to(add); });
        constraints.add_to(add);
    }

    const bool rf_alias_prune = [] {
        const char *p = ::getenv("CLOU_AXTYPES_RF_ALIAS_PRUNE");
        return p && std::string(p) != "0";
    }();
    const bool exact_com = [] {
        const char *p = ::getenv("CLOU_AXTYPES_EXACT_COM");
        return p && std::string(p) != "0";
    }();
    for (const Edge::Kind kind : {Edge::RF, Edge::RFX}) {
        axtypes::Rel& rel = (kind == Edge::RF) ? g.rf : g.rfx;

        std::vector<NodeRef> srcs, dsts;
        for (const NodeRef ref : refs) {
            if (possibly(exists_src(kind, ref))) { srcs.push_back(ref); }
            if (possibly(exists_dst(kind, ref))) { dsts.push_back(ref); }
        }

        for (const NodeRef src : srcs) {
            const bool src_special = lookup(src).is_special();
            for (const NodeRef dst : dsts) {
                if (kind == Edge::RF && rf_alias_prune &&
                    !src_special && !lookup(dst).is_special() &&
                    compute_alias(src, dst) == llvm::AliasResult::NoAlias) {
                    continue;
                }
                z3::expr ex = context.FALSE;
                if (exact_com || src_special || lookup(dst).is_special()) {
                    ex = exists(kind, src, dst);
                } else if (kind == Edge::RF) {
                    ex = com_exists_precond(src, dst, WRITE, READ);
                } else {
                    const z3::expr pc = comx_exists_precond(src, dst, XSWRITE, XSREAD);
                    ex = pc.is_false() ? context.FALSE
                                       : (pc && Node::xsaccess_order_less(*this)(src, dst));
                }
                if (!possibly(ex)) { continue; }
                if (compute_alias(src, dst) == llvm::AliasResult::NoAlias) {
                    if (alias_prune) { continue; }
                    if (smt_prune) {
                        feas->push();
                        feas->add(ex);
                        const z3::check_result r = feas->check();
                        feas->pop();
                        if (r == z3::unsat) { continue; }
                    }
                }
                g.add(rel, static_cast<int>(src), static_cast<int>(dst));
            }
        }
    }

    // Dump the graph for the completeness test.
    if (const char *dd = ::getenv("CLOU_AXTYPES_DUMP_GRAPH")) {
        std::ofstream ofs(std::string(dd) + "/" + function_name() + ".overapprox");
        const auto dump = [&] (const char *k, const axtypes::Rel& r) {
            for (const auto& [s, d] : r) { ofs << k << " " << s << " " << d << "\n"; }
        };
        dump("addr", g.addr); dump("data", g.data); dump("ctrl", g.ctrl);
        dump("rf", g.rf); dump("rfx", g.rfx);
    }

    // Seeds. A transient read whose address is not fixed may return a secret and
    // is seeded <L,H>: any such read with CLOU_AXTYPES_UNGATED=1, otherwise only
    // when its index is attacker-controlled. After register elimination the index
    // is often a function argument rather than a load, so the address operand is
    // inspected in addition to the addr edges. CLOU_AXTYPES_RESIDUAL_SEED=0
    // disables that; =args restricts the ungated rule to arguments.
    enum { RES_OFF, RES_ARGS, RES_ALL } res_mode = RES_ALL;
    if (const char *r = ::getenv("CLOU_AXTYPES_RESIDUAL_SEED")) {
        const std::string s(r);
        if (s == "0") { res_mode = RES_OFF; } else if (s == "args") { res_mode = RES_ARGS; }
    }
    // What an address reaches through non-memory instructions. Bit 0: an argument.
    // Bit 1: another non-fixed value (a phi), or the walk gave up. Bit 2: a
    // non-pointer argument.
    const auto residual_leaves = [] (const llvm::Value *root) -> unsigned {
        std::vector<const llvm::Value *> work{root};
        std::unordered_set<const llvm::Value *> seen;
        unsigned mask = 0;
        int budget = 512;
        while (!work.empty()) {
            if (budget-- <= 0) { mask |= 2u; break; }
            const llvm::Value *v = work.back(); work.pop_back();
            if (!seen.insert(v).second) { continue; }
            if (llvm::isa<llvm::Argument>(v)) {
                mask |= 1u;
                if (!v->getType()->isPointerTy()) { mask |= 4u; }
                continue;
            }
            if (llvm::isa<llvm::Constant>(v) || llvm::isa<llvm::AllocaInst>(v)) { continue; }
            if (llvm::isa<llvm::LoadInst>(v) || llvm::isa<llvm::CallBase>(v)) { continue; }
            if (llvm::isa<llvm::PHINode>(v)) { mask |= 2u; }
            if (const auto *U = llvm::dyn_cast<llvm::User>(v)) {
                for (const llvm::Value *op : U->operands()) { work.push_back(op); }
            }
        }
        return mask;
    };
    const auto read_address = [&] (int eid) -> const llvm::Value * {
        const llvm::Instruction *I = lookup(static_cast<NodeRef>(eid)).inst->get_inst();
        if (const auto *L = llvm::dyn_cast_or_null<llvm::LoadInst>(I)) { return L->getPointerOperand(); }
        return nullptr;
    };
    unsigned n_residual_seeds = 0;
    if (const char *u = ::getenv("CLOU_AXTYPES_UNGATED"); u && std::string(u) != "0") {
        axtypes::apply_clou_secret_policy(g);
        if (res_mode != RES_OFF) {
            for (auto& [id, e] : g.events) {
                if (e.kind != axtypes::Kind::Read || !e.transient || e.base == axtypes::LEAK) { continue; }
                const llvm::Value *ptr = read_address(id);
                if (!ptr) { continue; }
                const unsigned mask = residual_leaves(ptr);
                if ((mask & 1u) || (res_mode == RES_ALL && mask != 0)) {
                    e.base = axtypes::LEAK;
                    ++n_residual_seeds;
                }
            }
        }
    } else {
        for (auto& [id, e] : g.events) { e.base = axtypes::PUBLIC; }
        for (const auto& [idx, acc] : addr_gep) {
            auto ae = g.events.find(acc);
            auto ie = g.events.find(idx);
            if (ae != g.events.end() && ie != g.events.end() &&
                ae->second.kind == axtypes::Kind::Read && ae->second.transient &&
                ie->second.attacker) {
                ae->second.base = axtypes::LEAK;
            }
        }
        if (res_mode != RES_OFF) {
            for (auto& [id, e] : g.events) {
                if (e.kind != axtypes::Kind::Read || !e.transient || e.base == axtypes::LEAK) { continue; }
                const auto *GEP = llvm::dyn_cast_or_null<llvm::GEPOperator>(read_address(id));
                if (!GEP) { continue; }
                for (const llvm::Value *idx : GEP->indices()) {
                    if (residual_leaves(idx) & 4u) {
                        e.base = axtypes::LEAK;
                        ++n_residual_seeds;
                        break;
                    }
                }
            }
        }
    }

    const auto loc_of = [&] (int eid) -> std::string {
        if (const llvm::Instruction *I = lookup(static_cast<NodeRef>(eid)).inst->get_inst())
            if (const llvm::DebugLoc& dl = I->getDebugLoc())
                return std::to_string(dl.getLine()) + ":" + std::to_string(dl.getCol());
        return {};
    };

    // Known-bits: the address stays within one cache line of a fixed object. A
    // public index range is not enough (B[s & 0xff] spans many lines), nor is a
    // constant offset from a loaded pointer (p->f lies wherever p points).
    // CLOU_AXTYPES_KB_ANYBASE=1 drops the fixed-base requirement.
    constexpr uint64_t CACHE_LINE = 64;
    const bool kb_anybase = [] {
        const char *p = ::getenv("CLOU_AXTYPES_KB_ANYBASE");
        return p && std::string(p) != "0";
    }();
    const auto fixed_base = [&] (const llvm::Value *p) -> bool {
        if (kb_anybase) { return true; }
        for (int budget = 64; budget-- > 0; ) {
            p = p->stripPointerCasts();
            const auto *G = llvm::dyn_cast<llvm::GEPOperator>(p);
            if (!G) { break; }
            if (!G->hasAllConstantIndices()) { return false; }
            p = G->getPointerOperand();
        }
        return llvm::isa<llvm::GlobalValue>(p) || llvm::isa<llvm::AllocaInst>(p);
    };
    const auto discharge_known_bits = [&] (int eid, uint64_t& maxoff_out) -> bool {
        maxoff_out = ~0ull;
        const llvm::Instruction *I = lookup(static_cast<NodeRef>(eid)).inst->get_inst();
        if (!I) { return false; }
        const llvm::Value *ptr = nullptr;
        if (const auto *L = llvm::dyn_cast<llvm::LoadInst>(I)) { ptr = L->getPointerOperand(); }
        else if (const auto *S = llvm::dyn_cast<llvm::StoreInst>(I)) { ptr = S->getPointerOperand(); }
        if (!ptr) { return false; }
        const auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(ptr);
        if (!GEP) { return false; }
        const llvm::DataLayout& DL = I->getModule()->getDataLayout();
        const uint64_t stride = DL.getTypeAllocSize(GEP->getResultElementType());
        const llvm::Value *var_idx = nullptr;
        bool all_const = true;
        for (const llvm::Value *idx : GEP->indices()) {
            if (llvm::isa<llvm::ConstantInt>(idx)) { continue; }
            all_const = false;
            if (var_idx) { return false; }
            var_idx = idx;
        }
        if (all_const) { maxoff_out = 0; return fixed_base(GEP->getPointerOperand()); }
        llvm::KnownBits kb = llvm::computeKnownBits(var_idx, DL);
        const llvm::APInt hi = ~kb.Zero;
        if (hi.getActiveBits() > 40) { return false; }
        const uint64_t maxoff = (hi.getZExtValue() + 1) * stride;
        maxoff_out = maxoff;
        const llvm::Align base_align = GEP->getPointerOperand()->getPointerAlignment(DL);
        return fixed_base(GEP->getPointerOperand()) &&
               base_align.value() >= CACHE_LINE && maxoff <= CACHE_LINE;
    };

    // SLH: the address slice contains the hardening marker __clou_slh* and the
    // access is transient. Trusted, not proved.
    const auto uses_slh_marker = [] (const llvm::Value *root) -> bool {
        std::vector<const llvm::Value *> work{root};
        std::unordered_set<const llvm::Value *> seen;
        int budget = 256;
        while (!work.empty() && budget-- > 0) {
            const llvm::Value *v = work.back(); work.pop_back();
            if (!seen.insert(v).second) { continue; }
            if (const auto *CI = llvm::dyn_cast<llvm::CallInst>(v)) {
                if (const llvm::Function *F = CI->getCalledFunction()) {
                    if (F->getName().starts_with("__clou_slh")) { return true; }
                }
            }
            if (const auto *U = llvm::dyn_cast<llvm::User>(v)) {
                for (const llvm::Value *op : U->operands()) { work.push_back(op); }
            }
        }
        return false;
    };
    const auto discharge_slh = [&] (int eid) -> bool {
        const Node& node = lookup(static_cast<NodeRef>(eid));
        if (!possibly(node.trans)) { return false; }
        const llvm::Instruction *I = node.inst->get_inst();
        if (!I) { return false; }
        const llvm::Value *ptr = nullptr;
        if (const auto *L = llvm::dyn_cast<llvm::LoadInst>(I)) { ptr = L->getPointerOperand(); }
        else if (const auto *S = llvm::dyn_cast<llvm::StoreInst>(I)) { ptr = S->getPointerOperand(); }
        if (!ptr) { return false; }
        return uses_slh_marker(ptr);
    };

    // Allowlist: CLOU_CT_SAFE=line:col,...
    std::unordered_set<std::string> ct_safe_locs;
    if (const char *env = ::getenv("CLOU_CT_SAFE")) {
        std::string s(env), tok; std::stringstream ss(s);
        while (std::getline(ss, tok, ',')) { if (!tok.empty()) { ct_safe_locs.insert(tok); } }
    }

    // Flag, discharge address obligations, check again.
    const auto cr0 = axtypes::check_containment(g);
    axtypes::FactDB db;
    for (const auto& v : cr0.violations) {
        if (v.obs_name != "AddrObs") { continue; }
        uint64_t span = 0;
        if (discharge_known_bits(v.eid, span)) {
            db.add(v.obs_name, v.eid, "known-bits", loc_of(v.eid));
        } else if (discharge_slh(v.eid)) {
            db.add(v.obs_name, v.eid, "slh", loc_of(v.eid));
        } else if (ct_safe_locs.count(loc_of(v.eid))) {
            db.add(v.obs_name, v.eid, "manual", loc_of(v.eid));
        }
    }
    auto cr = axtypes::check_containment(g, axtypes::make_refine(db));

    {
        // Refinement may only remove flags; otherwise keep the unrefined result.
        std::set<std::pair<std::string,int>> before;
        for (const auto& v : cr0.violations) { before.insert({v.obs_name, v.eid}); }
        bool violated = false;
        for (const auto& v : cr.violations) {
            if (!before.count({v.obs_name, v.eid})) { violated = true; break; }
        }
        if (violated) {
            llvm::errs() << "AXTYPES-REFINE: WARNING: refinement added a flag "
                            "(rule-1 violation); discarding refined result\n";
            cr = cr0;
        }
    }
    if (!db.log().empty()) { db.dump(); }

    // Explain each address violation.
    if (::getenv("CLOU_AXTYPES_TRACE")) {
        axtypes::Typing typing(g);
        std::map<int, std::vector<int>> addr_pred, data_pred, rf_pred;
        for (const auto& [s, d] : g.addr) { addr_pred[d].push_back(s); }
        for (const auto& [s, d] : g.data) { data_pred[d].push_back(s); }
        for (const auto& [s, d] : g.rf)   { rf_pred[d].push_back(s); }
        for (const auto& v : cr.violations) {
            if (v.obs_name != "AddrObs") { continue; }
            llvm::errs() << "TRACE AddrObs(" << v.eid << ")=" << v.ty.str()
                         << "  gamma=" << typing.gamma().at(v.eid).str()
                         << "  base=" << g.events.at(v.eid).base.str()
                         << "  @" << loc_of(v.eid) << "\n";
            for (int p : addr_pred[v.eid]) {
                const auto& pe = g.events.at(p);
                llvm::errs() << "    addr-pred " << p << " gamma="
                             << typing.gamma().at(p).str() << " base=" << pe.base.str()
                             << " kind=" << (int)pe.kind << " trans=" << pe.transient
                             << " atk=" << pe.attacker << " @" << loc_of(p) << "\n";
                if (pe.base != typing.gamma().at(p)) {
                    const auto show = [&] (const char *k, const std::vector<int>& srcs) {
                        for (int s : srcs) {
                            llvm::errs() << "        " << k << "-src " << s << " gamma="
                                         << typing.gamma().at(s).str() << " base="
                                         << g.events.at(s).base.str() << " kind="
                                         << (int)g.events.at(s).kind << " @" << loc_of(s) << "\n";
                        }
                    };
                    std::vector<int> rfx_s, data_s;
                    for (const auto& [s, d] : g.rfx)  { if (d == p) rfx_s.push_back(s); }
                    for (const auto& [s, d] : g.data) { if (d == p) data_s.push_back(s); }
                    show("rf", rf_pred[p]); show("rfx", rfx_s); show("data", data_s);
                }
            }
        }
    }

    // Report the transmitter class that was asked for.
    bool want_addr = custom_deps.empty();
    bool want_ctrl = (spectre_v1_mode.mode == SpectreV1Mode::BRANCH_PREDICATE);
    for (const auto& [kind, mode] : custom_deps) {
        if (kind == Edge::ADDR || kind == Edge::ADDR_GEP) { want_addr = true; }
        if (kind == Edge::CTRL) { want_ctrl = true; }
    }

    unsigned n_addr = 0, n_ctrl = 0;
    for (const auto& v : cr.violations) {
        const bool is_addr = (v.obs_name == "AddrObs");
        if (is_addr ? !want_addr : !want_ctrl) { continue; }
        if (is_addr) { ++n_addr; } else { ++n_ctrl; }
        const Node& node = lookup(static_cast<NodeRef>(v.eid));
        if (const llvm::Instruction *I = node.inst->get_inst()) {
            *out++ = I;
        }
    }

    llvm::errs() << "AXTYPES-ENGINE: " << function_name()
                 << " transmitters=" << cr.violations.size()
                 << " addr=" << n_addr << " ctrl=" << n_ctrl
                 << " residual_seeds=" << n_residual_seeds << "\n";
}

}
