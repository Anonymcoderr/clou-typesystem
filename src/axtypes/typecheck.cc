#include "typecheck.h"

namespace axtypes {

namespace {

// Least fixpoint of one component. The target component also follows rfx.
std::map<int, bool> component_fixpoint(const Graph& g, bool use_rfx) {
    std::map<int, bool> lvl;
    for (const auto& [id, e] : g.events)
        lvl[id] = use_rfx ? e.base.t : e.base.a;

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& [w, r] : g.rf)
            if (lvl.count(w) && lvl.count(r) && lvl[w] && !lvl[r]) { lvl[r] = true; changed = true; }
        for (const auto& [x, y] : g.data)
            if (lvl.count(x) && lvl.count(y) && lvl[x] && !lvl[y]) { lvl[y] = true; changed = true; }
        if (use_rfx)
            for (const auto& [w, r] : g.rfx)
                if (lvl.count(w) && lvl.count(r) && lvl[w] && !lvl[r]) { lvl[r] = true; changed = true; }
    }
    return lvl;
}

Ty join_all(const std::vector<Ty>& tys) {
    Ty acc = PUBLIC;
    for (const auto& t : tys) acc = acc.join(t);
    return acc;
}

}

std::map<int, Ty> event_typing(const Graph& g) {
    auto a = component_fixpoint(g, false);
    auto t = component_fixpoint(g, true);
    std::map<int, Ty> gamma;
    for (const auto& [id, e] : g.events)
        gamma[id] = Ty(a[id], t[id]);
    return gamma;
}

Typing::Typing(const Graph& g, RefineOp refine)
    : g_(g), gamma_(event_typing(g)), refine_(std::move(refine)) {}

// The joins below read unrefined event types. Refinement is applied once,
// to the final observation type.
Ty Typing::eval(int eid) const { return gamma_.at(eid); }

Ty Typing::ValObs(int eid) const { return refine_("ValObs", eid, gamma_.at(eid)); }

Ty Typing::AddrTy(int m) const {
    Ty tau = g_.events.at(m).base_addr;
    for (int e : g_.preds(g_.addr, m)) tau = tau.join(gamma_.at(e));
    return refine_("AddrObs", m, tau);
}

Ty Typing::DataTy(int w) const {
    std::vector<Ty> tys;
    for (int e : g_.preds(g_.data, w)) tys.push_back(gamma_.at(e));
    return refine_("StoreObs", w, join_all(tys));
}

Ty Typing::PredTy(int b) const {
    std::vector<Ty> tys;
    for (int e : g_.preds(g_.data, b)) tys.push_back(gamma_.at(e));
    return refine_("PredObs", b, join_all(tys));
}

// Clou draws ctrl edges from the deciding read, not from a branch node; the
// read's own type then stands for the predicate type.
Ty Typing::CtrlTy(int u) const {
    std::vector<Ty> tys;
    for (int c : g_.preds(g_.ctrl, u)) {
        const Event& ce = g_.events.at(c);
        tys.push_back(ce.kind == Kind::Branch ? PredTy(c) : gamma_.at(c));
    }
    return refine_("CtrlObs", u, join_all(tys));
}

std::vector<std::pair<std::string, int>> cache_observer_obsset(const Graph& g) {
    std::vector<std::pair<std::string, int>> obs;
    for (const Event *e : g.memory_events()) {
        obs.emplace_back("AddrObs", e->id);
        obs.emplace_back("CtrlObs", e->id);
    }
    return obs;
}

ContainResult check_containment(const Graph& g, RefineOp refine) {
    Typing ty(g, refine);
    ContainResult res;
    for (const auto& [obs_name, eid] : cache_observer_obsset(g)) {
        Ty tau = (obs_name == "AddrObs") ? ty.AddrTy(eid) : ty.CtrlTy(eid);
        if (!tau.stable())
            res.violations.push_back({obs_name, eid, tau, g.events.at(eid).name});
    }
    res.ok = res.violations.empty();
    return res;
}

}
