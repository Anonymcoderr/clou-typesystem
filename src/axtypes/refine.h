#pragma once

// Refinement facts and the operator built from them. A fact lowers the target
// component of one observation to its architectural component, so facts only
// remove flags; a wrong fact hides the one leak it certifies.

#include <cstdio>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "lattice.h"
#include "typecheck.h"

namespace axtypes {

struct Obligation {
    std::string obs;
    int eid;
    bool operator<(const Obligation& o) const {
        return std::tie(obs, eid) < std::tie(o.obs, o.eid);
    }
};

struct DischargedFact {
    Obligation ob;
    std::string source;  // known-bits, slh or manual
    std::string loc;  // line:col
};

class FactDB {
public:
    void add(const std::string& obs, int eid, const std::string& source,
             const std::string& loc = "") {
        discharged_.insert({obs, eid});
        log_.push_back({{obs, eid}, source, loc});
    }
    bool proves_stable_T(const std::string& obs, int eid) const {
        return discharged_.count({obs, eid}) > 0;
    }
    const std::vector<DischargedFact>& log() const { return log_; }

    // Every discharge is logged.
    void dump(std::FILE *f = stderr) const {
        for (const auto& d : log_)
            std::fprintf(f, "REFINE-FACT: %s(%d) discharged by %s%s%s\n",
                         d.ob.obs.c_str(), d.ob.eid, d.source.c_str(),
                         d.loc.empty() ? "" : " @ ", d.loc.c_str());
    }

private:
    std::set<Obligation> discharged_;
    std::vector<DischargedFact> log_;
};

inline RefineOp make_refine(const FactDB& db) {
    return [&db](const std::string& obs, int eid, Ty tau) -> Ty {
        if (!db.proves_stable_T(obs, eid)) { return tau; }
        Ty refined(tau.a, tau.a);
        assert(lvl_leq(refined.t, tau.t) && "refinement must not raise pi_T");
        assert(refined.a == tau.a && "refinement must not touch pi_A");
        return refined;
    };
}

}
