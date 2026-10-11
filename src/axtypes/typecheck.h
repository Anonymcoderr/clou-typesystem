#pragma once

// Event typing, observation typing and the containment check.

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "graph.h"
#include "lattice.h"

namespace axtypes {

// Least event typing.
std::map<int, Ty> event_typing(const Graph& g);

// (observation, event, type) -> refined type. May only lower the target component.
using RefineOp = std::function<Ty(const std::string&, int, Ty)>;
inline Ty no_refine(const std::string&, int, Ty tau) { return tau; }

class Typing {
public:
    explicit Typing(const Graph& g, RefineOp refine = no_refine);

    Ty ValObs(int eid) const;
    Ty AddrTy(int m) const;
    Ty DataTy(int w) const;
    Ty PredTy(int b) const;
    Ty CtrlTy(int u) const;

    const std::map<int, Ty>& gamma() const { return gamma_; }

private:
    const Graph& g_;
    std::map<int, Ty> gamma_;
    RefineOp refine_;
    Ty eval(int eid) const;
};

struct Violation {
    std::string obs_name;
    int eid;
    Ty ty;
    std::string name;
};

// Checked set of the cache observer: AddrObs and CtrlObs of every memory event.
std::vector<std::pair<std::string, int>> cache_observer_obsset(const Graph& g);

// ok iff every checked observation is stable.
struct ContainResult {
    bool ok;
    std::vector<Violation> violations;
};
ContainResult check_containment(const Graph& g, RefineOp refine = no_refine);

}
