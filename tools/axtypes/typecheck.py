"""Event typing, observation typing and the containment check."""
from __future__ import annotations
from typing import Callable, Dict, Optional

from lattice import Ty, L, H, PUBLIC, join_all
from graph import Graph, Event, BRANCH


def _component_fixpoint(g: Graph, use_rfx: bool) -> Dict[int, bool]:
    """Least fixpoint of one component; the target component also follows rfx."""
    lvl: Dict[int, bool] = {}
    for e in g.events.values():
        seed = e.base.t if use_rfx else e.base.a
        lvl[e.id] = seed

    changed = True
    while changed:
        changed = False
        for (w, r) in g.rf:
            if w in lvl and r in lvl and lvl[w] and not lvl[r]:
                lvl[r] = True
                changed = True
        for (x, y) in g.data:
            if x in lvl and y in lvl and lvl[x] and not lvl[y]:
                lvl[y] = True
                changed = True
        if use_rfx:
            for (w, r) in g.rfx:
                if w in lvl and r in lvl and lvl[w] and not lvl[r]:
                    lvl[r] = True
                    changed = True
    return lvl


def event_typing(g: Graph) -> Dict[int, Ty]:
    """Least event typing."""
    a = _component_fixpoint(g, use_rfx=False)
    t = _component_fixpoint(g, use_rfx=True)
    gamma: Dict[int, Ty] = {}
    for eid in g.events:
        gamma[eid] = Ty(a[eid], t[eid])
    return gamma


# (observation, event, type) -> refined type. May only lower the target component.
RefineOp = Callable[[str, int, Ty], Ty]


def no_refine(_obs: str, _eid: int, tau: Ty) -> Ty:
    return tau


class Typing:
    """Observation types of a graph. Joins read event types; refinement is applied once, to the result."""

    def __init__(self, g: Graph, refine: RefineOp = no_refine):
        self.g = g
        self.gamma = event_typing(g)
        self.refine = refine

    def ValObs(self, eid: int) -> Ty:
        return self.refine("ValObs", eid, self.gamma[eid])

    def AddrTy(self, m: int) -> Ty:
        base = self.g.events[m].base_addr
        tau = base.join(join_all(self.gamma[e] for e in self.g.addr_sources(m)))
        return self.refine("AddrObs", m, tau)

    def DataTy(self, w: int) -> Ty:
        tau = join_all(self.gamma[e] for e in self.g.data_sources(w))
        return self.refine("StoreObs", w, tau)

    def PredTy(self, b: int) -> Ty:
        tau = join_all(self.gamma[e] for e in self.g.data_sources(b))
        return self.refine("PredObs", b, tau)

    # Clou draws ctrl edges from the deciding read, not from a branch node; the
    # read's own type then stands for the predicate type.
    def CtrlTy(self, u: int) -> Ty:
        def contrib(c):
            return self.PredTy(c) if self.g.events[c].kind == BRANCH else self.gamma[c]
        tau = join_all(contrib(c) for c in self.g.ctrl_branches(u))
        return self.refine("CtrlObs", u, tau)


def cache_observer_obsset(g: Graph):
    """Checked set of the cache observer: AddrObs and CtrlObs of every memory event."""
    obs = []
    for e in g.memory_events():
        obs.append(("AddrObs", e.id))
        obs.append(("CtrlObs", e.id))
    return obs


def obs_type(ty: Typing, obs_name: str, eid: int) -> Ty:
    if obs_name == "AddrObs":
        return ty.AddrTy(eid)
    if obs_name == "CtrlObs":
        return ty.CtrlTy(eid)
    if obs_name == "ValObs":
        return ty.ValObs(eid)
    if obs_name == "StoreObs":
        return ty.DataTy(eid)
    if obs_name == "PredObs":
        return ty.PredTy(eid)
    raise ValueError(f"unknown observation {obs_name}")


class Violation:
    def __init__(self, obs_name: str, eid: int, ty: Ty, g: Graph):
        self.obs_name = obs_name
        self.eid = eid
        self.ty = ty
        self.name = g.events[eid].name

    def __repr__(self):
        loc = f"{self.name}" if self.name else f"event {self.eid}"
        return f"{self.obs_name}({self.eid}) = {self.ty}  [{loc}]"


def check_containment(g: Graph, refine: RefineOp = no_refine,
                      obsset=None):
    """Return (ok, violations): ok iff every checked observation is stable."""
    ty = Typing(g, refine)
    if obsset is None:
        obsset = cache_observer_obsset(g)
    violations = []
    for (obs_name, eid) in obsset:
        tau = obs_type(ty, obs_name, eid)
        if not tau.stable():
            violations.append(Violation(obs_name, eid, tau, g))
    return (len(violations) == 0, violations)
