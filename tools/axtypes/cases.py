"""The four case studies of the paper as graphs, with the types the paper derives."""
from __future__ import annotations

from graph import Graph, READ, WRITE, BRANCH
from lattice import Ty, PUBLIC, LEAK, SECRET
from typecheck import Typing, no_refine


def spectre_v1():
    """Transient 5S reads the secret through rfx; the probe 6S leaks it in its address."""
    g = Graph()
    g.add_event(0, WRITE, name="wpub", base=PUBLIC)
    g.add_event(1, WRITE, name="wsec", base=SECRET)
    g.add_event(2, READ, name="2:R y")
    g.add_event(3, BRANCH, name="b:branch")
    g.add_event(5, READ, name="5:R A+r2")
    g.add_event(6, READ, name="6:R B+r4")
    g.add_event(15, READ, name="5S:R A+r2", transient=True)
    g.add_event(16, READ, name="6S:R B+r4", transient=True)
    g.add_event(99, "special", name="EXIT", is_receiver=True)

    for r in (2, 5):
        g.add("rf", 0, r)
    # 5S has no rf, only rfx from the secret write
    g.add("rfx", 1, 15)
    g.add("data", 2, 3)
    g.add("addr", 2, 5)
    g.add("addr", 2, 15)
    g.add("addr", 5, 6)
    g.add("addr", 15, 16)
    for u in (5, 6, 15, 16):
        g.add("ctrl", 3, u)

    expected = {
        "gamma": {2: PUBLIC, 5: PUBLIC, 6: PUBLIC, 15: LEAK, 16: PUBLIC},
        "PredTy_b": PUBLIC,
        "AddrTy_6S": LEAK,
        "AddrTy_5S": PUBLIC,
        "leaks": {("AddrObs", 16)},
    }
    return g, expected


def spectre_v1_slh():
    """Same graph; the SLH fact lowers AddrObs(6S) and containment holds."""
    g, _ = spectre_v1()

    def refine(obs, eid, tau):
        if obs == "AddrObs" and eid == 16:
            return Ty(tau.a, tau.a)
        return tau

    expected = {
        "gamma": {15: LEAK, 16: PUBLIC},
        "AddrTy_6S": PUBLIC,
        "leaks": set(),
    }
    return g, refine, expected


def spectre_v4():
    """The transient load rS forwards the stale secret store through rfx; tS leaks it."""
    g = Graph()
    g.add_event(0, WRITE, name="ws:store secret", base=SECRET)
    g.add_event(1, WRITE, name="wp:store public", base=PUBLIC)
    g.add_event(2, READ, name="rS:R p", transient=True)
    g.add_event(3, READ, name="tS:R B+x1", transient=True)
    g.add_event(99, "special", name="EXIT", is_receiver=True)

    g.add("rfx", 0, 2)
    g.add("addr", 2, 3)

    expected = {
        "gamma": {2: LEAK, 3: PUBLIC},
        "AddrTy_t": LEAK,
        "leaks": {("AddrObs", 3)},
    }
    return g, expected


def spectre_rsb():
    """The return target is public; the target-only gadget g1 is seeded <L,H>."""
    g = Graph()
    g.add_event(0, WRITE, name="wstk:correct target", base=PUBLIC)
    g.add_event(1, WRITE, name="wRSB:poisoned target", base=PUBLIC)
    g.add_event(2, READ, name="et:target read")
    g.add_event(3, BRANCH, name="bret:return branch")
    # target-only read of a secret
    g.add_event(4, READ, name="g1:R secret_ptr", transient=True, base=LEAK)
    g.add_event(5, READ, name="g2:R B+g1", transient=True)
    g.add_event(99, "special", name="EXIT", is_receiver=True)

    g.add("rf", 0, 2)
    g.add("rfx", 1, 2)
    g.add("data", 2, 3)
    g.add("ctrl", 3, 4)
    g.add("ctrl", 3, 5)
    g.add("addr", 4, 5)

    expected = {
        "gamma": {2: PUBLIC, 4: LEAK, 5: PUBLIC},
        "PredTy_bret": PUBLIC,
        "AddrTy_g2": LEAK,
        "leaks": {("AddrObs", 5)},
    }
    return g, expected
