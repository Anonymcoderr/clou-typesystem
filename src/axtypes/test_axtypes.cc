// Unit tests for the type checker: the rules, the four case studies, refinement.

#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>

#include "graph.h"
#include "lattice.h"
#include "typecheck.h"
#include "refine.h"

using namespace axtypes;

static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; }         \
        else { std::printf("ok:   %s\n", msg); }                             \
    } while (0)

static bool eq(const std::map<int, Ty>& g, int id, Ty want) {
    auto it = g.find(id);
    return it != g.end() && it->second == want;
}

static void test_rules() {
    {
        Graph g;
        g.add_event(0, Kind::Write, false, SECRET);
        g.add_event(1, Kind::Read);
        g.add(g.rfx, 0, 1);
        auto gamma = event_typing(g);
        CHECK(eq(gamma, 1, LEAK), "T-RFX: transient read from secret is <L,H>");
    }
    {
        Graph g;
        g.add_event(0, Kind::Write, false, SECRET);
        g.add_event(1, Kind::Read);
        g.add(g.rf, 0, 1);
        auto gamma = event_typing(g);
        CHECK(eq(gamma, 1, SECRET), "RF: committed read from secret is <H,H>");
    }
    {
        Graph g;
        g.add_event(0, Kind::Read, false, SECRET);
        g.add_event(1, Kind::Write);
        g.add_event(2, Kind::Read);
        g.add(g.data, 0, 1);
        g.add(g.rf, 1, 2);
        auto gamma = event_typing(g);
        CHECK(eq(gamma, 2, SECRET), "DATA+RF transitive propagation is <H,H>");
    }
    {
        Graph g;
        g.add_event(0, Kind::Read, false, LEAK);
        g.add_event(1, Kind::Read);
        g.add(g.addr, 0, 1);
        Typing ty(g);
        CHECK(ty.AddrTy(1) == LEAK, "D-Addr: address inherits <L,H>");
        CHECK(ty.ValObs(1) == PUBLIC, "VAL: value stays <L,L>");
    }
    {
        Graph g;
        g.add_event(0, Kind::Read, false, SECRET);
        g.add_event(1, Kind::Branch);
        g.add_event(2, Kind::Read);
        g.add(g.data, 0, 1);
        g.add(g.ctrl, 1, 2);
        Typing ty(g);
        CHECK(ty.PredTy(1) == SECRET, "D-Pred: predicate is <H,H>");
        CHECK(ty.CtrlTy(2) == SECRET, "D-Ctrl: control context is <H,H>");
    }
}

static Graph spectre_v1() {
    Graph g;
    g.add_event(0, Kind::Write, false, PUBLIC, PUBLIC, "wpub");
    g.add_event(1, Kind::Write, false, SECRET, PUBLIC, "wsec");
    g.add_event(2, Kind::Read, false, PUBLIC, PUBLIC, "2:R y");
    g.add_event(3, Kind::Branch, false, PUBLIC, PUBLIC, "b");
    g.add_event(5, Kind::Read, false, PUBLIC, PUBLIC, "5:R A");
    g.add_event(6, Kind::Read, false, PUBLIC, PUBLIC, "6:R B");
    g.add_event(15, Kind::Read, true, PUBLIC, PUBLIC, "5S");
    g.add_event(16, Kind::Read, true, PUBLIC, PUBLIC, "6S");
    for (int r : {2, 5}) g.add(g.rf, 0, r);
    g.add(g.rfx, 1, 15);
    g.add(g.data, 2, 3);
    g.add(g.addr, 2, 5); g.add(g.addr, 2, 15);
    g.add(g.addr, 5, 6); g.add(g.addr, 15, 16);
    for (int u : {5, 6, 15, 16}) g.add(g.ctrl, 3, u);
    return g;
}

static Graph spectre_v4() {
    Graph g;
    g.add_event(0, Kind::Write, false, SECRET, PUBLIC, "ws");
    g.add_event(1, Kind::Write, false, PUBLIC, PUBLIC, "wp");
    g.add_event(2, Kind::Read, true, PUBLIC, PUBLIC, "rS");
    g.add_event(3, Kind::Read, true, PUBLIC, PUBLIC, "tS");
    g.add(g.rfx, 0, 2);
    g.add(g.addr, 2, 3);
    return g;
}

static Graph spectre_rsb() {
    Graph g;
    g.add_event(0, Kind::Write, false, PUBLIC, PUBLIC, "wstk");
    g.add_event(1, Kind::Write, false, PUBLIC, PUBLIC, "wRSB");
    g.add_event(2, Kind::Read, false, PUBLIC, PUBLIC, "et");
    g.add_event(3, Kind::Branch, false, PUBLIC, PUBLIC, "bret");
    g.add_event(4, Kind::Read, true, LEAK, PUBLIC, "g1");
    g.add_event(5, Kind::Read, true, PUBLIC, PUBLIC, "g2");
    g.add(g.rf, 0, 2); g.add(g.rfx, 1, 2);
    g.add(g.data, 2, 3);
    g.add(g.ctrl, 3, 4); g.add(g.ctrl, 3, 5);
    g.add(g.addr, 4, 5);
    return g;
}

static void test_case_studies() {
    {
        Graph g = spectre_v1();
        auto gm = event_typing(g);
        CHECK(eq(gm, 15, LEAK), "v1: Gamma*(5S)=<L,H>");
        CHECK(eq(gm, 16, PUBLIC), "v1: Gamma*(6S)=<L,L> (value public)");
        Typing ty(g);
        CHECK(ty.AddrTy(16) == LEAK, "v1: AddrTy(6S)=<L,H> (transmitter)");
        CHECK(ty.AddrTy(15) == PUBLIC, "v1: AddrTy(5S)=<L,L> (own address safe)");
        CHECK(ty.PredTy(3) == PUBLIC, "v1: PredTy(b)=<L,L>");
        auto c = check_containment(g);
        CHECK(!c.ok && c.violations.size() == 1 &&
              c.violations[0].obs_name == "AddrObs" && c.violations[0].eid == 16,
              "v1: containment fails at AddrObs(6S)");
    }
    {
        Graph g = spectre_v1();
        RefineOp slh = [](const std::string& obs, int eid, Ty tau) -> Ty {
            if (obs == "AddrObs" && eid == 16) return Ty(tau.a, tau.a);
            return tau;
        };
        Typing ty(g, slh);
        CHECK(ty.AddrTy(16) == PUBLIC, "SLH: AddrTy(6S) refined to <L,L>");
        auto c = check_containment(g, slh);
        CHECK(c.ok, "SLH: containment restored");
    }
    {
        Graph g = spectre_v4();
        auto gm = event_typing(g);
        CHECK(eq(gm, 2, LEAK), "v4: Gamma*(rS)=<L,H> (stale forward)");
        CHECK(eq(gm, 3, PUBLIC), "v4: Gamma*(t)=<L,L>");
        Typing ty(g);
        CHECK(ty.AddrTy(3) == LEAK, "v4: AddrTy(t)=<L,H>");
        auto c = check_containment(g);
        CHECK(!c.ok, "v4: containment fails");
    }
    {
        Graph g = spectre_rsb();
        auto gm = event_typing(g);
        CHECK(eq(gm, 2, PUBLIC), "rsb: Gamma*(et)=<L,L> (public return target)");
        CHECK(eq(gm, 4, LEAK), "rsb: Gamma*(g1)=<L,H> (pair-valued seed)");
        CHECK(eq(gm, 5, PUBLIC), "rsb: Gamma*(g2)=<L,L>");
        Typing ty(g);
        CHECK(ty.AddrTy(5) == LEAK, "rsb: AddrTy(g2)=<L,H>");
        CHECK(ty.PredTy(3) == PUBLIC, "rsb: PredTy(bret)=<L,L>");
        auto c = check_containment(g);
        CHECK(!c.ok, "rsb: containment fails");
    }
}

static void test_refinement() {
    FactDB db;
    CHECK(!db.proves_stable_T("AddrObs", 6), "FactDB: undischarged obligation is not stable");
    db.add("AddrObs", 6, "manual", "5:19");
    CHECK(db.proves_stable_T("AddrObs", 6), "FactDB: discharged obligation records");
    CHECK(db.log().size() == 1, "FactDB: audit log records the discharge");

    RefineOp r = make_refine(db);
    CHECK(r("AddrObs", 6, LEAK) == PUBLIC, "refine: discharged <L,H> -> <L,L>");
    CHECK(r("AddrObs", 7, LEAK) == LEAK, "refine: undischarged is identity");
    CHECK(r("CtrlObs", 6, LEAK) == LEAK, "refine: different obs family not discharged");
    db.add("AddrObs", 9, "manual", "");
    CHECK(make_refine(db)("AddrObs", 9, SECRET) == SECRET, "refine: <H,H> cannot be lowered");

    Graph g = spectre_v1();
    auto c0 = check_containment(g);
    FactDB db2; db2.add("AddrObs", 16, "manual", "");
    auto c1 = check_containment(g, make_refine(db2));
    std::set<std::pair<std::string,int>> before;
    for (const auto& v : c0.violations) before.insert({v.obs_name, v.eid});
    bool only_removes = true;
    for (const auto& v : c1.violations)
        if (!before.count({v.obs_name, v.eid})) only_removes = false;
    CHECK(only_removes, "refine: containment(refined) flags subset containment(unrefined)");
    CHECK(c1.ok, "refine: discharging the sole transmitter restores containment");
}

int main() {
    test_rules();
    test_case_studies();
    test_refinement();
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("\nALL PASS\n");
    return 0;
}
