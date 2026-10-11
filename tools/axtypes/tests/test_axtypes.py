"""Unit tests for the type checker.

Run: PYTHONPATH=tools/axtypes python3 -m unittest discover -s tools/axtypes/tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lattice import Ty, L, H, PUBLIC, LEAK, SECRET, join_all, lvl_leq
from graph import Graph, READ, WRITE, BRANCH
from typecheck import (event_typing, Typing, check_containment,
                    cache_observer_obsset, no_refine)
import cases


class TestLattice(unittest.TestCase):
    def test_elements(self):
        self.assertEqual((PUBLIC.a, PUBLIC.t), (L, L))
        self.assertEqual((LEAK.a, LEAK.t), (L, H))
        self.assertEqual((SECRET.a, SECRET.t), (H, H))

    def test_join(self):
        self.assertEqual(PUBLIC.join(LEAK), LEAK)
        self.assertEqual(PUBLIC.join(SECRET), SECRET)
        self.assertEqual(LEAK.join(SECRET), SECRET)
        self.assertEqual(LEAK.join(PUBLIC), LEAK)

    def test_stability(self):
        self.assertTrue(PUBLIC.stable())
        self.assertTrue(SECRET.stable())
        self.assertFalse(LEAK.stable())
        self.assertTrue(LEAK.is_unstable_leak())
        self.assertFalse(SECRET.is_unstable_leak())

    def test_invariant_enforced(self):
        with self.assertRaises(ValueError):
            Ty(H, L)

    def test_empty_join(self):
        self.assertEqual(join_all([]), PUBLIC)


class TestEventRules(unittest.TestCase):
    """Each event-typing rule in isolation."""

    def test_base(self):
        g = Graph()
        g.add_event(0, READ, base=SECRET)
        g.add_event(1, READ, base=PUBLIC)
        g.add_event(2, READ, base=LEAK)
        gamma = event_typing(g)
        self.assertEqual(gamma[0], SECRET)
        self.assertEqual(gamma[1], PUBLIC)
        self.assertEqual(gamma[2], LEAK)

    def test_rf_propagates_both_components(self):
        g = Graph()
        g.add_event(0, WRITE, base=SECRET)
        g.add_event(1, READ)
        g.add("rf", 0, 1)
        gamma = event_typing(g)
        self.assertEqual(gamma[1], SECRET)

    def test_data_propagates_both_components(self):
        g = Graph()
        g.add_event(0, READ, base=SECRET)
        g.add_event(1, WRITE)
        g.add("data", 0, 1)
        gamma = event_typing(g)
        self.assertEqual(gamma[1], SECRET)

    def test_trfx_raises_only_target(self):
        g = Graph()
        g.add_event(0, WRITE, base=SECRET)
        g.add_event(1, READ)
        g.add("rfx", 0, 1)
        gamma = event_typing(g)
        self.assertEqual(gamma[1], LEAK)

    def test_rfx_does_not_touch_architectural(self):
        g = Graph()
        g.add_event(0, WRITE, base=SECRET)
        g.add_event(1, READ)
        g.add("rfx", 0, 1)
        gamma = event_typing(g)
        self.assertEqual(gamma[1].a, L)
        self.assertEqual(gamma[1].t, H)

    def test_transitive_propagation(self):
        g = Graph()
        g.add_event(0, READ, base=SECRET)
        g.add_event(1, WRITE)
        g.add_event(2, READ)
        g.add("data", 0, 1)
        g.add("rf", 1, 2)
        gamma = event_typing(g)
        self.assertEqual(gamma[2], SECRET)

    def test_pair_invariant_preserved(self):
        for builder in (cases.spectre_v1, cases.spectre_v4, cases.spectre_rsb):
            g, _ = builder()
            gamma = event_typing(g)
            for eid, ty in gamma.items():
                self.assertTrue(lvl_leq(ty.a, ty.t),
                                f"{builder.__name__} event {eid}: {ty} violates lA<=lT")


class TestObservationRules(unittest.TestCase):
    def test_d_addr_joins_addr_predecessors_and_base(self):
        g = Graph()
        g.add_event(0, READ, base=LEAK)
        g.add_event(1, READ, base_addr=PUBLIC)
        g.add("addr", 0, 1)
        ty = Typing(g)
        self.assertEqual(ty.AddrTy(1), LEAK)
        self.assertEqual(ty.ValObs(1), PUBLIC)

    def test_d_addr_base_seed(self):
        g = Graph()
        g.add_event(0, READ, base_addr=SECRET)
        ty = Typing(g)
        self.assertEqual(ty.AddrTy(0), SECRET)

    def test_d_pred_and_d_ctrl_chain(self):
        g = Graph()
        g.add_event(0, READ, base=SECRET)
        g.add_event(1, BRANCH)
        g.add_event(2, READ)
        g.add("data", 0, 1)
        g.add("ctrl", 1, 2)
        ty = Typing(g)
        self.assertEqual(ty.PredTy(1), SECRET)
        self.assertEqual(ty.CtrlTy(2), SECRET)

    def test_multi_source_addr_join(self):
        g = Graph()
        g.add_event(0, READ, base=PUBLIC)
        g.add_event(1, READ, base=LEAK)
        g.add_event(2, READ)
        g.add("addr", 0, 2)
        g.add("addr", 1, 2)
        ty = Typing(g)
        self.assertEqual(ty.AddrTy(2), LEAK)


class TestCaseStudies(unittest.TestCase):
    """The four case studies, with the types the paper derives."""

    def _check_gamma(self, g, expected):
        gamma = event_typing(g)
        for eid, ty in expected["gamma"].items():
            self.assertEqual(gamma[eid], ty,
                             f"event {eid} ({g.events[eid].name}): got {gamma[eid]}, want {ty}")

    def test_spectre_v1(self):
        g, exp = cases.spectre_v1()
        self._check_gamma(g, exp)
        ty = Typing(g)
        self.assertEqual(ty.AddrTy(16), exp["AddrTy_6S"])
        self.assertEqual(ty.AddrTy(15), exp["AddrTy_5S"])
        self.assertEqual(ty.PredTy(3), exp["PredTy_b"])
        ok, viol = check_containment(g)
        self.assertFalse(ok)
        leaks = {(v.obs_name, v.eid) for v in viol}
        self.assertEqual(leaks, exp["leaks"])

    def test_spectre_v1_slh_refinement(self):
        g, refine, exp = cases.spectre_v1_slh()
        ty = Typing(g, refine)
        self.assertEqual(ty.AddrTy(16), exp["AddrTy_6S"])
        ok, viol = check_containment(g, refine)
        self.assertTrue(ok, f"SLH should restore containment, got {viol}")

    def test_spectre_v4(self):
        g, exp = cases.spectre_v4()
        self._check_gamma(g, exp)
        ty = Typing(g)
        self.assertEqual(ty.AddrTy(3), exp["AddrTy_t"])
        ok, viol = check_containment(g)
        self.assertFalse(ok)
        self.assertEqual({(v.obs_name, v.eid) for v in viol}, exp["leaks"])

    def test_spectre_rsb(self):
        g, exp = cases.spectre_rsb()
        self._check_gamma(g, exp)
        ty = Typing(g)
        self.assertEqual(ty.AddrTy(5), exp["AddrTy_g2"])
        self.assertEqual(ty.PredTy(3), exp["PredTy_bret"])
        ok, viol = check_containment(g)
        self.assertFalse(ok)
        self.assertEqual({(v.obs_name, v.eid) for v in viol}, exp["leaks"])


class TestContainmentProperties(unittest.TestCase):
    def test_public_program_is_contained(self):
        g = Graph()
        g.add_event(0, READ)
        g.add_event(1, READ)
        g.add("addr", 0, 1)
        g.add("rf", 0, 1)
        ok, viol = check_containment(g)
        self.assertTrue(ok)
        self.assertEqual(viol, [])

    def test_secret_stable_is_contained(self):
        g = Graph()
        g.add_event(0, READ, base=SECRET)
        g.add_event(1, READ, base_addr=SECRET)
        g.add("addr", 0, 1)
        ok, viol = check_containment(g)
        self.assertTrue(ok, f"stable <H,H> must not be flagged: {viol}")

    def test_refinement_monotone_lowers(self):
        g, exp = cases.spectre_v1()
        ok0, v0 = check_containment(g)

        def refine(obs, eid, tau):
            if obs == "AddrObs" and eid == 16:
                return Ty(tau.a, tau.a)
            return tau
        ok1, v1 = check_containment(g, refine)
        self.assertFalse(ok0)
        self.assertTrue(ok1)
        self.assertTrue(len(v1) <= len(v0))


if __name__ == "__main__":
    unittest.main()
