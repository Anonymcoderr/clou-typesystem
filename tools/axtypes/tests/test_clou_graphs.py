"""The checker on witness graphs exported by Clou.

Each cloupy_graph_<n0>_..._<tx>.json is a leak the SMT search found; the last
number is the transmitter. The checker must reject the graph and flag that
transmitter's address.
"""
import glob
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loader import load_clou_graph
from typecheck import check_containment

DATA = os.path.join(os.path.dirname(__file__), "data")


def transmitter_ref(path: str) -> int:
    nums = re.findall(r"\d+", os.path.basename(path))
    return int(nums[-1])


class TestClouWitnessGraphs(unittest.TestCase):
    def _graphs(self):
        return sorted(glob.glob(os.path.join(DATA, "cloupy_graph_*.json")))

    def test_data_present(self):
        self.assertTrue(self._graphs(), "no exported witness graphs in tests/data")

    def test_every_witness_flagged_as_leak(self):
        for path in self._graphs():
            g = load_clou_graph(path)
            ok, viol = check_containment(g)
            self.assertFalse(ok, f"{os.path.basename(path)} is a leak witness but "
                                 f"containment held")
            self.assertTrue(viol)

    def test_transmitter_is_flagged(self):
        for path in self._graphs():
            g = load_clou_graph(path)
            _ok, viol = check_containment(g)
            flagged_addr = {v.eid for v in viol if v.obs_name == "AddrObs"}
            tx = transmitter_ref(path)
            self.assertIn(tx, flagged_addr,
                          f"{os.path.basename(path)}: transmitter {tx} not flagged "
                          f"(flagged AddrObs = {sorted(flagged_addr)})")

    def test_flagged_are_transient_array_reads_or_writes(self):
        for path in self._graphs():
            g = load_clou_graph(path)
            _ok, viol = check_containment(g)
            for v in viol:
                if v.obs_name == "AddrObs":
                    self.assertTrue(g.events[v.eid].is_memory())
                    self.assertTrue(g.addr_sources(v.eid),
                                    f"{v.eid} flagged but has no addr predecessors")

    def test_no_secret_seed_means_contained(self):
        for path in self._graphs():
            g = load_clou_graph(path, secret_seed=False)
            ok, viol = check_containment(g)
            self.assertTrue(ok, f"{os.path.basename(path)} flagged without any "
                                f"secret seed: {viol}")


if __name__ == "__main__":
    unittest.main()
