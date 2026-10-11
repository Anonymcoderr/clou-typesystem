"""Load graphs exported by Clou (cloupy-graph-v1) and seed them.

Clou's benchmarks carry no secrecy labels. A transient read at a data-dependent
address may return a secret, so it is seeded <L,H>.
"""
from __future__ import annotations
import json

from graph import Graph, READ, WRITE, BRANCH, SPECIAL
from lattice import PUBLIC, LEAK

_KIND = {"read": READ, "write": WRITE, "branch": BRANCH,
         "special": SPECIAL, "receiver": SPECIAL, "other": "other"}


def load_clou_graph(path: str, secret_seed: bool = True) -> Graph:
    with open(path) as f:
        d = json.load(f)
    assert d.get("version") == "cloupy-graph-v1", d.get("version")
    g = Graph()
    for e in d["events"]:
        kind = _KIND.get(e["kind"], "other")
        g.add_event(e["id"], kind,
                    transient=(e.get("exec_mode") == "spec"),
                    name=e.get("name", ""),
                    is_receiver=bool(e.get("is_receiver")))
    for e in d["edges"]:
        k = e["kind"]
        if k in ("rf", "rfx", "data", "addr", "ctrl", "po", "tfo"):
            g.add(k, e["src"], e["dst"])

    if secret_seed:
        apply_clou_secret_policy(g)
    return g


def apply_clou_secret_policy(g: Graph) -> None:
    """Seed every transient read that has an address predecessor."""
    has_incoming_addr = {m for (_e, m) in g.addr}
    for ev in g.events.values():
        if ev.kind == READ and ev.transient and ev.id in has_incoming_addr:
            ev.base = LEAK
        else:
            ev.base = PUBLIC
