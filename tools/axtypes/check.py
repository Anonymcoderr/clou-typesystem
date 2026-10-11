#!/usr/bin/env python3
"""Run the containment check on graphs exported by Clou.

Usage: check.py <graph.json | dir> [--no-seed]
Exit status 1 if some graph is not contained.
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from loader import load_clou_graph
from typecheck import check_containment


def run(path: str, seed: bool) -> bool:
    g = load_clou_graph(path, secret_seed=seed)
    ok, viol = check_containment(g)
    tag = "CONTAINED" if ok else "LEAK"
    print(f"[{tag:9}] {os.path.basename(path)}")
    for v in viol:
        nm = g.events[v.eid].name.split("!dbg")[0].strip()
        print(f"    {v.obs_name}({v.eid}) = {v.ty}   {nm}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="a cloupy_graph_*.json file or a directory of them")
    ap.add_argument("--no-seed", action="store_true",
                    help="disable the Clou threat-model secret policy")
    args = ap.parse_args()

    if os.path.isdir(args.path):
        files = sorted(glob.glob(os.path.join(args.path, "cloupy_graph_*.json")))
    else:
        files = [args.path]
    if not files:
        print("no cloupy_graph_*.json found", file=sys.stderr)
        return 2

    all_ok = True
    n_leak = 0
    for f in files:
        ok = run(f, seed=not args.no_seed)
        all_ok = all_ok and ok
        n_leak += (0 if ok else 1)
    print(f"\n{len(files)} graph(s): {n_leak} not contained, {len(files)-n_leak} contained")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
