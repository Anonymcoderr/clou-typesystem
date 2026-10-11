#!/usr/bin/env python3
"""Graph completeness: every edge of an SMT witness must be in the over-approximated graph.

Both engines run on the same IR, so node ids agree.
Usage: graph_complete.py [--plugin P] [--clang clang-18]
"""
import argparse
import glob
import json
import os
import re
import subprocess
import resource

_RLIMIT_GB = os.environ.get("CLOU_RLIMIT_GB")
def _mem_limit():
    if _RLIMIT_GB:
        b = int(float(_RLIMIT_GB) * 1024**3)
        resource.setrlimit(resource.RLIMIT_AS, (b, b))
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KINDS = {"addr", "data", "ctrl", "rf", "rfx"}

CASES = [
    ("test/pht1.c", "--spectre-v1=mode=classic", "victim_function_.*"),
    ("test/pht2.c", "--spectre-v1=mode=classic", "victim_function_.*"),
    ("test/pht5.c", "--spectre-v1=mode=classic", "victim_function_.*"),
    ("test/pht9.c", "--spectre-v1=mode=classic", "victim_function_.*"),
    ("test/pht12.c", "--spectre-v1=mode=classic", "victim_function_.*"),
    ("test/stl1.c", "--spectre-v4", "case_1"),
    ("test/stl2.c", "--spectre-v4", "case_2"),
    ("test/fwd1.c", "--spectre-v1=mode=classic", ".*"),
]
COMMON = "-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --aa=transient --partial"


def compile_run(src, mode, sel, extra_env, extra_args, plugin, clang, out):
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)
    os.makedirs(os.path.join(out, "cloupy"), exist_ok=True)
    args = f"-o {out} {COMMON} {mode} -f{sel} {extra_args}"
    env = dict(os.environ, LCM_ARGS=args, **extra_env)
    subprocess.run(
        [clang, "-g", "-fdeclspec", "-I", os.path.join(ROOT, "test"),
         "-Wno-#warnings", f"-fpass-plugin={plugin}", "-c", "-emit-llvm", "-S",
         "-o", os.path.join(out, "o.ll"), os.path.join(ROOT, src)],
        env=env, capture_output=True, text=True,
        preexec_fn=_mem_limit if _RLIMIT_GB else None)
    return out


def witness_edges(out):
    """{func: set((kind,src,dst))} unioned over all SMT witness graphs."""
    res = {}
    for jf in glob.glob(os.path.join(out, "cloupy", "*", "*.json")):
        fn = os.path.basename(os.path.dirname(jf))
        try:
            d = json.load(open(jf))
        except Exception:
            continue
        s = res.setdefault(fn, set())
        for e in d.get("edges", []):
            if e["kind"] in KINDS:
                s.add((e["kind"], e["src"], e["dst"]))
    return res


def overapprox_edges(dumpdir):
    res = {}
    for df in glob.glob(os.path.join(dumpdir, "*.overapprox")):
        fn = os.path.basename(df)[:-len(".overapprox")]
        s = res.setdefault(fn, set())
        for line in open(df):
            k, a, b = line.split()
            s.add((k, int(a), int(b)))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin", default=os.path.join(ROOT, "build-clean/src/libclou.so"))
    ap.add_argument("--clang", default="clang-18")
    a = ap.parse_args()

    total_fns = 0
    total_witness_edges = 0
    incomplete = []
    for src, mode, sel in CASES:
        work = tempfile.mkdtemp()
        smt_out = compile_run(src, mode, sel, {"CLOU_AXTYPES_ENGINE": "0"},
                              "--cloupy-json", a.plugin, a.clang,
                              os.path.join(work, "smt"))
        dumpdir = os.path.join(work, "dump"); os.makedirs(dumpdir)
        compile_run(src, mode, sel,
                    {"CLOU_AXTYPES_ENGINE": "1", "CLOU_NO_MEM2REG": "1",
                     "CLOU_AXTYPES_DUMP_GRAPH": dumpdir},
                    "", a.plugin, a.clang, os.path.join(work, "axt"))

        wit = witness_edges(smt_out)
        over = overapprox_edges(dumpdir)
        for fn, wedges in wit.items():
            if not wedges:
                continue
            total_fns += 1
            total_witness_edges += len(wedges)
            oedges = over.get(fn, set())
            missing = wedges - oedges
            tag = "ok" if not missing else "INCOMPLETE"
            print(f"[{tag}] {os.path.basename(src)}::{fn}  witness_edges={len(wedges)}  "
                  f"over_approx={len(oedges)}  missing={len(missing)}")
            if missing:
                for m in sorted(missing)[:8]:
                    print(f"      MISSING from over-approx: {m}")
                incomplete.append((src, fn, missing))

    print(f"\n{total_fns} witnessed functions, {total_witness_edges} witness edges checked; "
          f"incompleteness: {len(incomplete)}")
    print("PASS: over-approximation contains every witness edge" if not incomplete
          else "FAIL: over-approximation missing witness edges (possible missed leaks)")
    return 1 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
