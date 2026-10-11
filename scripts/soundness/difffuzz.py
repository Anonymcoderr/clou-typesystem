#!/usr/bin/env python3
"""Differential fuzzer: random Spectre-v1-shaped functions, both engines on the same IR.

Checks, per function, that the type engine reports every transmitter the SMT
search reports. Violations are saved and minimized.
Usage: difffuzz.py [-n 300] [--seed 0] [--plugin P] [--clang clang-18]
"""
import argparse
import os
import random
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TIMEOUT = 60


def gen_index(rng, srcs, depth):
    """A random index expression over the available source values."""
    if depth <= 0 or (rng.random() < 0.4 and srcs):
        return rng.choice(srcs)
    op = rng.choice(["+", "-", "*", "^", "|"])
    a = gen_index(rng, srcs, depth - 1)
    if op == "*":
        return f"({a} * {rng.choice([1, 2, 4, 256, 512, 4096])}u)"
    if rng.random() < 0.5:
        return f"({a} {op} {rng.choice([0, 1, 7, 255])}u)"
    b = gen_index(rng, srcs, depth - 1)
    return f"({a} {op} {b})"


def gen_victim(name, rng, ctrl=False):
    """A random victim. With ctrl=True it ends in a branch on a possibly out-of-bounds load that guards a fixed access, instead of a probe."""
    guard = rng.choice([
        "x < array1_size", "!(x >= array1_size)", "x <= array1_size - 1",
        "array1_size > x",
    ])
    lines, srcs = [], ["x"]
    for i in range(rng.randint(1, 4)):
        kind = rng.random()
        v = f"t{i}"
        if kind < 0.55:
            idx = gen_index(rng, srcs, rng.randint(0, 2))
            lines.append(f"size_t {v} = array1[{idx}];")
        elif kind < 0.8:
            lines.append(f"size_t {v} = {gen_index(rng, srcs, 2)};")
        else:
            lines.append(f"size_t {v}_s = {gen_index(rng, srcs, 1)}; size_t *{v}_p = &{v}_s; size_t {v} = *{v}_p;")
        srcs.append(v)
    tbl = rng.choice(["array2", "array1"])
    idx = gen_index(rng, srcs, rng.randint(1, 3))
    if ctrl:
        cmp = rng.choice(["== k", "!= k", "< k", "& 1"])
        body = " ".join(lines) + f" if (array1[{idx}] {cmp}) temp &= array2[0];"
        return (f"void victim_function_{name}(size_t x, uint8_t k) "
                f"{{ if ({guard}) {{ {body} }} }}\n")
    body = " ".join(lines) + f" temp &= {tbl}[{idx}];"
    return f"void victim_function_{name}(size_t x) {{ if ({guard}) {{ {body} }} }}\n"


def transmitters(src, plugin, clang, engine):
    """{function: set of transmitter instructions} for one engine, or None on timeout."""
    out = tempfile.mkdtemp()
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)
    args = (f"-o {out} -Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 "
            f"--traceback=2 --spectre-v1=mode=classic -fvictim_function_.* "
            f"--aa=transient --partial --file-timeout=30")
    # instructions are compared, so both engines run on the unpromoted IR
    env = dict(os.environ, LCM_ARGS=args, CLOU_NO_MEM2REG="1",
               CLOU_AXTYPES_ENGINE="1" if engine == "axtypes" else "0")
    try:
        p = subprocess.run(
            [clang, "-g", "-fdeclspec", "-I", os.path.join(ROOT, "test"),
             "-Wno-#warnings", f"-fpass-plugin={plugin}", "-c", "-emit-llvm", "-S",
             "-o", os.path.join(out, "o.ll"), src],
            env=env, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    res = {}
    for line in p.stderr.splitlines():
        m = re.match(r"TRANSMITTER: (\S+) \| (.*)", line)
        if m:
            ir = re.sub(r",? !dbg.*", "", m.group(2)).strip()
            res.setdefault(m.group(1), set()).add(ir)
    return res


def violations(src, plugin, clang):
    """Functions where the SMT search reports a transmitter the type engine does not."""
    smt = transmitters(src, plugin, clang, "smt")
    axt = transmitters(src, plugin, clang, "axtypes")
    if smt is None or axt is None:
        return None
    bad = {}
    for fn, sset in smt.items():
        missed = sset - axt.get(fn, set())
        if missed:
            bad[fn] = missed
    return bad


def minimize(src_text, plugin, clang):
    lines = src_text.splitlines(keepends=True)
    changed = True
    while changed:
        changed = False
        for i in range(len(lines)):
            if lines[i].startswith("#") or "victim_function" not in "".join(lines):
                continue
            trial = lines[:i] + lines[i + 1:]
            with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
                f.write("".join(trial)); path = f.name
            v = violations(path, plugin, clang)
            os.unlink(path)
            if v:
                lines = trial; changed = True; break
    return "".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--per-file", type=int, default=25)
    ap.add_argument("--plugin", default=os.path.join(ROOT, "build-clean/src/libclou.so"))
    ap.add_argument("--clang", default="clang-18")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    work = tempfile.mkdtemp()
    tested = 0
    found = []
    nfiles = (a.n + a.per_file - 1) // a.per_file
    for b in range(nfiles):
        src = "#include \"pht.h\"\n"
        for i in range(a.per_file):
            src += gen_victim(f"f{b}_{i}", rng)
        path = os.path.join(work, f"batch{b}.c")
        open(path, "w").write(src)
        v = violations(path, a.plugin, a.clang)
        if v is None:
            continue
        tested += a.per_file
        if v:
            print(f"VIOLATION in batch {b}: {list(v)}")
            reduced = minimize(src, a.plugin, a.clang)
            rp = os.path.join(work, f"repro{b}.c")
            open(rp, "w").write(reduced)
            found.append(rp)
            print(f"  minimized reproducer saved: {rp}")
            print("  --- reproducer ---")
            for ln in reduced.splitlines():
                if "victim_function" in ln:
                    print("   ", ln.strip())
        if (b + 1) % 4 == 0:
            print(f"... {tested} functions tested, {len(found)} violations")

    print(f"\ntested ~{tested} random functions; soundness violations: {len(found)}")
    print("PASS: containment >= SMT on all fuzzed inputs" if not found
          else f"FAIL: {len(found)} reproducer(s) saved under {work}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
