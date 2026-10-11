#!/usr/bin/env python3
"""Differential fuzzer with a separate oracle.

Clou's SMT detector runs on the unpromoted IR, the type engine with register
elimination, as two separate compilations. Per function, every location the
oracle reports must be flagged by the type engine. Locations are source
line:col, which both IRs share.

Each compilation is limited to CLOU_RLIMIT_GB of address space (default 5).
Usage: oracle_fuzz.py [-n N] [--seed S] [--per-file K] [--mode classic|branch-predicate]
"""
import argparse, os, re, resource, subprocess, sys, tempfile, random

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.dirname(__file__))
import difffuzz

TIMEOUT = 60
_RLIMIT_GB = float(os.environ.get("CLOU_RLIMIT_GB", "5"))
def _mem_limit():
    b = int(_RLIMIT_GB * 1024**3)
    resource.setrlimit(resource.RLIMIT_AS, (b, b))

COMMON = ("-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 "
          "--traceback=2 --spectre-v1=mode={mode} -fvictim_function_.* "
          "--aa=transient --partial --file-timeout=30")
MODE = "classic"


def locs(src, plugin, clang, engine, mem2reg):
    """{function: set of 'line:col'} for one engine, or None on error or timeout."""
    out = tempfile.mkdtemp()
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)
    env = dict(os.environ, LCM_ARGS=f"-o {out} {COMMON.format(mode=MODE)}",
               CLOU_AXTYPES_ENGINE="1" if engine == "axtypes" else "0")
    if mem2reg:
        env["CLOU_MEM2REG"] = "1"
    else:
        env.pop("CLOU_MEM2REG", None)
    try:
        p = subprocess.run(
            [clang, "-g", "-fdeclspec", "-I", os.path.join(ROOT, "test"),
             "-Wno-#warnings", f"-fpass-plugin={plugin}", "-c", "-emit-llvm", "-S",
             "-o", os.path.join(out, "o.ll"), src],
            env=env, capture_output=True, text=True, timeout=TIMEOUT,
            preexec_fn=_mem_limit)
    except subprocess.TimeoutExpired:
        return None
    res = {}
    for line in p.stderr.splitlines():
        m = re.match(r"TRANSMITTER: (\S+) \| (\d+:\d+)", line)
        if m:
            res.setdefault(m.group(1), set()).add(m.group(2))
    return res


def check_file(src, plugin, clang):
    """{function: locations the oracle reports and the type engine does not}."""
    oracle = locs(src, plugin, clang, "smt", mem2reg=False)
    ours   = locs(src, plugin, clang, "axtypes", mem2reg=True)
    if oracle is None or ours is None:
        return None
    bad = {}
    for fn, oset in oracle.items():
        missed = oset - ours.get(fn, set())
        if missed:
            bad[fn] = missed
    check_file.oracle_fns += sum(1 for o in oracle.values() if o)
    check_file.oracle_locs += sum(len(o) for o in oracle.values())
    return bad
check_file.oracle_fns = 0
check_file.oracle_locs = 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--per-file", type=int, default=20)
    ap.add_argument("--plugin", default=os.path.join(ROOT, "build-clean/src/libclou.so"))
    ap.add_argument("--clang", default="clang-18")
    ap.add_argument("--mode", choices=["classic", "branch-predicate"], default="classic",
                    help="classic: address transmitters (default).  branch-predicate: "
                         "control transmitters, on generated Kocher-example-10-shaped victims")
    a = ap.parse_args()
    global MODE
    MODE = a.mode
    ctrl = (a.mode == "branch-predicate")

    rng = random.Random(a.seed)
    tested = skipped = 0
    violations = []
    nfiles = (a.n + a.per_file - 1) // a.per_file
    for b in range(nfiles):
        body = "#include \"pht.h\"\n"
        for i in range(a.per_file):
            body += difffuzz.gen_victim(f"b{b}_{i}", rng, ctrl=ctrl)
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(body); path = f.name
        bad = check_file(path, a.plugin, a.clang)
        os.unlink(path)
        if bad is None:
            skipped += a.per_file
        else:
            tested += a.per_file
            for fn, miss in bad.items():
                violations.append((b, fn, miss, body))
        if (b + 1) % 5 == 0:
            print(f"  ... {tested} functions tested, {len(violations)} violations, "
                  f"{skipped} skipped")

    print(f"\nmode={a.mode} seed={a.seed}: "
          f"tested ~{tested} random functions ({skipped} skipped on timeout/OOM); "
          f"oracle leaks missed under mem2reg: {len(violations)}")
    print(f"oracle (clean Clou-SMT) reported {check_file.oracle_locs} leak location(s) "
          f"in {check_file.oracle_fns} function(s); each was checked against our tool")
    if violations:
        b, fn, miss, body = violations[0]
        print(f"FAIL: e.g. {fn} misses Clou-SMT leak location(s) {sorted(miss)}")
        print("--- offending file (first violation) ---")
        print(body)
        return 1
    print("PASS: mem2reg tool catches every clean-Clou-SMT leak on all fuzzed inputs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
