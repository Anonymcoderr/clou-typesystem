#!/usr/bin/env python3
"""Mutation test: leak-preserving variants of the v1/v4 gadgets must stay flagged.

Also runs a few secure controls that must not be flagged.
Usage: metamorphic.py [--plugin PATH] [--clang clang-18]
Exit status 1 if a leaking variant is missed.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

V1_HEAD = ('#include "pht.h"\n'
           'struct mm_rec { int a; int b; };\n'
           'extern struct mm_rec *mm_tab[16];\n')
# v1, address transmitters
V1_VARIANTS = {
    "base":        "if (x < array1_size) temp &= array2[array1[x] * 512];",
    "spill":       "size_t i = x; if (i < array1_size) temp &= array2[array1[i] * 512];",
    "negcond":     "if (!(x >= array1_size)) temp &= array2[array1[x] * 512];",
    "ptr":         "uint8_t *pa = array1, *pb = array2; if (x < array1_size) temp &= pb[pa[x] * 512];",
    "arith_ident": "if (x < array1_size) temp &= array2[((array1[x] + 0u) * 256u) * 2u];",
    "wide_stride": "if (x < array1_size) temp &= array2[array1[x] * 4096];",
    "idx_local":   "if (x < array1_size) { size_t k = array1[x]; temp &= array2[(k + 0) * 512]; }",
    "int_cast":    "if (x < array1_size) { int k = (int)array1[x]; temp &= array2[(unsigned)k * 512]; }",
    "idx_via_ptr": "size_t j = x; size_t *pj = &j; if (*pj < array1_size) temp &= array2[array1[*pj] * 512];",
    "reload":      "size_t j; j = x; if (j < array1_size) { volatile size_t v = j; temp &= array2[array1[(size_t)v] * 512]; }",
    "chained":     "if (x < array1_size) { uint8_t a = array1[x]; temp &= array2[(size_t)a * 512]; }",
    "double_spill":"if (x < array1_size) { size_t a = array1[x]; size_t b = a; size_t c = b; temp &= array2[c * 512]; }",
    "xor_arith":   "if (x < array1_size) temp &= array2[(array1[x] ^ 0u) * 512];",
    "or_arith":    "if (x < array1_size) temp &= array2[(array1[x] | 0u) * 512];",
    "sub_arith":   "if (x < array1_size) temp &= array2[(array1[x] * 512u) - 0u];",
    "ptr_ptr":     "uint8_t *pa = array1; uint8_t **ppa = &pa; if (x < array1_size) temp &= array2[(*ppa)[x] * 512];",
    "add_two_ld":  "if (x < array1_size) { size_t a = array1[x]; temp &= array2[(a + (array1[0] & 0u)) * 512]; }",
    "while_guard": "while (x < array1_size) { temp &= array2[array1[x] * 512]; break; }",
    "gep_offset":  "if (x < array1_size) temp &= *(array2 + array1[x] * 512);",
    "signed_idx":  "if (x < array1_size) { long k = (long)array1[x]; temp &= array2[(size_t)(k * 512)]; }",
    "nested_paren":"if (x < array1_size) temp &= array2[(((array1[(((x)))]) * 512))];",
    "comma_expr":  "if (x < array1_size) temp &= array2[(0u, array1[x]) * 512];",
    "ternary_idx": "if (x < array1_size) temp &= array2[(x ? array1[x] : 0) * 512];",
    "struct_ptr":  "struct { uint8_t *a, *b; } s = {array1, array2}; if (x < array1_size) temp &= s.b[s.a[x] * 512];",
    # the out-of-bounds read yields a pointer; the leak is the field access through it
    "ptr_field":   "if (x < array1_size) temp &= mm_tab[x]->b;",
    "ptr_field2":  "if (x < array1_size) { struct mm_rec *p = mm_tab[x]; temp &= p->a; temp &= p->b; }",
    "switch_guard":"switch (x < array1_size) { case 1: temp &= array2[array1[x] * 512]; break; default: break; }",
    "switch_multi":"switch (x & 3) { case 0: temp &= array2[array1[x] * 512]; break; case 1: temp &= array2[array1[x] * 256]; break; default: break; }",
}
V1_INLINE = (
    "static inline uint8_t leak_acc(size_t i){ return array1[i]; }\n"
    "void victim_function_inline(size_t x){ if (x < array1_size) temp &= array2[leak_acc(x) * 512]; }\n"
)

V1_KNOWN_GAPS = {}

# controls: constant index, and no bounds-check branch
V1_SECURE = {
    "const_idx":   "temp &= array2[array1[3] * 512];",
    "no_window":   "temp &= array2[array1[x & 7] * 512];",
}

V4_HEAD = '#include "stl.h"\n'
# v4, store bypass
V4_VARIANTS = {
    "base":   "uint32_t r = idx & (array_size - 1); publicarray[r] = 0; temp &= publicarray2[secretarray[r] * 512];",
    "spill":  "uint32_t r = idx & (array_size - 1); uint32_t s = r; publicarray[s] = 0; temp &= publicarray2[secretarray[s] * 512];",
    "ptr":    "uint32_t r = idx & (array_size - 1); uint8_t *pp = publicarray; pp[r] = 0; temp &= publicarray2[secretarray[r] * 512];",
}

# v1, control transmitters (Kocher example 10): the out-of-bounds value decides a
# branch that guards an access to a fixed location
VC_PARAM = "size_t x, uint8_t k"
VC_VARIANTS = {
    "cmp_arg":   "if (x < array1_size) { if (array1[x] == k) temp &= array2[0]; }",
    "cmp_const": "if (x < array1_size) { if (array1[x] == 42) temp &= array2[0]; }",
    "cmp_ne":    "if (!(x >= array1_size)) { if (array1[x] != k) temp &= array2[0]; }",
    "cmp_lt":    "if (x < array1_size) { if (array1[x] < k) temp &= array2[0]; }",
    "cmp_bit":   "if (x < array1_size) { if (array1[x] & 1) temp &= array2[0]; }",
    "cmp_local": "if (x < array1_size) { uint8_t v = array1[x]; if (v == k) temp &= array2[0]; }",
    "cmp_spill": "size_t i = x; if (i < array1_size) { if (array1[i] == k) temp &= array2[0]; }",
    "cmp_store": "if (x < array1_size) { if (array1[x] == k) temp = 1; }",
    "cmp_arith": "if (x < array1_size) { if ((array1[x] ^ 0u) + 0u == k) temp &= array2[0]; }",
    "cmp_while": "if (x < array1_size) { while (array1[x] == k) { temp &= array2[0]; break; } }",
}
VC_SECURE = {
    "public_pred": "if (x < array1_size) { if (k == 3) temp &= array2[0]; }",
    "const_idx":   "if (array1[3] == k) temp &= array2[0];",
}


def emit(path, head, variants, inline_extra="", secure=None, known_gaps=None,
         param="size_t x"):
    with open(path, "w") as f:
        f.write(head)
        for name, body in variants.items():
            f.write(f"void victim_function_{name}({param}) {{ {body} }}\n")
        for name, body in (secure or {}).items():
            f.write(f"void victim_function_secure_{name}({param}) {{ {body} }}\n")
        for name, body in (known_gaps or {}).items():
            f.write(f"void victim_function_knowngap_{name}({param}) {{ {body} }}\n")
        if inline_extra:
            f.write(inline_extra)


def run_engine(src, mode, extra_inc, plugin, clang, field="addr"):
    out = tempfile.mkdtemp()
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)
    args = (f"-o {out} -Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 "
            f"--traceback=2 {mode} -fvictim_function_.* --aa=transient --partial")
    env = dict(os.environ, CLOU_AXTYPES_ENGINE="1", LCM_ARGS=args)
    p = subprocess.run(
        [clang, "-g", "-fdeclspec", "-I", os.path.join(ROOT, "test"), extra_inc,
         "-Wno-#warnings", f"-fpass-plugin={plugin}", "-c", "-emit-llvm", "-S",
         "-o", os.path.join(out, "o.ll"), src],
        env=env, capture_output=True, text=True)
    counts = {}
    for m in re.finditer(r"AXTYPES-ENGINE: (victim_function_\S+) transmitters=\d+ addr=(\d+) ctrl=(\d+)",
                         p.stderr):
        counts[m.group(1)] = int(m.group(2) if field == "addr" else m.group(3))
    return counts, p.stderr


def check(counts, variants_names, secure_names, label, gap_names=()):
    missed, fp, ok = [], [], 0
    for n in variants_names:
        fn = f"victim_function_{n}"
        c = counts.get(fn)
        if c is None:
            missed.append(f"{fn} (not analysed)")
        elif c < 1:
            missed.append(f"{fn} (no transmitter)")
        else:
            ok += 1
    for n in secure_names:
        c = counts.get(f"victim_function_secure_{n}", 0)
        if c and c > 0:
            fp.append(f"victim_function_secure_{n} ({c} — false positive)")
    print(f"[{label}] leak variants flagged: {ok}/{len(variants_names)}"
          + (f"   secure controls clean: {len(secure_names)-len(fp)}/{len(secure_names)}" if secure_names else ""))
    for m in missed:
        print(f"    SOUNDNESS FAIL: {m}")
    for x in fp:
        print(f"    precision note: {x}")
    for n in gap_names:
        c = counts.get(f"victim_function_knowngap_{n}", 0)
        status = "now flagged (improved!)" if c and c > 0 else "still a gap (documented)"
        print(f"    known gap [{n}]: {status}")
    return len(missed) == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin", default=os.path.join(ROOT, "build-clean/src/libclou.so"))
    ap.add_argument("--clang", default="clang-18")
    a = ap.parse_args()

    work = tempfile.mkdtemp()
    ok = True

    v1 = os.path.join(work, "mut_v1.c")
    emit(v1, V1_HEAD, V1_VARIANTS, inline_extra=V1_INLINE, secure=V1_SECURE,
         known_gaps=V1_KNOWN_GAPS)
    c1, _ = run_engine(v1, "--spectre-v1=mode=classic", "-DNONE=0", a.plugin, a.clang)
    ok &= check(c1, list(V1_VARIANTS) + ["inline"], list(V1_SECURE), "v1",
                gap_names=list(V1_KNOWN_GAPS))

    vc = os.path.join(work, "mut_v1_ctrl.c")
    emit(vc, V1_HEAD, VC_VARIANTS, secure=VC_SECURE, param=VC_PARAM)
    cc, _ = run_engine(vc, "--spectre-v1=mode=branch-predicate", "-DNONE=0", a.plugin,
                       a.clang, field="ctrl")
    ok &= check(cc, list(VC_VARIANTS), list(VC_SECURE), "v1-ctrl")

    v4 = os.path.join(work, "mut_v4.c")
    emit(v4, V4_HEAD, V4_VARIANTS, param="uint32_t idx")
    c4, _ = run_engine(v4, "--spectre-v4", "-DNONE=0", a.plugin, a.clang)
    ok &= check(c4, list(V4_VARIANTS), [], "v4")

    print("PASS: no missed leaks across mutants" if ok else "FAIL: missed leak(s) detected")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
