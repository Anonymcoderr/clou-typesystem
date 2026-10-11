#!/bin/bash
# Tests for the refinement procedures. Known-bits must discharge an address
# confined to one cache line of a fixed object and refuse the rest; the SLH
# marker and the allowlist must discharge and be logged.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:-$ROOT/build-clean/src/libclou.so}"
CLANG="${2:-clang-18}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ARGS="-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --spectre-v1=mode=classic -fvictim_function_.* --aa=transient --partial"

cat > "$WORK/line.c" <<'EOF'
#include "pht.h"
unsigned char linebuf[64] __attribute__((aligned(64)));
void victim_function_kbline(size_t x) {
    if (x < array1_size)
        temp &= linebuf[array1[x] & 63];   /* single aligned cache line */
}
EOF

cat > "$WORK/slh.c" <<'EOF'
#include "pht.h"
extern unsigned long __clou_slh(unsigned long) __attribute__((const)); /* SLH marker */
void victim_function_slh(size_t x) {          /* hardened */
    if (x < array1_size)
        temp &= array2[__clou_slh(array1[x]) * 512];
}
void victim_function_noslh(size_t x) {        /* NOT hardened -> real leak */
    if (x < array1_size)
        temp &= array2[array1[x] * 512];
}
EOF

# p->field where p was read out of bounds: constant offset, secret base
cat > "$WORK/ptrfield.c" <<'EOF'
#include "pht.h"
struct rec { int a; int b; };
extern struct rec *rec_table[16];
void victim_function_ptrfield(size_t x) {
    if (x < array1_size)
        temp &= rec_table[x]->b;
}
EOF

# one function, selected by -f<regex>
run_fn() { # $1=src $2=fnregex
  local out="$WORK/o.$RANDOM"; mkdir -p "$out/logs"
  CLOU_AXTYPES_ENGINE=1 LCM_ARGS="-o $out -Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --spectre-v1=mode=classic -f$2 --aa=transient --partial" \
    "$CLANG" -g -fdeclspec -I "$ROOT/test" -Wno-\#warnings -fpass-plugin="$PLUGIN" \
    -c -emit-llvm -S -o "$out/o.ll" "$1" 2>"$out/err.log"
  echo "$out/err.log"
}

run() { # $1=src [$2=CLOU_CT_SAFE]
  local out="$WORK/o.$RANDOM"; mkdir -p "$out/logs"
  CLOU_CT_SAFE="${2:-}" CLOU_AXTYPES_ENGINE=1 LCM_ARGS="-o $out $ARGS" \
    "$CLANG" -g -fdeclspec -I "$ROOT/test" -Wno-\#warnings -fpass-plugin="$PLUGIN" \
    -c -emit-llvm -S -o "$out/o.ll" "$1" 2>"$out/err.log"
  echo "$out/err.log"
}

fail=0
# Passes iff the procedure logs a discharge. The transmitter count is not
# checked: other, unrelated transmitters may remain.
discharges() { # $1=desc $2=source $3=logfile
  if grep -q "discharged by $2" "$3"; then echo "ok:   $1"
  else echo "FAIL: $1 (no '$2' discharge logged)"; fail=1; fi
}
# Passes iff a transmitter remains and the procedure did not discharge it.
refuses() { # $1=desc $2=source $3=logfile
  local tx; tx=$(grep -c '^TRANSMITTER:' "$3")
  if [ "$tx" -ge 1 ] && ! grep -q "discharged by $2" "$3"; then echo "ok:   $1"
  else echo "FAIL: $1 (tx=$tx, or wrongly discharged by $2)"; fail=1; fi
}

discharges "known-bits DISCHARGES single-aligned-line mask"  known-bits "$(run "$WORK/line.c")"
refuses    "known-bits REFUSES range mask (Spectre-v1 leak)" known-bits "$(run "$ROOT/test/pht1.c")"
refuses    "known-bits REFUSES p->field via a loaded pointer" known-bits "$(run "$WORK/ptrfield.c")"
discharges "manual channel discharges + audits"              manual     "$(run "$ROOT/test/pht1.c" 5:19)"
discharges "SLH DISCHARGES hardened transient access"        slh        "$(run_fn "$WORK/slh.c" victim_function_slh)"
refuses    "SLH REFUSES unhardened access (real leak)"       slh        "$(run_fn "$WORK/slh.c" victim_function_noslh)"

[ "$fail" = 0 ] && echo "PASS: refinement discharge soundness boundary holds" || echo "FAILED"
exit $fail
