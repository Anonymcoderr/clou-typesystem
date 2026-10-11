#!/bin/bash
# Run each litmus test with both engines on the same IR (no register elimination)
# and check that the type engine reports every transmitter the SMT engine reports.
# Usage: scripts/axtypes-engine-cmp.sh [<plugin.so>] [<clang>]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:-$ROOT/build-clean/src/libclou.so}"
CLANG="${2:-clang-18}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
COMMON="-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --aa=transient --partial"

txset() { # $1=src $2=spec $3=fsel $4=engine  -> prints sorted transmitters
  local out="$WORK/o.$RANDOM"; mkdir -p "$out/logs"
  local ev=0; [ "$4" = axtypes ] && ev=1
  # per-test arguments, e.g. pht10 uses mode=branch-predicate
  local argfile="${1%.c}.args" extra=""
  [ -f "$argfile" ] && extra="$(tr '\n' ' ' <"$argfile")"
  # instructions are compared, so both engines run on the unpromoted IR
  CLOU_AXTYPES_ENGINE=$ev CLOU_NO_MEM2REG=1 LCM_ARGS="-o $out $COMMON $2 $extra $3" \
    "$CLANG" -g -fdeclspec -Wno-\#warnings -fpass-plugin="$PLUGIN" \
    -c -emit-llvm -S -o "$out/test.ll" "$1" 2>"$out/err.log"
  grep "^TRANSMITTER:" "$out/err.log" 2>/dev/null | sed -E 's/,? !dbg.*//' | sort -u
}

declare -a TESTS
for t in "$ROOT"/test/pht*.c;  do TESTS+=("$t|--spectre-v1=mode=classic|-fvictim_function_.*"); done
for t in "$ROOT"/test/fwd*.c;  do TESTS+=("$t|--spectre-v1=mode=classic|"); done
for t in "$ROOT"/test/stl1.c "$ROOT"/test/stl2.c "$ROOT"/test/stl6.c; do
  n="$(basename "$t" .c | sed 's/stl//')"; TESTS+=("$t|--spectre-v4|-fcase_$n"); done

unsound=0; total=0; overapprox=0
for spec in "${TESTS[@]}"; do
  IFS='|' read -r src sp fs <<<"$spec"
  [ -f "$src" ] || continue
  total=$((total+1))
  txset "$src" "$sp" "$fs" smt     > "$WORK/smt.txt"
  txset "$src" "$sp" "$fs" axtypes > "$WORK/axt.txt"
  missed="$(comm -23 "$WORK/smt.txt" "$WORK/axt.txt")"
  extra="$(comm -13 "$WORK/smt.txt" "$WORK/axt.txt")"
  ns=$(wc -l <"$WORK/smt.txt"); na=$(wc -l <"$WORK/axt.txt")
  tag="OK"
  if [ -n "$missed" ]; then tag="UNSOUND"; unsound=$((unsound+1)); fi
  if [ -n "$extra" ]; then overapprox=$((overapprox+1)); fi
  printf "%-24s smt=%2d axtypes=%2d  %s\n" "$(basename "$src")" "$ns" "$na" "$tag"
  [ -n "$missed" ] && printf "    MISSED: %s\n" "$missed"
done
echo "----"
echo "tests=$total  unsound(missed a transmitter)=$unsound  over-approx(extra)=$overapprox"
[ "$unsound" -eq 0 ] && echo "PASS: containment engine is sound on all $total litmus tests" || echo "FAIL"
exit $([ "$unsound" -eq 0 ] && echo 0 || echo 1)
