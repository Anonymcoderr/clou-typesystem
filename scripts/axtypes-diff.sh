#!/bin/bash
# Run Clou's SMT engine on the litmus tests with witness export and check that
# the type checker flags the transmitter of every witness.
# Usage: scripts/axtypes-diff.sh [<plugin.so>] [<clang>]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:-$ROOT/build-clean/src/libclou.so}"
CLANG="${2:-clang-18}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

COMMON="-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --aa=transient --partial --cloupy-json"

run() { # $1=src $2=spec $3=fsel
  local out="$WORK/$(basename "$1" .c).$RANDOM"
  mkdir -p "$out/logs" "$out/cloupy"
  LCM_ARGS="-o $out $COMMON $2 $3" \
    "$CLANG" -g -fdeclspec -Wno-\#warnings -fpass-plugin="$PLUGIN" \
    -c -emit-llvm -S -o "$out/test.ll" "$1" 2>"$out/err.log"
  grep "AXTYPES:" "$out/err.log" 2>/dev/null
}

ALL=""
for t in "$ROOT"/test/pht1.c "$ROOT"/test/pht2.c "$ROOT"/test/pht5.c \
         "$ROOT"/test/pht12.c "$ROOT"/test/pht14.c; do
  [ -f "$t" ] && ALL+=$'\n'"$(run "$t" '--spectre-v1=mode=classic' '-fvictim_function_.*')"
done
for t in "$ROOT"/test/stl1.c "$ROOT"/test/stl2.c "$ROOT"/test/stl6.c; do
  n="$(basename "$t" .c | sed 's/stl//')"
  [ -f "$t" ] && ALL+=$'\n'"$(run "$t" '--spectre-v4' "-fcase_$n")"
done
for t in "$ROOT"/test/fwd1.c "$ROOT"/test/fwd2.c "$ROOT"/test/fwd3.c; do
  [ -f "$t" ] && ALL+=$'\n'"$(run "$t" '--spectre-v1=mode=classic' '')"
done

TOTAL=$(printf '%s\n' "$ALL" | grep -c "AXTYPES:")
DISAGREE=$(printf '%s\n' "$ALL" | grep -c "agree=no")
echo "witnesses checked: $TOTAL   disagreements: $DISAGREE"
if [ "$TOTAL" -eq 0 ]; then echo "ERROR: no witnesses produced"; exit 2; fi
if [ "$DISAGREE" -ne 0 ]; then
  echo "FAIL: type checker disagreed with SMT engine on $DISAGREE witness(es):"
  printf '%s\n' "$ALL" | grep "agree=no"
  exit 1
fi
echo "PASS: axtypes containment agrees with SMT engine on all $TOTAL witnesses"
