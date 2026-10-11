#!/bin/bash
# Transmitter counts of both engines on the PHT and STL litmus suites, and the
# number of source locations the SMT engine reports that the type engine does
# not (expected: 0). PHT runs in address mode; example 10 leaks through control
# flow and is shown separately in control mode.
# Usage: scripts/litmus-table.sh [<plugin.so>] [<clang>]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:-$ROOT/build-clean/src/libclou.so}"
CLANG="${2:-clang-18}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ARGS="-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --aa=transient --partial"

run() { # src args engine
  local out="$WORK/o.$RANDOM$RANDOM" ev=0; mkdir -p "$out/logs"
  [ "$3" = types ] && ev=1
  ( cd "$out" && CLOU_AXTYPES_ENGINE=$ev LCM_ARGS="-o $out $ARGS $2" \
      "$CLANG" -g -fdeclspec -Wno-\#warnings -fpass-plugin="$PLUGIN" \
      -c -emit-llvm -S -o test.ll "$1" 2>err.log >/dev/null )
  grep "^TRANSMITTER:" "$out/err.log" | sed -E 's/,? !dbg.*//' | sort -u > "$WORK/$3.instr"
  grep -oE "^TRANSMITTER: [^ ]+ \| [0-9]+:[0-9]+" "$out/err.log" | LC_ALL=C sort -u > "$WORK/$3.loc"
  rm -rf "$out"
}

suite() { # label, then "src|args" ...
  local label="$1" ts=0 tt=0 tm=0 spec src args name ns nt miss; shift
  printf "\n%s\n%-10s %5s %6s %7s\n" "$label" test SMT types missed
  for spec in "$@"; do
    IFS='|' read -r src args <<<"$spec"
    name="$(basename "$src" .c)"
    run "$src" "$args" smt; run "$src" "$args" types
    ns=$(wc -l <"$WORK/smt.instr"); nt=$(wc -l <"$WORK/types.instr")
    miss=$(LC_ALL=C comm -23 "$WORK/smt.loc" "$WORK/types.loc" | wc -l)
    printf "%-10s %5d %6d %7d\n" "$name" "$ns" "$nt" "$miss"
    ts=$((ts+ns)); tt=$((tt+nt)); tm=$((tm+miss))
  done
  printf "%-10s %5d %6d %7d\n" total "$ts" "$tt" "$tm"
}

PHT=(); for i in $(seq 1 15); do
  PHT+=("$ROOT/test/pht$i.c|-fvictim_function_.* --spectre-v1=mode=classic"); done
STL=(); for i in $(seq 1 13); do
  a="--spectre-v4 -fcase_$i"
  [ -f "$ROOT/test/stl$i.args" ] && a="$a $(tr '\n' ' ' <"$ROOT/test/stl$i.args")"
  STL+=("$ROOT/test/stl$i.c|$a"); done

suite "PHT, address transmitters" "${PHT[@]}"
suite "PHT example 10, control transmitters" "$ROOT/test/pht10.c|-fvictim_function_.* --spectre-v1=mode=branch-predicate"
suite "STL" "${STL[@]}"
