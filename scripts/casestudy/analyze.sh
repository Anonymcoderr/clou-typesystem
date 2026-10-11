#!/bin/bash
# Analyse one function of a configured library and print the source locations
# (line:col) of the transmitters flagged in it.
#
# Usage: analyze.sh <openssl|sodium> <file> <function> <v1-data|v1-ctrl|v4>
#
# ENGINE=axtypes (default) runs the type engine with ungated seeds and register
# elimination. ENGINE=smt runs Clou's SMT detector and prints its
# transmitters.txt.
#
# The Clou options below (--fast --batch --functions --callees) are the ones
# its case studies use. With a bare -f<regex> neither engine reports anything
# on these functions.
set -euo pipefail

LCM_BUILD="${LCM_BUILD:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../build-clean" && pwd)}"
PLUGIN="$LCM_BUILD/src/libclou.so"
LIB="$1"; FILE="$2"; FUNC="$3"; MODE="$4"

case "$LIB" in
  openssl) DIR="$LCM_BUILD/openssl"
           INC="-Iinclude -I. -Iproviders/common/include -Iproviders/implementations/include -Icrypto";;
  sodium)  DIR="$LCM_BUILD/libsodium-stable/src/libsodium"
           INC="-I. -I./include/sodium -DCONFIGURED=1";;
  *) echo "unknown lib '$LIB' (expected openssl|sodium)" >&2; exit 1;;
esac

case "$MODE" in
  v1-data) M="--spectre-v1=mode=classic";;
  v1-ctrl) M="--spectre-v1=mode=branch-predicate";;
  v4)      M="--spectre-v4=concrete-sourced-stores=no";;
  *) echo "unknown mode '$MODE' (expected v1-data|v1-ctrl|v4)" >&2; exit 1;;
esac

if [ "${ENGINE:-axtypes}" = smt ]; then
  ENGINE_ENV=(CLOU_AXTYPES_ENGINE=0)
else
  ENGINE_ENV=(CLOU_AXTYPES_ENGINE=1 CLOU_MEM2REG=1 CLOU_AXTYPES_UNGATED=1)
fi

OUT="$(mktemp -d)"; echo "$FUNC" > "$OUT/api.txt"
cd "$DIR"
LOG="$OUT/log"
env "${ENGINE_ENV[@]}" CLOU_RLIMIT_GB="${CLOU_RLIMIT_GB:-6}" \
  LCM_ARGS="--aa=transient --fast --batch -o $OUT --functions=$OUT/api.txt --max-trans=250 --window=500 --lsq=50 --callees $M" \
  timeout "${TIMEOUT:-300}" \
  clang-18 $INC -g -O0 -Wno-everything -fpass-plugin="$PLUGIN" -c -o "$OUT/o.o" "$FILE" >"$LOG" 2>&1 || true

if [ "${ENGINE:-axtypes}" = smt ]; then
  echo "SMT transmitters written to: $OUT/transmitters.txt" >&2
  cat "$OUT/transmitters.txt" 2>/dev/null || true
else
  grep -oE "TRANSMITTER: $FUNC \| [0-9]+:[0-9]+" "$LOG" | grep -oE "[0-9]+:[0-9]+" | sort -u
  rm -rf "$OUT"
fi
