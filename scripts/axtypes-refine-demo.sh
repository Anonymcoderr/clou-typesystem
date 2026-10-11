#!/bin/bash
# The type engine flags pht1's transmitter; an allowlist entry (CLOU_CT_SAFE)
# for that location removes the flag.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:-$ROOT/build-clean/src/libclou.so}"
CLANG="${2:-clang-18}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ARGS="-Epo,tfo,addr,addr_gep,rf,rfx -d250 --window 500 --lsq=50 --traceback=2 --spectre-v1=mode=classic -fvictim_function_.* --aa=transient --partial"

count() { # $1=CLOU_CT_SAFE
  local out="$WORK/o.$RANDOM"; mkdir -p "$out/logs"
  CLOU_CT_SAFE="$1" CLOU_AXTYPES_ENGINE=1 LCM_ARGS="-o $out $ARGS" \
    "$CLANG" -g -fdeclspec -Wno-\#warnings -fpass-plugin="$PLUGIN" \
    -c -emit-llvm -S -o "$out/test.ll" "$ROOT/test/pht1.c" 2>"$out/err.log"
  grep -c '^TRANSMITTER:' "$out/err.log"
}

# find the transmitter's source location
out="$WORK/probe"; mkdir -p "$out/logs"
CLOU_AXTYPES_ENGINE=1 LCM_ARGS="-o $out $ARGS" "$CLANG" -g -fdeclspec -Wno-\#warnings \
  -fpass-plugin="$PLUGIN" -c -emit-llvm -S -o "$out/test.ll" "$ROOT/test/pht1.c" 2>"$out/err.log"
LOC="$(grep '^TRANSMITTER:' "$out/err.log" | grep -oE '[0-9]+:[0-9]+' | head -1)"

before="$(count "")"
after="$(count "$LOC")"
echo "pht1 transmitters: before refinement=$before, after refining $LOC=$after"
if [ "$before" -ge 1 ] && [ "$after" -eq 0 ]; then
  echo "PASS: refinement collapses the leak (containment restored)"
  exit 0
else
  echo "FAIL: expected before>=1 and after==0"
  exit 1
fi
