#!/bin/bash
# Constant-time crypto in the configuration used for bug detection (ungated
# seeds, register elimination): tea, Poly1305 and the Salsa20 core must report
# no transmitter. Salsa20 and Poly1305 come from the TweetNaCl copy in crypto/.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LCM_BUILD="${LCM_BUILD:-$REPO/build-clean}"
PLUGIN="$LCM_BUILD/src/libclou.so"

run() { # tag  file  func  timeout
  local tag="$1" file="$2" func="$3" tmo="$4"
  local dir base OUT line n
  dir="$(dirname "$file")"; base="$(basename "$file")"
  OUT="$(mktemp -d)"; echo "$func" > "$OUT/api.txt"
  line=$(cd "$dir" && CLOU_AXTYPES_ENGINE=1 CLOU_MEM2REG=1 CLOU_AXTYPES_UNGATED=1 \
      CLOU_RLIMIT_GB="${CLOU_RLIMIT_GB:-6}" \
      LCM_ARGS="--aa=transient --fast --batch -o $OUT --functions=$OUT/api.txt --max-trans=250 --window=500 --lsq=50 --callees --spectre-v1=mode=classic" \
      timeout "$tmo" clang-18 -I. -g -O0 -Wno-everything -fpass-plugin="$PLUGIN" -c -o "$OUT/o.o" "$base" 2>&1 \
    | grep -oE "AXTYPES-ENGINE: $func transmitters=[0-9]+ addr=[0-9]+ ctrl=[0-9]+" | head -1 \
    | sed -E "s/^AXTYPES-ENGINE: $func //")   # the target's own line; its graph includes the inlined callees
  n=$(echo "$line" | grep -oE "transmitters=[0-9]+" | grep -oE "[0-9]+" || true)
  printf "%-10s %-34s %-40s %s\n" "$tag" "$func" "${line:-<no output / timeout>}" \
    "$([ "${n:-1}" = 0 ] && echo LEAK-FREE || echo "FLAGGED(${n:-?})")"
  rm -rf "$OUT"
}

echo "Constant-time crypto (expect 0 transmitters):"
printf "%-10s %-34s %-40s %s\n" "CASE" "FUNCTION" "ENGINE" "VERDICT"
run tea      "$REPO/test/tea/tea_encrypt_wrapper.c" encipher                          120
run Poly1305 "$HERE/crypto/tweetnacl_poly.c"        crypto_onetimeauth_poly1305_tweet 120
run Salsa20  "$HERE/crypto/tweetnacl_sym.c"         crypto_core_salsa20_tweet         400  # ~2 s
