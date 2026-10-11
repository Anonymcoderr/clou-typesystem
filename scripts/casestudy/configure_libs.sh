#!/bin/bash
# Configure the fetched OpenSSL and libsodium trees so that their generated
# headers exist. No full build: only the files containing the bugs are compiled.
set -euo pipefail

LCM_BUILD="${LCM_BUILD:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../build-clean" && pwd)}"

echo "[configure] OpenSSL"
cd "$LCM_BUILD/openssl"
./Configure CC=clang-18 CFLAGS="-g -O0" no-asm no-tests
make -j"$(nproc)" build_generated

echo "[configure] libsodium"
cd "$LCM_BUILD/libsodium-stable"
./configure --disable-asm CC=clang-18 \
  CPPFLAGS="-UHAVE_INLINE_ASM -UHAVE_EMMINTRIN_H -UHAVE_C_VARARRAYS -UHAVE_ALLOCA -g -Wno-cpp" \
  CFLAGS="-O0 -g"

echo "[configure] done"
