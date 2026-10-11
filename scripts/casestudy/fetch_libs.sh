#!/bin/bash
# Fetch the sources for the case study into $LCM_BUILD (default: build-clean).
# OpenSSL is pinned to the revision the clou-bugs corpus refers to.
set -euo pipefail

LCM_BUILD="${LCM_BUILD:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../build-clean" && pwd)}"
OPENSSL_COMMIT=065121ff198a84106023013420dedd57ac4ff53a
LIBSODIUM_TARBALL=https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz

cd "$LCM_BUILD"

echo "[fetch] OpenSSL @ ${OPENSSL_COMMIT}"
rm -rf openssl && mkdir openssl && cd openssl
git init -q
git remote add origin https://github.com/openssl/openssl.git
git fetch --depth 1 -q origin "$OPENSSL_COMMIT"
git checkout -q FETCH_HEAD

cd "$LCM_BUILD"
echo "[fetch] libsodium release tarball"
rm -rf libsodium-stable libsodium-stable.tar.gz
wget -q "$LIBSODIUM_TARBALL" -O libsodium-stable.tar.gz
tar xzf libsodium-stable.tar.gz

echo "[fetch] done -> $LCM_BUILD/{openssl,libsodium-stable}"
