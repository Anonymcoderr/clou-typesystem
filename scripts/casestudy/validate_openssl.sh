#!/bin/bash
# For each OpenSSL Spectre bug that Clou reported, analyse the function with the
# type engine and check that the documented transmitter line is flagged.
# Run fetch_libs.sh and configure_libs.sh first.
#
# EVP_PKEY_asn1_get0 only returns the out-of-bounds value; its transmitter is in
# the caller, so it is analysed from EVP_PKEY_asn1_find_str.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# tag | lib | file | function | mode | line of the documented transmitter
# (where the tainted value is dereferenced, not where it is read)
BUGS=(
  "TXT_DB_create_index|openssl|crypto/txt_db/txt_db.c|TXT_DB_create_index|v1-data|184"
  "ts_check_status_info|openssl|crypto/ts/ts_rsp_verify.c|ts_check_status_info|v1-data|390"   # ERR_raise_data() dereferences status_text (OOB read at :364)
  "SSL_get_shared_sigalgs|openssl|ssl/t1_lib.c|SSL_get_shared_sigalgs|v1-data|2420"           # shsigalgs->hash; :2418 is the OOB read, not the transmitter
  "ssl_has_cert|openssl|ssl/t1_lib.c|ssl_has_cert|v1-ctrl|2366"          # gadget in ssl_local.h
  "HASH_FINAL|openssl|crypto/sha/sha256.c|SHA256_Final|v4|196"           # gadget in md32_common.h
  "HASH_UPDATE|openssl|crypto/sha/sha256.c|SHA256_Update|v4|150"         # gadget in md32_common.h
  "EVP_PKEY_asn1_get0|openssl|crypto/asn1/ameth_lib.c|EVP_PKEY_asn1_find_str|v1-data|136"  # OOB read at :53 in the callee, transmitter in this caller
)

printf "%-24s %-8s %-14s %s\n" "BUG" "EXPECT" "FLAGGED@line" "VERDICT"
pass=0
for b in "${BUGS[@]}"; do
  IFS='|' read -r tag lib file func mode want <<<"$b"
  flagged="$(ENGINE=axtypes "$HERE/analyze.sh" "$lib" "$file" "$func" "$mode" || true)"
  lines="$(echo "$flagged" | grep -oE '^[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')"
  if echo "$flagged" | grep -qE "^${want}:"; then verdict="DETECTED"; pass=$((pass+1)); else verdict="not-pinned"; fi
  printf "%-24s %-8s %-14s %s\n" "$tag" "$want" "$want" "$verdict  (flagged: ${lines:-none})"
done
echo
echo "Detected at documented transmitter: ${pass}/${#BUGS[@]} bugs (EVP_PKEY_asn1_get0 via its caller EVP_PKEY_asn1_find_str)."
