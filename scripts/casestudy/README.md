# Case studies: OpenSSL bugs and constant-time crypto

## OpenSSL

Clou found Spectre v1 and v4 gadgets in OpenSSL; they are documented in the
[`nmosier/clou-bugs`](https://github.com/nmosier/clou-bugs) corpus. This harness
runs the type engine on the same OpenSSL revision and checks that the documented
transmitter of each bug is among the lines it flags.

```sh
export LCM_BUILD=$PWD/build-clean        # directory containing src/libclou.so
scripts/casestudy/fetch_libs.sh          # OpenSSL at 065121ff, libsodium 1.0.20
scripts/casestudy/configure_libs.sh      # generates headers, no full build
scripts/casestudy/validate_openssl.sh
```

The sources are fetched into `$LCM_BUILD` and are not part of the repository.

| Bug | Analysed function | Kind | Documented transmitter | Flagged |
|---|---|---|---|---|
| `TXT_DB_create_index` | same | v1, address | `db->index[field]` passed to `lh_OPENSSL_STRING_free` | yes |
| `ts_check_status_info` | same | v1, address | `ERR_raise_data(.., status_text, ..)` | yes |
| `SSL_get_shared_sigalgs` | same | v1, address | `shsigalgs->hash` | yes |
| `ssl_has_cert` | same | v1, control | `s->cert->pkeys[idx]` | yes |
| `HASH_FINAL` | `SHA256_Final` | v4, address | `p[n] = 0x80` | yes |
| `HASH_UPDATE` | `SHA256_Update` | v4, address | `memcpy(p + n, ...)` | yes |
| `EVP_PKEY_asn1_get0` | `EVP_PKEY_asn1_find_str` | v1, address | `strlen(ameth->pem_str)` in the caller | yes |

`EVP_PKEY_asn1_get0` only returns the out-of-bounds value
(`standard_methods[idx]`); the transmitter is in its caller. It is therefore
analysed from the in-library caller `EVP_PKEY_asn1_find_str`, with callees
inlined. Analysed on its own it has no transmitter to report.

The corpus also lists a control-flow variant of `HASH_UPDATE`. It is not part of
this harness.

`analyze.sh` runs one function and prints the flagged locations. `ENGINE=smt`
runs Clou's SMT detector instead, for comparison. Both use the options of Clou's
own case studies (`--aa=transient --fast --batch --functions=<list> --callees`).
With a bare `-f<regex>` neither engine reports anything on these functions.

The harness uses ungated seeds (`CLOU_AXTYPES_UNGATED=1`). The default policy
seeds only reads with an attacker-controlled index and misses bugs where the
taint analysis does not mark the index.

## Constant-time crypto

```sh
scripts/casestudy/precision_crypto.sh
```

In the same configuration the type engine reports no transmitter on:

| Case | Function | Transmitters | Time |
|---|---|---|---|
| tea | `encipher` | 0 | under 1 s |
| Poly1305 | `crypto_onetimeauth_poly1305_tweet` | 0 | about 1 s |
| Salsa20 core | `crypto_core_salsa20_tweet` | 0 | about 2 s |

Without register elimination (`CLOU_NO_MEM2REG=1`) the same runs flag 33
instructions in Poly1305 and 28 in the Salsa20 core. The zeros are not vacuous:
the transient array reads of these functions are seeded, and none of the seeded
values reaches an address or a guard.

Salsa20 and Poly1305 come from the public-domain TweetNaCl copy in `crypto/`
(see `crypto/NOTICE`); tea is `test/tea/`.
