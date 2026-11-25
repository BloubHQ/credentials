# Known-answer vectors

Official test vectors of the primitive families of part 9 of `docs/design.md` (HPKE,
TurboSHAKE, KangarooTwelve, ML-DSA, SM2). None was downloaded for this repository: each was
taken from a crate in the Cargo registry (fetched by `cargo` like any dependency), and is kept here with its
provenance. The tests that read them are in
`crates/engine/src/vectors_part9.rs`.

## `hpke-rfc9180.json`

A subset of the test vectors of RFC 9180 (HPKE), from the CFRG repository of the draft,
<https://github.com/cfrg/draft-irtf-cfrg-hpke>, `test-vectors.json` at commit `5f503c5` (the
vectors of RFC 9180 appendix A, in JSON).

- Source file: `test-vectors-5f503c5.json`, shipped in the `hpke` 0.13.0 crate
  (`hpke-0.13.0.crate`, SHA-256
  `f65d16b699dd1a1fa2d851c970b0c971b388eeeb40f744252b8de48860980c8f`); the file itself has
  SHA-256 `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` (5,892,257
  bytes).
- Subset: every one of the 128 suites and modes (KEM 0x0010, 0x0012, 0x0020, 0x0021 with
  KDF 0x0001 and 0x0003 and every AEAD, export-only included, in the four modes), all 384
  exports, and the encryptions at sequence numbers 0, 1, 255 and 256 (384 in all; the
  export-only suites have none). Each kept encryption gets a `seq` member. Made with
  `hpke_subset.py`.
- This file: SHA-256 `32ab28c20892bd5e4c9fdf915edfe39454d5e49eb3ea7a246d15342708a9e087`.

The CFRG file has no vector for KEM 0x0011 (DHKEM(P-384, HKDF-SHA384)) or KDF 0x0002
(HKDF-SHA384); those are checked by round trips and against the other suites' code paths.

## `turboshake-rfc9861.json`

The TurboSHAKE128 and TurboSHAKE256 vectors of RFC 9861 section 5 with domain bytes 0x06 and
0x07, as the `turboshake` 0.7.1 crate ships them (`tests/data/turboshake{128,256}_{6,7}.blb`
in `turboshake-0.7.1.crate`, SHA-256
`f892c6904b0bd5a9241eac848347abcbbbd2b9f3892bad23ac3e6efab8d6f06a`), decoded from the
crate's `blobby` format with `turboshake_blobby.py`:

| File | SHA-256 |
| --- | --- |
| `turboshake128_6.blb` | `4ac164c7c0304e1910ed771bc6aac0481f626eed34544deaeb03eb9debd77365` |
| `turboshake128_7.blb` | `ee31dee95ee7d5ec6c4d304c3193806a1196dea7f26b3db3dfe12866ce772a61` |
| `turboshake256_6.blb` | `3045c29d7726656b17cb13cef257b6ec22f0749a7f2cfe1f0576b15cb4935624` |
| `turboshake256_7.blb` | `358249455ae45d148f6e9af3d3afa64974360366bffb6b64aa24280ca49337e5` |

- 25 records: `message` (hex) or, when `pattern_len` is not 0, the RFC's pattern `ptn(n)`
  (byte `j` is `j mod 251`) of that length; `skip` output bytes are dropped before `output`.
- This file: SHA-256 `c7742308f8cbc4aefbf70c83cbb5b48f18f8be487429249045d9cd4cff78163a`.

Other domain bytes are checked through KangarooTwelve, whose single-node case is
TurboSHAKE with domain byte 0x07 and whose tree uses 0x0B and 0x06.

## KangarooTwelve

The KT128 and KT256 vectors of RFC 9861 section 5 are copied into the test from the tests of
the `k12` 0.5.1 crate, which cite that section (`tests/mod.rs` of `k12-0.5.1.crate`, SHA-256
`38a8cc72399dffa4a445bc5f5a84d4af4d441c76604231bc52e9c529c1d47693`; the file itself SHA-256
`b5b79ead48e5bbe486a1529ab9d6833b8bf3e1065f879b19d4a74aa04eb37a0d`).

## ML-DSA

`ML-DSA-{44,65,87}-seed.priv` and `ML-DSA-{44,65,87}.pub` are the examples of the IETF LAMPS
ML-DSA certificate profile, <https://github.com/lamps-wg/dilithium-certificates/tree/main/examples>
(the seed `00 01 .. 1f` and its public key), as the `ml-dsa` 0.1.2 crate ships them in
`tests/examples` (`ml-dsa-0.1.2.crate`, SHA-256
`6f6d49c3f3f0e10e18ca975ffda66f8da0ec36521c1d911adcbc521bf0743f5c`):

| File | SHA-256 |
| --- | --- |
| `ML-DSA-44-seed.priv` | `1f3d0545ff888b8558127fa4a86e866a450b074e0850d9c0471b46a2a2c8a2a7` |
| `ML-DSA-44.pub` | `e8c997db43b377029f99957c26a9eb4ddf628bf88f95603b9f8a5cb56ffb57c0` |
| `ML-DSA-65-seed.priv` | `3022c858985bc5e8284cff673c06d78d55e88152fcf9a6f5e61ad9f63e5f0e0c` |
| `ML-DSA-65.pub` | `2362f97f1a94de086f16877e903d859157c6726f5e60f8e4d7309b21cbff2bb0` |
| `ML-DSA-87-seed.priv` | `855cdfe5bea4a003e5a2d5f58fb78e7d96ed019f68812f41a6be1125b796a846` |
| `ML-DSA-87.pub` | `503f443502bea293ca6b67d0e0668dd87d047273621aa74a7eed89804bcae6b5` |

They check `mldsa_public` (key generation, FIPS 204 Algorithm 6). `mldsa_sign` is hedged, so
it has no known answer: its signatures are checked with the crate's verifier.

## SM2

`sm2-pkcs8-private-key.der` is `tests/examples/pkcs8-private-key.der` of the `sm2` 0.14.0
crate (`sm2-0.14.0.crate`, SHA-256
`5a9d91aad47b30a5a5011032bed8d4b4192d7d5174ab3ed3e4dd22341ba8a5ac`; the file SHA-256
`75a7c58d1411c06784309f3343d5c207ea3988d208aba9de58be935108fdad32`). The test copies the
public key, identifier and OpenSSL signature of that crate's `tests/sm2dsa.rs` (SHA-256
`c72d7174521b1bf2466e3a8a790e5b0a17057ec3aec42ef63b551497c89aeb46`). The OpenSSL signature
used a random nonce, so `sm2_sign` (RFC 6979 nonce) is checked by verification, not by
equality. No vector of GB/T 32918 itself is included.

## Brainpool

No ECDSA vector for brainpoolP256r1 or brainpoolP384r1 ships with the `bp256` and `bp384`
0.14.0 crates (RFC 5639 gives the curves, RFC 7027 ECDH values only): `ecdsa_sign_prehash` on
`bp256` and `bp384` is checked by verification with the `bp256` and `bp384` crates. Not checked
against a known answer.
