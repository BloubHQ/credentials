# Fixtures of the tests of `attest`

Only the tests read these files; no built program contains them. The pinned root,
`src/aws-nitro-enclaves-root-g1.der`, is described at the end.

The signing certificate of a Nitro attestation document is valid for about three hours. The
tests pass at any time because the chain is validated at the time the document states.

All files below come from the repository
[`pickle-com/credential-enclave`](https://github.com/pickle-com/credential-enclave)
(Apache License 2.0), branch `main`, fetched on 2026-11-25, and are byte-identical to the files
named there. Its own fixture READMEs (`verify/tests/fixtures/README.md` and
`protocol/tests/fixtures/README.md`) describe them; what they say is summarized here.

## `nitro-attestation-prerelease.cbor`

- What it is: a Nitro attestation document (COSE_Sign1, 4627 bytes, untagged) of a
  production-mode enclave, the answer of a node to an attestation call. `module_id`
  `i-00e27c4213a488340-enc01a0f5b621ecd411`, time 2026-10-01T04:26:30Z. PCR0, PCR1 and PCR2
  are those of `measurements-prerelease.json`. Its user data is the binding of a node of that
  other program, not a `NodeIdentity::report_data` of this one.
- Source: `verify/tests/fixtures/nitro-attestation-alpha-prerelease.cbor`.
- License: Apache-2.0.
- SHA-256: `7b3cdc1ee62fe725f157a6f13ce486e12dc110f7cd9182d0b6efffc69b679269`

## `nitro-attestation-prerelease.nonce`

- What it is: the 32-byte nonce of the call that document answers,
  `488818963c99ac32f3c43f92a73f1ee1978e32ed1a597020cb0efaf2957978de` in hex.
- Source: `verify/tests/fixtures/nitro-attestation-alpha-prerelease.cbor.nonce`.
- License: Apache-2.0.
- SHA-256: `8af79b6d107bdc5419b3889117f8abc084e501c4407e7e27f340a6b307762591`

## `measurements-prerelease.json`

- What it is: the `measurements.json` of the build the document comes from (release `v1.0.0`
  of a pre-release build, commit `7a7f628d991bc6646bafcc4a2a3fa4a424f74995`, with a table of
  the inputs of the build, which `attest` ignores).
- Source: `verify/tests/fixtures/measurements-prerelease.json`.
- License: Apache-2.0.
- SHA-256: `22edae8512f61915751eb9bf5f2ae80031827c1dec4362caf63614affc842d81`

## `nitro-attestation-debug.cbor`

- What it is: a Nitro attestation document (4748 bytes) of a debug-mode enclave: PCR0, PCR1
  and PCR2 are all zero. Its nonce is 256 bytes, which the tests read from the document.
  `module_id` `i-0918f6c55e3b61d89-enc018aa8b8e2285d13`, time 2023-09-18T15:03:30Z.
- Source: `protocol/tests/fixtures/nitro-attestation-document.cbor`, itself the base64
  decoding of `test-data/valid-attestation-doc-base64` of
  [`evervault/attestation-doc-validation`](https://github.com/evervault/attestation-doc-validation)
  at commit `6e477381464fbfefe1afa606052f9ad81b99120d`.
- License: Apache-2.0 (both repositories).
- SHA-256: `6f80ac250af2f06f1e423051f64a8b29926cc474a728d0bf1f7a4d21074ec9e5`

## `unrelated-root.der`

- What it is: a self-signed CA certificate (DER, 503 bytes, `CN=unrelated-root, O=Pickle
  Test`, ECDSA P-384), to which no document chains. The tests pin it in the place of the AWS
  root and expect `ChainUntrusted`. Its private key was not published.
- Source: `protocol/tests/fixtures/unrelated-root.der`.
- License: Apache-2.0.
- SHA-256: `24d6b5c9f929a8063e17c5e94187d3fdc123ac4a847e24cc0ef54b6a7cd92639`

## `src/aws-nitro-enclaves-root-g1.der` (not a fixture: the pinned root)

- What it is: the AWS Nitro Enclaves Root-G1 certificate in DER (533 bytes), the root AWS
  publishes in `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`.
- Source: `protocol/src/aws-nitro-enclaves-root-g1.der` of `pickle-com/credential-enclave`.
- SHA-256: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`, the fingerprint
  AWS documents for that root; the test `the_pinned_root_is_aws_nitro_enclaves_root_g1`
  checks it.
