# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org);
before 1.0, minor versions may break formats and APIs.

## Unreleased

### Changed

- Minimum Rust 1.88 (was 1.87): `time` 0.3.47, which fixes RUSTSEC-2026-0009, needs it.

### Added

- Node continuity (`docs/design.md` section 11, part 10; section 10): a node hands its state
  to a node of a newer release. New crate `continuity`: successor statements
  (`successor.json`, "release X may hand over to the measurements of release Y") signed in the
  release workflow with Sigstore keyless signing (`cosign sign-blob --new-bundle-format`,
  `id-token: write`) and verified offline in Rust (Fulcio chain to a pinned root, the
  workflow identity, the signature, the `hashedrekord` entry, the Rekor signed entry timestamp
  and the inclusion proof to a signed checkpoint; no maintained pure-Rust verifier of the
  current RustCrypto generation existed); the four-message mutual-attestation protocol and
  its framing over vsock port 5003; test roots for Nitro and Sigstore behind the `testing`
  feature. Engine: `Node::hand_over` and `Node::take_over` (state sealed with HPKE to the
  successor; devices, retired devices, floors and limits always, user keys of grants with
  `allow_successor`), log events `HandOver`, `Continue` and `Carry`, one chain across nodes
  in `ChainVerifier`, errors `HandedOver` and `HandOverInvalid`; `GrantTerms::allow_successor`
  (default on, absent from old signed terms) and `GrantTerms::without_successor`. CLI:
  `credentials hand-over --from-cid --to-cid --statement --bundle`, `credentials grant
  --no-successor`, `credentials verify --next <log>` (JSON `hand_overs`). Enclave: the
  release name compiled in (`CREDENTIALS_RELEASE` from `build/build.sh`, so it is part of the
  measurements) and the hand-over listener. Release workflow: the successor statement, its
  signature and verification, and a check of the compiled Sigstore trust root against
  Sigstore's TUF repository. The compiled trust root
  (`crates/continuity/trust/trusted_root.json`) is empty until it is committed, so every
  statement is refused until then.
- `client`: `verify_successor` and `regrant` with `SuccessorPolicy` (`Automatic`,
  `AskOwner`, `Never`) for a node whose predecessor is gone; `grant_without_successor`; key
  backup (`generate_backup_key`, `wrap_keys`, `unwrap_keys`, format
  `credentials-key-backup/v1`); 6-digit device transfer over SPAKE2 (`start_transfer`,
  `join_transfer`; RustCrypto `spake2` 0.5.0-pre.0, HMAC key confirmation, three wrong codes
  per code, five minutes); errors `successor_refused`, `transfer_refused`, `backup_refused`;
  UniFFI and wasm bindings and the web smoke test.
- Fuzz targets `sigstore_bundle`, `fulcio_certificate`, `successor_statement`,
  `handover_package`, `key_transfer`.

- Trusted code sandbox (`docs/design.md` section 11, part 7; `docs/sandbox.md`): the IR step
  `run {module, entry, inputs, into}` runs a WebAssembly module fetched from the
  destination's own origin (`{"url": ..., "sha256": ...}`, fetched as a logged `GET` over the
  operation's connection, pin checked) or a reviewed library compiled into the node
  (`{"library": "lenprefix8"}`). Its output may only go into a request the policy fixes to
  that origin; signing refuses `return`, the caller's request, another destination, a field,
  a second origin, and temporary values captured from a response to a request that carried
  it. New crate `sandbox` (wasmi 1.1.0, chosen over wasmtime 51 and wasmi 2.0.3 by
  measurement): fuel (10⁹), 64 MiB memory, 64 KiB output, four host functions, no WASI,
  clock or randomness. Errors `ModuleRefused` and `Sandbox`. Summaries list `runs` and a
  `module_input` form, and flag `run_unpinned`. Fuzz target `sandbox_module`. JavaScript:
  boa compiled to WebAssembly measured inside the sandbox; shipping plan in
  `docs/sandbox.md`.
- Operations that wait (`docs/design.md` section 11, part 5; `docs/policy.md`, Operations
  that wait): an `await` step parks an operation in the node's memory under a random id
  (at most 8 per owner, 256 and 128 MiB in all, five minutes, dropped on revoke and restart)
  and the caller gets `Output::Pending` (`challenge {id, challenge, hint, expires_ms}` or
  `approval_required {id, summary}`); it resumes with `Body::Resume {id}`, as the same
  caller on the same record and operation only.
  - Code challenges (`sms`, `email`, `app`, `3ds`): the owner's device answers with
    `DeviceKey::answer_challenge`, signed and sealed to the node (`engine::session`,
    `Node::answer`, `POST /answer`); the code becomes a secret temporary value and is never
    logged.
  - External challenges: the node polls a fixed status request of the policy when the caller
    resumes, no sooner than `every_ms`, and goes on, fails or keeps waiting by its
    conditions.
  - Approvals at run time: an operation with `"approval": true`, every use of a `card`, and a
    payment no spending limit covers or above one wait before anything is sent for an
    `Approval` over the node-built summary (`Node::approve`, `POST /approve`).
  - Payments and spending limits (section 8b): `"payment"` reads an amount only from a
    required, bounded query parameter or JSON input member, or the policy; owner-signed
    `SpendingLimits` (`engine::limits`, `DeviceKey::sign_limits`, `Node::set_limits`,
    `POST /limits`) per currency and merchant, per payment, rolling day and 30 days, counted
    under one lock and restored from sealed log entries.
  - Sessions: a secret field with `"session": {lifetime_ms, expires, renew}`; the node writes
    the expiry when it captures the session and, when it lapsed, runs the renewal operation
    first or refuses with `session_expired` (`renew: owner`), after which the device seals a
    new one with `Record::update`.
  - Log events `answer`, `approve`, `limits` and `spend`; errors `Pending`, `ParkedUnknown`,
    `ParkedFull` (HTTP 429), `ChallengeFailed`, `AnswerInvalid`, `SessionExpired`,
    `LimitsInvalid`.
  - `client` crate (UniFFI and wasm): `answer_challenge`, `sign_resume_call`, `sign_limits`,
    `update_record`; `approve` and `approval_hash` also take the pending reply.
  - Fuzz targets `decimal_amount` and `owner_waits`.
- Typed items (`docs/design.md` section 11, part 3): a policy may bind its record to a kind
  (`"item": {"kind": ..., "pins": {...}, "signoff": [...]}`), a schema of secret, masked
  and public fields with checks and a shape of what its policies may do. Twelve reviewed
  kinds ship in the node (`card`, `login`, `oauth`, `identity`, `totp`, `ssh`, `database`,
  `ftp`, `mail`, `queue`, `vpn`, `api`); custom kinds are signed by the owner's device
  (`DeviceKey::sign_kind`) and checked like policies. The node re-derives the shape on every
  signature check and refuses a wider policy. Checks: Luhn, expiry (by the node's clock on
  every use), security code length per IIN brand, exact origins, hosts, integers, lengths,
  patterns, lists, e-mail addresses, dates, base32 seeds of at least 128 bits, base64 keys,
  SSH host keys, and owner sign-offs for plain-text connections.
- `describe` (operation `:describe`, body `{"kind": "describe"}`): the public fields and
  the node-computed masked projections of a typed record, never a secret field; any listed
  caller, logged as a `describe` entry.
- `engine::policy::summarize(policy, previous)`: per secret, where it can go and in what
  form; per operation, requests, projections and inputs; risk flags (`outside_origin`,
  `wildcard`, `plain_http`, `plain_signoff`, `raw_input`, `derive_reversible`, `relay`,
  `relay_broad`, `response_all`, `query_any`, `encoded_percent`, `override_params`,
  `client_certificate`, `wider`, `new_destination`) and the diff against a previous version.
- `crates/engine/policy.schema.json` (`engine::policy::JSON_SCHEMA`): a JSON Schema (draft
  2020-12) of the policy IR, item bindings and kinds, tested against every policy of the
  README, its translations, `docs/policy.md`, the converted fixtures and the reviewed kinds.
- Approvals (`engine::approval`): the format of the node-built `ApprovalSummary`, its
  SHA-256, the owner device's `Approval` over it and its verification. Parking an operation
  until the approval arrives is part 5.
- `client` crate: `summarize`, `policy_json_schema`, `item_kinds`, `sign_kind`,
  `sign_describe_call`, `approval_hash`, `approve` (UniFFI and wasm); `seal_record` checks a
  typed record's values against its kind by the device's clock.
- Fuzz target `kind_schema`; `policy_json` also summarizes.

- `compute` steps: a template rendered into a name later steps read, with exactly the
  properties of its template in the analysis.
- Input schemas for operations with no connection: `raw` (length, pattern), `json` (closed:
  types, fixed values, allowed values, pattern, decimal bounds, members the node sets from its
  clock; duplicate keys refused, the checked value re-serialized) and `rlp` (closed,
  canonical, optional prefix, fixed and allowed items, integer bounds).
- `credentials policy upgrade OLD --out NEW`, and `upgrade_policy` in the `client` crate.
- Fuzz targets `policy_upgrade`, `caller_request` and `input_schema`.
- Template functions, the first group of the primitives of `docs/design.md` section 8d, each
  with its taint rule (`docs/policy.md`) and threat-model rows:
  - structure: `slice(value, start, length)`, `between(value, start, end)` (empty delimiters
    mean the ends), `add(a, b)` on signed 64-bit decimals, `json_set_number(object, key,
    integer)`, and the fixed-width integer encoders `u8`, `be64`, `le16`, `le32`, `le64` next
    to `be16` and `be32`; `random(n)`;
  - hashes and MACs: `md4`, `sha384`, `sha512_256`, `hmac_md5`, `hmac_sha384`, and
    `pbkdf2(hash, password, salt, rounds[, length])` for SHA-1, -256, -384 and -512
    (`pbkdf2_sha256` stays);
  - signatures: `rsa_sign_pkcs1(hash, key, msg)` (SHA-1, -256, -384, -512),
    `rsa_sign_pss(hash, key, msg)` (SHA-256, -384, -512), `p521_sign` (`rsa_sign_*_sha256`
    stay);
  - key agreement: `ecdh(curve, peer[, private])` and `ecdh_public(curve)` on P-256, P-384,
    P-521 and X25519, with one ephemeral key pair per curve and operation that never leaves
    the node, or a static private key from a field;
  - encryption: `chacha20_poly1305_encrypt`, AES-192 keys in `aes_gcm_encrypt`, and
    `rsa_encrypt_oaep(hash, public_key, msg)` / `rsa_encrypt_pkcs1(public_key, msg)`, whose
    public key may not be chosen by the caller.
- New analysis rules: a secret and a chosen value may not meet in `slice`, `between`, `add`
  or `json_set_number`; hash and curve names must be fixed by the policy; an RSA encryption
  key may not come from request variables or `$input`; every `ecdh` result is a secret that
  a plain hash does not clean.
- Template functions, the second group of section 8d, whole families, each with its taint
  rule (`docs/policy.md`), threat-model rows and an exfiltration test:
  - hashes: `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `shake128(msg, length)`,
    `shake256(msg, length)`;
  - KDFs over SHA-256, -384 and -512: `hkdf(hash, ikm, salt, info, length)`,
    `hkdf_expand(hash, prk, info, length)`, `concat_kdf(hash, z, other_info, length)`
    (SP 800-56A, as JOSE and COSE ECDH-ES use it), `kbkdf_counter(hash, key, fixed_input,
    length)` (SP 800-108 counter mode over HMAC);
  - Kerberos: `nfold(value, bits)` and `kerberos_dk(key, constant)` (RFC 3961);
  - AES modes and MACs: `aes_cbc_hmac_encrypt` (RFC 7518 5.2), `aes_ccm_encrypt` (any nonce
    length 7-13 and even tag 4-16), `aes_eax_encrypt`, `aes_cts_encrypt` (CBC-CS3, RFC 3962),
    `aes_cmac` (RFC 4493), `aes_cbc_mac`; key wrapping `aes_kw_wrap` (RFC 3394) and
    `aes_kwp_wrap` (RFC 5649);
  - signatures: `ed448_sign(key, msg[, context])`, `ecdsa_sign_prehash(curve, key, digest)`
    on P-256, P-384, P-521 and secp256k1, `dsa_sign` / `dsa_sign_der(hash, key, msg)`
    (RFC 6979 nonces);
  - key agreement: X448 in `ecdh` and `ecdh_public`;
  - CBOR in its deterministic form (RFC 8949 4.2.1): `cbor_int`, `cbor_bytes`, `cbor_text`,
    `cbor_array`, `cbor_map`, `cbor_tag`, enough for `COSE_Sign1`, `COSE_Mac0`,
    `COSE_Encrypt0` and their `Sig_structure`, `MAC_structure` and `Enc_structure`.
- New analysis rules: a key derived from a secret is a secret and not controlled (rule 8); no
  length argument may depend on a secret (rule 9); block-cipher MACs are one-way only under a
  secret key; in `cbor_map` a secret key may not meet a chosen key.
- Known-answer tests from FIPS 202, RFC 3394, 3610, 3961, 3962, 4493, 5649, 5869, 6979,
  7518, 7748, 8009, 8032, 8949, 9052, NIST SP 800-38A/B/C, NIST CAVP (KBKDF), Wycheproof
  (HKDF-SHA-384/512) and the EAX paper (`engine/src/vectors_families.rs`); the in-house CCM
  matches the `ccm` crate on every nonce and tag length.
- Dependencies: `aes-kw` 0.3, `cmac` 0.8, `eax` 0.6, `cts` 0.7, `shake` 0.1, `dsa` 0.7
  (`hazmat`, for signing), `ed448-goldilocks` 0.14.0-pre.15 and `x448` 0.14.0-pre.12
  (pre-releases, pinned exactly); `ccm` 0.6 for tests only.
- Capture sources `html` (one compound selector over the `html5gum` tokenizer; an attribute
  or the element's text) and `regex` (the `regex` crate, linear time, a chosen group), at most
  2 MiB read, 256-byte selectors and patterns; `regex` also reads stream bytes. Fuzz targets
  `html_capture` and `regex_capture`.
- Known-answer tests from RFC 1320, 2202, 4231, 6070, 6979, 7748, 7914, 8439, FIPS 180, the
  GCM specification, NIST CAVP (ECC CDH) and the PKCS #1 v2.1 vectors (`engine/src/vectors.rs`).
- Dependencies: `rsa` 0.10, `p521` 0.14, `md4` 0.11, `x25519-dalek` 3 (already in the tree
  through `hpke`), `regex` 1 (no Unicode tables), `html5gum` 0.9; the `ecdh` features of
  `p256` and `p384`.

- `client` crate: the app side for iOS, Android and the web, one Rust implementation over
  `engine` and `attest` with a string and bytes API: device, user and caller keys as base64url
  (`generate_key`, `import_key`, `public_key`); `nonce` and `verify_node` /
  `verify_attestation_reply`, which check the Nitro attestation and the identity binding and
  make the only `VerifiedNode`; `grant`, which takes a `VerifiedNode` verified within five
  minutes from a nonce used once; `revoke`, `endorse_device`, `retire_device`,
  `sign_policy`, `seal_record`, `rewrap_record`, `pin_record`, `sign_call`,
  `sign_derive_call`. One error type with stable codes. Swift and Kotlin bindings through
  UniFFI 0.32 (generated by the workspace binary `uniffibindgen`), JavaScript through
  wasm-bindgen (time from `Date.now()`, randomness from `crypto.getRandomValues`).
  `build/client.sh` builds the web package (with a Node smoke test), the Android libraries
  (arm64-v8a, x86_64) and an XCFramework (device and simulator); CI builds all three, and
  releases attach `client-wasm-<tag>.tgz`, `client-android-<tag>.zip` and
  `client-ios-<tag>.xcframework.zip` with a `client` SBOM. The threat model now covers grants
  from web pages and app key storage.
- AWS Nitro Enclaves. The `enclave` crate and program: a fresh node key at every boot (after
  checking that the kernel draws randomness from the NSM), the HTTP API of `credentials serve`
  on vsock, and `GET /attestation?nonce=` with an NSM attestation document whose `user_data`
  is `NodeIdentity::report_data()`. Egress and the log go through the parent instance:
  `credentials host` forwards HTTP to the enclave, relays `CONNECT host:port` tunnels (TLS
  stays in the enclave; optional `--allow` list) and writes one synced JSONL log per node key,
  confirming each entry only after `sync_data`.
- Reproducible enclave image: `build/build.sh` (static musl build in a Rust image pinned by
  digest, `SOURCE_DATE_EPOCH`, path remapping, `--locked`; `nitro-cli` from a pinned Amazon
  Linux image) writes `enclave.eif` and `measurements.json` (release, commit, PCR0/1/2, input
  digests); `build/reproduce.sh` builds twice and fails if the measurements differ. CI runs it
  on changes to the enclave and its build; releases attach `enclave.eif` and
  `measurements.json`, include them in `SHA256SUMS` and the provenance attestation, and print
  the measurements in the notes.
- `server` crate: the HTTP server of a node, shared by `credentials serve` and the enclave,
  over any connection (`Connection`), log sink (`Sink`) and transport, with `Hooks` for
  checkpoints and extra endpoints; the `relay` crate holds the vsock protocol between an
  enclave and its host.
- `transport`: `TlsTransport` runs over any byte stream a `Connector` opens (`TcpConnector` by
  default; `TlsTransport::connector`).

- `transport` crate: a TLS transport on rustls (ring provider, Mozilla roots, client
  certificates, connect/read/total deadlines, size limits, erasing buffers), tests against
  local TLS servers with fixed test certificates, and the `github_user` example.
- Sealed grants: a device signs the terms of a grant and seals them with the user key to the
  node (HPKE, RFC 9180). Nodes accept grants only from devices they know for the owner
  (first use trusted) and refuse replays. `NodeIdentity::report_data()` for TEE quotes.
- Signed revocations (`DeviceKey::revoke`).
- Pins in grants; records the owner never pinned are refused (`Error::RecordUnpinned`).
- Use details (host, path, body hash) in the log are sealed to the owner's user key;
  `log::open_detail` and `credentials verify --owner <owner> --user-key <file>` read them.
- `guessable` fields: derivations may not return a check for guesses of a PIN or password.
- P-384 signing with RustCrypto `p384` (erased on drop; raw 48-byte keys accepted).
- Documentation: README in English with diagrams, policy reference, threat model, security
  policy, contributing guide.
- CI: tests on Linux, macOS and Windows and on the MSRV (1.87), docs with warnings denied,
  `cargo deny check` with licenses, a reproducible-build check, fuzzing, caching and
  cancellation of superseded runs.
- `cli` crate: the `credentials` tool. `keygen`, `policy check|sign`, `seal`, `grant`, `revoke`,
  `device`, `pin`, `call`, `node identity`, and `serve`, which runs a node over HTTP with a
  durable JSONL log and a signed head.
- `credentials verify`: flags in any order, `--json` summary, `--help`, documented exit codes
  (0 valid, 1 invalid, 2 usage or I/O), `--head` checked against `--owner` files, and a clear
  message when an entry belongs to another owner. A first entry whose signature fails asks
  whether the key is the node's log key; checkpoint times are printed as RFC 3339 UTC next
  to milliseconds; with `--owner --head`, a checkpoint past the owner's last entry is warned
  about (`"owner_tail_unchecked"` in `--json`). `log::owner_entries` picks one owner's entries.
- `credentials`: documented exit codes (0 ok, 1 other, 2 usage, 3 refused by the node, 4 rate
  limited, 5 connection, transport, log or I/O failure); `policy check` takes a signed policy
  too (`--device <key>` checks its signature); a signed and an unsigned policy given in each
  other's place are named as such; `seal` names the field and rule a value breaks (`field
  `key` is empty`); `grant` without `--pin` warns that calls are refused until a record is
  pinned; a key file readable by others is warned about on Unix.
- `credentials serve`: connections are capped (`--max-connections`, 503 beyond), each request
  must arrive within 10 seconds, a body larger than `--max-body` (4 MiB by default) is refused
  before it is read, and reads of `/identity` and `/checkpoint` never wait behind acts. The
  checkpoint file is written only when the log grew.
- Signed calls in one value: `call::SignedCall`, `CallerKey::sign_call`, `Node::run` and
  `call::Output`; requests, responses and exchanges serialize to JSON.
- Policy builders in `build` (`Policy::new().with_field(..)`, `Operation::http(..)`, `Step`,
  `Exchange`, `Source`, `Capture`).
- `GrantTerms::new(owner, Duration)`, `GrantTerms::pin(&record)`, `node::now_ms()`;
  `UserKey::to_b64` / `from_b64`.
- Device retirement: `DeviceKey::retire`, `Node::retire_device`, `Event::Retire`.
- `Node::restore_anchored`: restart from a log and a checkpoint kept outside the operator's
  reach; a cut log is refused.
- Examples: `oauth_refresh`, `aws_sigv4`, `jwt_derive`, `imap_stream`, `node_restore`.
- Tests that the README quick start matches the example, and an end-to-end doctest.
- Fuzz targets (`template_parse`, `policy_json`, `log_entry`), run in CI.
- Release workflow: binaries for Linux, macOS and Windows, `SHA256SUMS`, CycloneDX SBOM and
  build provenance; Scorecard; Dependabot groups; CODEOWNERS; Code of Conduct; DCO sign-off.
- READMEs in Korean, Simplified Chinese and Japanese (`docs/i18n`).
- `attest` crate: verifies AWS Nitro Enclaves attestation documents (COSE_Sign1 with ES384,
  certificate chain to the pinned AWS Nitro Enclaves Root-G1 at the document's time, nonce,
  PCR0–2 against accepted `measurements.json` entries, debug enclaves refused) and binds them
  to `NodeIdentity::report_data()`. Tested on real documents of a production and a debug
  enclave.
- `credentials attest --document <file|-> --nonce <b64url> --measurements <file>
  [--identity <file>]` prints the verified release, PCRs and time; a refused document exits 3.
- `credentials grant --attestation <file> --nonce <b64url> --measurements <file>`: the grant is
  sealed only if the document verifies and vouches for the node identity. Without
  `--attestation`, `grant` warns.

### Changed

- Every use of a `card` item waits for the owner's approval (`"approval": true` in the kind's
  shape); the `login` kind has a public `session_expires` field. `Step::Await`,
  `Operation::payment`, `Operation::approval`, `FieldSpec::session` and `Shape::approval` are
  new members; `call::Output::Pending`, `call::Body::Resume`, `caller::Payload::Resume` are
  new variants. `Node::http`, `stream` and `derive` fail with `Error::Pending` where `run`
  returns the pending reply.
- `Policy` has an optional first member `item`; a policy without it signs and verifies as
  before. `call::Body::Describe`, `call::Output::Describe`, `caller::Payload::Describe`,
  `log::Event::Describe` and the errors `KindInvalid`, `KindSignature`, `FieldInvalid`,
  `ApprovalInvalid` and `NotAnItem` are new variants. `Record::seal` checks a typed record's
  values against its kind (without a clock); `Node` checks them with its clock on every use.
- **Policy format (breaking).** Operations are one step language over a connection instead of
  the kinds `http`, `stream` and `derive`: `open` (`https`, `tls`, or none), `send`,
  `receive`, `compute`, `return`; `repeat` and `if` are parsed and refused for now. The policy
  signing domain is `policy/v4`: every policy must be converted and **signed again**.
  `credentials policy upgrade` and `engine::policy::legacy::upgrade_json` convert the old
  format and print what they narrowed. In Rust, `Operation::https`, `Operation::tls`,
  `Operation::local` and `Operation::then` with `Send`, `Receive`, `Return` and
  `CallerRequest` replace `Operation::http`, `Operation::stream`, `Step` and `Exchange`.
- A caller's HTTPS request is checked against a contract on its `send`: methods, path
  templates matched exactly (`*`, `**`, whole-segment `{name}` placeholders) instead of path
  prefixes, headers, and query parameters with their values.
- An HTTPS operation returns the status and only the headers and JSON members its `return`
  lists (`"body": "all"` for the whole body); before, the whole response went back.
- A stream relays the caller's exchanges only when its `return` lists patterns their sends
  match whole; before, any exchange ran.
- An operation that reads `$input` declares an `input` schema; new error
  `Error::InputInvalid { rule }` (a caller error, HTTP 400 from the server).
- Policy errors that name a step use its index in `steps` (`operations[0].steps[2].capture[0]`)
  and path errors name the rule that failed (`path holds an encoded /, \ or .`).
- `crates/engine/src/vectors.rs` is formatted (the base branch failed `cargo fmt --check`).
- The render budget of 32 signatures per operation also counts key agreements.
- `crates/engine/src/primitives.rs` is stored with LF line endings, like every other file.

- `CHANGELOG.md` moved to `docs/`, `deny.toml` to `.github/` (`cargo deny --config .github/deny.toml check`).
- Fuzz targets moved from `fuzz/` to `crates/fuzz/`.
- Releases attach one CycloneDX SBOM per shipped artifact instead of one per crate:
  `credentials-<tag>.cdx.json` for the `credentials` binary (every target's dependencies) and
  `enclave-<tag>.cdx.json` for the enclave program (`x86_64-unknown-linux-musl`), both in
  `SHA256SUMS` and the provenance attestation.
- Crate layout: the vsock wire between an enclave and its host (ports, the `CONNECT` tunnel,
  the log protocol, `RelaySink`, vsock) moved from `server::relay` to the new `relay` crate,
  and `credentials host` to the new `host` library crate (`host::run`, its own error type);
  the `credentials` binary only parses the command line and keeps its exit codes. The JSONL
  log file and its checkpoint (`FileSink`, `HeadFile`, `head_path`) moved from the `cli`
  crate to `server::logfile`. `host` depends on neither `attest`, `verify` nor `cli`.
- Crate directories and package names are `engine`, `transport`, `verify` and `cli`. The log
  verifier is the `credentials verify` subcommand (the `verify` crate is its library); only the
  `credentials` binary ships. The packages are not published to crates.io.
- `credentials serve` runs on its own small HTTP/1.1 server instead of `tiny_http`.
- `Endorsement` carries the node and issue time (domain `endorse/v2`); `Event::Device` carries
  the issue time.
- Errors carry context: `FieldMissing { field }`, `DestinationDenied { host }`,
  `OperationUnknown { name }`, `CallerDenied { caller, operation }`, `MethodDenied { method }`,
  `PathDenied { path }`, `LogBehindAnchor { len, anchor }`, `SignatureInvalid`; policy errors
  name the unknown name. `Outcome` is `#[must_use]`.
- `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md` moved to `.github/`.
- `Node::grant` takes a `SealedGrant`; `Node::revoke` takes a `Revocation`.
- Log events: `Grant` carries the issue time and pins; `Revoke` carries the issue time and
  device; `Use`, `Stream` and `Derive` carry a `SealedDetail`.

### Security

- A secret can no longer set an output's length or a cut: `random(n)`, the length of
  `pbkdf2_sha256` and `pbkdf2`, the start and length of `slice`, the delimiters of `between`
  and the text `replace` looks for are refused when tainted, as the new key-derivation lengths
  are; before, `len(random(key))` returned a number taken from the secret.
- Closes the gaps of the policy audit; each has a regression test in
  `crates/engine/tests/audit_bounds.rs` that shows the attack refused before the log:
  - a caller could add query parameters to a signed request (another action for the same
    signature) and read whatever the server returned: query allow-list per name and value,
    and response projection;
  - a caller could send a query name the policy injects, first: refused;
  - `..;`, `%252e%252e` and `..%3b` passed the path check: segments are checked as sent,
    without `;` parameters, after one and two decodings, and `%25` is refused unless the
    contract allows it;
  - `_method` in the query or body could turn a POST into a DELETE: refused unless the
    contract allows it;
  - a caller could place a path parameter (a secret) in its own query: placeholders are whole
    segments of signed templates;
  - a derivation signed any input: input schemas;
  - a stream relayed any command after the login: relay patterns.
- `crates/transport/examples/aws_sigv4.rs` claimed the caller could only send
  `GET https://sts.amazonaws.com/`, but the caller could pick the action; the example now pins
  `Action` and `Version` and projects the response. `docs/threat-model.md` claimed dot
  segments and encoded separators were refused; `..;` and double encoding were not.
- Template analysis: encryption under a secret field hides only the key; a secret in its
  message, nonce or data stays tainted. Hashes and MACs of a secret no longer count as secret
  keys. A `guessable` field may reach a derivation output only through `len`.
- A node refuses grants, endorsements, retirements and caller signatures issued before it
  started, so a saved grant or call does not work again after a restart.
- The replay cache has a quota per caller (100,000 per window) and refuses times more than
  60 seconds ahead; one caller can no longer fill it for everyone.
- Endorsements name the node and the issue time; a retired device cannot add itself back.
- `Node::revoke` writes the log before it changes state.
- Policy JSON refuses unknown keys next to every tag, including variants without fields.
- The transport erases bytes read past a delimiter.
- A plain hash of a secret alone stays tainted (it equals the key of a long HMAC key or an
  Ed25519 seed); a secret and a chosen value may not meet across the number arguments of
  `time`, `totp` and `pbkdf2_sha256`.
- Once an owner has a device, a new device joins only through an endorsement; the user key
  alone no longer lets a retired device back in under a fresh key.
- A clock set back behind the node's start no longer re-opens what was signed before a
  restart.
- Grant, pin and generation errors are given only after the policy and the caller's
  signature verify; a call of the wrong kind spends no nonce or rate limit.
- The number of owners on a node is capped (`MAX_OWNERS`).

## Earlier

- Callers with per-call signatures, replay protection and rate limits; path prefixes and header
  allowlists; strict response parsing; reflection search over encodings; template taint and
  oracle analysis; render budgets; record generations and pins; per-owner log chains and
  signed checkpoints; restore and reconcile; a thread-safe node.
