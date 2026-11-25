# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org);
before 1.0, minor versions may break formats and APIs.

## Unreleased

### Added

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
