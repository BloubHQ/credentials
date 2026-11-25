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
  `log::open_detail` and `verify --owner <owner> --user-key <file>` read them.
- `guessable` fields: derivations may not return a check for guesses of a PIN or password.
- P-384 signing with RustCrypto `p384` (erased on drop; raw 48-byte keys accepted).
- Documentation: README in English with diagrams, policy reference, threat model, security
  policy, contributing guide.
- CI: tests on Linux, macOS and Windows, docs with warnings denied, `cargo deny check` with
  licenses, reproducible-build check.

### Changed

- `Node::grant` takes a `SealedGrant`; `Node::revoke` takes a `Revocation`.
- Log events: `Grant` carries the issue time and pins; `Revoke` carries the issue time and
  device; `Use`, `Stream` and `Derive` carry a `SealedDetail`.

## Earlier

- Callers with per-call signatures, replay protection and rate limits; path prefixes and header
  allowlists; strict response parsing; reflection search over encodings; template taint and
  oracle analysis; render budgets; record generations and pins; per-owner log chains and
  signed checkpoints; restore and reconcile; a thread-safe node.
