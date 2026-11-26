# Fuzzing

Fuzz targets for the `engine` crate, run with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). This directory is its own Cargo workspace, not a member of the main one, because
it needs a nightly compiler.

| Target | Input | Checks |
| --- | --- | --- |
| `template_parse` | Bytes, read as lossy UTF-8 | `Template::parse`, then `names`, `vars`, `analyze`, `tainted` and `guessable` with every kind of name; a template that breaks a rule must count as tainted and guessable. |
| `policy_json` | JSON | `Policy` deserialization (the step language), `Policy::summary`, `policy::summarize` against itself and an empty policy, and `DeviceKey::sign_policy`, which checks every rule; bad policies must be refused with an error, never a panic. |
| `kind_schema` | A line of JSON, then a value | `KindSchema` deserialization and `validate`, `check_value` of the value on every field with and without a clock, `sign_kind`, then a policy binding the kind with the value as every pin and field: `validate`, `item::check_values`, `item::describe`, `summarize`; errors, never a panic. |
| `policy_upgrade` | JSON of the format before steps | `policy::legacy::upgrade_json`, then `summary` and `sign_policy` on the result; a conversion always has notes, and nothing panics. |
| `caller_request` | A byte choosing one of four fixed contracts (two with a JSON or form body contract), then the JSON of a `Request` | `Request::validate` and `Request::checked`, the caller contract (path templates, query rules, override names, injected names, body contracts); an accepted path holds no dot segment and no encoded `.`, `/` or ``; a body the node wrote again reads back to the same bytes and goes with the contract's content type. |
| `input_schema` | A byte choosing a JSON, RLP or raw schema, then the input | `Input::apply`; what a schema accepts it accepts again once checked. |
| `html_capture` | Bytes: a selector, an attribute choice and a page | `extract::html`, the `html` capture source: no panic on any selector or page, pages over `MAX_SCAN` refused, texts within `MAX_CAPTURE`. |
| `regex_capture` | Bytes: a pattern, a group and a text | `extract::regex`, the `regex` capture source: no panic on any pattern or text; a match is a part of the text. |
| `sandbox_module` | A byte choosing the reviewed library `lenprefix8` or a module that follows, then inputs split on 0xff | `sandbox::check` and `sandbox::run_with` (small fuel and memory) with two entry names: any module and inputs end in an output within `MAX_OUTPUT` and the fuel given, or a fixed error, never a panic; a module that runs passes the checks; the library frames inputs exactly. |
| `log_entry` | JSON | `SignedEntry` deserialization, `SignedEntry::hash`, `verify_chain` on a one-entry chain, and that `ChainVerifier` agrees with it. |
| `decimal_amount` | Bytes, read as lossy UTF-8; the first nine also as minor units and an exponent | `limits::scaled`, the decimal amounts of spending limits, `show`, `decimal` and `from_minor`: no panic; an accepted amount prints and reads back the same, and minor units scale exactly; `policy::read_amount` (body amounts, minor or decimal, JSON number or text) accepts only the spelling it prints back, within its bound. |
| `owner_waits` | JSON, then the bytes as a code | `SealedAnswer`, `Approval`, `SpendingLimits`, `Pending` and `SignedCall` (a resume) deserialization, and `Node::answer`, `approve`, `set_limits` and `run` on a node with nothing waiting and no grant; `DeviceKey::answer_challenge` of the bytes; errors, never a panic. |
| `owner_controls` | JSON, also as an expiry | `DelegationRequest` and `DelegationChange` deserialization, `Delegation::validate`, `Node::delegate` and `change_delegation` on a node with no grant and no device (both refused), `delegation::check_narrower` of a valid policy against itself, and `policy::vend::parse_time` / `parse_rfc3339` in every format: errors, never a panic; a `seconds` expiry never ends before now. |
| `sigstore_bundle` | JSON | `continuity::sigstore::Bundle` deserialization and `verify` against a trust root whose keys are not keys: every parser of the bundle (protobuf-JSON integers, base64, the certificate) runs, and nothing verifies. |
| `fulcio_certificate` | DER, read also as a log entry body and as UTF-8 | The minimal DER and X.509 reader of the continuity crate (extensions, subject alternative names, the Fulcio OIDs, duplicates refused), the `hashedrekord` body check, and the checkpoint (signed note) reader; errors, never a panic. |
| `successor_statement` | JSON, a release name, and 16 bytes of index and size then 32-byte hashes | `Statement::from_json` (a statement that reads is never a downgrade), `SignedStatement` and `TrustRoot` deserialization, `release::Version` order, and the RFC 6962 inclusion proof check on the hashes. |
| `handover_package` | JSON, also as a length-framed message | The frames of the hand-over protocol (`continuity::wire`), `HandOver` deserialization, and `Node::take_over` on a fresh node, which must refuse a package not sealed to it and log nothing. |
| `key_transfer` | UTF-8 | `client::unwrap_keys` with a fixed backup key, a transfer offer and a sealed transfer with a fixed code, and an answer to a real offer: none opens, nothing panics. |
| `cdp_message` | Bytes: one CDP message from a browser, also as lossy UTF-8 | `engine::cdp::parse`, then every typed reader of a browser fill on its result (`frame_tree`, `targets`, `session_id`, `context_id`, `remote`, `navigated`), and `WebOrigin::parse` / `of_url`: no panic; a frame tree that reads is bounded and lists each frame after its parent, a target list is bounded, an origin serializes to what reads back the same. |
| `protocol_servers` | A byte choosing one of 12 cases and the size of the pieces, then a server's bytes | Each protocol client (SSH, PostgreSQL, MySQL, SMTP, IMAP, Redis, MQTT 3.1.1 and 5, AMQP) against those bytes as its server, and the parsers of SSH keys, `KEXINIT`, SCRAM, the MySQL greeting and SFTP paths: no panic; no SSH sign-in without the pinned key, no PostgreSQL sign-in without the SCRAM proof, no MQTT message on a topic not subscribed to, no AMQP bodies past the limit. |

The HTTP response parser in `crates/engine/src/response.rs` is not public, so it has no
target here.

## Running

Install a nightly toolchain and cargo-fuzz once:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
```

Then, from the repository root:

```sh
cargo +nightly fuzz list --fuzz-dir crates/fuzz
cargo +nightly fuzz run --fuzz-dir crates/fuzz template_parse                          # until stopped or a crash
cargo +nightly fuzz run --fuzz-dir crates/fuzz policy_json -- -max_total_time=60      # for 60 seconds
```

CI runs every target for 60 seconds on each push to `main` and each pull request, and keeps
crashing inputs as the `fuzz-artifacts` artifact of a failed run.

A crash is written to `crates/fuzz/artifacts/<target>/`. Reproduce it with

```sh
cargo +nightly fuzz run --fuzz-dir crates/fuzz <target> crates/fuzz/artifacts/<target>/<crash-file>
```

and turn it into a regular test in the engine before fixing it. The corpus grows in
`corpus/<target>/`; neither directory is committed. libFuzzer needs Linux or macOS (on
Windows use WSL). `cargo check --manifest-path crates/fuzz/Cargo.toml` type-checks the targets on
stable.
