# Fuzzing

Fuzz targets for the `engine` crate, run with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). This directory is its own Cargo workspace, not a member of the main one, because
it needs a nightly compiler.

| Target | Input | Checks |
| --- | --- | --- |
| `template_parse` | Bytes, read as lossy UTF-8 | `Template::parse`, then `names`, `vars`, `analyze`, `tainted` and `guessable` with every kind of name; a template that breaks a rule must count as tainted and guessable. |
| `policy_json` | JSON | `Policy` deserialization, `Policy::summary`, and `DeviceKey::sign_policy`, which checks every rule; bad policies must be refused with an error, never a panic. |
| `log_entry` | JSON | `SignedEntry` deserialization, `SignedEntry::hash`, `verify_chain` on a one-entry chain, and that `ChainVerifier` agrees with it. |

The HTTP response parser in `crates/engine/src/response.rs` is not public, so it has no
target here.

## Running

Install a nightly toolchain and cargo-fuzz once:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
```

Then, from the repository root or this directory:

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run template_parse                          # until stopped or a crash
cargo +nightly fuzz run policy_json -- -max_total_time=60      # for 60 seconds
```

CI runs every target for 60 seconds on each push to `main` and each pull request, and keeps
crashing inputs as the `fuzz-artifacts` artifact of a failed run.

A crash is written to `artifacts/<target>/`. Reproduce it with

```sh
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```

and turn it into a regular test in the engine before fixing it. The corpus grows in
`corpus/<target>/`; neither directory is committed. libFuzzer needs Linux or macOS (on
Windows use WSL). `cargo check --manifest-path crates/fuzz/Cargo.toml` type-checks the targets on
stable.
