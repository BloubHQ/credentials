# Contributing

Thank you for helping. Security issues go to [SECURITY.md](SECURITY.md), not to issues.

## Before you start

For anything larger than a fix, open an issue first and describe the problem. New kinds of
credential should almost always be **policy data**, not code: if a credential needs a new
primitive (a hash, a signature scheme), add that primitive to the template language and show
the policy that uses it.

## Building and checking

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

CI also runs on macOS and Windows, builds with the minimum Rust version (1.87), runs
`cargo audit` and `cargo deny check`, and checks that two builds are identical.

## Rules of the code

- No `unsafe`. No `unwrap`, `expect`, `panic!` or indexing in library code (the lints deny
  them); tests may allow them.
- Errors in the engine are `thiserror` enums and never carry a secret.
- A secret lives in `Secret` or `Zeroizing`. Buffers that hold one are sized before they are
  filled, so no reallocation frees an unerased copy.
- Every limit is a named constant with a test at its edge.
- Code, comments and messages are in English.
- A fix for a bug comes with a test that fails without it. A change made for speed or memory
  comes with measured numbers before and after.

## Pull requests

Keep them focused, describe what changes and why, and say how you tested it. By contributing
you agree that your contribution is licensed under the Apache License 2.0.

## Sign-off

Every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org): by adding the line

```text
Signed-off-by: Your Name <you@example.com>
```

you certify that you wrote the change or otherwise have the right to submit it under the
project's license. `git commit -s` adds the line for you, using your `user.name` and
`user.email`; `git commit --amend -s` or `git rebase --signoff main` adds it to commits you
already made.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
