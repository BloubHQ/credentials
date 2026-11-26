#!/usr/bin/env bash
# Builds the reviewed JavaScript library module (crates/sandbox/js) for wasm32-unknown-unknown
# and writes it to crates/sandbox/libraries/js.wasm, or with --check compares the build with
# the file checked in and fails when they differ.
#
# Every input is fixed: the Rust of rust-toolchain.toml with its wasm32-unknown-unknown
# standard library, crates/sandbox/js/Cargo.lock (--locked), the release profile of the
# module's Cargo.toml, and the paths compiled into the module (remapped below, so the
# directory of the checkout and of cargo do not matter). The module has no C code, so no C
# compiler is involved. The bytes are those of a build on Windows (x86_64-pc-windows-msvc
# host): file names inside the module keep the host's path separator, so CI checks on
# windows-latest (.github/workflows/ci.yml, job js-module).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
crate="$root/crates/sandbox/js"
out="$root/crates/sandbox/libraries/js.wasm"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# The native form of a path: on Windows (Git Bash, MSYS) rustc sees C:/... paths.
native() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

export CARGO_TARGET_DIR="$crate/target"
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH=0
# getrandom (a dependency of boa through rand) has no source of randomness on this target;
# the `unsupported` backend makes it fail if called. The module never calls it: the prelude
# deletes Math.random, its only user.
export RUSTFLAGS="--cfg getrandom_backend=\"unsupported\" --remap-path-prefix=$(native "$crate")=/js --remap-path-prefix=$(native "$cargo_home")=/cargo"

(cd "$crate" && cargo build --release --locked --target wasm32-unknown-unknown)
built="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/js_module.wasm"

if [ "${1:-}" = "--check" ]; then
  sha256sum "$built" "$out"
  cmp "$built" "$out"
else
  cp "$built" "$out"
  sha256sum "$out"
fi
