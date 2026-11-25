# The trusted code sandbox

Layer 3 of `docs/design.md` (sections 2 and 8e; part 7 of section 11): code that must compute
on secret bytes runs in a WebAssembly sandbox inside the node, only when the code comes from
the destination's own origin (URL and optional SHA-256 in the signed policy) or from a
reviewed library compiled into the node, and its output reaches only that origin. The IR step
is `run` (`docs/policy.md`, `run`); the crate is `crates/sandbox`.

## What a module gets

| | |
| --- | --- |
| Imports | At most `input_count`, `input_len`, `input_read`, `output` of the module `credentials`. Anything else (WASI, a clock, randomness, an imported memory, table or global) is refused before the module runs. |
| Exports | `memory`, and the entry, a function `() -> ()`. |
| Inputs | At most 16, 1 MiB together: the rendered templates of the step. |
| Output | At most 64 KiB, in one or more `output` calls. |
| Fuel | 10⁹ units per run (wasmi's units, plus one per 64 bytes a host function copies). |
| Memory | 64 MiB of linear memory, one memory, at most 16 tables. |
| Structure | wasmi's strict limits: at most 10,000 functions, 1,000 globals, 100 tables, 1,000 element and data segments, 32 parameters and results, functions of 40 bytes on average once the code exceeds 1,000 bytes. |
| Proposals | Wasm 2.0 as compilers emit it by default (bulk memory, reference types, multi-value, sign extension, saturating conversions, mutable globals) and floats. Off: SIMD, memory64 (not compiled in), multi-memory, tail calls, extended constants, custom page sizes, wide arithmetic. |
| State | None: one engine, store and instance per run. The memory is erased before it is freed. |
| Errors | `ModuleTooLarge`, `ModuleInvalid`, `Import`, `NoMemory`, `Entry`, `Inputs`, `Fuel`, `Memory`, `Output`, `Trap`: fixed messages, no byte of the module, its inputs or its memory. |

Determinism: nothing a module can reach varies between runs, so it gives the same output for
the same inputs. Float NaNs keep the bits the CPU gives (wasmi 1.x has no NaN
canonicalisation); every node of a release runs on x86_64, so they are the same on every node
of a release. A test (`floats_are_deterministic`) checks one NaN twice.

## Choice of runtime (measured)

Measured on 2026-11-25/26 on the development PC (Windows 11, x86_64,
`x86_64-pc-windows-msvc`), Rust 1.97.1, release profile of the workspace (`lto = true`,
`codegen-units = 1`, `opt-level = 3`). **Not measured on `x86_64-unknown-linux-musl`**, the
enclave target: its standard library is not installed here and installing it is a
download. Sizes are of a stand-alone program that reads a module and runs it with the three
host functions above; "added" is against the same program without a runtime (142,848 bytes).

The CPU-bound module is SHA-256 (the `sha2` crate, `no_std`) of 1 MiB of input, compiled
for `wasm32-unknown-unknown` (10,220 bytes). Times are the median of 21 runs; compile +
instantiate is `Module::new` plus instantiation.

| Runtime | Added size | Compile + instantiate | SHA-256 of 1 MiB | Fuel | Notes |
| --- | --- | --- | --- | --- | --- |
| wasmtime 51.0.0, Cranelift | 11,463,168 B | 13.87 ms | 3.95 ms | 82,093,435 | Generates machine code at run time (JIT). |
| wasmi 2.0.3, tail-call dispatch | 1,435,136 B | 341 µs | 50.6 ms | 81,154,704 | Relies on the optimiser turning handler calls into jumps; without it the native stack grows per instruction (seen: a stack overflow in a test build). |
| wasmi 2.0.3, `portable-dispatch` | 1,440,768 B | 320 µs | 265.9 ms | 81,154,704 | **Crashed with an access violation** (exit `0xC0000005`) whenever wasmi was built at `opt-level` 2 or 3 and the program calling it at 0 (the workspace's test profile), in a host-function call; release builds ran. |
| **wasmi 1.1.0** (chosen) | **1,256,960 B** | **607–636 µs** | **136.7–137.8 ms** | 38,799,144 | Same mixed build: no crash. Validation always on. |

Through the `sandbox` crate itself (wasmi 1.1.0, release, same PC):

| Run | Median |
| --- | --- |
| SHA-256 of 1 MiB, whole `sandbox::run` (engine, compile, instantiate, run, erase) | 125.7 ms, 38,815,530 fuel |
| SHA-256 of 64 bytes, whole `sandbox::run` | 0.665 ms, 70,758 fuel |
| An infinite loop, until the fuel limit (10⁹) | 1.254 s, `Error::Fuel` |

Why wasmi 1.1.0:

- **No JIT**: an interpreter is plain Rust over a bytecode; no executable memory is written
  at run time, and there is no code generator to audit (Cranelift is most of wasmtime's
  11.5 MB). wasmtime is 29–35 times faster on the CPU-bound module, but the code this sandbox
  runs (packaging a password, a key exchange) is small; 137 ms for 1 MiB of SHA-256 is enough.
- **Size**: 1.26 MB added to the node instead of 11.46 MB.
- **Memory safety observed**: wasmi 2.0.3 crashed in a build configuration the workspace
  uses for its tests; the cause is in its `unsafe` executor (not investigated further). A
  runtime whose safety depends on the optimisation level is the wrong base for code that
  handles secrets. wasmi 1.1.0 passed the same build.
- **Limits**: fuel metering, a resource limiter for memory and tables, structural limits for
  untrusted modules, and traps for every failure.

Unsafe code: the `sandbox` crate has none (`unsafe_code = "forbid"`). Its runtime
dependencies do (files with `unsafe` in `src`, counted in the crates as published): `wasmi`
1.1.0 (27: the executor, its value stack, linear memory), `wasmi_core` (2), `wasmi_ir` (1),
`wasmi_collections` (3), `wasmparser` 0.239.0 (1), `spin` (7), `libm` (9), `bitflags` (1).
Licences: the four `wasmi` crates `MIT/Apache-2.0`, `wasmparser` `Apache-2.0 WITH
LLVM-exception OR Apache-2.0 OR MIT`, `spin` and `libm` `MIT`, `bitflags` `MIT OR
Apache-2.0`: all within `.github/deny.toml`'s allow list (`cargo deny` itself is not
installed here, so the check was read, not run). `wat` and `wast` (tests only) are `Apache-2.0 WITH
LLVM-exception OR Apache-2.0 OR MIT`.

## JavaScript

Measured: [boa](https://github.com/boa-dev/boa) 0.21.1 (`boa_engine`, no default features),
a JavaScript engine written in Rust, compiles for `wasm32-unknown-unknown` with cargo
dependencies only (no C toolchain) and runs **inside this sandbox unchanged**: the module
passes `sandbox::check` (the strict structural limits included) and imports only the host
functions.

The experiment (not in the repository, since a module's glue calls its imports through
`unsafe extern` blocks): a `cdylib` whose `run` reads input 0 as a script and inputs 1.. into
a global array `inputs`, evaluates the script and writes the completion value as a string.
`getrandom` 0.3 (used by boa for `Math.random` and hash seeds) was built with
`--cfg getrandom_backend="custom"` and a function that writes zeros, so the module has no
randomness of its own. Release, `opt-level = "s"`, LTO:

| | |
| --- | --- |
| Module | 3,983,657 bytes (under the 8 MiB limit) |
| `inputs[0] + ':' + inputs[1]` | 37.5 ms, 4,924,619 fuel (most of it creating the engine) |
| XOR of a 4-byte string, char by char | 43.5 ms, 6,068,311 fuel |
| A loop of 100,000 integer steps | 905 ms, 743,260,775 fuel |

So a site's login script of a few thousand operations fits the fuel limit; a script with
heavy loops does not and needs `run` of a WebAssembly build, a browser fill (section 6), or
case 1 of section 8e (expressing the steps as an IR policy).

What is missing before a JavaScript library ships in the node:

1. A reproducible build of the module inside the enclave image build
   (`build/Dockerfile.enclave`): the `wasm32-unknown-unknown` standard library in the pinned
   Rust image (today a `rustup target add`, a download the build must pin by digest), and the
   module's crate with its own `Cargo.lock`; the node then embeds its bytes like
   `lenprefix8`, so the JavaScript engine is part of PCR2.
2. The browser APIs the policy lists, emulated in the module (`crypto.subtle` over node
   primitives as host functions by name, `TextEncoder`, `atob`/`btoa`), and `Math.random` and
   `crypto.getRandomValues` from an input the node fills with random bytes.
3. A step form that names the script: a URL on the origin, pinned like a module, passed as
   input 0, with the same confinement of the output.
4. Its own fuzz target and review, and a decision on the engine (boa, or QuickJS compiled to
   WebAssembly, which needs a C toolchain for `wasm32`: clang is not installed on this PC, so
   QuickJS was not built or measured).

## Residual risks

- **Timing and failure.** Whether a module succeeds, runs out of fuel or traps, and how long
  it takes, can depend on the secret; the caller sees the outcome and the time of the call.
  The code is the site's own (or reviewed), and the site already holds the secret, so this
  is a channel only for a site that wants to leak its own users' passwords to a caller; it is
  accepted.
- **Unpinned modules.** Without `sha256`, whoever controls the origin's content (the site,
  or anyone who can change the file it serves) chooses the code. The owner's summary flags it
  (`run_unpinned`). The output still goes only to that origin.
- **An origin that echoes in another form.** The output is searched for in responses as is;
  a site that sends it back transformed (base64, reversed) is not recognised. What the
  response to such a request gives into temporary values is confined like the output itself,
  but a capture into a secret field is allowed (session tokens arrive that way) and that
  field is then analysed like any secret field.
- **Runtime bugs.** A flaw in wasmi's validator or executor could let a module out of the
  sandbox into the node's process. Pins narrow who can supply a module; the fuzz target
  `sandbox_module` feeds arbitrary modules and inputs to `sandbox::run`.
