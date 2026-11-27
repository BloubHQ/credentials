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
| Time | 5 s of wall clock per run, checked at every host call and after the run. A run is never paused to look at the clock (resuming a wasmi 1.1.0 call after it ran out of fuel is unsound, #95), so a stretch without a host call is bounded by fuel alone: 981,852,254 fuel of the JavaScript engine took 1.53 to 2.15 s on the measured host (8 release runs). |
| Memory | 64 MiB of linear memory, one memory, at most 16 tables. |
| Lower bounds | A signed policy may lower fuel, memory, time and the size of a script (`limits`), never raise them. |
| Structure | wasmi's strict limits: at most 10,000 functions, 1,000 globals, 100 tables, 1,000 element and data segments, 32 parameters and results, functions of 40 bytes on average once the code exceeds 1,000 bytes. |
| Proposals | Wasm 2.0 as compilers emit it by default (bulk memory, reference types, multi-value, sign extension, saturating conversions, mutable globals) and floats. Off: SIMD, memory64 (not compiled in), multi-memory, tail calls, extended constants, custom page sizes, wide arithmetic. |
| State | None: one engine, store and instance per run. The memory is erased before it is freed. |
| Errors | `ModuleTooLarge`, `ModuleInvalid`, `Import`, `NoMemory`, `Entry`, `Inputs`, `Fuel`, `Memory`, `Output`, `Time`, `Trap`, `Refused`, `Interpreter`: fixed messages, no byte of the module, its inputs or its memory. A panic inside wasmi is caught and comes back as `Interpreter`; a JavaScript source that is not UTF-8 is `Refused` before the engine runs. |

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

Unsafe code, the one exception: the guest crate `crates/sandbox/js` (compiled to WebAssembly, never linked into the host) uses `unsafe` only as syntax in `src/abi.rs`, an `unsafe extern` block declaring the four host imports as `safe fn` and `#[unsafe(no_mangle)]` on the `run` export; it dereferences no pointer. Every host crate keeps `unsafe_code = "forbid"`.

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

A site's signing script runs on the reviewed library module `js`: the
[boa](https://github.com/boa-dev/boa) engine 0.21.1 compiled to `wasm32-unknown-unknown`
(`crates/sandbox/js`), run by the sandbox like any other module, through the same four host
functions and under the same limits. The policy names the script (`docs/policy.md`, `run`): a
URL on the destination's own origin with its SHA-256 (required), fetched by the node, and the
function to call. `sandbox::run_script` passes the source as input 0, the function name as
input 1 and the step's inputs as the function's arguments (`Uint8Array`s, at most 14); what the
function returns (a `Uint8Array`, an `ArrayBuffer`, a string as UTF-8, or a promise of one)
is the output. An exception, a missing function or a value of another type is `Trap`.

What a script finds:

| | |
| --- | --- |
| Language | ECMAScript as boa 0.21 implements it: classes, closures, generators, `async`/`await` (pending jobs run until the returned promise settles), typed arrays, `DataView`, `BigInt`, `JSON`, `RegExp`, `Map`/`Set`, `Proxy`, `eval` (inside the same sandbox). No `Intl`. |
| Added by the prelude (`crates/sandbox/js/src/prelude.js`) | `TextEncoder`, `TextDecoder` (UTF-8, one U+FFFD per maximal invalid subpart), `atob`, `btoa`. |
| Taken away | `Date` and `Math.random` (deleted before the script runs; the engine's clock is fixed at 0 and the time zone offset is 0). A script gets the time and random bytes from its inputs (`{{ $unix }}`, `{{ $nonce }}`). |
| Not there | Any I/O: `fetch`, `XMLHttpRequest`, `WebSocket`, `require`, `import` (no module loader), timers, `console`, `WebAssembly`, `crypto`. The engine module imports nothing but the four host functions; `sandbox::check` refuses anything else. |

The engine module is checked in (`crates/sandbox/libraries/js.wasm`) and compiled into the
node (PCR2); the node hands it out only when its SHA-256 equals `sandbox::JS_SHA256`, and a
policy may pin it too (`{"library": "js", "sha256": ...}`). It is built from its locked
sources by `build/js-module.sh`: cargo dependencies only, no C compiler, paths remapped;
the CI job `js-module` builds it again on `windows-latest` and compares the bytes (the
bytes are a Windows host's: the file names compiled into the module keep the host's path
separator). Built twice here in two directories: the same bytes. The module's glue
(`crates/sandbox/js/src/abi.rs`) is the only place of the module's crate that needs
`unsafe` syntax: the `extern` block of the four imports (declared `safe`) and the exported
`run` (`no_mangle`); it dereferences no pointer.

`getrandom` (boa's dependency through `rand`) is built with its `unsupported` backend: it
fails if called, and its only caller, `Math.random`, is deleted.

### Choice of engine (measured)

Measured on 2026-11-27 on the development PC (Windows 11, x86_64), Rust 1.97.1, both modules
built `opt-level = "s"`, LTO, `panic = "abort"`, run by `crates/sandbox` built in release.
Each time is the median of 21 whole runs of `sandbox::run_with` (a new engine, compiling and
instantiating the module, running, erasing the memory), the script parsed in each run; the
test is `measure` in `crates/sandbox/tests/js.rs` (`cargo test --release -p sandbox --test js
-- --ignored --nocapture measure`, `JS_CANDIDATE=<path>` for another module). The scripts are
`crates/sandbox/tests/fixtures/hs256.js` (SHA-256, HMAC-SHA256 and HS256 JWT in plain
JavaScript) and a JSON parse-and-stringify loop. Both modules ran the same prelude.

| | boa 0.21.1 (chosen) | QuickJS-NG 0.16.2 (rquickjs 0.14.0) |
| --- | --- | --- |
| Module | 3,401,557 B | 812,453 B |
| `sandbox::check` (decode, validate) | 26.2 ms | 8.5 ms |
| Cold start (empty function) | 66.0 ms, 30.1 M fuel | 30.7 ms, 15.8 M fuel |
| One HMAC-SHA256 | 128.7 ms, 75.8 M fuel | 45.9 ms, 296.9 M fuel |
| One HS256 JWT | 163.2 ms, 93.3 M fuel | 53.5 ms, 414.4 M fuel |
| JSON transform × 1,000 | 783 ms, 441 M fuel | 227 ms, 325 M fuel |
| HMAC chain × 10 | 575 ms, 285 M fuel | over the fuel limit (10⁹) |
| HMAC chain × 40 | 2.03 s, 982 M fuel | over the fuel limit |
| Imports | the four host functions | the four, and `env.__rquickjs_host_now_us` (a clock), which had to be defined inside the module to pass the checks |
| Build | cargo only, no C compiler | clang for `wasm32`, and a prebuilt `libc.a` (2,670,504 B of wasi-libc) shipped inside `rquickjs-sys`; on Windows the crate's build script passes a `\\?\` include path clang cannot search, worked around by a second copy of the headers |
| Guest code | Rust | C |
| Licence | `Unlicense OR MIT` (boa); the module's other dependencies are in the allow list of `.github/deny.toml` but for `foldhash` 0.2.0 (`Zlib`, through hashbrown; `foldhash` 0.1.5, also `Zlib`, is already in the node's Cargo.lock) | MIT (QuickJS-NG, rquickjs); wasi-libc MIT and Apache-2.0 |

A second run of `measure` on the final module (SHA-256 `07caa809…`) gave the same fuel to
the unit and times of 68.6 ms (cold start), 132.6 ms (HMAC), 164.7 ms (JWT), 716 ms (JSON)
and 1.54 s (chain × 40): wall times vary by up to a quarter between runs, fuel does not. The
node's release binary (`credentials.exe`, `x86_64-pc-windows-msvc`) grew from 13,692,928 to
17,140,736 bytes (+3,447,808) with the engine module in it.

An HMAC chain of 1,000 iterations, as the plan asked, does not fit one run on either engine:
on boa each further HMAC costs about 23 M fuel (from the ×10 and ×40 runs), so 1,000 would
take about 2.3·10¹⁰ fuel, 23 times the cap (derived, not run). Within the cap boa runs about
40 HMACs, QuickJS about 3: wasmi charges QuickJS's code about 6.5 M fuel per millisecond
against boa's 0.6 M, so the fuel cap, which bounds work by WebAssembly instructions, admits
less of it.

Why boa: it runs as a guest with nothing but the sandbox's imports; it builds from its
locked sources with cargo alone, so the checked-in module is reproducible without a C
toolchain or a prebuilt library of unknown provenance; its fuel per unit of work is a
quarter of QuickJS's on the signing benchmark, so the node's fixed fuel cap admits four
times the signing work; and the guest is Rust. QuickJS is 2.8–3.5 times faster by the clock,
starts in half the time and is a quarter of the size; the size costs the node 3.4 MB instead
of 0.8 MB. Not measured: other engines (none written in Rust besides boa is complete enough
to run typical scripts), and `x86_64-unknown-linux-musl`, the enclave target.

What a script may not do in one run: about 13 HMAC-SHA256 computations in JavaScript, or a
few thousand JSON round trips. Heavier code needs `run` of a WebAssembly build, a browser fill
(`docs/design.md`, section 6) or case 1 of section 8e.

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
- **Engine bugs.** A flaw in boa lets a script corrupt or read the engine module's own
  memory, which holds only that run's inputs and output; it stays inside the WebAssembly
  sandbox, and the output stays confined to the script's origin, which wrote the script and
  receives the secret anyway. The fuzz target `sandbox_script` feeds arbitrary sources and
  arguments to `sandbox::run_script`.
- **Time limit.** The wall-clock bound depends on the machine: on a slow or loaded host a
  script that passes elsewhere may stop with `Time`. Fuel is the bound that does not.
