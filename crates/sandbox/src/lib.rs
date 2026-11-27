//! The trusted code sandbox of the credentials node (layer 3 of `docs/design.md`).
//!
//! [`run`] executes one exported function of a WebAssembly module on byte inputs and returns
//! the bytes it wrote. The module gets nothing else: no WASI, no clock, no randomness, no
//! I/O, no other module, no state from an earlier run. It may import only these functions of
//! the module `credentials`:
//!
//! | Import | Type | Effect |
//! | --- | --- | --- |
//! | `input_count` | `() -> i32` | The number of inputs. |
//! | `input_len` | `(index: i32) -> i32` | The length of an input, or `-1` when there is none. |
//! | `input_read` | `(index: i32, ptr: i32)` | Copies the whole input to `ptr` in the exported memory. |
//! | `output` | `(ptr: i32, len: i32)` | Appends `len` bytes at `ptr` to the output. |
//!
//! The module exports its memory as `memory` and the entry as a function `() -> ()`. A
//! module that imports anything else or breaks the structural limits of
//! [`wasmi::EnforcedLimits::strict`] is refused before it runs. A start function, if the
//! module has one, runs first under the same limits.
//!
//! The runtime is [wasmi](https://github.com/wasmi-labs/wasmi), an interpreter: no code is
//! generated at run time. Nothing a module can reach varies between runs (no clock, no
//! randomness, no host state), so a module gives the same output for the same inputs on every
//! node of a release. Execution costs fuel (wasmi's units, plus one per 64 bytes a host
//! function copies) and stops at [`MAX_FUEL`]; the memory stops at [`MAX_MEMORY`]; the wall
//! clock stops it at [`MAX_TIME`] (checked at every host call and after the run). Every
//! failure is a fixed [`Error`]: nothing the module computes reaches an error message. The
//! memory is erased before it is freed.
//!
//! [`run_script`] runs a JavaScript source on the reviewed library module [`JS`] (the boa
//! engine compiled to WebAssembly, `crates/sandbox/js`), through the same ABI.
//!
//! The choice of runtime and of the JavaScript engine, with their measurements, is in
//! `docs/sandbox.md`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use wasmi::errors::{ErrorKind, InstantiationError};
use wasmi::{
    Caller, CompilationMode, Config, EnforcedLimits, Engine, Extern, ExternType, Linker, Module,
    Store, StoreLimits, StoreLimitsBuilder, TrapCode,
};
use zeroize::{Zeroize, Zeroizing};

mod libraries;

pub use libraries::{JS, JS_SHA256, LIBRARIES, library, library_sha256};

/// The module name of the host functions.
pub const HOST: &str = "credentials";
/// The host functions a module may import.
pub const IMPORTS: [&str; 4] = ["input_count", "input_len", "input_read", "output"];
/// Largest module accepted, in bytes.
pub const MAX_MODULE: usize = 8 * 1024 * 1024;
/// Most inputs of one run.
pub const MAX_INPUTS: usize = 16;
/// Most bytes of all inputs of one run together.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
/// Largest output, in bytes.
pub const MAX_OUTPUT: usize = 64 * 1024;
/// Most fuel of one run: 1.25 s of the interpreter on the measured host (`docs/sandbox.md`).
pub const MAX_FUEL: u64 = 1_000_000_000;
/// Most linear memory of one run, in bytes.
pub const MAX_MEMORY: usize = 64 * 1024 * 1024;
/// Longest entry name.
pub const MAX_ENTRY: usize = 64;
/// Longest run by the wall clock, checked at every host call and after the run. A stretch
/// without a host call is bounded by fuel alone, the bound that does not depend on the machine.
/// The run is never paused and resumed to look at the clock: resuming a wasmi 1.1.0 call after
/// it ran out of fuel can land on an instruction parameter, which is undefined behaviour in a
/// release build (#95).
pub const MAX_TIME: Duration = Duration::from_secs(5);
/// Largest JavaScript source of [`run_script`], in bytes.
pub const MAX_SCRIPT: usize = 256 * 1024;
/// Most arguments of a JavaScript function: the inputs left after the source and the name.
pub const MAX_SCRIPT_ARGS: usize = MAX_INPUTS - 2;

/// Bytes copied by a host function per unit of fuel.
const COPY_PER_FUEL: usize = 64;

/// Why a run failed. Every message is fixed: no byte of the module, its inputs or its memory
/// appears in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The module is larger than [`MAX_MODULE`].
    #[error("module larger than the limit")]
    ModuleTooLarge,
    /// The module does not decode or validate, or breaks a structural limit (functions,
    /// globals, tables, segments, parameters).
    #[error("module invalid")]
    ModuleInvalid,
    /// The module imports something other than the host functions.
    #[error("module imports something the sandbox does not provide")]
    Import,
    /// The module exports no memory named `memory`.
    #[error("module exports no memory")]
    NoMemory,
    /// The entry is not an exported function `() -> ()`, or its name is not a token.
    #[error("entry missing or not a function () -> ()")]
    Entry,
    /// More than [`MAX_INPUTS`] inputs, or more than [`MAX_INPUT_BYTES`] in all.
    #[error("inputs over the limits")]
    Inputs,
    /// The run used its fuel.
    #[error("module ran out of fuel")]
    Fuel,
    /// The module asked for more memory than its limit.
    #[error("module reached the memory limit")]
    Memory,
    /// The output grew past [`MAX_OUTPUT`].
    #[error("output larger than the limit")]
    Output,
    /// The run took longer than its time limit.
    #[error("module ran out of time")]
    Time,
    /// A JavaScript source larger than its limit or not UTF-8, or a library module whose bytes
    /// do not match the hash compiled into the node.
    #[error("script or library refused")]
    Refused,
    /// The module trapped (unreachable, out of bounds, division by zero, stack overflow, a bad
    /// call to a host function).
    #[error("module trapped")]
    Trap,
    /// The interpreter itself failed (a panic inside wasmi, caught): the run is abandoned and
    /// its memory wiped.
    #[error("the interpreter failed")]
    Interpreter,
}

/// The limits of one run. [`Limits::default`] is the most a node allows; a signed policy may
/// set lower ones, never higher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Fuel, at most [`MAX_FUEL`].
    pub fuel: u64,
    /// Linear memory in bytes, at most [`MAX_MEMORY`].
    pub memory: usize,
    /// Wall-clock time, at most [`MAX_TIME`].
    pub time: Duration,
    /// For [`run_script`]: the largest source, at most [`MAX_SCRIPT`].
    pub script: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel: MAX_FUEL,
            memory: MAX_MEMORY,
            time: MAX_TIME,
            script: MAX_SCRIPT,
        }
    }
}

/// What a run gave back.
#[derive(Debug)]
pub struct Ran {
    /// The bytes the module wrote, erased when dropped.
    pub output: Zeroizing<Vec<u8>>,
    /// The fuel it used.
    pub fuel: u64,
}

struct Host {
    inputs: Vec<Zeroizing<Vec<u8>>>,
    output: Zeroizing<Vec<u8>>,
    limits: StoreLimits,
    /// A failure a host function saw, reported instead of the trap it causes.
    fault: Option<Error>,
    /// When the run must have ended by the wall clock.
    deadline: Instant,
    /// The module's memory, once the instance or a host function has seen it. The handle
    /// stays valid in the store after an instance is lost to a failed start function.
    memory: Option<wasmi::Memory>,
}

fn config() -> Config {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .compilation_mode(CompilationMode::LazyTranslation)
        .enforced_limits(EnforcedLimits::strict())
        // Proposals beyond what compilers emit by default stay off: less to audit.
        .wasm_multi_memory(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_custom_page_sizes(false)
        .wasm_wide_arithmetic(false);
    config
}

fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ENTRY
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Checks a module without running it: size, decoding, validation, structural limits, imports
/// and the exported memory. A node runs this on a fetched module before [`run`] does the same.
pub fn check(module: &[u8]) -> Result<(), Error> {
    compile(&Engine::new(&config()), module).map(|_| ())
}

/// Tests only: the import of [`tests::PANIC`] is linked too.
#[cfg(test)]
fn test_import(module: &str, name: &str) -> bool {
    (module, name) == tests::PANIC
}

#[cfg(not(test))]
fn test_import(_module: &str, _name: &str) -> bool {
    false
}

fn compile(engine: &Engine, bytes: &[u8]) -> Result<Module, Error> {
    if bytes.len() > MAX_MODULE {
        return Err(Error::ModuleTooLarge);
    }
    let module = Module::new(engine, bytes).map_err(|_| Error::ModuleInvalid)?;
    let imports_ok = module.imports().all(|import| {
        let named = (import.module() == HOST && IMPORTS.contains(&import.name()))
            || test_import(import.module(), import.name());
        named && matches!(import.ty(), ExternType::Func(_))
    });
    if !imports_ok {
        return Err(Error::Import);
    }
    let memory = module
        .exports()
        .any(|export| export.name() == "memory" && matches!(export.ty(), ExternType::Memory(_)));
    if !memory {
        return Err(Error::NoMemory);
    }
    Ok(module)
}

/// Runs `entry` of `module` on `inputs` under the node's limits ([`Limits::default`]).
pub fn run(module: &[u8], entry: &str, inputs: &[&[u8]]) -> Result<Ran, Error> {
    run_with(module, entry, inputs, Limits::default())
}

/// Runs `entry` of `module` on `inputs` under `limits` (each capped at the node's).
pub fn run_with(
    module: &[u8],
    entry: &str,
    inputs: &[&[u8]],
    limits: Limits,
) -> Result<Ran, Error> {
    run_observed(module, entry, inputs, limits, &mut |_| {})
}

/// [`run_with`], showing `observe` the module's memory as it is left after the wipe: `None`
/// when the run never had one. The tests check through it that every path wipes.
fn run_observed(
    module: &[u8],
    entry: &str,
    inputs: &[&[u8]],
    limits: Limits,
    observe: &mut dyn FnMut(Option<&[u8]>),
) -> Result<Ran, Error> {
    if !is_token(entry) {
        return Err(Error::Entry);
    }
    let total = inputs
        .iter()
        .map(|i| i.len())
        .fold(0usize, usize::saturating_add);
    if inputs.len() > MAX_INPUTS || total > MAX_INPUT_BYTES {
        return Err(Error::Inputs);
    }
    let fuel = limits.fuel.min(MAX_FUEL);
    let memory = limits.memory.min(MAX_MEMORY);
    let time = limits.time.min(MAX_TIME);
    let started = Instant::now();
    // One engine per run: nothing compiled or cached is shared between runs.
    let engine = Engine::new(&config());
    let module = compile(&engine, module)?;
    let host = Host {
        inputs: inputs.iter().map(|i| Zeroizing::new(i.to_vec())).collect(),
        output: Zeroizing::new(Vec::new()),
        limits: StoreLimitsBuilder::new()
            .memory_size(memory)
            .memories(1)
            .tables(16)
            .table_elements(1 << 20)
            .instances(1)
            .trap_on_grow_failure(true)
            .build(),
        fault: None,
        deadline: started.checked_add(time).unwrap_or(started),
        memory: None,
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|host| &mut host.limits);
    // The start function and the entry share all the fuel, given once: a call is never resumed
    // after it ran out (see `MAX_TIME`).
    store.set_fuel(fuel).map_err(|_| Error::Fuel)?;
    let linker = linker(&engine)?;
    // A panic inside the interpreter (one was found by fuzzing, in wasmi 1.1.0) ends this run
    // with an error instead of unwinding into the node; the release profile unwinds.
    let called = catch_unwind(AssertUnwindSafe(|| {
        linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|error| stopped(&error, Error::ModuleInvalid))
            .and_then(|instance| {
                // The handle is kept in the store's data, outside this closure, before the entry
                // can fail.
                if let Some(memory) = instance.get_memory(&store, "memory") {
                    store.data_mut().memory = Some(memory);
                }
                let func = instance
                    .get_typed_func::<(), ()>(&store, entry)
                    .map_err(|_| Error::Entry)?;
                func.call(&mut store, ())
                    .map_err(|error| stopped(&error, Error::Trap))
            })
    }))
    .unwrap_or(Err(Error::Interpreter));
    let left = store.get_fuel().unwrap_or(0);
    let used = fuel.saturating_sub(left);
    // The memory may hold inputs and whatever the module derived from them: it is wiped on
    // every path, whether the run finished, trapped, ran out of fuel or time, or was refused.
    let memory = store.data().memory;
    if let Some(memory) = memory {
        memory.data_mut(&mut store).zeroize();
    }
    observe(memory.map(|memory| memory.data(&store)));
    let late = started.elapsed() > time;
    let host = store.data_mut();
    if let Some(fault) = host.fault {
        return Err(fault);
    }
    match called {
        // Between host calls only fuel stops a run: one that ran out of fuel after its time
        // was up is reported as over its time.
        Err(Error::Fuel) if late => return Err(Error::Time),
        other => other?,
    }
    // A run that finished within its fuel but past its time is refused too.
    if late {
        return Err(Error::Time);
    }
    Ok(Ran {
        output: core::mem::take(&mut host.output),
        fuel: used,
    })
}

/// Runs the function `entry` of a JavaScript `script` on `args` with the reviewed engine
/// module [`JS`], under `limits` (each capped at the node's). The script is input 0, the
/// name input 1, the arguments the rest; the engine calls the function with each argument
/// as a `Uint8Array` and writes what it returns (`crates/sandbox/js`).
pub fn run_script(
    script: &[u8],
    entry: &str,
    args: &[&[u8]],
    limits: Limits,
) -> Result<Ran, Error> {
    // A source is UTF-8 text; any other bytes are refused before the engine sees them.
    if script.len() > limits.script.min(MAX_SCRIPT) || core::str::from_utf8(script).is_err() {
        return Err(Error::Refused);
    }
    if !is_token(entry) {
        return Err(Error::Entry);
    }
    if args.len() > MAX_SCRIPT_ARGS {
        return Err(Error::Inputs);
    }
    let module = library(JS).ok_or(Error::Refused)?;
    let mut inputs: Vec<&[u8]> = Vec::with_capacity(args.len().saturating_add(2));
    inputs.push(script);
    inputs.push(entry.as_bytes());
    inputs.extend_from_slice(args);
    run_with(module, "run", &inputs, limits)
}

/// What stopped a module, from the error of wasmi: fuel, memory, or `other`.
fn stopped(error: &wasmi::Error, other: Error) -> Error {
    match (error.as_trap_code(), error.kind()) {
        (Some(TrapCode::OutOfFuel), _) => Error::Fuel,
        (Some(TrapCode::GrowthOperationLimited), _)
        | (
            _,
            ErrorKind::Memory(_)
            | ErrorKind::Table(_)
            | ErrorKind::Instantiation(
                InstantiationError::FailedToInstantiateMemory(_)
                | InstantiationError::FailedToInstantiateTable(_),
            ),
        ) => Error::Memory,
        _ => other,
    }
}

/// The memory a host function reads or writes.
fn memory_of(caller: &mut Caller<'_, Host>) -> Result<wasmi::Memory, wasmi::Error> {
    remember_memory(caller);
    match caller.data().memory {
        Some(memory) => Ok(memory),
        None => Err(fail(caller, Error::NoMemory)),
    }
}

/// Keeps the handle of the module's memory for the wipe, before anything the host gives the
/// module can reach it.
fn remember_memory(caller: &mut Caller<'_, Host>) {
    if caller.data().memory.is_none() {
        caller.data_mut().memory = caller.get_export("memory").and_then(Extern::into_memory);
    }
}

/// Records why a host function failed and returns the trap that stops the module.
fn fail(caller: &mut Caller<'_, Host>, error: Error) -> wasmi::Error {
    let host = caller.data_mut();
    if host.fault.is_none() {
        host.fault = Some(error);
    }
    wasmi::Error::from(TrapCode::UnreachableCodeReached)
}

/// Charges the fuel of copying `len` bytes, and looks at the clock.
fn charge(caller: &mut Caller<'_, Host>, len: usize) -> Result<(), wasmi::Error> {
    if Instant::now() > caller.data().deadline {
        return Err(fail(caller, Error::Time));
    }
    let cost = u64::try_from(len / COPY_PER_FUEL)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let left = caller.get_fuel().unwrap_or(0);
    match left.checked_sub(cost) {
        Some(left) => caller.set_fuel(left).map_err(|_| fail(caller, Error::Fuel)),
        None => {
            let _ = caller.set_fuel(0);
            Err(fail(caller, Error::Fuel))
        }
    }
}

/// Looks at the clock in a host function that copies nothing.
fn on_time(caller: &mut Caller<'_, Host>) -> Result<(), wasmi::Error> {
    if Instant::now() > caller.data().deadline {
        return Err(fail(caller, Error::Time));
    }
    Ok(())
}

fn input_index(caller: &Caller<'_, Host>, index: i32) -> Option<usize> {
    usize::try_from(index)
        .ok()
        .filter(|i| *i < caller.data().inputs.len())
}

fn linker(engine: &Engine) -> Result<Linker<Host>, Error> {
    let mut linker = Linker::<Host>::new(engine);
    linker
        .func_wrap(
            HOST,
            "input_count",
            |mut caller: Caller<'_, Host>| -> Result<i32, wasmi::Error> {
                remember_memory(&mut caller);
                on_time(&mut caller)?;
                Ok(i32::try_from(caller.data().inputs.len()).unwrap_or(i32::MAX))
            },
        )
        .map_err(|_| Error::Import)?;
    linker
        .func_wrap(
            HOST,
            "input_len",
            |mut caller: Caller<'_, Host>, index: i32| -> Result<i32, wasmi::Error> {
                remember_memory(&mut caller);
                on_time(&mut caller)?;
                Ok(input_index(&caller, index)
                    .and_then(|i| caller.data().inputs.get(i))
                    .map_or(-1, |input| i32::try_from(input.len()).unwrap_or(-1)))
            },
        )
        .map_err(|_| Error::Import)?;
    linker
        .func_wrap(
            HOST,
            "input_read",
            |mut caller: Caller<'_, Host>, index: i32, ptr: i32| -> Result<(), wasmi::Error> {
                let Some(index) = input_index(&caller, index) else {
                    return Err(fail(&mut caller, Error::Trap));
                };
                let memory = memory_of(&mut caller)?;
                let len = caller.data().inputs.get(index).map_or(0, |i| i.len());
                charge(&mut caller, len)?;
                // The input is copied out of the host state first: the memory and the state
                // are borrowed through the same store.
                let input = caller.data().inputs.get(index).cloned().unwrap_or_default();
                let offset = ptr as u32 as usize;
                memory
                    .write(&mut caller, offset, &input)
                    .map_err(|_| fail(&mut caller, Error::Trap))
            },
        )
        .map_err(|_| Error::Import)?;
    linker
        .func_wrap(
            HOST,
            "output",
            |mut caller: Caller<'_, Host>, ptr: i32, len: i32| -> Result<(), wasmi::Error> {
                let len = len as u32 as usize;
                let total = caller.data().output.len().saturating_add(len);
                if total > MAX_OUTPUT {
                    return Err(fail(&mut caller, Error::Output));
                }
                let memory = memory_of(&mut caller)?;
                charge(&mut caller, len)?;
                let mut bytes = Zeroizing::new(vec![0u8; len]);
                memory
                    .read(&caller, ptr as u32 as usize, &mut bytes)
                    .map_err(|_| fail(&mut caller, Error::Trap))?;
                caller.data_mut().output.extend_from_slice(&bytes);
                Ok(())
            },
        )
        .map_err(|_| Error::Import)?;
    // Tests only: a host function that panics, so that a panic unwinding through wasmi is
    // tested on the path a panic inside the interpreter takes.
    #[cfg(test)]
    linker
        .func_wrap(tests::PANIC.0, tests::PANIC.1, tests::panic_inside)
        .map_err(|_| Error::Import)?;
    Ok(linker)
}

#[cfg(test)]
mod tests;
