//! The reviewed JavaScript library module of the credentials sandbox (`docs/sandbox.md`,
//! JavaScript): the [boa](https://github.com/boa-dev/boa) engine compiled to
//! `wasm32-unknown-unknown`, run by the sandbox like any other module, with no import but the
//! sandbox's four host functions.
//!
//! Its entry `run` reads the inputs of the run:
//!
//! | Input | Meaning |
//! | --- | --- |
//! | 0 | The script, UTF-8 (the node checked its SHA-256 against the signed policy). |
//! | 1 | The name of the function the script defines, called once the script has run. |
//! | 2.. | The arguments of that function, each a `Uint8Array`. |
//!
//! The function returns a `Uint8Array`, an `ArrayBuffer` or a string (written as UTF-8), or a
//! promise of one (pending jobs run until it settles); those bytes are the output. A script
//! that throws, a function that is missing, or a value of another type stops the module with a
//! trap: nothing the script computed reaches the node but the output.
//!
//! What a run may depend on is its inputs only: the prelude (`prelude.js`) deletes `Date` and
//! `Math.random`, the engine's clock is fixed, modules cannot be imported, and the engine has
//! no I/O of its own. The prelude adds `TextEncoder`, `TextDecoder` (UTF-8), `atob` and
//! `btoa`.

use std::rc::Rc;

use boa_engine::builtins::promise::PromiseState;
use boa_engine::context::time::FixedClock;
use boa_engine::context::{ContextBuilder, HostHooks};
use boa_engine::object::builtins::{JsArrayBuffer, JsUint8Array};
use boa_engine::{Context, JsResult, JsString, JsValue, Source};

#[cfg(target_arch = "wasm32")]
mod abi;

/// The prelude, evaluated before the script.
const PRELUDE: &str = include_str!("prelude.js");

/// Host hooks with no time zone: the local offset is always zero.
struct Hooks;

impl HostHooks for Hooks {
    fn local_timezone_offset_seconds(&self, _unix_time_seconds: i64) -> i32 {
        0
    }
}

/// Why a run failed. The module traps on every one, so the reason never leaves it.
#[derive(Debug)]
struct Failed;

impl From<boa_engine::JsError> for Failed {
    fn from(_: boa_engine::JsError) -> Self {
        Failed
    }
}

/// Runs the script on the inputs and returns the output bytes, or `None` when the script
/// fails (the module then traps).
pub fn execute(inputs: &[Vec<u8>]) -> Option<Vec<u8>> {
    run_script(inputs).ok()
}

fn run_script(inputs: &[Vec<u8>]) -> Result<Vec<u8>, Failed> {
    let (script, rest) = inputs.split_first().ok_or(Failed)?;
    let (name, args) = rest.split_first().ok_or(Failed)?;
    let name = core::str::from_utf8(name).map_err(|_| Failed)?;
    let mut context = ContextBuilder::new()
        .clock(Rc::new(FixedClock::from_millis(0)))
        .host_hooks(Rc::new(Hooks))
        .can_block(false)
        .build()?;
    context.eval(Source::from_bytes(PRELUDE))?;
    context.eval(Source::from_bytes(script.as_slice()))?;
    let function = context
        .global_object()
        .get(JsString::from(name), &mut context)?
        .as_callable()
        .ok_or(Failed)?;
    let args = args
        .iter()
        .map(|bytes| {
            JsUint8Array::from_iter(bytes.iter().copied(), &mut context).map(JsValue::from)
        })
        .collect::<JsResult<Vec<_>>>()?;
    let mut value = function.call(&JsValue::undefined(), &args, &mut context)?;
    if let Some(promise) = value.as_promise() {
        context.run_jobs()?;
        value = match promise.state() {
            PromiseState::Fulfilled(value) => value,
            PromiseState::Pending | PromiseState::Rejected(_) => return Err(Failed),
        };
    }
    bytes_of(&value, &mut context)
}

/// The bytes of the function's result.
fn bytes_of(value: &JsValue, context: &mut Context) -> Result<Vec<u8>, Failed> {
    if let Some(text) = value.as_string() {
        return text
            .to_std_string()
            .map(String::into_bytes)
            .map_err(|_| Failed);
    }
    let object = value.as_object().ok_or(Failed)?;
    if let Ok(array) = JsUint8Array::from_object(object.clone()) {
        return Ok(array.iter(context).collect());
    }
    let buffer = JsArrayBuffer::from_object(object)?;
    let data = buffer.data().ok_or(Failed)?;
    Ok(data.to_vec())
}
