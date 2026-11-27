//! Runs arbitrary JavaScript sources on the engine module (`js`) in the sandbox. The bytes up
//! to the first 0xff are the script; the rest, split on 0xff, are the arguments of its
//! function `f`. Limits are small so that each run is quick: a script never crashes the host,
//! never exceeds its limits, and fails only with a fixed error (a panic inside the
//! interpreter is caught and comes back as `Interpreter`).

#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use sandbox::{Error, Limits, MAX_OUTPUT};

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|b| *b == 0xff);
    let script = parts.next().unwrap_or_default();
    let args: Vec<&[u8]> = parts.take(sandbox::MAX_SCRIPT_ARGS).collect();
    let limits = Limits {
        fuel: 40_000_000,
        memory: 16 * 1024 * 1024,
        time: Duration::from_secs(2),
        ..Limits::default()
    };
    match sandbox::run_script(script, "f", &args, limits) {
        Ok(ran) => {
            assert!(ran.output.len() <= MAX_OUTPUT);
            assert!(ran.fuel <= limits.fuel);
        }
        Err(
            Error::Trap
            | Error::Fuel
            | Error::Memory
            | Error::Output
            | Error::Time
            | Error::Refused
            | Error::Interpreter,
        ) => {}
        Err(other) => panic!("unexpected error {other:?}"),
    }
});
