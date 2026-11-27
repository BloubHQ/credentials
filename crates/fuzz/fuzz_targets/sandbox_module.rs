//! Runs arbitrary WebAssembly modules and inputs in the sandbox of the `run` step. The first
//! byte chooses the module: the reviewed library `lenprefix8` (the rest is its inputs) or the
//! bytes that follow (a 2-byte little-endian length, the module, then the inputs). Inputs are
//! split on 0xff. Limits are small so that each run is quick.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox::{Error, Limits, MAX_OUTPUT};

fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let library = sandbox::library("lenprefix8").unwrap_or_default();
    let (module, inputs) = if choice & 1 == 0 {
        (library, rest)
    } else {
        let Some((len, rest)) = rest.split_first_chunk::<2>() else {
            return;
        };
        let len = usize::from(u16::from_le_bytes(*len)).min(rest.len());
        rest.split_at(len)
    };
    let inputs: Vec<&[u8]> = inputs.split(|b| *b == 0xff).collect();
    let limits = Limits {
        fuel: 1_000_000,
        memory: 4 * 1024 * 1024,
        ..Limits::default()
    };
    let checked = sandbox::check(module);
    for entry in ["run", "entry"] {
        match sandbox::run_with(module, entry, &inputs, limits) {
            Ok(ran) => {
                assert!(ran.output.len() <= MAX_OUTPUT);
                assert!(ran.fuel <= limits.fuel);
                assert!(checked.is_ok(), "a module that runs passes the checks");
            }
            // A module the checks refuse never runs; one they pass may still fail to link
            // (an import of the wrong type) or to instantiate.
            Err(Error::ModuleTooLarge | Error::Import | Error::NoMemory) => {
                assert!(checked.is_err(), "refused before it runs");
            }
            Err(_) => {}
        }
    }
    // The library frames inputs of at most 255 bytes, 16 at most.
    if choice & 1 == 0 && inputs.len() <= 16 && inputs.iter().all(|i| i.len() <= 255) {
        let total: usize = inputs.iter().map(|i| i.len() + 1).sum();
        if let Ok(ran) = sandbox::run(module, "run", &inputs) {
            assert_eq!(ran.output.len(), total);
        }
    }
});
