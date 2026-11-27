#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use super::*;

const IMPORTS_WAT: &str = r#"
  (import "credentials" "input_count" (func $input_count (result i32)))
  (import "credentials" "input_len" (func $input_len (param i32) (result i32)))
  (import "credentials" "input_read" (func $input_read (param i32 i32)))
  (import "credentials" "output" (func $output (param i32 i32)))
"#;

fn wasm(body: &str) -> Vec<u8> {
    wat::parse_str(format!("(module {IMPORTS_WAT} {body})")).unwrap()
}

/// Reads input 0 to offset 0 and writes it back.
fn echo() -> Vec<u8> {
    wasm(
        r#"(memory (export "memory") 1)
           (func (export "run")
             (call $input_read (i32.const 0) (i32.const 0))
             (call $output (i32.const 0) (call $input_len (i32.const 0))))"#,
    )
}

const SECRET: &[u8] = b"test-secret-7f3a9c";

#[test]
fn library_matches_its_source() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/libraries");
    // The libraries written as WebAssembly text; `js` is checked by its hash (tests/js.rs).
    for name in ["lenprefix8"] {
        let text = std::fs::read_to_string(format!("{dir}/{name}.wat")).unwrap();
        let compiled = wat::parse_str(&text).unwrap();
        if std::env::var_os("SANDBOX_WRITE_LIBRARIES").is_some() {
            std::fs::write(format!("{dir}/{name}.wasm"), &compiled).unwrap();
            continue;
        }
        assert!(
            library(name) == Some(compiled.as_slice()),
            "{name}.wasm is not {name}.wat compiled; run with SANDBOX_WRITE_LIBRARIES=1"
        );
        assert!(check(&compiled).is_ok(), "{name} passes the checks");
    }
    assert!(library("nope").is_none());
}

#[test]
fn lenprefix8_frames_its_inputs() {
    let module = library("lenprefix8").unwrap();
    let ran = run(module, "run", &[b"ab", b"", b"xyz"]).unwrap();
    assert_eq!(ran.output.as_slice(), b"\x02ab\x00\x03xyz");
    let long = vec![7u8; 256];
    assert_eq!(
        run(module, "run", &[&long]).unwrap_err(),
        Error::Trap,
        "an input of 256 bytes traps"
    );
    // An input that needs a second page of memory.
    let big = vec![1u8; 255];
    let inputs: Vec<&[u8]> = (0..16).map(|_| big.as_slice()).collect();
    let ran = run(module, "run", &inputs).unwrap();
    assert_eq!(ran.output.len(), 16 * 256);
}

#[test]
fn echo_returns_the_input_and_is_deterministic() {
    let module = echo();
    let a = run(&module, "run", &[SECRET]).unwrap();
    let b = run(&module, "run", &[SECRET]).unwrap();
    assert!(
        a.output.as_slice() == SECRET,
        "the echo gives its input back"
    );
    assert_eq!(a.fuel, b.fuel);
    assert!(a.output == b.output, "same input, same output");
}

#[test]
fn floats_are_deterministic() {
    // 0/0 in f32, written as its bits: a NaN whose bits are those of the CPU (x86_64 for every
    // node of a release), the same on every run.
    let module = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run")
             (i32.store (i32.const 0)
               (i32.reinterpret_f32 (f32.div (f32.const 0) (f32.const 0))))
             (call $output (i32.const 0) (i32.const 4)))"#,
    );
    let a = run(&module, "run", &[]).unwrap();
    let b = run(&module, "run", &[]).unwrap();
    assert!(f32::from_le_bytes(a.output.as_slice().try_into().unwrap()).is_nan());
    assert_eq!(a.output, b.output);
}

#[test]
fn fuel_runs_out() {
    let module = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run") (loop $l (br $l)))"#,
    );
    let small = Limits {
        fuel: 10_000,
        ..Limits::default()
    };
    assert_eq!(
        run_with(&module, "run", &[], small).unwrap_err(),
        Error::Fuel
    );
    // At the node's limit too: the loop stops, on fuel (1.25 s in release on the measured
    // host) or, on a slower host such as a debug build among parallel tests, on time.
    let stopped = run(&module, "run", &[]).unwrap_err();
    assert!(matches!(stopped, Error::Fuel | Error::Time), "{stopped:?}");
    // Copies cost fuel: reading a large input in a loop stops early.
    let reader = wasm(
        r#"(memory (export "memory") 17)
           (func (export "run") (loop $l (call $input_read (i32.const 0) (i32.const 0)) (br $l)))"#,
    );
    let input = vec![0u8; MAX_INPUT_BYTES];
    let limits = Limits {
        fuel: 1_000_000,
        ..Limits::default()
    };
    let started = std::time::Instant::now();
    assert_eq!(
        run_with(&reader, "run", &[&input], limits).unwrap_err(),
        Error::Fuel
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn memory_runs_out() {
    let grow = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run") (loop $l (drop (memory.grow (i32.const 16))) (br $l)))"#,
    );
    assert_eq!(run(&grow, "run", &[]).unwrap_err(), Error::Memory);
    let limits = Limits {
        memory: 2 * 65536,
        ..Limits::default()
    };
    let one = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run") (drop (memory.grow (i32.const 2))))"#,
    );
    assert_eq!(
        run_with(&one, "run", &[], limits).unwrap_err(),
        Error::Memory
    );
    // A module that starts larger than the limit is refused before it runs.
    let large = wasm(r#"(memory (export "memory") 1025) (func (export "run"))"#);
    assert_eq!(run(&large, "run", &[]).unwrap_err(), Error::Memory);
}

#[test]
fn imports_beyond_the_host_functions_are_refused() {
    for import in [
        r#"(import "wasi_snapshot_preview1" "clock_time_get" (func (param i32 i64 i32) (result i32)))"#,
        r#"(import "wasi_snapshot_preview1" "random_get" (func (param i32 i32) (result i32)))"#,
        r#"(import "credentials" "clock" (func (result i64)))"#,
        r#"(import "credentials" "output" (global i32))"#,
    ] {
        let module = wat::parse_str(format!(
            r#"(module {import} (memory (export "memory") 1) (func (export "run")))"#
        ))
        .unwrap();
        assert_eq!(check(&module).unwrap_err(), Error::Import, "{import}");
        assert_eq!(run(&module, "run", &[]).unwrap_err(), Error::Import);
    }
    // An imported memory, even exported again.
    let module = wat::parse_str(
        r#"(module (import "env" "memory" (memory 1)) (export "memory" (memory 0)) (func (export "run")))"#,
    )
    .unwrap();
    assert_eq!(check(&module).unwrap_err(), Error::Import);
    // The right name with the wrong type fails when it is linked.
    let module = wat::parse_str(
        r#"(module (import "credentials" "output" (func (param i64)))
                   (memory (export "memory") 1) (func (export "run")))"#,
    )
    .unwrap();
    assert_eq!(run(&module, "run", &[]).unwrap_err(), Error::ModuleInvalid);
}

#[test]
fn shape_errors() {
    let no_memory = wasm(r#"(func (export "run"))"#);
    assert_eq!(run(&no_memory, "run", &[]).unwrap_err(), Error::NoMemory);
    // A start function runs first, under the same limits.
    let start = wasm(
        r#"(memory (export "memory") 1)
           (func $s (call $output (i32.const 0) (i32.const 1)))
           (start $s)
           (func (export "run") (call $output (i32.const 0) (i32.const 1)))"#,
    );
    assert_eq!(run(&start, "run", &[]).unwrap().output.as_slice(), [0, 0]);
    let spin = wasm(
        r#"(memory (export "memory") 1) (func $s (loop $l (br $l))) (start $s) (func (export "run"))"#,
    );
    let small = Limits {
        fuel: 10_000,
        ..Limits::default()
    };
    assert_eq!(run_with(&spin, "run", &[], small).unwrap_err(), Error::Fuel);
    let module = echo();
    assert_eq!(run(&module, "nope", &[]).unwrap_err(), Error::Entry);
    assert_eq!(run(&module, "", &[]).unwrap_err(), Error::Entry);
    assert_eq!(run(&module, "a b", &[]).unwrap_err(), Error::Entry);
    let typed = wasm(r#"(memory (export "memory") 1) (func (export "run") (param i32))"#);
    assert_eq!(run(&typed, "run", &[]).unwrap_err(), Error::Entry);
    assert_eq!(
        run(b"\0asm\x01\0\0\0garbage", "run", &[]).unwrap_err(),
        Error::ModuleInvalid
    );
    assert_eq!(run(b"", "run", &[]).unwrap_err(), Error::ModuleInvalid);
    let huge = vec![0u8; MAX_MODULE + 1];
    assert_eq!(run(&huge, "run", &[]).unwrap_err(), Error::ModuleTooLarge);
}

#[test]
fn input_and_output_bounds() {
    let module = echo();
    let many: Vec<&[u8]> = (0..=MAX_INPUTS).map(|_| b"x".as_slice()).collect();
    assert_eq!(run(&module, "run", &many).unwrap_err(), Error::Inputs);
    let big = vec![0u8; MAX_INPUT_BYTES + 1];
    assert_eq!(run(&module, "run", &[&big]).unwrap_err(), Error::Inputs);
    // No input 0: a trap.
    assert_eq!(run(&module, "run", &[]).unwrap_err(), Error::Trap);
    // Reading past the memory, and writing from past it.
    let past = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run") (call $input_read (i32.const 0) (i32.const 65535)))"#,
    );
    assert_eq!(run(&past, "run", &[b"ab"]).unwrap_err(), Error::Trap);
    let negative = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run") (call $output (i32.const -1) (i32.const 4)))"#,
    );
    assert_eq!(run(&negative, "run", &[]).unwrap_err(), Error::Trap);
    // More output than the limit, in one call and in many.
    let large = wasm(
        r#"(memory (export "memory") 2)
           (func (export "run") (call $output (i32.const 0) (i32.const 65537)))"#,
    );
    assert_eq!(run(&large, "run", &[]).unwrap_err(), Error::Output);
    let repeated = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run") (loop $l (call $output (i32.const 0) (i32.const 1024)) (br $l)))"#,
    );
    assert_eq!(run(&repeated, "run", &[]).unwrap_err(), Error::Output);
    // Counts and lengths.
    let count = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run")
             (i32.store (i32.const 0) (call $input_count))
             (i32.store (i32.const 4) (call $input_len (i32.const 1)))
             (i32.store (i32.const 8) (call $input_len (i32.const 7)))
             (i32.store (i32.const 12) (call $input_len (i32.const -1)))
             (call $output (i32.const 0) (i32.const 16)))"#,
    );
    let ran = run(&count, "run", &[b"a", b"bcd"]).unwrap();
    let words: Vec<i32> = ran
        .output
        .chunks(4)
        .map(|c| i32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    assert_eq!(words, [2, 3, -1, -1]);
}

#[test]
fn errors_never_carry_module_bytes() {
    // A module that reads the secret, writes it to its memory, then traps: the error is one
    // fixed message.
    let module = wasm(
        r#"(memory (export "memory") 1)
           (func (export "run")
             (call $input_read (i32.const 0) (i32.const 0))
             (unreachable))"#,
    );
    let error = run(&module, "run", &[SECRET]).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(
        !text.as_bytes().windows(SECRET.len()).any(|w| w == SECRET),
        "the error holds no input"
    );
    assert_eq!(error, Error::Trap);
}

#[test]
fn stack_overflow_traps() {
    let module = wasm(
        r#"(memory (export "memory") 1)
           (func $f (call $f))
           (func (export "run") (call $f))"#,
    );
    assert_eq!(run(&module, "run", &[]).unwrap_err(), Error::Trap);
}
