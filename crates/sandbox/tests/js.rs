//! The JavaScript library module (`js`, boa compiled to WebAssembly) in the sandbox: results
//! against native implementations, determinism, the limits, and what a script cannot reach.
//! Assertion messages never print the key or the output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{KeyInit, Mac};
use sandbox::{Error, JS, JS_SHA256, Limits, MAX_SCRIPT, library, library_sha256, run_script};
use sha2::{Digest, Sha256};

const HS256: &str = include_str!("fixtures/hs256.js");
const KEY: &[u8] = b"test-key-5b1e0c7d";

fn native_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn js(script: &str, entry: &str, args: &[&[u8]]) -> Result<Vec<u8>, Error> {
    run_script(script.as_bytes(), entry, args, Limits::default()).map(|r| r.output.to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_engine_is_the_pinned_module() {
    let module = library(JS).unwrap();
    assert_eq!(hex(&Sha256::digest(module)), JS_SHA256);
    assert_eq!(
        library_sha256(JS).map(|d| hex(&d)).as_deref(),
        Some(JS_SHA256)
    );
    assert!(
        sandbox::check(module).is_ok(),
        "the engine passes the sandbox's checks"
    );
}

#[test]
fn hmac_matches_the_native_result() {
    let long_key = [0x42u8; 100];
    let block_key = [0x17u8; 64];
    let long_message = [0xa5u8; 300];
    for (key, message) in [
        (KEY, b"" as &[u8]),
        (KEY, b"abc"),
        (&block_key[..], b"exactly one block of key"),
        (&long_key[..], &long_message[..]),
    ] {
        let got = js(HS256, "sign", &[key, message]).unwrap();
        assert!(
            got == native_hmac(key, message),
            "HMAC-SHA256 in JavaScript differs from the native one (key of {} bytes, message of {} bytes)",
            key.len(),
            message.len()
        );
    }
    // A promise is awaited.
    let got = js(HS256, "signLater", &[KEY, b"later"]).unwrap();
    assert!(got == native_hmac(KEY, b"later"), "async entry differs");
}

#[test]
fn jwt_matches_the_native_result() {
    let got = js(HS256, "jwt", &[KEY, "user-ü".as_bytes(), b"1700000000"]).unwrap();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(r#"{"sub":"user-ü","iat":1700000000}"#.as_bytes());
    let input = format!("{header}.{claims}");
    let expected = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(native_hmac(KEY, input.as_bytes()))
    );
    assert!(
        got == expected.as_bytes(),
        "the JWT of the script differs from the native one"
    );
}

#[test]
fn runs_are_deterministic_and_have_no_clock_or_randomness() {
    let a = run_script(HS256.as_bytes(), "sign", &[KEY, b"same"], Limits::default()).unwrap();
    let b = run_script(HS256.as_bytes(), "sign", &[KEY, b"same"], Limits::default()).unwrap();
    assert!(a.output == b.output, "same inputs, same output");
    assert_eq!(a.fuel, b.fuel, "same inputs, same fuel");
    let probe = r#"function probe() {
        return [typeof Date, typeof Math.random, typeof performance, typeof crypto,
                typeof setTimeout, typeof setInterval, typeof queueMicrotask].join(",");
    }"#;
    assert_eq!(
        js(probe, "probe", &[]).unwrap(),
        b"undefined,undefined,undefined,undefined,undefined,undefined,undefined"
    );
    // A script that reaches for them fails.
    for body in [
        "return String(Date.now());",
        "return String(new Date().getTime());",
        "return String(Math.random());",
    ] {
        let script = format!("function f() {{ {body} }}");
        assert_eq!(js(&script, "f", &[]).unwrap_err(), Error::Trap, "{body}");
    }
}

#[test]
fn a_script_reaches_no_io() {
    let probe = r#"function probe() {
        return [typeof fetch, typeof XMLHttpRequest, typeof WebSocket, typeof require,
                typeof process, typeof Deno, typeof WebAssembly, typeof importScripts,
                typeof print, typeof console].join(",");
    }"#;
    assert_eq!(
        js(probe, "probe", &[]).unwrap(),
        b"undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined"
    );
    for script in [
        "function f() { return fetch('https://example.com/'); }",
        "function f() { return require('fs'); }",
        "async function f() { const m = await import('./other.js'); return m.x; }",
        "function f() { return new XMLHttpRequest(); }",
        // `eval` stays inside the same sandbox, and still finds no I/O.
        "function f() { return eval('fetch')('x'); }",
    ] {
        assert_eq!(js(script, "f", &[]).unwrap_err(), Error::Trap, "{script}");
    }
    // A module script cannot be loaded: `import` at the top level does not parse as a script.
    assert_eq!(
        js("import x from 'y'; function f() { return 'x'; }", "f", &[]).unwrap_err(),
        Error::Trap
    );
}

#[test]
fn fuel_memory_and_time_stop_a_script() {
    let spin = "function f() { for (;;) {} }";
    let small = Limits {
        fuel: 50_000_000,
        ..Limits::default()
    };
    assert_eq!(
        run_script(spin.as_bytes(), "f", &[], small).unwrap_err(),
        Error::Fuel
    );
    // At the node's limits the infinite loop stops on fuel (about 1.7 s in a release build
    // on the measured host), or on the 5 s time limit when the host is slower (a debug build
    // among parallel tests).
    let started = Instant::now();
    let stopped = js(spin, "f", &[]).unwrap_err();
    assert!(matches!(stopped, Error::Fuel | Error::Time), "{stopped:?}");
    assert!(started.elapsed() < Duration::from_secs(30));
    // A time limit stops it first.
    let quick = Limits {
        time: Duration::from_millis(100),
        ..Limits::default()
    };
    let started = Instant::now();
    assert_eq!(
        run_script(spin.as_bytes(), "f", &[], quick).unwrap_err(),
        Error::Time
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    // Memory: a script that keeps allocating stops at the cap.
    let hog = "function f() { const keep = []; for (;;) { keep.push(new Uint8Array(1 << 20)); } }";
    let capped = Limits {
        memory: 32 * 1024 * 1024,
        ..Limits::default()
    };
    assert_eq!(
        run_script(hog.as_bytes(), "f", &[], capped).unwrap_err(),
        Error::Memory
    );
    assert_eq!(js(hog, "f", &[]).unwrap_err(), Error::Memory);
    // Deep recursion is an exception of the engine, not a crash of the host.
    let deep = "function f() { return f(); }";
    assert_eq!(js(deep, "f", &[]).unwrap_err(), Error::Trap);
}

#[test]
fn script_size_entry_and_results() {
    let ok = "function f(a) { return a; }";
    let tight = Limits {
        script: ok.len() - 1,
        ..Limits::default()
    };
    assert_eq!(
        run_script(ok.as_bytes(), "f", &[], tight).unwrap_err(),
        Error::Refused
    );
    let huge = vec![b' '; MAX_SCRIPT + 1];
    assert_eq!(
        run_script(&huge, "f", &[], Limits::default()).unwrap_err(),
        Error::Refused
    );
    assert_eq!(js(ok, "f", &[b"\x00\xffbytes"]).unwrap(), b"\x00\xffbytes");
    assert_eq!(
        js(ok, "not a token", &[]).unwrap_err(),
        Error::Entry,
        "the entry is a token"
    );
    assert_eq!(js(ok, "missing", &[]).unwrap_err(), Error::Trap);
    assert_eq!(
        js("function f() { return 'é'; }", "f", &[]).unwrap(),
        "é".as_bytes()
    );
    assert_eq!(
        js(
            "function f() { return new Uint8Array([1, 2, 3]).buffer; }",
            "f",
            &[]
        )
        .unwrap(),
        [1, 2, 3]
    );
    assert_eq!(
        js(
            "function f() { return new Uint8Array([1, 2, 3, 4]).subarray(1, 3); }",
            "f",
            &[]
        )
        .unwrap(),
        [2, 3]
    );
    for bad in [
        "function f() { return 42; }",
        "function f() { return {}; }",
        "function f() { throw new Error('the secret'); }",
        "async function f() { throw new Error('later'); }",
        "function f() { return new Promise(() => {}); }",
        "this is not javascript",
    ] {
        assert_eq!(js(bad, "f", &[]).unwrap_err(), Error::Trap, "{bad}");
    }
    let args: Vec<&[u8]> = (0..sandbox::MAX_SCRIPT_ARGS)
        .map(|_| b"x" as &[u8])
        .collect();
    assert_eq!(
        js("function f(...a) { return String(a.length); }", "f", &args).unwrap(),
        b"14"
    );
    let too_many: Vec<&[u8]> = (0..=sandbox::MAX_SCRIPT_ARGS)
        .map(|_| b"x" as &[u8])
        .collect();
    assert_eq!(js(ok, "f", &too_many).unwrap_err(), Error::Inputs);
}

#[test]
fn the_web_apis_of_the_prelude() {
    let script = r#"
        function encode(s) { return new TextEncoder().encode(new TextDecoder().decode(s)); }
        function decode(b) { return new TextDecoder().decode(b); }
        function roundtrip(b) {
            let s = ""; for (const x of b) s += String.fromCharCode(x);
            return atob(btoa(s)) === s ? btoa(s) : "mismatch";
        }
        function big() { return (2n ** 100n).toString(16); }
    "#;
    let text = "a€😀ü".as_bytes();
    assert_eq!(js(script, "encode", &[text]).unwrap(), text);
    // Invalid UTF-8 decodes with U+FFFD per maximal invalid subpart, as browsers do.
    assert_eq!(
        js(script, "decode", &[b"a\xff\xe2\x82b\xed\xa0\x80"]).unwrap(),
        "a\u{fffd}\u{fffd}b\u{fffd}\u{fffd}\u{fffd}".as_bytes()
    );
    let bytes: Vec<u8> = (0..=255).collect();
    let expected = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert_eq!(
        js(script, "roundtrip", &[&bytes]).unwrap(),
        expected.as_bytes()
    );
    assert_eq!(
        js(script, "big", &[]).unwrap(),
        b"10000000000000000000000000"
    );
}

#[test]
fn errors_carry_no_script_bytes() {
    let script = "function f() { throw new Error('test-secret-7f3a9c'); }";
    let error = js(script, "f", &[]).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("test-secret"));
}

/// Measurements for `docs/sandbox.md`: module checks, cold start, one signature, a JSON
/// transform and the HMAC chain, each the median of 21 whole runs (engine, compile,
/// instantiate, run, erase). Run in release: `cargo test --release -p sandbox --test js --
/// --ignored --nocapture measure`. With `JS_CANDIDATE=<path>` the same runs use another
/// engine module built to the same ABI (input 0 the script, 1 the name, the rest the
/// arguments), to compare candidates.
#[test]
#[ignore = "a measurement, not a test"]
fn measure() {
    fn median(mut runs: Vec<Duration>) -> Duration {
        runs.sort();
        runs[runs.len() / 2]
    }
    let candidate = std::env::var_os("JS_CANDIDATE").map(|path| std::fs::read(path).unwrap());
    let module: &[u8] = candidate.as_deref().unwrap_or_else(|| library(JS).unwrap());
    let time = |script: &str, entry: &str, args: &[&[u8]]| {
        let mut inputs: Vec<&[u8]> = vec![script.as_bytes(), entry.as_bytes()];
        inputs.extend_from_slice(args);
        let mut runs = Vec::new();
        let mut fuel = 0;
        let mut output = Vec::new();
        for _ in 0..21 {
            let started = Instant::now();
            let ran = sandbox::run_with(module, "run", &inputs, Limits::default()).unwrap();
            runs.push(started.elapsed());
            fuel = ran.fuel;
            output = ran.output.to_vec();
        }
        (median(runs), fuel, output)
    };
    let mut checks = Vec::new();
    for _ in 0..21 {
        let started = Instant::now();
        sandbox::check(module).unwrap();
        checks.push(started.elapsed());
    }
    println!("module: {} bytes", module.len());
    println!("check (decode + validate): {:?}", median(checks));
    let (t, f, _) = time("function f() { return ''; }", "f", &[]);
    println!("cold start (empty function): {t:?}, {f} fuel");
    let (t, f, out) = time(HS256, "sign", &[KEY, b"message"]);
    assert!(
        out == native_hmac(KEY, b"message"),
        "the module's HMAC differs from the native one"
    );
    println!("one HMAC-SHA256 (script parsed each run): {t:?}, {f} fuel");
    let (t, f, _) = time(HS256, "jwt", &[KEY, b"user", b"1700000000"]);
    println!("one JWT HS256: {t:?}, {f} fuel");
    let json = r#"function f(n) {
        const count = Number(new TextDecoder().decode(n));
        let out = 0;
        for (let i = 0; i < count; i++) {
            const o = JSON.parse('{"user":"u' + i + '","scope":["a","b"],"n":' + i + '}');
            o.scope.push("c");
            out += JSON.stringify({ sub: o.user, scope: o.scope.join(" "), n: o.n * 2 }).length;
        }
        return String(out);
    }"#;
    let (t, f, _) = time(json, "f", &[b"1000"]);
    println!("JSON transform x1000: {t:?}, {f} fuel");
    for count in [1u32, 10, 40] {
        let n = count.to_string();
        let (t, f, _) = time(HS256, "chain", &[KEY, n.as_bytes()]);
        println!("HMAC chain x{count}: {t:?}, {f} fuel");
    }
}

/// A script that is not UTF-8 is refused before the engine sees it. These two bytes were found
/// by the fuzz target `sandbox_script`: given to the engine, they panicked wasmi 1.1.0 (#95).
#[test]
fn a_script_that_is_not_utf8_fails_without_a_panic() {
    let limits = Limits {
        fuel: 40_000_000,
        memory: 16 * 1024 * 1024,
        time: Duration::from_secs(2),
        ..Limits::default()
    };
    let result = std::panic::catch_unwind(|| run_script(b"\n\xb0", "f", &[], limits));
    let result = result.expect("the sandbox panicked");
    assert_eq!(
        result.err().map(|e| e.to_string()),
        Some(Error::Refused.to_string())
    );
}

/// The same bytes given to the engine module directly, past the UTF-8 check: the panic inside
/// wasmi is caught and the run fails with `Interpreter`, without unwinding into the caller.
#[test]
fn a_panic_inside_the_interpreter_is_an_error() {
    let limits = Limits {
        fuel: 40_000_000,
        memory: 16 * 1024 * 1024,
        time: Duration::from_secs(2),
        ..Limits::default()
    };
    let module = library(JS).unwrap();
    let inputs: [&[u8]; 2] = [b"\n\xb0", b"f"];
    let result = std::panic::catch_unwind(|| sandbox::run_with(module, "run", &inputs, limits));
    let result = result.expect("the panic reached the caller");
    assert_eq!(
        result.err().map(|e| e.to_string()),
        Some(Error::Interpreter.to_string())
    );
}
