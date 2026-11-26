//! Reviewed library modules: WebAssembly compiled into the node, so part of its measurement
//! (PCR2 of the enclave image). A policy names one with `{"library": "<name>"}` instead of a
//! URL, optionally with its SHA-256.
//!
//! - `lenprefix8` is checked in as its WebAssembly text (the reviewed source) next to the
//!   compiled bytes; a test compiles the text again and compares.
//! - `js` is the JavaScript engine (`crates/sandbox/js`, boa compiled to WebAssembly), built
//!   by `build/js-module.sh` from its locked sources; CI builds it again and compares the
//!   bytes. The node hands it out only when its SHA-256 is [`JS_SHA256`].

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// The names of the reviewed library modules, in order.
pub const LIBRARIES: [&str; 2] = ["lenprefix8", JS];

/// The name of the JavaScript engine module.
pub const JS: &str = "js";

/// The SHA-256 of `libraries/js.wasm`, as `build/js-module.sh` prints it.
pub const JS_SHA256: &str = "047fac9cea607354660b740dca4db755709f274e1655ff32905aca7cbb562b12";

const LENPREFIX8: &[u8] = include_bytes!("../libraries/lenprefix8.wasm");
const JS_MODULE: &[u8] = include_bytes!("../libraries/js.wasm");

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// True once the embedded engine is checked against [`JS_SHA256`].
fn js_verified() -> bool {
    static VERIFIED: OnceLock<bool> = OnceLock::new();
    *VERIFIED.get_or_init(|| hex(&Sha256::digest(JS_MODULE)) == JS_SHA256)
}

/// The bytes of a reviewed library module, or `None` for an unknown name (or an engine whose
/// bytes do not match [`JS_SHA256`]).
pub fn library(name: &str) -> Option<&'static [u8]> {
    match name {
        "lenprefix8" => Some(LENPREFIX8),
        JS if js_verified() => Some(JS_MODULE),
        _ => None,
    }
}

/// The SHA-256 of a reviewed library module, the value a policy pins it with.
pub fn library_sha256(name: &str) -> Option<[u8; 32]> {
    library(name).map(|bytes| Sha256::digest(bytes).into())
}
