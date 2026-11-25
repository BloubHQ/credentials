//! Reviewed library modules: WebAssembly compiled into the node, so part of its measurement
//! (PCR2 of the enclave image). A policy names one with `{"library": "<name>"}` instead of a
//! URL. Each module is checked in as its WebAssembly text (the reviewed source) next to the
//! compiled bytes; a test compiles the text again and compares.

/// The names of the reviewed library modules, in order.
pub const LIBRARIES: [&str; 1] = ["lenprefix8"];

/// The bytes of a reviewed library module, or `None` for an unknown name.
pub fn library(name: &str) -> Option<&'static [u8]> {
    match name {
        "lenprefix8" => Some(include_bytes!("../libraries/lenprefix8.wasm")),
        _ => None,
    }
}
