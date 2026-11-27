//! The module's side of the sandbox ABI (`crates/sandbox`): the four host functions it
//! imports and the entry it exports.
//!
//! This file is the only place of the module where `unsafe` appears, and only as the syntax
//! the two declarations need: an `extern` block (the imports, declared `safe`) and an exported
//! symbol (`no_mangle`). Neither dereferences memory: a buffer's address is passed to the host
//! as an integer, and the host checks every access against the module's linear memory.
#![allow(unsafe_code)]

#[link(wasm_import_module = "credentials")]
unsafe extern "C" {
    /// The number of inputs.
    safe fn input_count() -> i32;
    /// The length of input `index`, or -1.
    safe fn input_len(index: i32) -> i32;
    /// Copies input `index` to `ptr` in the linear memory. The host checks the bounds and
    /// traps the module when the copy does not fit.
    safe fn input_read(index: i32, ptr: i32);
    /// Appends `len` bytes at `ptr` to the output, bounds checked by the host.
    safe fn output(ptr: i32, len: i32);
}

/// The address of a buffer as the host sees it: an offset in the linear memory (wasm32
/// addresses are 32 bits).
fn offset(bytes: &[u8]) -> i32 {
    bytes.as_ptr() as usize as i32
}

/// The address of a buffer the host writes into.
fn offset_mut(bytes: &mut [u8]) -> i32 {
    bytes.as_mut_ptr() as usize as i32
}

fn read_inputs() -> Vec<Vec<u8>> {
    let count = input_count().max(0);
    (0..count)
        .map(|index| {
            let len = usize::try_from(input_len(index)).unwrap_or(0);
            let mut buffer = vec![0u8; len];
            if len > 0 {
                // The host writes exactly `len` bytes into the buffer just allocated.
                input_read(index, offset_mut(&mut buffer));
            }
            buffer
        })
        .collect()
}

/// The entry: runs the script and writes its output, or traps.
#[unsafe(no_mangle)]
pub extern "C" fn run() {
    let inputs = read_inputs();
    match crate::execute(&inputs) {
        Some(bytes) => {
            if let Ok(len) = i32::try_from(bytes.len()) {
                output(offset(&bytes), len);
            } else {
                core::arch::wasm32::unreachable();
            }
        }
        None => core::arch::wasm32::unreachable(),
    }
}
