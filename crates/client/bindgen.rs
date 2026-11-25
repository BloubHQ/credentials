//! `uniffibindgen`: the binding generator of UniFFI, built from this workspace so its version
//! is the one the library was built with. Generate the Swift and Kotlin sources from a built
//! library:
//!
//! ```text
//! cargo run -p client --features bindgen --bin uniffibindgen -- //!     generate --library target/release/libclient.so --language kotlin --out-dir out/kotlin
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
