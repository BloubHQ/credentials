//! Now, Unix milliseconds. `std::time::SystemTime::now` panics on wasm32-unknown-unknown,
//! so the web build asks JavaScript (`Date.now()`).

/// Now, Unix milliseconds.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_ms() -> u64 {
    engine::node::now_ms()
}

/// Now, Unix milliseconds, from `Date.now()`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn now_ms() -> u64 {
    let now = js_sys::Date::now();
    if now.is_finite() && now > 0.0 {
        // A float of milliseconds since 1970 fits a u64 for the next 500 million years.
        now as u64
    } else {
        0
    }
}
