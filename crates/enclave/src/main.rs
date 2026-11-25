//! `enclave`: a credentials node inside an AWS Nitro Enclave. See the documentation of the
//! `enclave` library and "Running in a Nitro Enclave" in the README of the repository.

use std::process::ExitCode;

/// Every freed heap block is erased, including the buffers of dependencies (TLS records,
/// parsed keys) the engine cannot reach.
#[global_allocator]
static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match enclave::nitro::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!(
        "error: the enclave program runs only inside an AWS Nitro Enclave (Linux): it needs \
         /dev/nsm and vsock. Build the enclave image with enclave/build/build.sh, run it with \
         nitro-cli on the parent instance next to `credentials host`, or run a node anywhere \
         with `credentials serve`."
    );
    ExitCode::from(2)
}
