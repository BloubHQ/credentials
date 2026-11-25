//! The program inside a Nitro Enclave (Linux only): the NSM, the checks at boot, and the node
//! server on vsock.
//!
//! Parts adapted from pickle-com/credential-enclave (`enclave/src/platform/nitro.rs`,
//! Apache-2.0): the check of the kernel random source, the NSM descriptor held for the life
//! of the process, and the `CONNECT` preamble of the egress relay.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use engine::keys::NodeKey;
use engine::node::{Node, SystemClock};
use relay::vsock::{self, Vsock};
use relay::{
    EGRESS_PORT, HTTP_PORT, LOG_PORT, LogLink, PARENT_CID, RelayConnector, RelayError, RelaySink,
};
use server::{Options, Server};
use transport::{Socket, TlsTransport};

use crate::attestation::{AttestError, Attester, EnclaveHooks};

/// The kernel file that names the active hardware random source.
const RNG_CURRENT: &str = "/sys/class/misc/hw_random/rng_current";
/// The hardware random source of the Nitro Secure Module.
const RNG_NSM: &str = "nsm-hwrng";

/// Why the enclave program stopped.
#[derive(Debug, thiserror::Error)]
pub enum NitroError {
    /// The kernel random source is not the NSM: the node key would not come from it.
    #[error("the active hardware random source is {0:?}, not nsm-hwrng")]
    Entropy(String),
    /// The NSM could not be used.
    #[error(transparent)]
    Nsm(#[from] AttestError),
    /// The log writer of the host could not be reached, or refused.
    #[error("log writer of the host: {0}")]
    Log(#[from] RelayError),
    /// The log the host holds for this new node is not empty.
    #[error("the host already holds entries for this new node key; refusing to start")]
    LogNotEmpty,
    /// A socket failed.
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// The descriptor of `/dev/nsm`, closed when dropped. Requests take turns.
pub struct Nsm {
    fd: Mutex<i32>,
}

impl Nsm {
    /// Opens `/dev/nsm`.
    pub fn open() -> Result<Self, AttestError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(AttestError::Open);
        }
        Ok(Self { fd: Mutex::new(fd) })
    }

    fn request(&self, request: Request) -> Response {
        let fd = self.fd.lock().unwrap_or_else(PoisonError::into_inner);
        nsm_process_request(*fd, request)
    }

    /// Whether the enclave runs in debug mode: PCR0 is all zero then, and the parent instance
    /// can read the memory of the enclave. An attestation from it proves nothing, and a
    /// verifier refuses its zero PCRs.
    pub fn debug_mode(&self) -> Result<bool, AttestError> {
        match self.request(Request::DescribePCR { index: 0 }) {
            Response::DescribePCR { data, .. } => Ok(data.iter().all(|b| *b == 0)),
            Response::Error(code) => Err(AttestError::Nsm(format!("{code:?}"))),
            _ => Err(AttestError::Nsm("unexpected answer to DescribePCR".into())),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        let fd = self.fd.lock().unwrap_or_else(PoisonError::into_inner);
        nsm_exit(*fd);
    }
}

impl Attester for Nsm {
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestError> {
        let request = Request::Attestation {
            user_data: Some(user_data.to_vec().into()),
            nonce: Some(nonce.to_vec().into()),
            public_key: None,
        };
        match self.request(request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(code) => Err(AttestError::Nsm(format!("{code:?}"))),
            _ => Err(AttestError::Nsm("unexpected answer to Attestation".into())),
        }
    }
}

/// Refuses to start unless the kernel draws its randomness from the NSM: the node key is
/// generated from it.
pub fn check_entropy() -> Result<(), NitroError> {
    let current = std::fs::read_to_string(RNG_CURRENT)
        .map_err(|e| NitroError::Entropy(format!("unreadable ({e})")))?;
    if current.trim() != RNG_NSM {
        return Err(NitroError::Entropy(current.trim().to_string()));
    }
    Ok(())
}

fn dial(port: u32) -> io::Result<Box<dyn Socket>> {
    Ok(Box::new(Vsock::connect(PARENT_CID, port)?))
}

/// Boots the node and serves until the listener fails.
pub fn run() -> Result<(), NitroError> {
    check_entropy()?;
    let nsm = Nsm::open()?;
    if nsm.debug_mode()? {
        eprintln!(
            "warning: the enclave runs in debug mode: its PCRs are zero and no owner should \
             grant to it"
        );
    }
    // No sealed storage: every boot is a new node with a new key. Owners grant again.
    let key = NodeKey::generate();
    let (link, last) = LogLink::connect(|| dial(LOG_PORT), key.public())?;
    if last.is_some() {
        return Err(NitroError::LogNotEmpty);
    }
    let link = Arc::new(Mutex::new(link));
    let node = Node::new(key, RelaySink::new(Arc::clone(&link), None), SystemClock);
    let server = Server::new(
        node,
        || TlsTransport::new().connector(RelayConnector::new(|| dial(EGRESS_PORT))),
        Options::default(),
        EnclaveHooks::new(nsm, link),
    );
    server.checkpoint();
    let listener = vsock::listen(HTTP_PORT)?;
    eprintln!(
        "node {} started; listening on vsock port {HTTP_PORT}",
        server.node().public_key().to_b64()
    );
    server.run(listener.incoming().map(|stream| stream.map(Vsock)));
    Ok(())
}
