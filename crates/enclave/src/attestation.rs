//! The attestation endpoint, and the hooks of the enclave server.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::encoding::to_b64;
use engine::grant::NodeIdentity;
use engine::log::SignedHead;
use serde_json::json;
use server::relay::{SharedLink, send_head};
use server::{Hooks, Reply, Request, error_reply};

/// Largest nonce the NSM takes, in bytes.
pub const MAX_NONCE: usize = 512;

/// Why no attestation document was made.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    /// `/dev/nsm` could not be opened.
    #[error("cannot open /dev/nsm")]
    Open,
    /// The NSM answered with an error, or with something else than was asked.
    #[error("the NSM refused the request: {0}")]
    Nsm(String),
}

/// Makes attestation documents: the NSM in an enclave, a stand-in in tests.
pub trait Attester: Send + Sync {
    /// A signed attestation document that carries `user_data` and `nonce`.
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestError>;
}

/// Answers `GET /attestation?nonce=<base64url>` with `{identity, document}`: the identity of
/// the node and an attestation document (base64url) whose user data is
/// [`NodeIdentity::report_data`] of that identity and whose nonce is the one given.
pub fn attestation_reply(
    attester: &dyn Attester,
    request: &Request,
    identity: &NodeIdentity,
) -> Reply {
    if request.method != "GET" {
        return error_reply(405, format!("method {} not allowed here", request.method));
    }
    let Some(nonce) = request.query_param("nonce") else {
        return error_reply(
            400,
            "give a fresh nonce: /attestation?nonce=<base64url>".into(),
        );
    };
    let nonce = match URL_SAFE_NO_PAD.decode(nonce) {
        Ok(nonce) if !nonce.is_empty() && nonce.len() <= MAX_NONCE => nonce,
        Ok(_) => {
            return error_reply(400, format!("the nonce must be 1 to {MAX_NONCE} bytes"));
        }
        Err(_) => return error_reply(400, "the nonce is not base64url without padding".into()),
    };
    match attester.attest(&identity.report_data(), &nonce) {
        Ok(document) => (
            200,
            json!({ "identity": identity, "document": to_b64(&document) }),
        ),
        Err(e) => error_reply(500, e.to_string()),
    }
}

/// The hooks of the node server in an enclave: checkpoints go to the log writer of the host,
/// and `/attestation` is answered by the attester.
pub struct EnclaveHooks<A> {
    attester: A,
    link: SharedLink,
}

impl<A: Attester> EnclaveHooks<A> {
    /// Hooks that attest with `attester` and send checkpoints over `link`.
    pub fn new(attester: A, link: SharedLink) -> Self {
        Self { attester, link }
    }
}

impl<A: Attester> Hooks for EnclaveHooks<A> {
    fn checkpoint(&self, head: &SignedHead) {
        if let Err(e) = send_head(&self.link, head) {
            eprintln!("warning: the host did not keep a checkpoint: {e}");
        }
    }

    fn route(&self, request: &Request, identity: &NodeIdentity) -> Option<Reply> {
        (request.path == "/attestation")
            .then(|| attestation_reply(&self.attester, request, identity))
    }
}

#[cfg(test)]
mod tests {
    use engine::keys::NodeKey;
    use engine::node::{Node, SystemClock};

    use super::*;

    /// A stand-in for the NSM: the "document" is the user data followed by the nonce.
    struct Echo;

    impl Attester for Echo {
        fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestError> {
            Ok([user_data, nonce].concat())
        }
    }

    struct Refuse;

    impl Attester for Refuse {
        fn attest(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, AttestError> {
            Err(AttestError::Nsm("InternalError".into()))
        }
    }

    fn request(method: &str, query: &str) -> Request {
        Request {
            method: method.into(),
            path: "/attestation".into(),
            query: query.into(),
            body: Vec::new(),
        }
    }

    fn identity() -> NodeIdentity {
        Node::new(NodeKey::generate(), Discard, SystemClock).identity()
    }

    struct Discard;

    impl engine::log::LogSink for Discard {
        fn append(&mut self, _: &engine::log::SignedEntry) -> engine::Result<()> {
            Err(engine::Error::LogUnconfirmed)
        }
    }

    #[test]
    fn the_document_binds_the_identity_and_the_nonce() {
        let identity = identity();
        let nonce = [9u8; 32];
        let query = format!("nonce={}", to_b64(&nonce));
        let (status, body) = attestation_reply(&Echo, &request("GET", &query), &identity);
        assert_eq!(status, 200);
        let expected = [identity.report_data().as_slice(), &nonce].concat();
        assert_eq!(body.get("document"), Some(&json!(to_b64(&expected))));
        assert_eq!(body.get("identity"), Some(&json!(identity)));
    }

    #[test]
    fn bad_requests_are_refused() {
        let identity = identity();
        let status = |method: &str, query: &str| {
            attestation_reply(&Echo, &request(method, query), &identity).0
        };
        assert_eq!(status("GET", ""), 400);
        assert_eq!(status("GET", "nonce="), 400);
        assert_eq!(status("GET", "nonce=***"), 400);
        assert_eq!(
            status("GET", &format!("nonce={}", to_b64(&[0u8; 513]))),
            400
        );
        assert_eq!(status("POST", "nonce=AA"), 405);
        assert_eq!(
            status("GET", &format!("nonce={}", to_b64(&[0u8; 512]))),
            200
        );
        let refused = attestation_reply(&Refuse, &request("GET", "nonce=AA"), &identity);
        assert_eq!(refused.0, 500);
    }
}
