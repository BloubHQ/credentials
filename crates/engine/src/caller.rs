//! Callers: who asks a node to use a record.
//!
//! Every call carries an [`Authorization`]: the caller signs the node, the record (owner, id,
//! generation), the operation, a digest of what it asks for ([`Payload`]), the time and a
//! random nonce. A node accepts it only from a caller the policy lists for that operation,
//! within [`MAX_SKEW_MS`] of its clock, once.

use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{b64_array, canonical};
use crate::keys::{CallerKey, CallerPublicKey, NodePublicKey};
use crate::policy::Destination;
use crate::record::Record;
use crate::request::Request;
use crate::{Error, Result};

const AUTH_DOMAIN: &[u8] = b"call/v1\0";

/// The operation name a caller signs to ask for the description of a typed item. It is not a
/// token, so no operation of a policy can have it.
pub const DESCRIBE: &str = ":describe";

/// The rule of [`Error::CallerInvalid`] when the signature of a call does not verify.
pub const BAD_SIGNATURE: &str = concat!(
    "signature does not verify: sign the same record generation, operation and request ",
    "the node is given (a SignedCall keeps them together)"
);

/// Largest difference between the time of an authorization and the clock of the node.
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// One exchange of the caller on an authenticated stream: bytes written, then bytes read up to
/// and including the first of the delimiters `until`.
///
/// In JSON the bytes are base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerExchange {
    /// What is written.
    #[serde(with = "crate::encoding::b64_vec")]
    pub send: Vec<u8>,
    /// The delimiters that end the read.
    #[serde(with = "crate::encoding::b64_list")]
    pub until: Vec<Vec<u8>>,
}

/// What a call asks for.
#[derive(Clone, Copy, Debug)]
pub enum Payload<'a> {
    /// An HTTP operation, with the request of the caller when it sends one.
    Http(Option<&'a Request>),
    /// A stream operation.
    Stream {
        /// Where.
        destination: &'a Destination,
        /// The exchanges.
        exchanges: &'a [CallerExchange],
    },
    /// A derivation.
    Derive(&'a [u8]),
    /// The description of a typed item.
    Describe,
    /// Goes on with the waiting operation of this id.
    Resume(&'a [u8; 16]),
}

fn part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

impl Payload<'_> {
    /// SHA-256 over the parts of the payload, each prefixed by its length.
    pub fn sha256(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        match self {
            Payload::Http(None) => part(&mut h, b"http"),
            Payload::Http(Some(r)) => {
                part(&mut h, b"http-request");
                part(&mut h, r.method.as_str().as_bytes());
                part(&mut h, r.destination.host.as_bytes());
                part(&mut h, &r.destination.port.to_be_bytes());
                part(&mut h, r.path.as_bytes());
                part(&mut h, &(r.headers.len() as u64).to_be_bytes());
                for (name, value) in &r.headers {
                    part(&mut h, name.as_bytes());
                    part(&mut h, value.as_bytes());
                }
                part(&mut h, &r.body);
            }
            Payload::Stream {
                destination,
                exchanges,
            } => {
                part(&mut h, b"stream");
                part(&mut h, destination.host.as_bytes());
                part(&mut h, &destination.port.to_be_bytes());
                part(&mut h, &(exchanges.len() as u64).to_be_bytes());
                for e in *exchanges {
                    part(&mut h, &e.send);
                    part(&mut h, &(e.until.len() as u64).to_be_bytes());
                    for u in &e.until {
                        part(&mut h, u);
                    }
                }
            }
            Payload::Derive(input) => {
                part(&mut h, b"derive");
                part(&mut h, input);
            }
            Payload::Describe => part(&mut h, b"describe"),
            Payload::Resume(id) => {
                part(&mut h, b"resume");
                part(&mut h, id.as_slice());
            }
        }
        h.finalize().into()
    }
}

/// The signature of a caller over one call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    /// The name of the caller in the policy.
    pub caller: String,
    /// When the caller signed, Unix milliseconds.
    pub time_ms: u64,
    /// Random; a node accepts each nonce once.
    #[serde(with = "b64_array")]
    pub nonce: [u8; 16],
    /// Ed25519 signature of the caller.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct Body<'a> {
    node: &'a NodePublicKey,
    owner: &'a str,
    record_id: &'a str,
    generation: u64,
    operation: &'a str,
    #[serde(with = "b64_array")]
    payload: [u8; 32],
    caller: &'a str,
    time_ms: u64,
    #[serde(with = "b64_array")]
    nonce: [u8; 16],
}

/// What an authorization is about.
pub(crate) struct Call<'a> {
    pub node: &'a NodePublicKey,
    pub record: &'a Record,
    pub operation: &'a str,
    pub payload: [u8; 32],
}

impl Authorization {
    fn message(&self, call: &Call<'_>) -> Result<Vec<u8>> {
        canonical(
            AUTH_DOMAIN,
            &Body {
                node: call.node,
                owner: &call.record.owner,
                record_id: &call.record.id,
                generation: call.record.generation,
                operation: call.operation,
                payload: call.payload,
                caller: &self.caller,
                time_ms: self.time_ms,
                nonce: self.nonce,
            },
        )
    }

    pub(crate) fn verify(&self, key: &CallerPublicKey, call: &Call<'_>) -> Result<()> {
        key.verify(&self.message(call)?, &self.signature)
            .map_err(|_| Error::CallerInvalid {
                rule: BAD_SIGNATURE,
            })
    }
}

impl CallerKey {
    /// Signs one call of the caller named `caller` to `node`: `operation` of `record` with
    /// `payload`, at `time_ms`.
    pub fn authorize(
        &self,
        caller: &str,
        node: &NodePublicKey,
        record: &Record,
        operation: &str,
        payload: &Payload<'_>,
        time_ms: u64,
    ) -> Result<Authorization> {
        let mut nonce = [0u8; 16];
        UnwrapErr(SysRng).fill_bytes(&mut nonce);
        let mut auth = Authorization {
            caller: caller.to_string(),
            time_ms,
            nonce,
            signature: [0; 64],
        };
        let call = Call {
            node,
            record,
            operation,
            payload: payload.sha256(),
        };
        auth.signature = self.sign(&auth.message(&call)?);
        Ok(auth)
    }
}
