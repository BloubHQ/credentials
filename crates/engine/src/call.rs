//! A call as one value: what a caller signs and sends, and what a node runs.
//!
//! The record, operation and payload a caller signs are the ones the node checks, so they
//! travel together and cannot disagree. A [`SignedCall`] is plain data (JSON with base64url
//! bytes): an application builds it with [`CallerKey::sign_call`], sends it to the node by any
//! means, and the node runs it with [`crate::node::Node::run`].

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::caller::{Authorization, CallerExchange, Payload};
use crate::keys::{CallerKey, NodePublicKey};
use crate::node::{Clock, Response, StreamOutput, SystemClock};
use crate::policy::Destination;
use crate::record::Record;
use crate::request::Request;

/// What a call asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Body {
    /// An HTTP operation, with the request of the caller when a step sends one.
    Http {
        /// The request of the caller.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request: Option<Request>,
    },
    /// A stream operation.
    Stream {
        /// Where to connect (one of the destinations of the operation).
        destination: Destination,
        /// The exchanges after the script.
        exchanges: Vec<CallerExchange>,
    },
    /// A derivation.
    Derive {
        /// The input, `$input` to the template.
        #[serde(with = "crate::encoding::b64_vec")]
        input: Vec<u8>,
    },
}

impl Body {
    /// An HTTP call with the caller's request.
    pub fn http(request: Request) -> Self {
        Body::Http {
            request: Some(request),
        }
    }

    /// An HTTP call whose steps all send requests the policy fixes.
    pub fn http_fixed() -> Self {
        Body::Http { request: None }
    }

    /// A derivation of `input`.
    pub fn derive(input: &[u8]) -> Self {
        Body::Derive {
            input: input.to_vec(),
        }
    }

    pub(crate) fn payload(&self) -> Payload<'_> {
        match self {
            Body::Http { request } => Payload::Http(request.as_ref()),
            Body::Stream {
                destination,
                exchanges,
            } => Payload::Stream {
                destination,
                exchanges,
            },
            Body::Derive { input } => Payload::Derive(input),
        }
    }
}

/// One signed call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCall {
    /// The record to use.
    pub record: Record,
    /// The operation of its policy.
    pub operation: String,
    /// What the call asks for.
    pub body: Body,
    /// The caller's signature over all of the above, the node, the time and a nonce.
    pub auth: Authorization,
}

/// What an operation handed back.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    /// The last response of an HTTP operation.
    Http(Response),
    /// The reads of a stream operation.
    Stream(StreamOutput),
    /// The output of a derivation.
    Derive(Vec<u8>),
}

impl CallerKey {
    /// Signs a call of the caller named `caller` (its name in the policy) to `node`, now.
    pub fn sign_call(
        &self,
        caller: &str,
        node: &NodePublicKey,
        record: Record,
        operation: &str,
        body: Body,
    ) -> Result<SignedCall> {
        self.sign_call_at(caller, node, record, operation, body, SystemClock.now_ms())
    }

    /// [`CallerKey::sign_call`] at `time_ms` (Unix milliseconds).
    pub fn sign_call_at(
        &self,
        caller: &str,
        node: &NodePublicKey,
        record: Record,
        operation: &str,
        body: Body,
        time_ms: u64,
    ) -> Result<SignedCall> {
        let auth = self.authorize(caller, node, &record, operation, &body.payload(), time_ms)?;
        Ok(SignedCall {
            record,
            operation: operation.to_string(),
            body,
            auth,
        })
    }
}
