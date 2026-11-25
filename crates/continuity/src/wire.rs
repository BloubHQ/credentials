//! The hand-over over the host: each enclave listens on vsock port [`HANDOVER_PORT`] and
//! answers [`Request`]s with [`Response`]s; `credentials host hand-over` connects to both
//! enclaves and carries the four messages of [`crate::protocol`] between them ([`drive`]).
//!
//! Framing: a 4-byte big-endian length, then that many bytes of JSON. The host is not
//! trusted: every message is checked by the enclave that receives it, and the state travels
//! sealed to the successor's key. A frame longer than [`MAX_FRAME`] is refused before it is
//! read.

use std::io::{Read, Write};

use engine::log::LogSink;
use engine::node::{Clock, Node, TakenOver};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::protocol::{Attester, Challenge, Checks, Offer, Package, Predecessor, SuccessorSide};
use crate::statement::SignedStatement;
use crate::{Error, Result};

/// The vsock port of the hand-over in an enclave.
pub const HANDOVER_PORT: u32 = 5003;

/// The largest frame: a package of [`engine::node::MAX_PACKAGE`] bytes in base64url, and room
/// for the rest.
pub const MAX_FRAME: usize = engine::node::MAX_PACKAGE / 3 * 4 + 1024 * 1024;

/// What the host asks an enclave.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// To the predecessor: message 1.
    Challenge {},
    /// To the successor: message 2, answering `challenge` on `statement`.
    Offer {
        /// The predecessor's challenge.
        challenge: Challenge,
        /// The successor statement.
        statement: SignedStatement,
    },
    /// To the predecessor: message 3, handing over to the successor of `offer`.
    HandOver {
        /// The successor's offer.
        offer: Offer,
        /// The successor statement.
        statement: SignedStatement,
    },
    /// To the successor: message 4.
    TakeOver {
        /// The predecessor's package.
        package: Box<Package>,
        /// The successor statement.
        statement: SignedStatement,
    },
}

/// What an enclave answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Message 1.
    Challenge(Challenge),
    /// Message 2.
    Offer(Offer),
    /// Message 3.
    Package(Box<Package>),
    /// The successor took over.
    TakenOver {
        /// Owners whose state moved.
        owners: u64,
        /// Grants that moved.
        grants: u64,
    },
    /// The enclave refused; nothing moved on this side.
    Refused {
        /// Why.
        reason: String,
    },
}

/// Writes one frame.
pub fn write_frame<W: Write, T: Serialize>(stream: &mut W, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).map_err(|_| Error::Protocol("cannot encode a frame"))?;
    if body.len() > MAX_FRAME {
        return Err(Error::Protocol("a frame is too long"));
    }
    let len = u32::try_from(body.len()).map_err(|_| Error::Protocol("a frame is too long"))?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(|e| Error::Transport(e.to_string()))
}

/// Reads one frame; `None` at the end of the stream.
pub fn read_frame<R: Read, T: DeserializeOwned>(stream: &mut R) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Transport(e.to_string())),
    }
    let len = usize::try_from(u32::from_be_bytes(len))
        .map_err(|_| Error::Protocol("a frame is too long"))?;
    if len > MAX_FRAME {
        return Err(Error::Protocol("a frame is too long"));
    }
    let mut body = Vec::new();
    stream
        .take(u64::try_from(len).map_err(|_| Error::Protocol("a frame is too long"))?)
        .read_to_end(&mut body)
        .map_err(|e| Error::Transport(e.to_string()))?;
    if body.len() != len {
        return Err(Error::Transport("the stream ended inside a frame".into()));
    }
    parse_frame(&body).map(Some)
}

/// Reads the JSON of a frame.
pub fn parse_frame<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Error::Protocol("a frame is not a message"))
}

/// The hand-over service of one node.
pub struct Service<'a, S: LogSink, C: Clock, A: Attester> {
    node: &'a Node<S, C>,
    attester: A,
    predecessor: Predecessor,
    successor: SuccessorSide,
}

impl<'a, S: LogSink, C: Clock, A: Attester> Service<'a, S, C, A> {
    /// The service of `node`, which attests with `attester` and checks with `checks`.
    pub fn new(node: &'a Node<S, C>, attester: A, checks: Checks) -> Self {
        Self {
            node,
            attester,
            predecessor: Predecessor::new(checks.clone()),
            successor: SuccessorSide::new(checks),
        }
    }

    /// Answers one request at `now` (Unix milliseconds).
    pub fn answer(&self, request: Request, now: u64) -> Response {
        let refused = |e: Error| Response::Refused {
            reason: e.to_string(),
        };
        match request {
            Request::Challenge {} => self
                .predecessor
                .challenge(self.node, now)
                .map_or_else(refused, Response::Challenge),
            Request::Offer {
                challenge,
                statement,
            } => self
                .successor
                .offer(self.node, &self.attester, &challenge, &statement, now)
                .map_or_else(refused, Response::Offer),
            Request::HandOver { offer, statement } => self
                .predecessor
                .hand_over(self.node, &self.attester, &offer, &statement, now)
                .map_or_else(refused, |p| Response::Package(Box::new(p))),
            Request::TakeOver { package, statement } => self
                .successor
                .take_over(self.node, &package, &statement, now)
                .map_or_else(refused, |t| Response::TakenOver {
                    owners: t.owners,
                    grants: t.grants,
                }),
        }
    }

    /// Answers the requests of one connection until it ends.
    pub fn serve<T: Read + Write>(&self, stream: &mut T) -> Result<()> {
        while let Some(request) = read_frame::<_, Request>(stream)? {
            let response = self.answer(request, engine::node::now_ms());
            write_frame(stream, &response)?;
        }
        Ok(())
    }
}

fn ask<T: Read + Write>(stream: &mut T, request: &Request) -> Result<Response> {
    write_frame(stream, request)?;
    match read_frame::<_, Response>(stream)? {
        Some(Response::Refused { reason }) => Err(Error::Refused(reason)),
        Some(response) => Ok(response),
        None => Err(Error::Transport("the enclave closed the connection".into())),
    }
}

/// The host's side: carries the four messages between the predecessor (`old`) and the
/// successor (`new`). The host learns nothing it could use: it sees the identities, the
/// attestation documents and the sealed package.
pub fn drive<O: Read + Write, N: Read + Write>(
    old: &mut O,
    new: &mut N,
    statement: &SignedStatement,
) -> Result<TakenOver> {
    let unexpected = || Error::Protocol("an enclave answered out of turn");
    let Response::Challenge(challenge) = ask(old, &Request::Challenge {})? else {
        return Err(unexpected());
    };
    let Response::Offer(offer) = ask(
        new,
        &Request::Offer {
            challenge,
            statement: statement.clone(),
        },
    )?
    else {
        return Err(unexpected());
    };
    let Response::Package(package) = ask(
        old,
        &Request::HandOver {
            offer,
            statement: statement.clone(),
        },
    )?
    else {
        return Err(unexpected());
    };
    let Response::TakenOver { owners, grants } = ask(
        new,
        &Request::TakeOver {
            package,
            statement: statement.clone(),
        },
    )?
    else {
        return Err(unexpected());
    };
    Ok(TakenOver { owners, grants })
}
