//! The one sink of secret bytes.
//!
//! [`Transport::send`] and the [`Stream`]s of [`Transport::open`] are the only places where
//! bytes that hold a secret leave the engine, together with the [`ClientIdentity`] of a mutual
//! TLS handshake. The engine calls them only with a [`Confirmed`] of the entry of that act,
//! and only for the destination of that entry. An implementation must speak TLS that ends at
//! `destination` and nowhere else, and must not keep the identity after the connection.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::TransportKind;
use crate::log::Confirmed;
use crate::policy::Destination;
use crate::secret::Secret;
use crate::{Error, Result};

/// A client certificate and its private key, rendered from the templates of an operation.
pub struct ClientIdentity {
    cert: Secret<Vec<u8>>,
    key: Secret<Vec<u8>>,
}

impl ClientIdentity {
    /// An identity from a certificate chain and a private key (PEM). The engine makes these
    /// from the templates of an operation; transports and their tests may make their own.
    pub fn new(cert: Zeroizing<Vec<u8>>, key: Zeroizing<Vec<u8>>) -> Self {
        Self {
            cert: Secret::new(cert.to_vec()),
            key: Secret::new(key.to_vec()),
        }
    }

    /// The certificate chain, as the policy renders it.
    pub fn cert(&self) -> &[u8] {
        self.cert.expose()
    }

    /// The private key, as the policy renders it. For the TLS handshake only.
    pub fn key(&self) -> &[u8] {
        self.key.expose()
    }
}

impl core::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientIdentity(<redacted>)")
    }
}

/// The HTTP versions an HTTPS request may go over: the pin of the policy (`open.protocol`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Versions {
    /// HTTP/2 when the server offers it (ALPN `h2`), else HTTP/1.1.
    #[default]
    Any,
    /// HTTP/1.1 only (ALPN `http/1.1`).
    #[serde(rename = "http1")]
    Http1,
    /// HTTP/2 only (ALPN `h2`): a server that does not agree to it is refused.
    #[serde(rename = "h2")]
    Http2,
}

impl Versions {
    /// True when a request may go over `version`.
    pub fn allows(self, version: Version) -> bool {
        match self {
            Versions::Any => true,
            Versions::Http1 => version == Version::Http1,
            Versions::Http2 => version == Version::Http2,
        }
    }
}

/// The HTTP version a request went over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.1.
    Http1,
    /// HTTP/2.
    Http2,
}

/// What a read of a live connection found.
#[derive(Debug, PartialEq, Eq)]
pub enum Arrived {
    /// Bytes that came.
    Bytes(Vec<u8>),
    /// Nothing came within the wait.
    Nothing,
    /// The peer ended the connection (or the response) cleanly.
    End,
}

/// An open TLS connection.
pub trait Stream {
    /// Writes all of `bytes`.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
    /// Reads until one of `delimiters` was read and returns it with what came before. Fails
    /// with [`TransportKind::TooLarge`] after `max` bytes without a delimiter.
    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> Result<Vec<u8>>;

    /// Reads at most `max` bytes of what arrives within `wait`. Bytes a [`Stream::read_until`]
    /// read past its delimiter come first. The default refuses.
    fn read_some(&mut self, max: usize, wait: Duration) -> Result<Arrived> {
        let _ = (max, wait);
        Err(Error::transport(TransportKind::Unsupported, true))
    }

    /// Ends the connection. The default does nothing; the connection ends when dropped.
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Sends requests and opens connections.
pub trait Transport {
    /// Sends `wire` to `destination` over TLS (presenting `identity`, when given) and returns
    /// the response bytes. It should stop reading after `max_response` bytes and fail with
    /// [`TransportKind::TooLarge`]; the engine refuses a longer response anyway.
    fn send(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        max_response: usize,
    ) -> Result<Vec<u8>>;

    /// Opens a TLS connection to `destination`. A transport without streams keeps the default,
    /// which refuses.
    fn open(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
    ) -> Result<Box<dyn Stream + '_>> {
        let _ = (destination, identity);
        Err(Error::transport(TransportKind::Unsupported, false))
    }

    /// Sends one HTTP request over a version `versions` allows and returns the response with
    /// the version used. `wire` is the request in HTTP/1.1 form, as the engine built it; the
    /// response comes back in HTTP/1.1 form too (an HTTP/2 response is written as HTTP/1.1
    /// with a chunked body and its trailers), so one parser reads both.
    ///
    /// The default sends over HTTP/1.1 with [`Transport::send`] and refuses a request the
    /// policy pins to HTTP/2.
    fn exchange(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        max_response: usize,
        versions: Versions,
    ) -> Result<(Vec<u8>, Version)> {
        if !versions.allows(Version::Http1) {
            return Err(Error::transport(TransportKind::Downgrade, false));
        }
        self.send(destination, identity, wire, max_response)
            .map(|bytes| (bytes, Version::Http1))
    }

    /// Sends one HTTP request like [`Transport::exchange`] and hands back the connection, so
    /// the response is read as it arrives ([`Stream::read_some`], [`Stream::read_until`]),
    /// in HTTP/1.1 form. Over HTTP/1.1 the connection stays usable both ways after the
    /// response head (a WebSocket upgrade). The default refuses.
    fn exchange_streamed(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        versions: Versions,
    ) -> Result<(Box<dyn Stream + '_>, Version)> {
        let _ = (destination, identity, wire, versions);
        Err(Error::transport(TransportKind::Unsupported, false))
    }

    /// Opens a TCP connection with no TLS, for a protocol that encrypts itself (SSH): the
    /// engine writes nothing secret on it before its own key exchange has authenticated the
    /// server. The default refuses.
    fn open_plain(&mut self, destination: &Destination) -> Result<Box<dyn Stream + '_>> {
        let _ = destination;
        Err(Error::transport(TransportKind::Unsupported, false))
    }

    /// Opens a TCP connection, runs `prelude` on it in the clear (the `STARTTLS` exchange of
    /// a protocol, written by the engine, which carries nothing secret), then makes TLS to
    /// `destination` on the same connection and returns it. Bytes the server sent in the clear
    /// that the prelude did not read fail the call: they could be read as if they came over
    /// TLS. The default refuses.
    fn open_starttls(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        prelude: &mut dyn FnMut(&mut dyn Stream) -> Result<()>,
    ) -> Result<Box<dyn Stream + '_>> {
        let _ = (destination, identity, prelude);
        Err(Error::transport(TransportKind::Unsupported, false))
    }
}

/// How a protocol connection is opened.
pub(crate) enum Opening<'p> {
    /// TLS from the first byte.
    Tls,
    /// TCP; the protocol encrypts itself.
    Plain,
    /// A plain prelude, then TLS.
    Starttls(&'p mut dyn FnMut(&mut dyn Stream) -> Result<()>),
}

/// Opens the connection of a protocol operation. Consumes the confirmation: one entry, one
/// connection.
pub(crate) fn open_protocol<'t, T: Transport>(
    confirmed: Confirmed,
    transport: &'t mut T,
    destination: &Destination,
    identity: Option<&ClientIdentity>,
    opening: Opening<'_>,
) -> Result<(u64, Box<dyn Stream + 't>)> {
    let seq = confirmed.seq();
    let stream = match opening {
        Opening::Tls => transport.open(destination, identity)?,
        Opening::Plain => transport.open_plain(destination)?,
        Opening::Starttls(prelude) => transport.open_starttls(destination, identity, prelude)?,
    };
    Ok((seq, stream))
}

/// Hands the bytes to the transport. Consumes the confirmation: one entry, one request.
pub(crate) fn dispatch<T: Transport>(
    confirmed: Confirmed,
    transport: &mut T,
    destination: &Destination,
    identity: Option<&ClientIdentity>,
    wire: &Secret<Vec<u8>>,
    versions: Versions,
) -> Result<(u64, Vec<u8>)> {
    let seq = confirmed.seq();
    let max = crate::response::MAX_RESPONSE;
    let (mut response, version) =
        transport.exchange(destination, identity, wire.expose(), max, versions)?;
    // The transport is checked too: a response over a version the policy does not allow is
    // dropped unread.
    if !versions.allows(version) {
        zeroize::Zeroize::zeroize(&mut response);
        return Err(Error::transport(TransportKind::Downgrade, true));
    }
    if response.len() > max {
        zeroize::Zeroize::zeroize(&mut response);
        return Err(Error::transport(TransportKind::TooLarge, true));
    }
    Ok((seq, response))
}

/// Sends one request and hands back the connection its response arrives on. Consumes the
/// confirmation: one entry, one request.
pub(crate) fn dispatch_streamed<'t, T: Transport>(
    confirmed: Confirmed,
    transport: &'t mut T,
    destination: &Destination,
    identity: Option<&ClientIdentity>,
    wire: &Secret<Vec<u8>>,
    versions: Versions,
) -> Result<(u64, Box<dyn Stream + 't>)> {
    let seq = confirmed.seq();
    let (stream, version) =
        transport.exchange_streamed(destination, identity, wire.expose(), versions)?;
    if !versions.allows(version) {
        return Err(Error::transport(TransportKind::Downgrade, true));
    }
    Ok((seq, stream))
}

/// Opens the connection of a stream operation. Consumes the confirmation: one entry, one
/// connection.
pub(crate) fn open_stream<'t, T: Transport>(
    confirmed: Confirmed,
    transport: &'t mut T,
    destination: &Destination,
    identity: Option<&ClientIdentity>,
) -> Result<(u64, Box<dyn Stream + 't>)> {
    let seq = confirmed.seq();
    let stream = transport.open(destination, identity)?;
    Ok((seq, stream))
}
