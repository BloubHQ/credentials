//! The one sink of secret bytes.
//!
//! [`Transport::send`] and the [`Stream`]s of [`Transport::open`] are the only places where
//! bytes that hold a secret leave the engine, together with the [`ClientIdentity`] of a mutual
//! TLS handshake. The engine calls them only with a [`Confirmed`] of the entry of that act,
//! and only for the destination of that entry. An implementation must speak TLS that ends at
//! `destination` and nowhere else, and must not keep the identity after the connection.

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
    pub(crate) fn new(cert: Zeroizing<Vec<u8>>, key: Zeroizing<Vec<u8>>) -> Self {
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

/// An open TLS connection.
pub trait Stream {
    /// Writes all of `bytes`.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
    /// Reads until one of `delimiters` was read and returns it with what came before. Fails
    /// with [`TransportKind::TooLarge`] after `max` bytes without a delimiter.
    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> Result<Vec<u8>>;

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
}

/// Hands the bytes to the transport. Consumes the confirmation: one entry, one request.
pub(crate) fn dispatch<T: Transport>(
    confirmed: Confirmed,
    transport: &mut T,
    destination: &Destination,
    identity: Option<&ClientIdentity>,
    wire: &Secret<Vec<u8>>,
) -> Result<(u64, Vec<u8>)> {
    let seq = confirmed.seq();
    let max = crate::response::MAX_RESPONSE;
    let mut response = transport.send(destination, identity, wire.expose(), max)?;
    if response.len() > max {
        zeroize::Zeroize::zeroize(&mut response);
        return Err(Error::transport(TransportKind::TooLarge, true));
    }
    Ok((seq, response))
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
