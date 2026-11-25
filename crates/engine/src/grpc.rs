//! gRPC over HTTP/2 for unary calls: the length-prefixed message the node sends, and the one
//! it reads back.
//!
//! A gRPC `send` sets `content-type: application/grpc` and `te: trailers`, frames the body
//! as one uncompressed message, and pins the connection to HTTP/2 (the policy check refuses
//! it otherwise). The `grpc-status` and `grpc-message` of the answer come in its trailers
//! (or in its head, for an answer without a message), where captures and the projection read
//! them like headers.

use zeroize::Zeroizing;

use crate::{Error, Result};

/// The fixed end of the head of a gRPC request, in HTTP/1.1 form (the transport turns it
/// into HTTP/2 fields and drops the connection-specific ones).
pub(crate) const HEADERS: &[u8] = b"Content-Type: application/grpc\r\nTE: trailers\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";

/// The length-prefixed form of one message: no compression, the length in four bytes.
pub fn frame(message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(message.len()).map_err(|_| Error::Budget { what: "body" })?;
    let mut out = Zeroizing::new(Vec::with_capacity(message.len() + 5));
    out.push(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// The message of a unary answer: none (an answer that only carries a status) or exactly
/// one, uncompressed, whose length is the rest of the body.
pub fn unframe(body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let Some((&flag, rest)) = body.split_first() else {
        return Ok(Zeroizing::new(Vec::new()));
    };
    if flag != 0 {
        // The node offers no compression; a compressed message would hide its bytes from the
        // reflection search.
        return Err(invalid("compressed gRPC message"));
    }
    let len = rest
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or(invalid("gRPC message prefix"))?;
    let message = rest.get(4..).unwrap_or_default();
    if usize::try_from(len).ok() != Some(message.len()) {
        return Err(invalid("gRPC message length, or more than one message"));
    }
    Ok(Zeroizing::new(message.to_vec()))
}

/// True when a content type is gRPC (`application/grpc`, `application/grpc+proto`).
pub fn is_grpc(content_type: &[u8]) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower == b"application/grpc" || lower.starts_with(b"application/grpc+")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_refusals() {
        let framed = frame(b"\x0a\x03abc").unwrap();
        assert_eq!(framed.as_slice(), b"\x00\x00\x00\x00\x05\x0a\x03abc");
        assert_eq!(unframe(&framed).unwrap().as_slice(), b"\x0a\x03abc");
        assert!(unframe(b"").unwrap().is_empty());
        // Compressed, truncated prefix, two messages, a short message.
        for bad in [
            &b"\x01\x00\x00\x00\x01x"[..],
            b"\x00\x00\x00",
            b"\x00\x00\x00\x00\x01x\x00\x00\x00\x00\x01y",
            b"\x00\x00\x00\x00\x05xy",
        ] {
            assert!(unframe(bad).is_err());
        }
        assert!(is_grpc(b"application/grpc+proto"));
        assert!(!is_grpc(b"application/grpc-web"));
    }
}
