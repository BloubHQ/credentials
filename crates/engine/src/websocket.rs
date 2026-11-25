//! The WebSocket protocol (RFC 6455) on the client side: the opening handshake's key and
//! accept value, the frames the node sends, and a decoder of the frames a server sends.
//!
//! The decoder is strict: a server frame must not be masked, its reserved bits are zero (the
//! node offers no extension, so no compressed frame can hide a secret from the reflection
//! search), lengths use their shortest form, control frames are short and never fragmented,
//! a fragmented message is assembled whole before anything reads it, text is UTF-8, and a
//! message is at most the limit given.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

/// The GUID of RFC 6455, 1.3.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Longest payload of a control frame.
pub const MAX_CONTROL: usize = 125;

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

/// Why server frames could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The frame breaks RFC 6455; the text says how.
    #[error("WebSocket protocol error: {0}")]
    Protocol(&'static str),
    /// A message is larger than the limit.
    #[error("WebSocket message too large")]
    TooLarge,
}

/// A whole message (or control frame) from the server.
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    /// A text message (UTF-8, checked).
    Text(Zeroizing<Vec<u8>>),
    /// A binary message.
    Binary(Zeroizing<Vec<u8>>),
    /// A ping; the node answers with a pong of the same payload.
    Ping(Vec<u8>),
    /// A pong.
    Pong(Vec<u8>),
    /// The server closes, with its status code when it gave one.
    Close(Option<u16>),
}

/// A fresh `Sec-WebSocket-Key`: 16 random bytes in base64.
pub fn key() -> String {
    let mut nonce = [0u8; 16];
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    STANDARD.encode(nonce)
}

/// The `Sec-WebSocket-Accept` a server must answer to `key`.
pub fn accept(key: &str) -> String {
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(GUID);
    STANDARD.encode(hash.finalize())
}

/// A frame from the client: `FIN`, masked with a fresh random key.
pub fn encode(opcode: u8, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mask = [0u8; 4];
    UnwrapErr(SysRng).fill_bytes(&mut mask);
    encode_masked(opcode, payload, mask)
}

/// [`encode`] with a given mask (tests).
pub fn encode_masked(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 14));
    out.push(0x80 | (opcode & 0x0f));
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if let Ok(short) = u16::try_from(len) {
        out.push(0x80 | 126);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(
        payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, m)| byte ^ m),
    );
    out
}

/// The opcode of a text frame.
pub const OP_TEXT: u8 = TEXT;
/// The opcode of a binary frame.
pub const OP_BINARY: u8 = BINARY;
/// The opcode of a close frame.
pub const OP_CLOSE: u8 = CLOSE;
/// The opcode of a pong frame.
pub const OP_PONG: u8 = PONG;

/// One frame: FIN, opcode, payload.
type Frame = (bool, u8, Zeroizing<Vec<u8>>);

/// Reads the frames of a server out of the bytes that arrive.
pub struct Decoder {
    buf: Zeroizing<Vec<u8>>,
    /// The opcode and the payload of a message in fragments.
    partial: Option<(u8, Zeroizing<Vec<u8>>)>,
    max: usize,
}

impl Decoder {
    /// A decoder of messages of at most `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            partial: None,
            max,
        }
    }

    /// Adds bytes that arrived.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        // A frame header is at most 14 bytes: more buffered than a message and a header
        // cannot be one frame of the limit.
        if self.buf.len().saturating_add(bytes.len()) > self.max.saturating_add(14 + 1024) {
            return Err(FrameError::TooLarge);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// The next whole message, if the bytes so far hold one.
    pub fn message(&mut self) -> Result<Option<Message>, FrameError> {
        loop {
            let Some((fin, opcode, payload)) = self.frame()? else {
                return Ok(None);
            };
            let control = opcode & 0x8 != 0;
            if control {
                if !fin || payload.len() > MAX_CONTROL {
                    return Err(FrameError::Protocol("control frame fragmented or long"));
                }
                return Ok(Some(match opcode {
                    PING => Message::Ping(payload.to_vec()),
                    PONG => Message::Pong(payload.to_vec()),
                    CLOSE => Message::Close(close_code(&payload)?),
                    _ => return Err(FrameError::Protocol("unknown opcode")),
                }));
            }
            let (kind, mut data) = match (opcode, self.partial.take()) {
                (TEXT | BINARY, None) => (opcode, payload),
                (CONTINUATION, Some((kind, mut data))) => {
                    data.extend_from_slice(&payload);
                    (kind, data)
                }
                (CONTINUATION, None) => {
                    return Err(FrameError::Protocol("continuation without a message"));
                }
                (TEXT | BINARY, Some(_)) => {
                    return Err(FrameError::Protocol("new message inside a fragmented one"));
                }
                _ => return Err(FrameError::Protocol("unknown opcode")),
            };
            if data.len() > self.max {
                data.zeroize();
                return Err(FrameError::TooLarge);
            }
            if !fin {
                self.partial = Some((kind, data));
                continue;
            }
            return Ok(Some(if kind == TEXT {
                if core::str::from_utf8(&data).is_err() {
                    return Err(FrameError::Protocol("text that is not UTF-8"));
                }
                Message::Text(data)
            } else {
                Message::Binary(data)
            }));
        }
    }

    /// The next frame: FIN, opcode, payload.
    fn frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let (Some(&first), Some(&second)) = (self.buf.first(), self.buf.get(1)) else {
            return Ok(None);
        };
        if first & 0x70 != 0 {
            return Err(FrameError::Protocol(
                "reserved bits set (no extension was agreed)",
            ));
        }
        if second & 0x80 != 0 {
            return Err(FrameError::Protocol("a server frame is masked"));
        }
        let (len, at) = match second & 0x7f {
            126 => {
                let Some(bytes) = self.buf.get(2..4).and_then(|b| <[u8; 2]>::try_from(b).ok())
                else {
                    return Ok(None);
                };
                let len = u16::from_be_bytes(bytes);
                if len < 126 {
                    return Err(FrameError::Protocol("length not in its shortest form"));
                }
                (u64::from(len), 4)
            }
            127 => {
                let Some(bytes) = self
                    .buf
                    .get(2..10)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                else {
                    return Ok(None);
                };
                let len = u64::from_be_bytes(bytes);
                if len >> 63 != 0 || len <= u64::from(u16::MAX) {
                    return Err(FrameError::Protocol("length not in its shortest form"));
                }
                (len, 10)
            }
            short => (u64::from(short), 2),
        };
        let len = usize::try_from(len).map_err(|_| FrameError::TooLarge)?;
        if len > self.max {
            return Err(FrameError::TooLarge);
        }
        let Some(payload) = self.buf.get(at..at + len) else {
            return Ok(None);
        };
        let payload = Zeroizing::new(payload.to_vec());
        let rest = Zeroizing::new(self.buf.get(at + len..).unwrap_or_default().to_vec());
        self.buf = rest;
        Ok(Some((first & 0x80 != 0, first & 0x0f, payload)))
    }
}

fn close_code(payload: &[u8]) -> Result<Option<u16>, FrameError> {
    match payload {
        [] => Ok(None),
        [_] => Err(FrameError::Protocol("close payload of one byte")),
        [a, b, reason @ ..] => {
            if core::str::from_utf8(reason).is_err() {
                return Err(FrameError::Protocol("close reason that is not UTF-8"));
            }
            Ok(Some(u16::from_be_bytes([*a, *b])))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A server frame (unmasked).
    fn server(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
        if payload.len() < 126 {
            out.push(payload.len() as u8);
        } else {
            out.push(126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn rfc_accept_value() {
        // RFC 6455, 1.3.
        assert_eq!(
            accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(key().len(), 24);
    }

    #[test]
    fn client_frames_are_masked() {
        // RFC 6455, 5.7: "Hello", masked.
        let frame = encode_masked(TEXT, b"Hello", [0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(
            frame.as_slice(),
            [
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
        assert_eq!(encode(BINARY, &[0; 300])[1], 0x80 | 126);
        assert_eq!(encode(BINARY, &[0; 70_000])[1], 0x80 | 127);
    }

    #[test]
    fn messages_in_fragments_and_split_reads() {
        let mut bytes = server(false, TEXT, b"Hel");
        bytes.extend(server(true, PING, b"p"));
        bytes.extend(server(true, CONTINUATION, b"lo"));
        bytes.extend(server(true, BINARY, &[1, 2]));
        let mut d = Decoder::new(1024);
        let mut got = Vec::new();
        for byte in bytes {
            d.push(&[byte]).unwrap();
            while let Some(m) = d.message().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(
            got,
            [
                Message::Ping(b"p".to_vec()),
                Message::Text(Zeroizing::new(b"Hello".to_vec())),
                Message::Binary(Zeroizing::new(vec![1, 2])),
            ]
        );
    }

    #[test]
    fn malformed_frames_are_refused() {
        let masked = vec![0x81, 0x81, 0, 0, 0, 0, b'a'];
        let long_form = vec![0x82, 126, 0, 5, 1, 2, 3, 4, 5];
        let cases: Vec<Vec<u8>> = vec![
            masked,
            vec![0xc1, 0x01, b'a'],
            vec![0x83, 0x00],
            server(false, PING, b""),
            server(true, PING, &[0; 126]),
            server(true, CONTINUATION, b"x"),
            [server(false, TEXT, b"a"), server(true, TEXT, b"b")].concat(),
            server(true, TEXT, &[0xff, 0xfe]),
            server(true, CLOSE, &[3]),
            long_form,
        ];
        for (i, case) in cases.into_iter().enumerate() {
            let mut d = Decoder::new(1024);
            d.push(&case).unwrap();
            assert!(
                matches!(d.message(), Err(FrameError::Protocol(_))),
                "case {i}"
            );
        }
        let mut d = Decoder::new(4);
        d.push(&server(true, BINARY, b"12345")).unwrap();
        assert_eq!(d.message(), Err(FrameError::TooLarge));
        let mut d = Decoder::new(4);
        d.push(&server(false, BINARY, b"123")).unwrap();
        d.push(&server(true, CONTINUATION, b"45")).unwrap();
        assert_eq!(d.message(), Err(FrameError::TooLarge));
    }

    #[test]
    fn close_codes() {
        let mut d = Decoder::new(16);
        d.push(&server(true, CLOSE, &[0x03, 0xe8, b'o', b'k']))
            .unwrap();
        assert_eq!(d.message().unwrap(), Some(Message::Close(Some(1000))));
    }
}
