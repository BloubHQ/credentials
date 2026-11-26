//! An AMQP 0-9-1 client over TLS from the first byte: SASL `PLAIN` only, one channel with
//! publisher confirms, `basic.publish` to the exchanges and routing keys the policy fixes and
//! `basic.get` from the queues it fixes.
//!
//! What it refuses, and why:
//!
//! - any mechanism but `PLAIN` (it is the policy's, and it travels only inside TLS), and a
//!   server that does not offer it or asks for more (`connection.secure`);
//! - a protocol header in answer (the server speaks another version);
//! - heartbeats: the node asks for none, its connections are short and bounded by their
//!   limits;
//! - frames larger than the size agreed in `connection.tune`.
//!
//! A publication is `mandatory`, so one no queue takes comes back (`basic.return`) and fails
//! the command, and confirmed (`confirm.select`), so the command's status is the broker's
//! acknowledgement. A message got is acknowledged once it was read whole.

use std::time::Duration;

use zeroize::Zeroizing;

use super::io::Io;
use crate::{Error, Result};

/// The largest frame the node takes, in bytes (the server may agree to less).
const FRAME_MAX: u32 = 128 * 1024;
/// The smallest frame size the standard allows.
const FRAME_MIN: u32 = 4096;
/// Longest message body the node reads, in bytes.
pub const MAX_BODY: u64 = 16 * 1024 * 1024;
/// The channel the node uses.
const CHANNEL: u16 = 1;
/// Longest wait for one read.
const WAIT: Duration = Duration::from_millis(50);

const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;
const FRAME_END: u8 = 0xce;

// Classes and methods.
const CONNECTION: u16 = 10;
const CHANNEL_CLASS: u16 = 20;
const BASIC: u16 = 60;
const CONFIRM: u16 = 85;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

/// A big-endian reader over one frame.
struct Be<'a>(&'a [u8]);

impl<'a> Be<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| invalid("AMQP frame truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    fn uint(&mut self, n: usize) -> Result<u64> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn u8(&mut self) -> Result<u8> {
        u8::try_from(self.uint(1)?).map_err(|_| invalid("u8"))
    }

    fn u16(&mut self) -> Result<u16> {
        u16::try_from(self.uint(2)?).map_err(|_| invalid("u16"))
    }

    fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.uint(4)?).map_err(|_| invalid("u32"))
    }

    fn short(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn long(&mut self) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u32()?).map_err(|_| invalid("length"))?;
        self.take(n)
    }
}

fn short(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    out.push(
        u8::try_from(bytes.len()).map_err(|_| Error::RequestInvalid {
            rule: "an AMQP short string longer than 255 bytes",
        })?,
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn long(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::Encoding)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn frame(kind: u8, channel: u16, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let size = u32::try_from(payload.len()).map_err(|_| Error::Encoding)?;
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
    out.push(kind);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(payload);
    out.push(FRAME_END);
    Ok(out)
}

fn method(class: u16, id: u16, args: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(args.len() + 4);
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(args);
    out
}

/// True for a name of an exchange, a queue or a routing key the node sends: at most 255
/// bytes, no control byte.
pub fn name_ok(name: &[u8]) -> bool {
    name.len() <= 255 && !name.iter().any(|b| *b < 0x20 || *b == 0x7f)
}

/// A message got from a queue.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    /// The exchange it was published to.
    pub exchange: String,
    /// Its routing key.
    pub routing_key: String,
    /// True when it was delivered before.
    pub redelivered: bool,
    /// Its body.
    pub body: Zeroizing<Vec<u8>>,
}

impl Message {
    /// As JSON, the body as text or `{"base64": ...}`.
    pub fn json(&self) -> serde_json::Value {
        use base64::Engine as _;
        let body = match std::str::from_utf8(&self.body) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::json!({
                "base64": base64::engine::general_purpose::STANDARD.encode(self.body.as_slice())
            }),
        };
        serde_json::json!({
            "exchange": self.exchange, "routing_key": self.routing_key,
            "redelivered": self.redelivered, "payload": body,
        })
    }
}

/// What a command did: success, or the broker's refusal (`{"error": {"code", "message"}}`).
#[derive(Debug)]
pub struct Outcome {
    /// The result as JSON.
    pub json: serde_json::Value,
    /// True when the broker refused.
    pub failed: bool,
}

/// One frame of the server.
struct Frame {
    kind: u8,
    channel: u16,
    payload: Zeroizing<Vec<u8>>,
}

/// A connection with one open channel.
pub struct Client<'s> {
    io: Io<'s>,
    frame_max: u32,
    open: bool,
    next_tag: u64,
}

impl<'s> Client<'s> {
    /// Opens the connection on `vhost` with `PLAIN` as `user`, and channel 1 with confirms.
    pub fn connect(mut io: Io<'s>, vhost: &[u8], user: &[u8], password: &[u8]) -> Result<Self> {
        io.write(b"AMQP\x00\x00\x09\x01")?;
        let mut client = Client {
            io,
            frame_max: FRAME_MAX,
            open: false,
            next_tag: 1,
        };
        let start = client.expect(0, CONNECTION, 10)?;
        let mut p = Be(&start);
        if (p.u8()?, p.u8()?) != (0, 9) {
            return Err(untrusted("the server speaks another AMQP version"));
        }
        p.long()?;
        let mechanisms = p.long()?;
        if !mechanisms.split(|b| *b == b' ').any(|m| m == b"PLAIN") {
            return Err(untrusted("the server does not offer PLAIN"));
        }
        if user.contains(&0) || password.contains(&0) {
            return Err(Error::RequestInvalid {
                rule: "a PLAIN user or password cannot hold a NUL byte",
            });
        }
        let mut response = Zeroizing::new(vec![0]);
        response.extend_from_slice(user);
        response.push(0);
        response.extend_from_slice(password);
        let mut args = Zeroizing::new(Vec::new());
        long(&mut args, &[])?;
        short(&mut args, b"PLAIN")?;
        long(&mut args, &response)?;
        short(&mut args, b"en_US")?;
        client.send_method(0, &method(CONNECTION, 11, &args))?;
        drop(args);
        let (class, id, tune) = client.method(0)?;
        match (class, id) {
            (CONNECTION, 30) => {}
            (CONNECTION, 20) => {
                return Err(untrusted("the server asks for more than PLAIN"));
            }
            (CONNECTION, 50) => {
                return Err(Error::AuthRefused {
                    rule: "the server refused the sign-in",
                });
            }
            _ => return Err(invalid("an unexpected method during sign-in")),
        }
        let mut p = Be(&tune);
        // The node uses one channel, whatever the server allows.
        p.u16()?;
        let server_max = p.u32()?;
        p.u16()?;
        client.frame_max = match server_max {
            0 => FRAME_MAX,
            n if n < FRAME_MIN => return Err(invalid("a frame size below the minimum")),
            n => n.min(FRAME_MAX),
        };
        let mut ok = Vec::new();
        ok.extend_from_slice(&1u16.to_be_bytes());
        ok.extend_from_slice(&client.frame_max.to_be_bytes());
        ok.extend_from_slice(&0u16.to_be_bytes());
        client.send_method(0, &method(CONNECTION, 31, &ok))?;
        let mut open = Vec::new();
        short(&mut open, vhost)?;
        short(&mut open, b"")?;
        open.push(0);
        client.send_method(0, &method(CONNECTION, 40, &open))?;
        match client.method(0)? {
            (CONNECTION, 41, _) => {}
            (CONNECTION, 50, _) => {
                return Err(Error::AuthRefused {
                    rule: "the server refused the virtual host",
                });
            }
            _ => return Err(invalid("expected connection.open-ok")),
        }
        client.open_channel()?;
        Ok(client)
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    fn open_channel(&mut self) -> Result<()> {
        let mut args = Vec::new();
        short(&mut args, b"")?;
        self.send_method(CHANNEL, &method(CHANNEL_CLASS, 10, &args))?;
        self.expect(CHANNEL, CHANNEL_CLASS, 11)?;
        self.send_method(CHANNEL, &method(CONFIRM, 10, &[0]))?;
        self.expect(CHANNEL, CONFIRM, 11)?;
        self.open = true;
        self.next_tag = 1;
        Ok(())
    }

    fn send_method(&mut self, channel: u16, payload: &[u8]) -> Result<()> {
        let bytes = frame(FRAME_METHOD, channel, payload)?;
        self.io.write(&bytes)
    }

    fn try_frame(&mut self) -> Result<Option<Frame>> {
        let buffered = self.io.buffered();
        let Some(head) = buffered.get(..7) else {
            if buffered.starts_with(b"AMQP") && buffered.len() >= 4 {
                return Err(untrusted("the server answered with a protocol header"));
            }
            return Ok(None);
        };
        if head.starts_with(b"AMQP") {
            return Err(untrusted("the server answered with a protocol header"));
        }
        let mut p = Be(head);
        let kind = p.u8()?;
        let channel = p.u16()?;
        let size = p.u32()?;
        if size > self.frame_max {
            return Err(invalid("a frame larger than agreed"));
        }
        let size = usize::try_from(size).map_err(|_| invalid("size"))?;
        if buffered.len() < 7 + size + 1 {
            return Ok(None);
        }
        self.io.take(7)?;
        let payload = self.io.take(size)?;
        let end = self.io.take(1)?;
        if end.first() != Some(&FRAME_END) {
            return Err(invalid("a frame without its end byte"));
        }
        Ok(Some(Frame {
            kind,
            channel,
            payload,
        }))
    }

    fn frame(&mut self) -> Result<Frame> {
        loop {
            if let Some(frame) = self.try_frame()? {
                if frame.kind == FRAME_HEARTBEAT {
                    continue;
                }
                return Ok(frame);
            }
            self.io.poll(WAIT)?;
        }
    }

    /// The next method frame on `channel`: class, method and arguments.
    fn method(&mut self, channel: u16) -> Result<(u16, u16, Zeroizing<Vec<u8>>)> {
        let frame = self.frame()?;
        if frame.kind != FRAME_METHOD || frame.channel != channel {
            return Err(invalid("expected a method frame"));
        }
        let mut p = Be(&frame.payload);
        let class = p.u16()?;
        let id = p.u16()?;
        Ok((class, id, Zeroizing::new(p.0.to_vec())))
    }

    fn expect(&mut self, channel: u16, class: u16, id: u16) -> Result<Zeroizing<Vec<u8>>> {
        match self.method(channel)? {
            (c, i, body) if c == class && i == id => Ok(body),
            (CONNECTION, 50, _) => Err(Error::transport(crate::error::TransportKind::Closed, true)),
            _ => Err(invalid("an unexpected AMQP method")),
        }
    }

    /// A content header and its body frames.
    fn content(&mut self, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let header = self.frame()?;
        if header.kind != FRAME_HEADER || header.channel != CHANNEL {
            return Err(invalid("expected a content header"));
        }
        let mut p = Be(&header.payload);
        if p.u16()? != BASIC {
            return Err(invalid("a content header of another class"));
        }
        p.u16()?;
        let size = p.uint(8)?;
        if size > MAX_BODY || usize::try_from(size).map_or(true, |s| s > max) {
            return Err(Error::transport(
                crate::error::TransportKind::TooLarge,
                true,
            ));
        }
        let size = usize::try_from(size).map_err(|_| invalid("size"))?;
        let mut body = Zeroizing::new(Vec::with_capacity(size.min(1 << 20)));
        while body.len() < size {
            let part = self.frame()?;
            if part.kind != FRAME_BODY || part.channel != CHANNEL {
                return Err(invalid("expected a body frame"));
            }
            if body.len() + part.payload.len() > size {
                return Err(invalid("a body longer than its header said"));
            }
            body.extend_from_slice(&part.payload);
        }
        Ok(body)
    }

    /// The broker closed the channel: answer it, and give its reason as the result.
    fn channel_closed(&mut self, body: &[u8]) -> Result<Outcome> {
        let mut p = Be(body);
        let code = p.u16()?;
        let text = String::from_utf8_lossy(p.short()?).into_owned();
        self.send_method(CHANNEL, &method(CHANNEL_CLASS, 41, &[]))?;
        self.open = false;
        Ok(Outcome {
            json: serde_json::json!({"error": {"code": code, "message": text}}),
            failed: true,
        })
    }

    fn ensure_open(&mut self) -> Result<()> {
        if self.open {
            Ok(())
        } else {
            self.open_channel()
        }
    }

    /// Publishes `body` to `exchange` with `routing_key`, mandatory and confirmed.
    pub fn publish(&mut self, exchange: &[u8], routing_key: &[u8], body: &[u8]) -> Result<Outcome> {
        if !name_ok(exchange) || !name_ok(routing_key) {
            return Err(Error::RequestInvalid {
                rule: "an AMQP exchange or routing key: at most 255 bytes, no control byte",
            });
        }
        self.ensure_open()?;
        let mut args = Vec::new();
        args.extend_from_slice(&0u16.to_be_bytes());
        short(&mut args, exchange)?;
        short(&mut args, routing_key)?;
        // Mandatory, not immediate.
        args.push(0b01);
        self.send_method(CHANNEL, &method(BASIC, 40, &args))?;
        let mut header = Vec::new();
        header.extend_from_slice(&BASIC.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&(body.len() as u64).to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        let header = frame(FRAME_HEADER, CHANNEL, &header)?;
        self.io.write(&header)?;
        let chunk = usize::try_from(self.frame_max - 8).map_err(|_| Error::Encoding)?;
        for part in body.chunks(chunk.max(1)) {
            let bytes = frame(FRAME_BODY, CHANNEL, part)?;
            self.io.write(&bytes)?;
        }
        let tag = self.next_tag;
        self.next_tag = self.next_tag.saturating_add(1);
        let mut returned: Option<(u16, String)> = None;
        loop {
            let (class, id, args) = self.method(CHANNEL)?;
            match (class, id) {
                (BASIC, 50) => {
                    let mut p = Be(&args);
                    let code = p.u16()?;
                    let text = String::from_utf8_lossy(p.short()?).into_owned();
                    self.content(body.len().max(1 << 20))?;
                    returned = Some((code, text));
                }
                (BASIC, 80) | (BASIC, 120) => {
                    let mut p = Be(&args);
                    let acked = p.uint(8)?;
                    if acked != tag {
                        return Err(invalid("a confirmation of another publication"));
                    }
                    if let Some((code, text)) = returned {
                        return Ok(Outcome {
                            json: serde_json::json!({"error": {"code": code, "message": text}}),
                            failed: true,
                        });
                    }
                    let nack = id == 120;
                    return Ok(Outcome {
                        json: serde_json::json!({"confirmed": !nack}),
                        failed: nack,
                    });
                }
                (CHANNEL_CLASS, 40) => return self.channel_closed(&args),
                _ => return Err(invalid("an unexpected answer to a publication")),
            }
        }
    }

    /// Gets up to `count` messages from `queue`, acknowledging each, at most `max` bytes of
    /// bodies together.
    pub fn get(
        &mut self,
        queue: &[u8],
        count: usize,
        max: usize,
    ) -> Result<(Outcome, Vec<Message>)> {
        if !name_ok(queue) {
            return Err(Error::RequestInvalid {
                rule: "an AMQP queue name: at most 255 bytes, no control byte",
            });
        }
        self.ensure_open()?;
        let mut messages = Vec::new();
        let mut left = max;
        while messages.len() < count {
            let mut args = Vec::new();
            args.extend_from_slice(&0u16.to_be_bytes());
            short(&mut args, queue)?;
            args.push(0);
            self.send_method(CHANNEL, &method(BASIC, 70, &args))?;
            let (class, id, args) = self.method(CHANNEL)?;
            match (class, id) {
                (BASIC, 71) => {
                    let mut p = Be(&args);
                    let tag = p.uint(8)?;
                    let redelivered = p.u8()? & 1 != 0;
                    let exchange = String::from_utf8_lossy(p.short()?).into_owned();
                    let routing_key = String::from_utf8_lossy(p.short()?).into_owned();
                    let body = self.content(left)?;
                    left = left.saturating_sub(body.len());
                    let mut ack = Vec::new();
                    ack.extend_from_slice(&tag.to_be_bytes());
                    ack.push(0);
                    self.send_method(CHANNEL, &method(BASIC, 80, &ack))?;
                    messages.push(Message {
                        exchange,
                        routing_key,
                        redelivered,
                        body,
                    });
                }
                (BASIC, 72) => break,
                (CHANNEL_CLASS, 40) => return Ok((self.channel_closed(&args)?, messages)),
                _ => return Err(invalid("an unexpected answer to basic.get")),
            }
        }
        let json = serde_json::Value::Array(messages.iter().map(Message::json).collect());
        Ok((
            Outcome {
                json,
                failed: false,
            },
            messages,
        ))
    }

    /// Closes the connection.
    pub fn close(&mut self) {
        let mut args = Vec::new();
        args.extend_from_slice(&200u16.to_be_bytes());
        let _ = short(&mut args, b"");
        args.extend_from_slice(&0u32.to_be_bytes());
        let _ = self.send_method(0, &method(CONNECTION, 50, &args));
        self.io.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn frames_carry_their_end_byte() {
        let f = frame(FRAME_METHOD, 1, &[1, 2]).unwrap();
        assert_eq!(f.as_slice(), &[1, 0, 1, 0, 0, 0, 2, 1, 2, 0xce]);
        assert!(name_ok(b"amq.direct"));
        assert!(!name_ok(b"a\nb"));
        assert!(!name_ok(&[b'a'; 256]));
    }
}
