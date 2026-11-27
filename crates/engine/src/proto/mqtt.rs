//! An MQTT client, versions 3.1.1 (OASIS 2014) and 5.0 (OASIS 2019), over TLS from the first
//! byte: `CONNECT` with a user name and password (or a bearer token in the password), then
//! `PUBLISH` at QoS 0 or 1 and `SUBSCRIBE` to the filters the policy fixes or shapes.
//!
//! What it refuses, and why:
//!
//! - QoS 2 both ways: the node never asks for it, so a message at QoS 2 is a server that does
//!   not follow the protocol;
//! - a message on a topic no filter of the connection matches: the node hands back only what
//!   the policy subscribed to, whatever the broker sends;
//! - topic aliases, enhanced authentication (`AUTH`) and a will: never offered, so a server
//!   that uses them is refused;
//! - retained publications: the node never sets `RETAIN`, so a message it publishes does not
//!   outlive the connection on the broker.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::io::Io;
use crate::{Error, Result};

/// Longest packet of the server, in bytes.
pub const MAX_PACKET: usize = 16 * 1024 * 1024;
/// The keep-alive the node asks for, in seconds.
const KEEP_ALIVE: u16 = 60;
/// Most messages held while the node waits for an acknowledgement.
const MAX_PENDING: usize = 1024;
/// What the node reads of the properties of an MQTT 5 packet.
struct Properties {
    alias: bool,
    keep_alive: Option<u16>,
}

/// Longest wait for one read.
const WAIT: Duration = Duration::from_millis(50);

// Packet types (the high nibble of the first byte).
const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBACK: u8 = 4;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const UNSUBSCRIBE: u8 = 10;
const UNSUBACK: u8 = 11;
const PINGREQ: u8 = 12;
const PINGRESP: u8 = 13;
const DISCONNECT: u8 = 14;
const AUTH: u8 = 15;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

/// The protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// 3.1.1 (protocol level 4).
    V311,
    /// 5.0 (protocol level 5).
    V5,
}

/// A message the broker delivered.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    /// Its topic.
    pub topic: String,
    /// Its payload.
    pub payload: Zeroizing<Vec<u8>>,
    /// The QoS it came at.
    pub qos: u8,
    /// True when the broker had retained it.
    pub retain: bool,
}

impl Message {
    /// As JSON: `{"topic", "payload", "qos", "retain"}`, the payload as text or
    /// `{"base64": ...}`.
    pub fn json(&self) -> serde_json::Value {
        use base64::Engine as _;
        let payload = match std::str::from_utf8(&self.payload) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::json!({
                "base64": base64::engine::general_purpose::STANDARD.encode(self.payload.as_slice())
            }),
        };
        serde_json::json!({
            "topic": self.topic, "payload": payload, "qos": self.qos, "retain": self.retain,
        })
    }
}

/// True when `topic` is a topic name the node may publish to: 1 to 65535 bytes of UTF-8,
/// no NUL and no wildcard.
pub fn topic_ok(topic: &[u8]) -> bool {
    filter_ok(topic) && !topic.iter().any(|b| matches!(b, b'+' | b'#'))
}

/// True when `filter` is a well-formed topic filter: `+` only as a whole level, `#` only as
/// the whole last level, no NUL.
pub fn filter_ok(filter: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(filter) else {
        return false;
    };
    if text.is_empty() || text.len() > 65535 || text.contains('\0') {
        return false;
    }
    let levels: Vec<&str> = text.split('/').collect();
    let last = levels.len().saturating_sub(1);
    levels.iter().enumerate().all(|(i, level)| {
        (!level.contains('+') || *level == "+")
            && (!level.contains('#') || (*level == "#" && i == last))
    })
}

/// True when `topic` matches `filter` (MQTT 3.1.1, 4.7; 5.0, 4.7): `+` one level, `#` the
/// rest. A filter starting with a wildcard does not match a topic starting with `$`.
pub fn matches(filter: &str, topic: &str) -> bool {
    if topic.starts_with('$') && (filter.starts_with('+') || filter.starts_with('#')) {
        return false;
    }
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn varint(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut byte = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::RequestInvalid {
        rule: "an MQTT string longer than 65535 bytes",
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn packet(first: u8, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![first]);
    varint(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// A big-endian reader over one packet.
struct Be<'a>(&'a [u8]);

impl<'a> Be<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| invalid("MQTT packet truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| invalid("MQTT packet truncated"))
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([
            b.first().copied().unwrap_or(0),
            b.get(1).copied().unwrap_or(0),
        ]))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }

    fn varint(&mut self) -> Result<usize> {
        let mut value = 0usize;
        for i in 0..4 {
            let byte = self.u8()?;
            value |= usize::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(invalid("an MQTT length of more than four bytes"))
    }

    /// Skips the properties of an MQTT 5 packet; returns whether a topic alias was among them.
    fn properties(&mut self) -> Result<bool> {
        Ok(self.read_properties()?.alias)
    }

    /// Reads the properties of an MQTT 5 packet: whether a topic alias was among them, and
    /// the Server Keep Alive (`0x13`) of a CONNACK.
    fn read_properties(&mut self) -> Result<Properties> {
        let len = self.varint()?;
        let mut p = Be(self.take(len)?);
        let mut alias = false;
        let mut keep_alive = None;
        while !p.0.is_empty() {
            let id = p.varint()?;
            match id {
                // Byte.
                0x01 | 0x17 | 0x19 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2a => {
                    p.take(1)?;
                }
                // Server Keep Alive.
                0x13 => {
                    keep_alive = Some(p.u16()?);
                }
                // Two-byte integer.
                0x21 | 0x22 => {
                    p.take(2)?;
                }
                0x23 => {
                    alias = true;
                    p.take(2)?;
                }
                // Four-byte integer.
                0x02 | 0x11 | 0x18 | 0x27 => {
                    p.take(4)?;
                }
                // Variable byte integer.
                0x0b => {
                    p.varint()?;
                }
                // UTF-8 string or binary data.
                0x03 | 0x08 | 0x09 | 0x12 | 0x15 | 0x16 | 0x1a | 0x1c | 0x1f => {
                    p.string()?;
                }
                // String pair.
                0x26 => {
                    p.string()?;
                    p.string()?;
                }
                _ => return Err(invalid("an unknown MQTT property")),
            }
        }
        Ok(Properties { alias, keep_alive })
    }
}

/// A connected client.
pub struct Client<'s> {
    io: Io<'s>,
    version: Version,
    next_id: u16,
    filters: Vec<String>,
    pending: VecDeque<Message>,
    last_write: Instant,
    /// The keep-alive in force, in seconds: the one the node asked for, or the Server Keep
    /// Alive of an MQTT 5 broker ([MQTT-3.2.2-21]). 0 turns pings off.
    keep_alive: u16,
}

impl<'s> Client<'s> {
    /// Connects as `client_id` with `user` and `password` (a password or a token), with a
    /// clean session and no will.
    pub fn connect(
        io: Io<'s>,
        version: Version,
        client_id: &[u8],
        user: &[u8],
        password: &[u8],
    ) -> Result<Self> {
        let mut client = Client {
            io,
            version,
            next_id: 1,
            filters: Vec::new(),
            pending: VecDeque::new(),
            last_write: Instant::now(),
            keep_alive: KEEP_ALIVE,
        };
        let mut body = Zeroizing::new(Vec::new());
        string(&mut body, b"MQTT")?;
        body.push(match version {
            Version::V311 => 4,
            Version::V5 => 5,
        });
        // MQTT 3.1.1 allows a password only with a user name ([MQTT-3.1.2-22]): a token
        // alone goes with a user name of zero length.
        let with_user = !user.is_empty() || (version == Version::V311 && !password.is_empty());
        let mut flags = 0x02u8;
        if with_user {
            flags |= 0x80;
        }
        if !password.is_empty() {
            flags |= 0x40;
        }
        body.push(flags);
        body.extend_from_slice(&KEEP_ALIVE.to_be_bytes());
        if version == Version::V5 {
            // Maximum Packet Size: what the node reads at most.
            let mut props = vec![0x27];
            props.extend_from_slice(&(MAX_PACKET as u32).to_be_bytes());
            varint(&mut body, props.len());
            body.extend_from_slice(&props);
        }
        string(&mut body, client_id)?;
        if with_user {
            string(&mut body, user)?;
        }
        if !password.is_empty() {
            string(&mut body, password)?;
        }
        client.write(&packet(CONNECT << 4, &body))?;
        let (first, ack) = client.read()?;
        if first >> 4 != CONNACK {
            return Err(invalid("expected CONNACK"));
        }
        let mut p = Be(&ack);
        p.u8()?;
        let code = p.u8()?;
        if version == Version::V5
            && let Some(keep_alive) = p.read_properties()?.keep_alive
        {
            client.keep_alive = keep_alive;
        }
        match (version, code) {
            (_, 0) => Ok(client),
            (Version::V311, 4 | 5) | (Version::V5, 0x86 | 0x87 | 0x8c) => Err(Error::AuthRefused {
                rule: "the broker refused the credentials",
            }),
            _ => Err(Error::AuthRefused {
                rule: "the broker refused the connection",
            }),
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.last_write = Instant::now();
        self.io.write(bytes)
    }

    /// One whole packet when it is buffered: its first byte and its body.
    fn try_read(&mut self) -> Result<Option<(u8, Zeroizing<Vec<u8>>)>> {
        let buffered = self.io.buffered();
        let Some(&first) = buffered.first() else {
            return Ok(None);
        };
        let mut len = 0usize;
        let mut header = 1usize;
        let mut done = false;
        for i in 0..4 {
            let Some(&byte) = buffered.get(1 + i) else {
                return Ok(None);
            };
            len |= usize::from(byte & 0x7f) << (7 * i);
            header += 1;
            if byte & 0x80 == 0 {
                done = true;
                break;
            }
        }
        if !done {
            return Err(invalid("an MQTT length of more than four bytes"));
        }
        if len > MAX_PACKET {
            return Err(Error::transport(
                crate::error::TransportKind::TooLarge,
                true,
            ));
        }
        if buffered.len() < header + len {
            return Ok(None);
        }
        self.io.take(header)?;
        Ok(Some((first, self.io.take(len)?)))
    }

    fn read(&mut self) -> Result<(u8, Zeroizing<Vec<u8>>)> {
        loop {
            if let Some(packet) = self.try_read()? {
                return Ok(packet);
            }
            self.io.poll(WAIT)?;
        }
    }

    fn packet_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).unwrap_or(1);
        id
    }

    /// Handles a packet that is not the answer awaited: a message, a ping answer. Fails on
    /// anything else.
    fn other(&mut self, first: u8, body: &[u8]) -> Result<()> {
        match first >> 4 {
            PUBLISH => {
                let message = self.incoming(first, body)?;
                if let Some(message) = message {
                    if self.pending.len() >= MAX_PENDING {
                        return Err(invalid("too many messages held"));
                    }
                    self.pending.push_back(message);
                }
                Ok(())
            }
            PINGRESP => Ok(()),
            DISCONNECT => Err(Error::transport(crate::error::TransportKind::Closed, true)),
            AUTH => Err(untrusted(
                "enhanced authentication the node did not ask for",
            )),
            _ => Err(invalid("an unexpected MQTT packet")),
        }
    }

    /// A `PUBLISH` of the server: checked, acknowledged, and kept when a filter of the
    /// connection matches it.
    fn incoming(&mut self, first: u8, body: &[u8]) -> Result<Option<Message>> {
        let qos = (first >> 1) & 3;
        let retain = first & 1 != 0;
        if qos > 1 {
            return Err(untrusted("a message at a QoS the node did not ask for"));
        }
        let mut p = Be(body);
        let topic = p.string()?;
        let id = if qos == 1 { Some(p.u16()?) } else { None };
        if self.version == Version::V5 && p.properties()? {
            return Err(untrusted("a topic alias the node did not allow"));
        }
        let payload = Zeroizing::new(p.0.to_vec());
        if let Some(id) = id {
            let mut ack = id.to_be_bytes().to_vec();
            if self.version == Version::V5 {
                ack.push(0);
            }
            self.write(&packet(PUBACK << 4, &ack))?;
        }
        let topic = std::str::from_utf8(topic)
            .ok()
            .filter(|t| topic_ok(t.as_bytes()))
            .ok_or_else(|| invalid("a topic that is not a topic name"))?;
        if !self.filters.iter().any(|f| matches(f, topic)) {
            return Err(untrusted(
                "a message on a topic the node did not subscribe to",
            ));
        }
        Ok(Some(Message {
            topic: topic.to_string(),
            payload,
            qos,
            retain,
        }))
    }

    /// Waits for the answer of `kind` to packet `id`, keeping messages that come first.
    fn await_ack(&mut self, kind: u8, id: u16) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let (first, body) = self.read()?;
            if first >> 4 == kind {
                let mut p = Be(&body);
                if p.u16()? != id {
                    return Err(invalid("an acknowledgement of another packet"));
                }
                return Ok(Zeroizing::new(p.0.to_vec()));
            }
            self.other(first, &body)?;
        }
    }

    /// Publishes `payload` on `topic` at `qos` (0 or 1), never retained. For QoS 1, the
    /// broker's reason code (0 for success).
    pub fn publish(&mut self, topic: &[u8], payload: &[u8], qos: u8) -> Result<u8> {
        if !topic_ok(topic) {
            return Err(Error::RequestInvalid {
                rule: "an MQTT topic name: UTF-8, no NUL, no wildcard",
            });
        }
        if qos > 1 {
            return Err(Error::RequestInvalid { rule: "QoS 0 or 1" });
        }
        let mut body = Zeroizing::new(Vec::new());
        string(&mut body, topic)?;
        let id = (qos == 1).then(|| self.packet_id());
        if let Some(id) = id {
            body.extend_from_slice(&id.to_be_bytes());
        }
        if self.version == Version::V5 {
            body.push(0);
        }
        body.extend_from_slice(payload);
        self.write(&packet((PUBLISH << 4) | (qos << 1), &body))?;
        let Some(id) = id else {
            return Ok(0);
        };
        let rest = self.await_ack(PUBACK, id)?;
        Ok(rest.first().copied().unwrap_or(0))
    }

    /// Subscribes to `filter` at `qos`; the QoS the broker granted.
    pub fn subscribe(&mut self, filter: &str, qos: u8) -> Result<u8> {
        if !filter_ok(filter.as_bytes()) || qos > 1 {
            return Err(Error::RequestInvalid {
                rule: "an MQTT topic filter and QoS 0 or 1",
            });
        }
        let id = self.packet_id();
        let mut body = id.to_be_bytes().to_vec();
        if self.version == Version::V5 {
            body.push(0);
        }
        string(&mut body, filter.as_bytes())?;
        body.push(qos);
        self.write(&packet((SUBSCRIBE << 4) | 2, &body))?;
        // A message may come before the acknowledgement once the broker took the filter.
        self.filters.push(filter.to_string());
        let rest = self.await_ack(SUBACK, id)?;
        let mut p = Be(&rest);
        if self.version == Version::V5 {
            p.properties()?;
        }
        let granted = p.u8()?;
        if granted > qos {
            self.filters.retain(|f| f != filter);
            return Err(invalid("the broker refused the subscription"));
        }
        Ok(granted)
    }

    /// Unsubscribes from `filter`.
    pub fn unsubscribe(&mut self, filter: &str) -> Result<()> {
        let id = self.packet_id();
        let mut body = id.to_be_bytes().to_vec();
        if self.version == Version::V5 {
            body.push(0);
        }
        string(&mut body, filter.as_bytes())?;
        self.write(&packet((UNSUBSCRIBE << 4) | 2, &body))?;
        self.await_ack(UNSUBACK, id)?;
        self.filters.retain(|f| f != filter);
        self.pending
            .retain(|m| self.filters.iter().any(|f| matches(f, &m.topic)));
        Ok(())
    }

    /// The next message, within `wait`; `None` when none came. Sends a ping when the
    /// connection was quiet for half the keep-alive.
    pub fn poll_message(&mut self, wait: Duration) -> Result<Option<Message>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(message));
        }
        if self.keep_alive > 0
            && self.last_write.elapsed() >= Duration::from_millis(u64::from(self.keep_alive) * 500)
        {
            self.write(&[PINGREQ << 4, 0])?;
        }
        loop {
            if let Some((first, body)) = self.try_read()? {
                self.other(first, &body)?;
                if let Some(message) = self.pending.pop_front() {
                    return Ok(Some(message));
                }
                continue;
            }
            if !self.io.poll(wait)? {
                return Ok(None);
            }
        }
    }

    /// Messages for up to `wait`, at most `max` of them and `max_bytes` of payload.
    pub fn collect(
        &mut self,
        wait: Duration,
        max: usize,
        max_bytes: usize,
    ) -> Result<Vec<Message>> {
        let end = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        let mut out = Vec::new();
        let mut bytes = 0usize;
        while out.len() < max {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            if let Some(message) = self.poll_message(left.min(WAIT))? {
                bytes = bytes.saturating_add(message.payload.len() + message.topic.len());
                if bytes > max_bytes {
                    return Err(Error::transport(
                        crate::error::TransportKind::TooLarge,
                        true,
                    ));
                }
                out.push(message);
            }
        }
        Ok(out)
    }

    /// Says goodbye and closes.
    pub fn close(&mut self) {
        let _ = self.write(&[DISCONNECT << 4, 0]);
        self.io.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn filters_match_as_the_standard_says() {
        assert!(matches("a/+/c", "a/b/c"));
        assert!(!matches("a/+/c", "a/b/d/c"));
        assert!(matches("a/#", "a/b/c"));
        assert!(matches("a/#", "a"));
        assert!(matches("#", "x/y"));
        assert!(!matches("#", "$SYS/x"));
        assert!(!matches("+/x", "$SYS/x"));
        assert!(matches("$SYS/#", "$SYS/x"));
        assert!(!matches("a/b", "a/b/c"));
        assert!(filter_ok(b"a/+/#"));
        assert!(!filter_ok(b"a/#/b"));
        assert!(!filter_ok(b"a/b+"));
        assert!(!filter_ok(b"a\0b"));
        assert!(topic_ok(b"a/b"));
        assert!(!topic_ok(b"a/+"));
        assert!(!topic_ok(b""));
    }

    #[test]
    fn lengths_round_trip() {
        for n in [
            0usize,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
        ] {
            let mut out = Vec::new();
            varint(&mut out, n);
            assert_eq!(Be(&out).varint().unwrap(), n);
        }
        assert!(Be(&[0xff, 0xff, 0xff, 0xff, 0x01]).varint().is_err());
    }
}
