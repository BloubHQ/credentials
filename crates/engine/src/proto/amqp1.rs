//! An AMQP 1.0 client (OASIS AMQP 1.0, ISO/IEC 19464): TLS from the first byte or after the
//! TLS protocol header (section 5.2), the SASL layer (section 5.3) with the mechanism the policy
//! names, then one connection, one session and one link at a time: `send` puts one message on
//! an address the policy fixes, `receive` takes up to a number of messages from one, each with
//! the settle mode the policy names.
//!
//! What it refuses, and why:
//!
//! - a server that answers a protocol header with another layer or version (a server that
//!   skips SASL, or asks for TLS inside TLS), before anything secret is written;
//! - a mechanism the policy did not name, a server that does not offer it, and a challenge the
//!   mechanism does not take (only SCRAM-SHA-256 has challenges); SCRAM must prove the server
//!   knows the password before the outcome is taken;
//! - frames larger than the node announced ([`MAX_FRAME`]), a server that announces less than
//!   the minimum (512 bytes), any channel or link handle but 0 (the node announces
//!   `channel-max` 0 and `handle-max` 0), a performative the standard does not define, and one
//!   the state does not expect (an `attach` or `begin` the node did not ask for);
//! - values nested deeper than [`MAX_DEPTH`] or more than [`MAX_VALUES`] in one decode, so a
//!   frame of zero-width array elements cannot make the node allocate without bound, and a
//!   descriptor other than a `ulong` or a symbol of at most [`MAX_DESCRIPTOR`] bytes (an array
//!   repeats its descriptor for each element);
//! - a broker that changes the settle mode the node asked for, a delivery settled in another
//!   way than the link's mode, more deliveries than the credit given, and a transfer beyond the
//!   session's incoming window.
//!
//! Messages are bounded too: at most [`MAX_MESSAGE`] each (announced as `max-message-size`),
//! and the bytes the caller's result may hold together. Text the broker sends back in an error
//! (its condition and description) is scrubbed of the user name and the secret ([`Scrub`]).

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::io::{Io, Scrub};
use crate::error::TransportKind;
use crate::policy::{Mechanism, SettleMode};
use crate::{Error, Result};

/// The largest frame the node takes and sends, in bytes (announced as `max-frame-size`).
pub const MAX_FRAME: u32 = 64 * 1024;
/// The smallest `max-frame-size` the standard allows (`MIN-MAX-FRAME-SIZE`).
pub const MIN_MAX_FRAME: u32 = 512;
/// The deepest nesting of values the node decodes.
pub const MAX_DEPTH: usize = 16;
/// The most values one decode yields (a frame, or the sections of one message).
pub const MAX_VALUES: usize = 16 * 1024;
/// The largest message the node takes or sends, in bytes (announced as `max-message-size`).
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Longest address, in bytes.
pub const MAX_ADDRESS: usize = 1024;
/// Longest symbolic descriptor the node reads. A descriptor is a `ulong` or a `symbol`
/// (section 1.5); an array repeats its one descriptor for every element, so a long one would
/// multiply into memory.
pub const MAX_DESCRIPTOR: usize = 256;
/// The session's incoming window, in transfer frames.
const WINDOW: u32 = 1024;
/// Longest wait for one read.
const WAIT: Duration = Duration::from_millis(20);
/// Most rounds of a SASL exchange.
const MAX_SASL_ROUNDS: usize = 4;

/// The protocol header of the SASL layer.
pub const SASL_HEADER: &[u8; 8] = b"AMQP\x03\x01\x00\x00";
/// The protocol header of AMQP itself.
pub const AMQP_HEADER: &[u8; 8] = b"AMQP\x00\x01\x00\x00";
/// The protocol header that asks for TLS (section 5.2).
pub const TLS_HEADER: &[u8; 8] = b"AMQP\x02\x01\x00\x00";

/// A frame of AMQP.
pub const FRAME_AMQP: u8 = 0;
/// A frame of the SASL layer.
pub const FRAME_SASL: u8 = 1;

/// The descriptors of the performatives, the SASL frames, the delivery states and the parts of
/// a message the node knows.
pub mod code {
    /// `open`.
    pub const OPEN: u64 = 0x10;
    /// `begin`.
    pub const BEGIN: u64 = 0x11;
    /// `attach`.
    pub const ATTACH: u64 = 0x12;
    /// `flow`.
    pub const FLOW: u64 = 0x13;
    /// `transfer`.
    pub const TRANSFER: u64 = 0x14;
    /// `disposition`.
    pub const DISPOSITION: u64 = 0x15;
    /// `detach`.
    pub const DETACH: u64 = 0x16;
    /// `end`.
    pub const END: u64 = 0x17;
    /// `close`.
    pub const CLOSE: u64 = 0x18;
    /// `error`.
    pub const ERROR: u64 = 0x1d;
    /// `received`.
    pub const RECEIVED: u64 = 0x23;
    /// `accepted`.
    pub const ACCEPTED: u64 = 0x24;
    /// `rejected`.
    pub const REJECTED: u64 = 0x25;
    /// `released`.
    pub const RELEASED: u64 = 0x26;
    /// `modified`.
    pub const MODIFIED: u64 = 0x27;
    /// `source`.
    pub const SOURCE: u64 = 0x28;
    /// `target`.
    pub const TARGET: u64 = 0x29;
    /// `sasl-mechanisms`.
    pub const SASL_MECHANISMS: u64 = 0x40;
    /// `sasl-init`.
    pub const SASL_INIT: u64 = 0x41;
    /// `sasl-challenge`.
    pub const SASL_CHALLENGE: u64 = 0x42;
    /// `sasl-response`.
    pub const SASL_RESPONSE: u64 = 0x43;
    /// `sasl-outcome`.
    pub const SASL_OUTCOME: u64 = 0x44;
    /// The `header` of a message.
    pub const HEADER: u64 = 0x70;
    /// The `properties` of a message.
    pub const PROPERTIES: u64 = 0x73;
    /// A `data` section.
    pub const DATA: u64 = 0x75;
    /// An `amqp-sequence` section.
    pub const SEQUENCE: u64 = 0x76;
    /// An `amqp-value` section.
    pub const VALUE: u64 = 0x77;
}

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

fn refused(rule: &'static str) -> Error {
    Error::RequestInvalid { rule }
}

/// A value of the AMQP type system (section 1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `boolean`.
    Bool(bool),
    /// `ubyte`.
    Ubyte(u8),
    /// `ushort`.
    Ushort(u16),
    /// `uint` (all its encodings).
    Uint(u32),
    /// `ulong` (all its encodings).
    Ulong(u64),
    /// `byte`.
    Byte(i8),
    /// `short`.
    Short(i16),
    /// `int` (all its encodings).
    Int(i32),
    /// `long` (all its encodings).
    Long(i64),
    /// `float`, as its bits.
    Float(u32),
    /// `double`, as its bits.
    Double(u64),
    /// `decimal32`, `decimal64` or `decimal128`, as its bytes.
    Decimal(Vec<u8>),
    /// `char`, a UTF-32 code point.
    Char(u32),
    /// `timestamp`, milliseconds since the Unix epoch.
    Timestamp(i64),
    /// `uuid`.
    Uuid([u8; 16]),
    /// `binary`.
    Binary(Vec<u8>),
    /// `string` (UTF-8).
    String(String),
    /// `symbol` (ASCII).
    Symbol(String),
    /// `list`.
    List(Vec<Value>),
    /// `map`, its pairs in order.
    Map(Vec<(Value, Value)>),
    /// `array`: values of one constructor.
    Array(Vec<Value>),
    /// A described value: its descriptor and the value.
    Described(Box<Value>, Box<Value>),
}

impl Value {
    /// A described list, as a performative or a section is.
    pub fn described(code: u64, fields: Vec<Value>) -> Self {
        Value::Described(Box::new(Value::Ulong(code)), Box::new(Value::List(fields)))
    }

    /// The text of a `string` or `symbol`.
    pub fn text(&self) -> Option<&str> {
        match self {
            Value::String(s) | Value::Symbol(s) => Some(s),
            _ => None,
        }
    }

    /// The number of a `uint` (or of a smaller unsigned type).
    pub fn uint(&self) -> Option<u32> {
        match self {
            Value::Uint(n) => Some(*n),
            Value::Ushort(n) => Some(u32::from(*n)),
            Value::Ubyte(n) => Some(u32::from(*n)),
            _ => None,
        }
    }

    /// The value of a `boolean`.
    pub fn bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The numeric code of a descriptor, from a `ulong` or the symbolic name of a known one.
    fn descriptor_code(&self) -> Option<u64> {
        match self {
            Value::Ulong(n) => Some(*n),
            Value::Symbol(name) => symbolic(name),
            _ => None,
        }
    }

    /// The descriptor code and the fields of a described list.
    pub fn as_described_list(&self) -> Option<(u64, &[Value])> {
        match self {
            Value::Described(d, v) => match (d.descriptor_code(), v.as_ref()) {
                (Some(code), Value::List(fields)) => Some((code, fields)),
                _ => None,
            },
            _ => None,
        }
    }

    /// As JSON: numbers and text as they are, binary as `{"base64"}`, a described value as
    /// its value.
    pub fn json(&self) -> serde_json::Value {
        use base64::Engine as _;
        use serde_json::Value as J;
        match self {
            Value::Null => J::Null,
            Value::Bool(b) => J::Bool(*b),
            Value::Ubyte(n) => J::from(*n),
            Value::Ushort(n) => J::from(*n),
            Value::Uint(n) => J::from(*n),
            Value::Ulong(n) => J::from(*n),
            Value::Byte(n) => J::from(*n),
            Value::Short(n) => J::from(*n),
            Value::Int(n) => J::from(*n),
            Value::Long(n) | Value::Timestamp(n) => J::from(*n),
            Value::Float(bits) => J::from(f64::from(f32::from_bits(*bits))),
            Value::Double(bits) => J::from(f64::from_bits(*bits)),
            Value::Char(c) => J::String(char::from_u32(*c).map(String::from).unwrap_or_default()),
            Value::Uuid(bytes) => J::String(bytes.iter().map(|b| format!("{b:02x}")).collect()),
            Value::Decimal(bytes) | Value::Binary(bytes) => serde_json::json!({
                "base64": base64::engine::general_purpose::STANDARD.encode(bytes)
            }),
            Value::String(s) | Value::Symbol(s) => J::String(s.clone()),
            Value::List(items) | Value::Array(items) => {
                J::Array(items.iter().map(Value::json).collect())
            }
            Value::Map(pairs) => J::Array(
                pairs
                    .iter()
                    .map(|(k, v)| J::Array(vec![k.json(), v.json()]))
                    .collect(),
            ),
            Value::Described(_, v) => v.json(),
        }
    }
}

/// The code of a descriptor given by its symbolic name (section 2.7, 2.8, 3.2, 3.4, 3.5, 5.3).
fn symbolic(name: &str) -> Option<u64> {
    Some(match name {
        "amqp:open:list" => code::OPEN,
        "amqp:begin:list" => code::BEGIN,
        "amqp:attach:list" => code::ATTACH,
        "amqp:flow:list" => code::FLOW,
        "amqp:transfer:list" => code::TRANSFER,
        "amqp:disposition:list" => code::DISPOSITION,
        "amqp:detach:list" => code::DETACH,
        "amqp:end:list" => code::END,
        "amqp:close:list" => code::CLOSE,
        "amqp:error:list" => code::ERROR,
        "amqp:received:list" => code::RECEIVED,
        "amqp:accepted:list" => code::ACCEPTED,
        "amqp:rejected:list" => code::REJECTED,
        "amqp:released:list" => code::RELEASED,
        "amqp:modified:list" => code::MODIFIED,
        "amqp:source:list" => code::SOURCE,
        "amqp:target:list" => code::TARGET,
        "amqp:sasl-mechanisms:list" => code::SASL_MECHANISMS,
        "amqp:sasl-init:list" => code::SASL_INIT,
        "amqp:sasl-challenge:list" => code::SASL_CHALLENGE,
        "amqp:sasl-response:list" => code::SASL_RESPONSE,
        "amqp:sasl-outcome:list" => code::SASL_OUTCOME,
        "amqp:header:list" => code::HEADER,
        "amqp:properties:list" => code::PROPERTIES,
        "amqp:data:binary" => code::DATA,
        "amqp:amqp-sequence:list" => code::SEQUENCE,
        "amqp:amqp-value:*" => code::VALUE,
        _ => return None,
    })
}

/// A reader of encoded values, bounded in depth and in the number of values.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
    values: usize,
}

impl<'a> Decoder<'a> {
    /// Reads `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            values: 0,
        }
    }

    /// The bytes not read yet.
    pub fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.at..).unwrap_or_default()
    }

    /// True when every byte was read.
    pub fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| invalid("AMQP value truncated"))?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| invalid("AMQP value truncated"))?;
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn len(&mut self, wide: bool) -> Result<usize> {
        let n = if wide {
            self.u32()?
        } else {
            u32::from(self.u8()?)
        };
        usize::try_from(n).map_err(|_| invalid("AMQP length"))
    }

    fn count(&mut self) -> Result<()> {
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(invalid("too many AMQP values in one frame or message"));
        }
        Ok(())
    }

    /// The next value.
    pub fn value(&mut self) -> Result<Value> {
        self.value_at(0)
    }

    fn value_at(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(invalid("AMQP values nested too deep"));
        }
        let code = self.u8()?;
        if code == 0x00 {
            self.count()?;
            let descriptor = self.descriptor(depth + 1)?;
            let value = self.value_at(depth + 1)?;
            return Ok(Value::Described(Box::new(descriptor), Box::new(value)));
        }
        self.body(code, depth)
    }

    /// A descriptor: a `ulong`, or a `symbol` of at most [`MAX_DESCRIPTOR`] bytes.
    fn descriptor(&mut self, depth: usize) -> Result<Value> {
        match self.value_at(depth)? {
            d @ Value::Ulong(_) => Ok(d),
            Value::Symbol(s) if s.len() <= MAX_DESCRIPTOR => Ok(Value::Symbol(s)),
            _ => Err(invalid(
                "an AMQP descriptor that is not a ulong or a short symbol",
            )),
        }
    }

    /// The value after its constructor `code`.
    fn body(&mut self, code: u8, depth: usize) -> Result<Value> {
        self.count()?;
        Ok(match code {
            0x40 => Value::Null,
            0x41 => Value::Bool(true),
            0x42 => Value::Bool(false),
            0x56 => match self.u8()? {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => return Err(invalid("an AMQP boolean other than 0 or 1")),
            },
            0x50 => Value::Ubyte(self.u8()?),
            0x60 => Value::Ushort(u16::from_be_bytes(self.array()?)),
            0x70 => Value::Uint(self.u32()?),
            0x52 => Value::Uint(u32::from(self.u8()?)),
            0x43 => Value::Uint(0),
            0x80 => Value::Ulong(u64::from_be_bytes(self.array()?)),
            0x53 => Value::Ulong(u64::from(self.u8()?)),
            0x44 => Value::Ulong(0),
            0x51 => Value::Byte(i8::from_be_bytes(self.array()?)),
            0x61 => Value::Short(i16::from_be_bytes(self.array()?)),
            0x71 => Value::Int(i32::from_be_bytes(self.array()?)),
            0x54 => Value::Int(i32::from(i8::from_be_bytes(self.array()?))),
            0x81 => Value::Long(i64::from_be_bytes(self.array()?)),
            0x55 => Value::Long(i64::from(i8::from_be_bytes(self.array()?))),
            0x72 => Value::Float(self.u32()?),
            0x82 => Value::Double(u64::from_be_bytes(self.array()?)),
            0x74 => Value::Decimal(self.take(4)?.to_vec()),
            0x84 => Value::Decimal(self.take(8)?.to_vec()),
            0x94 => Value::Decimal(self.take(16)?.to_vec()),
            0x73 => Value::Char(self.u32()?),
            0x83 => Value::Timestamp(i64::from_be_bytes(self.array()?)),
            0x98 => Value::Uuid(self.array()?),
            0xa0 | 0xb0 => {
                let n = self.len(code == 0xb0)?;
                Value::Binary(self.take(n)?.to_vec())
            }
            0xa1 | 0xb1 => {
                let n = self.len(code == 0xb1)?;
                let text = std::str::from_utf8(self.take(n)?)
                    .map_err(|_| invalid("an AMQP string that is not UTF-8"))?;
                Value::String(text.to_string())
            }
            0xa3 | 0xb3 => {
                let n = self.len(code == 0xb3)?;
                let bytes = self.take(n)?;
                if !bytes.is_ascii() {
                    return Err(invalid("an AMQP symbol that is not ASCII"));
                }
                Value::Symbol(String::from_utf8_lossy(bytes).into_owned())
            }
            0x45 => Value::List(Vec::new()),
            0xc0 | 0xd0 | 0xc1 | 0xd1 => {
                let wide = code & 0xf0 == 0xd0;
                let items = self.compound(wide, |d| d.value_at(depth + 1))?;
                if code & 0x0f == 1 {
                    if items.len() % 2 != 0 {
                        return Err(invalid("an AMQP map with an odd number of values"));
                    }
                    let mut pairs = Vec::with_capacity(items.len() / 2);
                    let mut it = items.into_iter();
                    while let (Some(k), Some(v)) = (it.next(), it.next()) {
                        pairs.push((k, v));
                    }
                    Value::Map(pairs)
                } else {
                    Value::List(items)
                }
            }
            0xe0 | 0xf0 => self.array_body(code == 0xf0, depth)?,
            _ => return Err(invalid("an AMQP constructor the standard does not define")),
        })
    }

    /// An array: its size and count, its one constructor (a descriptor and a code, or a
    /// code), then each element with that constructor. Elements may take no byte (`null`,
    /// `true`), so the count of values bounds them, not the size.
    fn array_body(&mut self, wide: bool, depth: usize) -> Result<Value> {
        if depth + 1 > MAX_DEPTH {
            return Err(invalid("AMQP values nested too deep"));
        }
        let (count, end) = self.size_and_count(wide)?;
        let mut constructor = self.u8()?;
        let descriptor = if constructor == 0x00 {
            let d = self.descriptor(depth + 1)?;
            constructor = self.u8()?;
            Some(d)
        } else {
            None
        };
        if constructor == 0x00 {
            return Err(invalid("an AMQP array element described twice"));
        }
        let mut items = super::announced(count);
        for _ in 0..count {
            let item = self.body(constructor, depth + 1)?;
            items.push(match &descriptor {
                Some(d) => Value::Described(Box::new(d.clone()), Box::new(item)),
                None => item,
            });
            if self.at > end {
                return Err(invalid("an AMQP value longer than its size"));
            }
        }
        if self.at != end {
            return Err(invalid("an AMQP value shorter than its size"));
        }
        Ok(Value::Array(items))
    }

    /// The size and count of a compound value, and where it ends.
    fn size_and_count(&mut self, wide: bool) -> Result<(usize, usize)> {
        let size = self.len(wide)?;
        let end = self
            .at
            .checked_add(size)
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(|| invalid("AMQP value truncated"))?;
        let count = self.len(wide)?;
        if self.at > end {
            return Err(invalid("an AMQP value longer than its size"));
        }
        Ok((count, end))
    }

    /// A list or map: its size and count, then the values, which must fill the size exactly.
    fn compound(
        &mut self,
        wide: bool,
        mut item: impl FnMut(&mut Self) -> Result<Value>,
    ) -> Result<Vec<Value>> {
        let (count, end) = self.size_and_count(wide)?;
        // Each element takes at least its constructor byte, so the size bounds the count.
        if count > end.saturating_sub(self.at) {
            return Err(invalid("an AMQP count larger than its size"));
        }
        let mut items = super::announced(count);
        for _ in 0..count {
            items.push(item(self)?);
            if self.at > end {
                return Err(invalid("an AMQP value longer than its size"));
            }
        }
        if self.at != end {
            return Err(invalid("an AMQP value shorter than its size"));
        }
        Ok(items)
    }
}

/// Decodes one value that fills `bytes`.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut d = Decoder::new(bytes);
    let value = d.value()?;
    if !d.is_empty() {
        return Err(invalid("bytes after an AMQP value"));
    }
    Ok(value)
}

/// Overwrites the bytes of every binary and string inside `value` (a SASL response holds the
/// secret).
fn wipe(value: &mut Value) {
    use zeroize::Zeroize as _;
    match value {
        Value::Binary(b) | Value::Decimal(b) => b.zeroize(),
        Value::String(s) | Value::Symbol(s) => s.zeroize(),
        Value::List(items) | Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Map(pairs) => pairs.iter_mut().for_each(|(k, v)| {
            wipe(k);
            wipe(v);
        }),
        Value::Described(d, v) => {
            wipe(d);
            wipe(v);
        }
        _ => {}
    }
}

fn put_len(out: &mut Vec<u8>, short: u8, long: u8, bytes: &[u8]) -> Result<()> {
    match u8::try_from(bytes.len()) {
        Ok(n) => {
            out.push(short);
            out.push(n);
        }
        Err(_) => {
            out.push(long);
            let n = u32::try_from(bytes.len()).map_err(|_| Error::Encoding)?;
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Appends the encoding of `value` to `out`: the narrowest form for numbers, binaries,
/// strings and symbols, the 32-bit form for lists, maps and arrays (whose elements take the
/// wide form of their variant).
pub fn encode(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Described(d, v) => {
            out.push(0x00);
            encode(d, out)?;
            encode(v, out)?;
        }
        Value::Array(items) => encode_array(items, out)?,
        Value::List(items) if items.is_empty() => out.push(0x45),
        Value::Null => out.push(0x40),
        Value::Bool(true) => out.push(0x41),
        Value::Bool(false) => out.push(0x42),
        Value::Uint(0) => out.push(0x43),
        Value::Uint(n) => match u8::try_from(*n) {
            Ok(small) => out.extend_from_slice(&[0x52, small]),
            Err(_) => {
                out.push(0x70);
                out.extend_from_slice(&n.to_be_bytes());
            }
        },
        Value::Ulong(0) => out.push(0x44),
        Value::Ulong(n) => match u8::try_from(*n) {
            Ok(small) => out.extend_from_slice(&[0x53, small]),
            Err(_) => {
                out.push(0x80);
                out.extend_from_slice(&n.to_be_bytes());
            }
        },
        Value::Binary(b) => put_len(out, 0xa0, 0xb0, b)?,
        Value::String(s) => put_len(out, 0xa1, 0xb1, s.as_bytes())?,
        Value::Symbol(s) => put_len(out, 0xa3, 0xb3, s.as_bytes())?,
        other => {
            let code = wide_code(other).ok_or(Error::Encoding)?;
            out.push(code);
            body_of(other, out)?;
        }
    }
    Ok(())
}

/// The one constructor an array element of this variant takes (the wide forms).
fn wide_code(value: &Value) -> Option<u8> {
    Some(match value {
        Value::Null => 0x40,
        Value::Bool(_) => 0x56,
        Value::Ubyte(_) => 0x50,
        Value::Ushort(_) => 0x60,
        Value::Uint(_) => 0x70,
        Value::Ulong(_) => 0x80,
        Value::Byte(_) => 0x51,
        Value::Short(_) => 0x61,
        Value::Int(_) => 0x71,
        Value::Long(_) => 0x81,
        Value::Float(_) => 0x72,
        Value::Double(_) => 0x82,
        Value::Decimal(d) => match d.len() {
            4 => 0x74,
            8 => 0x84,
            16 => 0x94,
            _ => return None,
        },
        Value::Char(_) => 0x73,
        Value::Timestamp(_) => 0x83,
        Value::Uuid(_) => 0x98,
        Value::Binary(_) => 0xb0,
        Value::String(_) => 0xb1,
        Value::Symbol(_) => 0xb3,
        Value::List(_) => 0xd0,
        Value::Map(_) => 0xd1,
        Value::Array(_) | Value::Described(..) => return None,
    })
}

/// Size, count and body of a 32-bit list, map or array.
fn compound_body(out: &mut Vec<u8>, count: usize, body: &[u8]) -> Result<()> {
    let count = u32::try_from(count).map_err(|_| Error::Encoding)?;
    let size = u32::try_from(body.len() + 4).map_err(|_| Error::Encoding)?;
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

/// The bytes of a value after its wide constructor.
fn body_of(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    let wide = |out: &mut Vec<u8>, bytes: &[u8]| -> Result<()> {
        let n = u32::try_from(bytes.len()).map_err(|_| Error::Encoding)?;
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(bytes);
        Ok(())
    };
    match value {
        Value::Null => {}
        Value::Bool(b) => out.push(u8::from(*b)),
        Value::Ubyte(n) => out.push(*n),
        Value::Ushort(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Uint(n) | Value::Float(n) | Value::Char(n) => {
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Ulong(n) | Value::Double(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Byte(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Short(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Int(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Long(n) | Value::Timestamp(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Decimal(d) => out.extend_from_slice(d),
        Value::Uuid(u) => out.extend_from_slice(u),
        Value::Binary(b) => wide(out, b)?,
        Value::String(s) | Value::Symbol(s) => wide(out, s.as_bytes())?,
        Value::List(items) => {
            let mut body = Zeroizing::new(Vec::new());
            for item in items {
                encode(item, &mut body)?;
            }
            compound_body(out, items.len(), &body)?;
        }
        Value::Map(pairs) => {
            let mut body = Zeroizing::new(Vec::new());
            for (k, v) in pairs {
                encode(k, &mut body)?;
                encode(v, &mut body)?;
            }
            compound_body(out, pairs.len() * 2, &body)?;
        }
        Value::Array(_) | Value::Described(..) => return Err(Error::Encoding),
    }
    Ok(())
}

/// An array (32-bit form) of values of one variant, each in its wide form.
fn encode_array(items: &[Value], out: &mut Vec<u8>) -> Result<()> {
    let code = match items.first() {
        Some(first) => wide_code(first).ok_or(Error::Encoding)?,
        None => 0x40,
    };
    let mut body = Zeroizing::new(vec![code]);
    for item in items {
        if wide_code(item) != Some(code) {
            return Err(Error::Encoding);
        }
        body_of(item, &mut body)?;
    }
    out.push(0xf0);
    compound_body(out, items.len(), &body)
}

/// A frame read from the server.
#[derive(Debug)]
pub struct Frame {
    /// [`FRAME_AMQP`] or [`FRAME_SASL`].
    pub kind: u8,
    /// The channel.
    pub channel: u16,
    /// The body after the extended header: empty for a heartbeat.
    pub body: Zeroizing<Vec<u8>>,
}

/// The first frame of `bytes`, and how many bytes it took, or `None` when it has not all
/// arrived. A frame is at most `max` bytes, with a data offset of at least 2 words inside it,
/// of a type the node knows.
pub fn parse_frame(bytes: &[u8], max: u32) -> Result<Option<(usize, Frame)>> {
    if bytes.len() >= 4 && bytes.starts_with(b"AMQP") {
        return Err(untrusted(
            "the server sent a protocol header inside a layer",
        ));
    }
    let Some(head) = bytes.get(..8) else {
        return Ok(None);
    };
    let mut d = Decoder::new(head);
    let size = d.u32()?;
    let doff = d.u8()?;
    let kind = d.u8()?;
    let channel = u16::from_be_bytes(d.array()?);
    if size < 8 {
        return Err(invalid("an AMQP frame shorter than its header"));
    }
    if size > max {
        return Err(invalid(
            "an AMQP frame larger than the node's max-frame-size",
        ));
    }
    let start = usize::from(doff) * 4;
    let size = usize::try_from(size).map_err(|_| invalid("AMQP frame size"))?;
    if doff < 2 || start > size {
        return Err(invalid("an AMQP frame with a bad data offset"));
    }
    if kind != FRAME_AMQP && kind != FRAME_SASL {
        return Err(invalid("an AMQP frame of an unknown type"));
    }
    let Some(whole) = bytes.get(..size) else {
        return Ok(None);
    };
    let body = Zeroizing::new(whole.get(start..).unwrap_or_default().to_vec());
    Ok(Some((
        size,
        Frame {
            kind,
            channel,
            body,
        },
    )))
}

/// A frame of `kind` on `channel` with `body` (data offset 2).
pub fn frame(kind: u8, channel: u16, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let size = u32::try_from(body.len() + 8).map_err(|_| Error::Encoding)?;
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 8));
    out.extend_from_slice(&size.to_be_bytes());
    out.push(2);
    out.push(kind);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// A performative or SASL frame body: its code, its fields, and the payload after it (the
/// message of a `transfer`).
#[derive(Debug)]
pub struct Performative {
    /// The descriptor code (see [`code`]).
    pub code: u64,
    /// The fields, in order; one not given reads as `null`.
    pub fields: Vec<Value>,
    /// The bytes after the performative.
    pub payload: Zeroizing<Vec<u8>>,
}

impl Performative {
    /// The field at `i`, or `null`.
    pub fn field(&self, i: usize) -> &Value {
        self.fields.get(i).unwrap_or(&Value::Null)
    }
}

/// True for a performative or SASL frame the standard defines.
fn known(code: u64) -> bool {
    (code::OPEN..=code::CLOSE).contains(&code)
        || (code::SASL_MECHANISMS..=code::SASL_OUTCOME).contains(&code)
}

/// Reads the performative at the start of a frame body; a code the standard does not define
/// is refused.
pub fn performative(body: &[u8]) -> Result<Performative> {
    let mut d = Decoder::new(body);
    let value = d.value()?;
    let payload = Zeroizing::new(d.rest().to_vec());
    let Value::Described(descriptor, fields) = value else {
        return Err(invalid("an AMQP frame body that is not a performative"));
    };
    let code = descriptor
        .descriptor_code()
        .filter(|c| known(*c))
        .ok_or_else(|| invalid("an AMQP performative the standard does not define"))?;
    let fields = match *fields {
        Value::List(fields) => fields,
        _ => return Err(invalid("an AMQP performative that is not a list")),
    };
    Ok(Performative {
        code,
        fields,
        payload,
    })
}

/// True for an address the node names: 1 to 1024 bytes of UTF-8 with no control byte.
pub fn address_ok(address: &[u8]) -> bool {
    !address.is_empty()
        && address.len() <= MAX_ADDRESS
        && std::str::from_utf8(address).is_ok()
        && !address.iter().any(|b| *b < 0x20 || *b == 0x7f)
}

/// A message taken from an address.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    /// Its body: the `data` sections together, or an `amqp-value` that is text or binary.
    pub body: Zeroizing<Vec<u8>>,
    /// An `amqp-value` or `amqp-sequence` body of other types, as JSON.
    pub value: Option<serde_json::Value>,
    /// `properties.subject`.
    pub subject: Option<String>,
    /// `properties.message-id`, as JSON.
    pub message_id: Option<serde_json::Value>,
    /// `properties.content-type`.
    pub content_type: Option<String>,
    /// `header.delivery-count`.
    pub delivery_count: u32,
    /// The message as it came, for the reflection search.
    pub raw: Zeroizing<Vec<u8>>,
}

impl Message {
    /// Reads the sections of an encoded message (one decode: its bounds cover them all).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let mut message = Message {
            body: Zeroizing::new(Vec::new()),
            value: None,
            subject: None,
            message_id: None,
            content_type: None,
            delivery_count: 0,
            raw: Zeroizing::new(bytes.to_vec()),
        };
        while !d.is_empty() {
            let Value::Described(descriptor, section) = d.value()? else {
                return Err(invalid("an AMQP message section that is not described"));
            };
            match (descriptor.descriptor_code(), *section) {
                (Some(code::HEADER), Value::List(fields)) => {
                    message.delivery_count = fields.get(4).and_then(Value::uint).unwrap_or(0);
                }
                (Some(code::PROPERTIES), Value::List(fields)) => {
                    message.message_id = fields
                        .first()
                        .filter(|v| **v != Value::Null)
                        .map(Value::json);
                    message.subject = fields.get(3).and_then(Value::text).map(str::to_string);
                    message.content_type = fields.get(6).and_then(Value::text).map(str::to_string);
                }
                (Some(code::DATA | code::VALUE), Value::Binary(bytes)) => {
                    message.body.extend_from_slice(&bytes);
                }
                (Some(code::VALUE), Value::String(text)) => {
                    message.body.extend_from_slice(text.as_bytes());
                }
                (Some(code::VALUE), other) => message.value = Some(other.json()),
                (Some(code::SEQUENCE), list @ Value::List(_)) => {
                    message.value = Some(list.json());
                }
                (Some(code::DATA | code::SEQUENCE | code::HEADER | code::PROPERTIES), _) => {
                    return Err(invalid("an AMQP message section of the wrong type"));
                }
                // Annotations, application properties and the footer are not handed back.
                _ => {}
            }
        }
        Ok(message)
    }

    /// As JSON: `{"payload", "subject", "message_id", "content_type", "delivery_count"}`,
    /// the payload as text, `{"base64"}`, or the value of another type.
    pub fn json(&self) -> serde_json::Value {
        use base64::Engine as _;
        let payload = match (&self.value, std::str::from_utf8(&self.body)) {
            (Some(value), _) => value.clone(),
            (None, Ok(text)) => serde_json::Value::String(text.to_string()),
            (None, Err(_)) => serde_json::json!({
                "base64": base64::engine::general_purpose::STANDARD.encode(self.body.as_slice())
            }),
        };
        serde_json::json!({
            "payload": payload,
            "subject": self.subject,
            "message_id": self.message_id,
            "content_type": self.content_type,
            "delivery_count": self.delivery_count,
        })
    }
}

/// What a command did, as JSON, and whether the broker refused it.
#[derive(Debug)]
pub struct Outcome {
    /// The result.
    pub json: serde_json::Value,
    /// True when the broker refused (a rejected, released or modified delivery, a link it
    /// would not attach).
    pub failed: bool,
}

/// The direction of a link.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Sender,
    Receiver,
}

impl Role {
    /// `role` as the standard encodes it: `false` for a sender.
    fn wire(self) -> bool {
        self == Role::Receiver
    }
}

/// The settle modes of a link as the node asks for them: `snd-settle-mode` (0 unsettled, 1
/// settled) and `rcv-settle-mode` (0 first, 1 second).
fn modes(mode: SettleMode) -> (u8, u8) {
    match mode {
        SettleMode::Settled => (1, 0),
        SettleMode::First => (0, 0),
        SettleMode::Second => (0, 1),
    }
}

/// An open connection with its one session.
pub struct Client<'s> {
    io: Io<'s>,
    scrub: Scrub,
    /// The largest frame the server takes.
    max_out: usize,
    /// How often the node must send something (half the server's `idle-time-out`).
    keepalive: Option<Duration>,
    last_write: Instant,
    /// Session state: the next transfer id each way, and the windows.
    next_outgoing_id: u32,
    next_incoming_id: u32,
    remote_incoming_window: u32,
    incoming_left: u32,
    next_delivery_id: u32,
    next_tag: u64,
    links: u64,
}

impl<'s> Client<'s> {
    /// Signs in with `mechanism` as `user` with `secret` through the SASL layer, then opens the
    /// connection to `hostname` and a session. Nothing secret is written before the server's
    /// SASL header and mechanisms are known.
    pub fn connect(
        io: Io<'s>,
        mechanism: Mechanism,
        user: &[u8],
        secret: &[u8],
        hostname: &[u8],
    ) -> Result<Self> {
        let mut client = Client {
            io,
            scrub: Scrub::new(&[user, secret]),
            max_out: MIN_MAX_FRAME as usize,
            keepalive: None,
            last_write: Instant::now(),
            next_outgoing_id: 0,
            next_incoming_id: 0,
            remote_incoming_window: 0,
            incoming_left: WINDOW,
            next_delivery_id: 0,
            next_tag: 0,
            links: 0,
        };
        client.header(SASL_HEADER)?;
        client.sasl(mechanism, user, secret, hostname)?;
        client.header(AMQP_HEADER)?;
        client.open(hostname)?;
        client.begin()?;
        Ok(client)
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.io.write(bytes)?;
        self.last_write = Instant::now();
        Ok(())
    }

    /// Writes the protocol header of a layer and reads the server's, which must be the same.
    fn header(&mut self, header: &[u8; 8]) -> Result<()> {
        self.write(header)?;
        let theirs = self.io.take(8)?;
        if theirs.as_slice() == header {
            return Ok(());
        }
        if theirs.starts_with(b"AMQP") {
            return Err(untrusted(
                "the server answered with another AMQP layer or version",
            ));
        }
        Err(invalid("the server did not answer with an AMQP header"))
    }

    /// Sends a performative on channel 0, with `payload` after it.
    fn send(&mut self, kind: u8, value: &Value, payload: &[u8]) -> Result<()> {
        let mut body = Zeroizing::new(Vec::new());
        encode(value, &mut body)?;
        body.extend_from_slice(payload);
        if body.len() + 8 > self.max_out {
            return Err(Error::transport(TransportKind::TooLarge, false));
        }
        let bytes = frame(kind, 0, &body)?;
        self.write(&bytes)
    }

    /// The next frame, within the connection's bounds, or `None` once `until` passed.
    /// Heartbeats are skipped, and the node sends its own when the server asked for them.
    fn next_frame(&mut self, until: Option<Instant>) -> Result<Option<Frame>> {
        loop {
            if let Some((n, frame)) = parse_frame(self.io.buffered(), MAX_FRAME)? {
                self.io.take(n)?;
                if frame.channel != 0 {
                    return Err(untrusted("a frame on a channel the node did not open"));
                }
                if frame.body.is_empty() {
                    continue;
                }
                return Ok(Some(frame));
            }
            if until.is_some_and(|u| Instant::now() >= u) {
                return Ok(None);
            }
            self.tick()?;
            self.io.poll(WAIT)?;
        }
    }

    /// Sends an empty frame when the server's idle time-out asks for one.
    fn tick(&mut self) -> Result<()> {
        if let Some(every) = self.keepalive
            && self.last_write.elapsed() >= every
        {
            let empty = frame(FRAME_AMQP, 0, &[])?;
            self.write(&empty)?;
        }
        Ok(())
    }

    /// The next performative of the SASL layer.
    fn sasl_frame(&mut self) -> Result<Performative> {
        let frame = self
            .next_frame(None)?
            .ok_or_else(|| invalid("no SASL frame"))?;
        if frame.kind != FRAME_SASL {
            return Err(untrusted("an AMQP frame before SASL ended"));
        }
        performative(&frame.body)
    }

    /// The initial response of `mechanism`, and the SCRAM state when it is SCRAM.
    fn initial(
        mechanism: Mechanism,
        user: &[u8],
        secret: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, Option<super::postgres::Scram>)> {
        Ok(match mechanism {
            Mechanism::Plain => {
                if user.contains(&0) || secret.contains(&0) {
                    return Err(refused("a PLAIN user or password holds no NUL byte"));
                }
                let mut r = Zeroizing::new(vec![0]);
                r.extend_from_slice(user);
                r.push(0);
                r.extend_from_slice(secret);
                (r, None)
            }
            // The authorization identity; the TLS client certificate authenticates.
            Mechanism::External => (Zeroizing::new(user.to_vec()), None),
            Mechanism::Xoauth2 => {
                if user.iter().chain(secret).any(|b| *b < 0x20) {
                    return Err(refused("an XOAUTH2 user or token holds no control byte"));
                }
                let mut r = Zeroizing::new(b"user=".to_vec());
                r.extend_from_slice(user);
                r.extend_from_slice(b"\x01auth=Bearer ");
                r.extend_from_slice(secret);
                r.extend_from_slice(b"\x01\x01");
                (r, None)
            }
            Mechanism::ScramSha256 => {
                let s = super::postgres::Scram::with_user(user)?;
                (Zeroizing::new(s.first().into_bytes()), Some(s))
            }
            _ => return Err(refused("a SASL mechanism AMQP 1.0 does not take")),
        })
    }

    /// Sends a SASL frame whose fields hold a response, then wipes the fields.
    fn send_sasl(&mut self, code: u64, fields: Vec<Value>) -> Result<()> {
        let mut value = Value::described(code, fields);
        let sent = self.send(FRAME_SASL, &value, &[]);
        wipe(&mut value);
        sent
    }

    fn sasl(
        &mut self,
        mechanism: Mechanism,
        user: &[u8],
        secret: &[u8],
        host: &[u8],
    ) -> Result<()> {
        let name = match mechanism {
            Mechanism::Plain => "PLAIN",
            Mechanism::External => "EXTERNAL",
            Mechanism::ScramSha256 => "SCRAM-SHA-256",
            Mechanism::Xoauth2 => "XOAUTH2",
            _ => return Err(refused("a SASL mechanism AMQP 1.0 does not take")),
        };
        let offered = self.sasl_frame()?;
        if offered.code != code::SASL_MECHANISMS {
            return Err(invalid("expected sasl-mechanisms"));
        }
        let listed = match offered.field(0) {
            Value::Symbol(one) => one == name,
            Value::Array(all) => all.iter().any(|m| m.text() == Some(name)),
            _ => false,
        };
        if !listed {
            return Err(untrusted(
                "the server does not offer the policy's mechanism",
            ));
        }
        let (response, mut scram) = Self::initial(mechanism, user, secret)?;
        let host = std::str::from_utf8(host).map_err(|_| refused("a host name in UTF-8"))?;
        self.send_sasl(
            code::SASL_INIT,
            vec![
                Value::Symbol(name.into()),
                Value::Binary(response.to_vec()),
                Value::String(host.into()),
            ],
        )?;
        drop(response);
        let mut proven = scram.is_none();
        let mut answered = false;
        for _ in 0..MAX_SASL_ROUNDS {
            let p = self.sasl_frame()?;
            match p.code {
                code::SASL_CHALLENGE => {
                    let Some(s) = scram.as_mut() else {
                        return Err(untrusted("a SASL challenge the mechanism does not take"));
                    };
                    let Value::Binary(challenge) = p.field(0) else {
                        return Err(invalid("a SASL challenge without its bytes"));
                    };
                    let answer = if proven {
                        return Err(untrusted("a SASL challenge after the server's proof"));
                    } else if answered {
                        // The server-final message, before the outcome.
                        s.verify(challenge)?;
                        proven = true;
                        Zeroizing::new(Vec::new())
                    } else {
                        answered = true;
                        s.last(challenge, secret)?
                    };
                    self.send_sasl(code::SASL_RESPONSE, vec![Value::Binary(answer.to_vec())])?;
                }
                code::SASL_OUTCOME => {
                    let outcome = match p.field(0) {
                        Value::Ubyte(c) => *c,
                        _ => return Err(invalid("a SASL outcome without its code")),
                    };
                    if outcome != 0 {
                        return Err(Error::AuthRefused {
                            rule: "the server refused the sign-in",
                        });
                    }
                    if !proven {
                        let (Some(s), Value::Binary(data), true) =
                            (scram.as_ref(), p.field(1), answered)
                        else {
                            return Err(untrusted(
                                "SCRAM: the server signed in without proving it knows the password",
                            ));
                        };
                        s.verify(data)?;
                    }
                    return Ok(());
                }
                _ => return Err(invalid("an unexpected SASL frame")),
            }
        }
        Err(untrusted("a SASL exchange longer than its mechanism"))
    }

    /// The next performative of the connection, or `None` once `until` passed. A `close` or
    /// `end` of the server ends the connection, as does an `open` or `begin` the node did
    /// not ask for; a transfer counts against the session's incoming window.
    fn next(&mut self, until: Option<Instant>) -> Result<Option<Performative>> {
        let Some(frame) = self.next_frame(until)? else {
            return Ok(None);
        };
        if frame.kind != FRAME_AMQP {
            return Err(untrusted("a SASL frame after SASL ended"));
        }
        let p = performative(&frame.body)?;
        match p.code {
            code::CLOSE => Err(Error::transport(TransportKind::Closed, true)),
            code::END => Err(untrusted("the server ended the session")),
            code::SASL_MECHANISMS..=code::SASL_OUTCOME => {
                Err(untrusted("a SASL performative after SASL ended"))
            }
            code::OPEN | code::BEGIN => Err(untrusted("an open or begin the node did not ask for")),
            code::TRANSFER => {
                if self.incoming_left == 0 {
                    return Err(untrusted("the server overran the session's window"));
                }
                self.incoming_left -= 1;
                self.next_incoming_id = self.next_incoming_id.wrapping_add(1);
                Ok(Some(p))
            }
            _ => Ok(Some(p)),
        }
    }

    /// The next performative of the connection, within its bounds.
    fn next_now(&mut self) -> Result<Performative> {
        self.next(None)?.ok_or_else(|| invalid("no AMQP frame"))
    }

    /// The next frame, which must be `code` (while the connection and session open).
    fn expect_frame(&mut self, code: u64) -> Result<Performative> {
        let frame = self
            .next_frame(None)?
            .ok_or_else(|| invalid("no AMQP frame"))?;
        if frame.kind != FRAME_AMQP {
            return Err(untrusted("a SASL frame after SASL ended"));
        }
        let p = performative(&frame.body)?;
        match p.code {
            c if c == code => Ok(p),
            code::CLOSE => Err(Error::transport(TransportKind::Closed, true)),
            _ => Err(invalid("an unexpected performative while opening")),
        }
    }

    fn open(&mut self, hostname: &[u8]) -> Result<()> {
        let mut id = [0u8; 12];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| Error::Encoding)?;
        let container: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let hostname =
            std::str::from_utf8(hostname).map_err(|_| refused("a host name in UTF-8"))?;
        let open = Value::described(
            code::OPEN,
            vec![
                Value::String(format!("credentials-{container}")),
                Value::String(hostname.into()),
                Value::Uint(MAX_FRAME),
                Value::Ushort(0),
            ],
        );
        self.send(FRAME_AMQP, &open, &[])?;
        let theirs = self.expect_frame(code::OPEN)?;
        let max = match theirs.field(2) {
            Value::Null => u32::MAX,
            v => v
                .uint()
                .ok_or_else(|| invalid("a max-frame-size that is not a uint"))?,
        };
        if max < MIN_MAX_FRAME {
            return Err(invalid("a max-frame-size below the minimum"));
        }
        self.max_out = usize::try_from(max.min(MAX_FRAME)).map_err(|_| Error::Encoding)?;
        if let Some(ms) = theirs.field(4).uint().filter(|ms| *ms > 0) {
            self.keepalive = Some(Duration::from_millis(u64::from(ms / 2).max(500)));
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<()> {
        let begin = Value::described(
            code::BEGIN,
            vec![
                Value::Null,
                Value::Uint(self.next_outgoing_id),
                Value::Uint(WINDOW),
                Value::Uint(WINDOW),
                Value::Uint(0),
            ],
        );
        self.send(FRAME_AMQP, &begin, &[])?;
        let theirs = self.expect_frame(code::BEGIN)?;
        if theirs.field(0) != &Value::Ushort(0) {
            return Err(untrusted("a begin for a session the node did not open"));
        }
        self.next_incoming_id = theirs
            .field(1)
            .uint()
            .ok_or_else(|| invalid("a begin without next-outgoing-id"))?;
        self.remote_incoming_window = theirs
            .field(2)
            .uint()
            .ok_or_else(|| invalid("a begin without incoming-window"))?;
        Ok(())
    }

    /// A `flow` that renews the session's incoming window, and for the node's receiving link
    /// gives `credit` from `delivery_count`.
    fn session_flow(&mut self, link: Option<(u32, u32)>) -> Result<()> {
        self.incoming_left = WINDOW;
        let mut fields = vec![
            Value::Uint(self.next_incoming_id),
            Value::Uint(WINDOW),
            Value::Uint(self.next_outgoing_id),
            Value::Uint(WINDOW),
        ];
        if let Some((delivery_count, credit)) = link {
            fields.extend([
                Value::Uint(0),
                Value::Uint(delivery_count),
                Value::Uint(credit),
                Value::Null,
                Value::Bool(false),
                Value::Bool(false),
            ]);
        }
        self.send(FRAME_AMQP, &Value::described(code::FLOW, fields), &[])
    }

    /// The error of a `detach` or `rejected` as JSON, scrubbed of the sign-in.
    fn error_json(&self, error: &Value) -> serde_json::Value {
        let (condition, description) = match error.as_described_list() {
            Some((code::ERROR, fields)) => (
                fields.first().and_then(Value::text).unwrap_or_default(),
                fields.get(1).and_then(Value::text).unwrap_or_default(),
            ),
            _ => ("", ""),
        };
        let scrub =
            |text: &str| String::from_utf8_lossy(&self.scrub.apply(text.as_bytes())).into_owned();
        serde_json::json!({"condition": scrub(condition), "description": scrub(description)})
    }

    /// Attaches the link of `role` to `address` with `mode`: `Ok(Ok(count))` when the broker
    /// attached it (with the initial delivery count of a broker that sends), `Ok(Err(..))`
    /// with the refusal when it did not.
    fn attach(
        &mut self,
        role: Role,
        address: &str,
        mode: SettleMode,
    ) -> Result<core::result::Result<u32, Outcome>> {
        self.links = self.links.wrapping_add(1);
        let (snd, rcv) = modes(mode);
        let terminus = |code, address: Option<&str>| {
            Value::described(
                code,
                vec![address.map_or(Value::Null, |a| Value::String(a.into()))],
            )
        };
        let (source, target) = match role {
            Role::Sender => (
                terminus(code::SOURCE, None),
                terminus(code::TARGET, Some(address)),
            ),
            Role::Receiver => (
                terminus(code::SOURCE, Some(address)),
                terminus(code::TARGET, None),
            ),
        };
        let fields = vec![
            Value::String(format!("credentials-{}", self.links)),
            Value::Uint(0),
            Value::Bool(role.wire()),
            Value::Ubyte(snd),
            Value::Ubyte(rcv),
            source,
            target,
            Value::Null,
            Value::Bool(false),
            match role {
                Role::Sender => Value::Uint(0),
                Role::Receiver => Value::Null,
            },
            Value::Ulong(MAX_MESSAGE as u64),
        ];
        self.send(FRAME_AMQP, &Value::described(code::ATTACH, fields), &[])?;
        let theirs = self.next_now()?;
        match theirs.code {
            code::ATTACH => {}
            code::DETACH => return self.refused_link(&theirs).map(Err),
            _ => return Err(invalid("expected attach")),
        }
        if theirs.field(1).uint() != Some(0) {
            return Err(untrusted("a link handle the node did not offer"));
        }
        if theirs.field(2).bool() != Some(!role.wire()) {
            return Err(untrusted("the broker attached a link of the same role"));
        }
        // A terminus the broker did not set means it refused; its detach follows.
        let terminus = match role {
            Role::Sender => theirs.field(6),
            Role::Receiver => theirs.field(5),
        };
        if *terminus == Value::Null {
            let detach = self.next_now()?;
            if detach.code != code::DETACH {
                return Err(invalid("expected detach after a refused attach"));
            }
            return self.refused_link(&detach).map(Err);
        }
        // A mode the broker changes is refused, not taken: the caller's guarantee is the
        // policy's. `rcv-settle-mode` absent is `first`; `snd-settle-mode` absent is `mixed`,
        // which only the broker's receiving end may answer (it settles as the node sends).
        let snd_theirs = match theirs.field(3) {
            Value::Null => 2,
            Value::Ubyte(m) => *m,
            _ => return Err(invalid("a snd-settle-mode that is not a ubyte")),
        };
        let rcv_theirs = match theirs.field(4) {
            Value::Null => 0,
            Value::Ubyte(m) => *m,
            _ => return Err(invalid("a rcv-settle-mode that is not a ubyte")),
        };
        let snd_ok = snd_theirs == snd || (role == Role::Sender && snd_theirs == 2);
        if !snd_ok || rcv_theirs != rcv {
            return Err(untrusted("the broker changed the link's settle mode"));
        }
        let initial = match role {
            Role::Sender => 0,
            Role::Receiver => theirs
                .field(9)
                .uint()
                .ok_or_else(|| invalid("a sending attach without initial-delivery-count"))?,
        };
        Ok(Ok(initial))
    }

    /// The broker refused the link: its detach answered, and its error as the outcome.
    fn refused_link(&mut self, detach: &Performative) -> Result<Outcome> {
        let json = serde_json::json!({"error": self.error_json(detach.field(2))});
        self.detach_reply()?;
        Ok(Outcome { json, failed: true })
    }

    /// Sends the node's `detach` of its link.
    fn detach_reply(&mut self) -> Result<()> {
        let detach = Value::described(code::DETACH, vec![Value::Uint(0), Value::Bool(true)]);
        self.send(FRAME_AMQP, &detach, &[])
    }

    /// Detaches the link and waits for the broker's `detach`, and its error if it has one.
    /// Transfers in flight are dropped (unsettled ones go back to the broker with the link).
    fn detach(&mut self) -> Result<Option<serde_json::Value>> {
        self.detach_reply()?;
        loop {
            let p = self.next_now()?;
            match p.code {
                code::DETACH => {
                    let error = p.field(2);
                    return Ok((*error != Value::Null).then(|| self.error_json(error)));
                }
                code::TRANSFER | code::FLOW | code::DISPOSITION => {
                    if self.incoming_left < WINDOW / 2 {
                        self.session_flow(None)?;
                    }
                }
                _ => return Err(invalid("an unexpected performative while detaching")),
            }
        }
    }

    /// Takes a `flow`: the broker's incoming window for the session, and for the node's link
    /// the credit it gives now (`delivery-count` + `link-credit` - `sent`).
    fn flow(&mut self, p: &Performative, sent: u32) -> Result<Option<u32>> {
        let next_in = p.field(0).uint().unwrap_or(0);
        let window = p
            .field(1)
            .uint()
            .ok_or_else(|| invalid("a flow without incoming-window"))?;
        self.remote_incoming_window = next_in
            .wrapping_add(window)
            .wrapping_sub(self.next_outgoing_id);
        if *p.field(4) == Value::Null {
            return Ok(None);
        }
        if p.field(4).uint() != Some(0) {
            return Err(untrusted("a flow for a link the node did not attach"));
        }
        let count = p.field(5).uint().unwrap_or(0);
        let credit = p.field(6).uint().unwrap_or(0);
        Ok(Some(count.wrapping_add(credit).wrapping_sub(sent)))
    }

    /// Sends `body` to `address` as one `data` section, settled as `mode` says: `settled`
    /// sends it settled (at most once), `first` waits for the broker's outcome, `second`
    /// waits for it and settles after the broker (section 3.4).
    pub fn send_message(
        &mut self,
        address: &[u8],
        body: &[u8],
        mode: SettleMode,
    ) -> Result<Outcome> {
        if !address_ok(address) {
            return Err(refused(
                "an AMQP address: 1 to 1024 bytes of UTF-8, no control byte",
            ));
        }
        let address = std::str::from_utf8(address).map_err(|_| Error::Encoding)?;
        let mut message = Zeroizing::new(Vec::new());
        let mut section = Value::Described(
            Box::new(Value::Ulong(code::DATA)),
            Box::new(Value::Binary(body.to_vec())),
        );
        let encoded = encode(&section, &mut message);
        wipe(&mut section);
        encoded?;
        if message.len() > MAX_MESSAGE {
            return Err(Error::transport(TransportKind::TooLarge, false));
        }
        if let Err(refusal) = self.attach(Role::Sender, address, mode)? {
            return Ok(refusal);
        }
        let mut credit = 0u32;
        while credit == 0 {
            let p = self.next_now()?;
            match p.code {
                code::FLOW => credit = self.flow(&p, 0)?.unwrap_or(credit),
                code::DETACH => return self.refused_link(&p),
                _ => return Err(invalid("an unexpected performative before credit")),
            }
        }
        let settled = mode == SettleMode::Settled;
        let id = self.next_delivery_id;
        self.next_delivery_id = self.next_delivery_id.wrapping_add(1);
        let tag = self.next_tag.to_be_bytes().to_vec();
        self.next_tag = self.next_tag.wrapping_add(1);
        let transfer = |more: bool| {
            Value::described(
                code::TRANSFER,
                vec![
                    Value::Uint(0),
                    Value::Uint(id),
                    Value::Binary(tag.clone()),
                    Value::Uint(0),
                    Value::Bool(settled),
                    Value::Bool(more),
                ],
            )
        };
        let mut head = Vec::new();
        encode(&transfer(true), &mut head)?;
        let room = self.max_out.saturating_sub(8 + head.len()).max(1);
        let chunks: Vec<&[u8]> = message.chunks(room).collect();
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.into_iter().enumerate() {
            while self.remote_incoming_window == 0 {
                let p = self.next_now()?;
                match p.code {
                    code::FLOW => {
                        self.flow(&p, 0)?;
                    }
                    code::DETACH => return self.refused_link(&p),
                    _ => return Err(invalid("an unexpected performative while sending")),
                }
            }
            self.send(FRAME_AMQP, &transfer(i < last), chunk)?;
            self.next_outgoing_id = self.next_outgoing_id.wrapping_add(1);
            self.remote_incoming_window = self.remote_incoming_window.saturating_sub(1);
        }
        let outcome = if settled {
            Outcome {
                json: serde_json::json!({"settled": true}),
                failed: false,
            }
        } else {
            match self.outcome_of(id, mode)? {
                Ok(outcome) => outcome,
                // The broker detached the link instead of answering.
                Err(refusal) => return Ok(refusal),
            }
        };
        if let Some(error) = self.detach()? {
            return Ok(Outcome {
                json: serde_json::json!({"error": error}),
                failed: true,
            });
        }
        Ok(outcome)
    }

    /// Waits for the broker's disposition of delivery `id`, and settles it after the broker
    /// when the mode is `second` (or the broker did not settle).
    fn outcome_of(
        &mut self,
        id: u32,
        mode: SettleMode,
    ) -> Result<core::result::Result<Outcome, Outcome>> {
        loop {
            let p = self.next_now()?;
            match p.code {
                code::FLOW => {
                    self.flow(&p, 1)?;
                    continue;
                }
                code::DETACH => return self.refused_link(&p).map(Err),
                code::DISPOSITION => {}
                _ => return Err(invalid("an unexpected performative after a transfer")),
            }
            if p.field(0).bool() != Some(true) {
                return Err(untrusted(
                    "a disposition of a sender on the node's sending link",
                ));
            }
            let first = p
                .field(1)
                .uint()
                .ok_or_else(|| invalid("a disposition without first"))?;
            let last = p.field(2).uint().unwrap_or(first);
            if !(first..=last).contains(&id) {
                return Err(untrusted(
                    "a disposition of a delivery the node did not send",
                ));
            }
            let settled = p.field(3).bool().unwrap_or(false);
            let state = p.field(4);
            let (name, error) = match state.as_described_list() {
                Some((code::ACCEPTED, _)) => ("accepted", None),
                Some((code::REJECTED, fields)) => (
                    "rejected",
                    Some(self.error_json(fields.first().unwrap_or(&Value::Null))),
                ),
                Some((code::RELEASED, _)) => ("released", None),
                Some((code::MODIFIED, _)) => ("modified", None),
                // A `received` state is progress, not an outcome.
                Some((code::RECEIVED, _)) if !settled => continue,
                _ => return Err(invalid("a disposition without an outcome")),
            };
            if mode == SettleMode::Second && settled {
                return Err(untrusted(
                    "the broker settled first on a link that settles second",
                ));
            }
            if !settled {
                let settle = Value::described(
                    code::DISPOSITION,
                    vec![
                        Value::Bool(false),
                        Value::Uint(id),
                        Value::Null,
                        Value::Bool(true),
                        state.clone(),
                    ],
                );
                self.send(FRAME_AMQP, &settle, &[])?;
            }
            let mut json = serde_json::json!({"outcome": name});
            if let (Some(error), Some(map)) = (error, json.as_object_mut()) {
                map.insert("error".into(), error);
            }
            return Ok(Ok(Outcome {
                json,
                failed: name != "accepted",
            }));
        }
    }

    /// Takes up to `count` messages from `address` within `wait`, settled as `mode` says: in
    /// `settled` the broker sends them settled (at most once); in `first` the node accepts and
    /// settles each; in `second` it accepts each and waits for the broker to settle. At most
    /// `max` bytes of messages together.
    pub fn receive(
        &mut self,
        address: &[u8],
        count: usize,
        wait: Duration,
        mode: SettleMode,
        max: usize,
    ) -> Result<(Outcome, Vec<Message>)> {
        if !address_ok(address) {
            return Err(refused(
                "an AMQP address: 1 to 1024 bytes of UTF-8, no control byte",
            ));
        }
        let address = std::str::from_utf8(address).map_err(|_| Error::Encoding)?;
        let credit = u32::try_from(count).map_err(|_| Error::Encoding)?;
        let initial = match self.attach(Role::Receiver, address, mode)? {
            Ok(initial) => initial,
            Err(refusal) => return Ok((refusal, Vec::new())),
        };
        self.session_flow(Some((initial, credit)))?;
        let until = Instant::now().checked_add(wait);
        let mut messages = Vec::new();
        let mut deliveries = 0usize;
        let mut left = max;
        let mut partial: Option<(u32, Zeroizing<Vec<u8>>)> = None;
        while messages.len() < count {
            let Some(p) = self.next(until)? else {
                break;
            };
            match p.code {
                code::TRANSFER => {}
                code::FLOW => {
                    self.flow(&p, 0)?;
                    continue;
                }
                code::DETACH => {
                    let json = serde_json::json!({"error": self.error_json(p.field(2))});
                    self.detach_reply()?;
                    return Ok((Outcome { json, failed: true }, messages));
                }
                code::DISPOSITION => continue,
                _ => return Err(invalid("an unexpected performative while receiving")),
            }
            if p.field(0).uint() != Some(0) {
                return Err(untrusted("a transfer on a link the node did not attach"));
            }
            if self.incoming_left < WINDOW / 2 {
                self.session_flow(None)?;
            }
            if p.field(9).bool() == Some(true) {
                // Aborted: the broker gave the delivery up.
                partial = None;
                continue;
            }
            let more = p.field(5).bool().unwrap_or(false);
            let id = match (&partial, p.field(1).uint()) {
                (Some((id, _)), None) => *id,
                (Some((id, _)), Some(given)) if given == *id => *id,
                (Some(_), Some(_)) => {
                    return Err(untrusted("a transfer of another delivery before one ended"));
                }
                (None, Some(given)) => {
                    deliveries += 1;
                    if deliveries > count {
                        return Err(untrusted("more deliveries than the credit the node gave"));
                    }
                    given
                }
                (None, None) => return Err(invalid("a transfer without its delivery-id")),
            };
            let (_, mut bytes) = partial
                .take()
                .unwrap_or_else(|| (id, Zeroizing::new(Vec::new())));
            if bytes.len().saturating_add(p.payload.len()) > MAX_MESSAGE.min(left) {
                return Err(Error::transport(TransportKind::TooLarge, true));
            }
            bytes.extend_from_slice(&p.payload);
            if more {
                partial = Some((id, bytes));
                continue;
            }
            let settled = p.field(4).bool().unwrap_or(false);
            if settled != (mode == SettleMode::Settled) {
                return Err(untrusted(
                    "a delivery settled otherwise than the link's mode",
                ));
            }
            left = left.saturating_sub(bytes.len());
            let message = Message::parse(&bytes)?;
            if mode != SettleMode::Settled {
                self.accept(id, mode)?;
            }
            messages.push(message);
        }
        if let Some(error) = self.detach()? {
            let json = serde_json::json!({"error": error});
            return Ok((Outcome { json, failed: true }, messages));
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

    /// Accepts delivery `id`: settled at once (`first`), or unsettled until the broker
    /// settles it (`second`).
    fn accept(&mut self, id: u32, mode: SettleMode) -> Result<()> {
        let first = mode == SettleMode::First;
        let accept = Value::described(
            code::DISPOSITION,
            vec![
                Value::Bool(true),
                Value::Uint(id),
                Value::Null,
                Value::Bool(first),
                Value::described(code::ACCEPTED, Vec::new()),
            ],
        );
        self.send(FRAME_AMQP, &accept, &[])?;
        if first {
            return Ok(());
        }
        loop {
            let p = self.next_now()?;
            match p.code {
                code::DISPOSITION => {
                    let from = p.field(1).uint().unwrap_or(u32::MAX);
                    let to = p.field(2).uint().unwrap_or(from);
                    if p.field(0).bool() == Some(false)
                        && (from..=to).contains(&id)
                        && p.field(3).bool() == Some(true)
                    {
                        return Ok(());
                    }
                }
                code::FLOW => {
                    self.flow(&p, 0)?;
                }
                _ => {
                    return Err(untrusted("the broker did not settle an accepted delivery"));
                }
            }
        }
    }

    /// Ends the session and closes the connection.
    pub fn close(&mut self) {
        let _ = self.send(FRAME_AMQP, &Value::described(code::END, Vec::new()), &[]);
        let _ = self.send(FRAME_AMQP, &Value::described(code::CLOSE, Vec::new()), &[]);
        self.io.close();
    }
}

/// The TLS protocol header before TLS (section 5.2): the node writes it, and the server must
/// answer with the same header and nothing else before the handshake.
pub fn prelude(io: &mut Io<'_>) -> Result<()> {
    io.write(TLS_HEADER)?;
    let theirs = io.take(8)?;
    if theirs.as_slice() != TLS_HEADER {
        return Err(untrusted("the server does not take the AMQP TLS header"));
    }
    io.expect_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    /// 64 KiB of the smallest frames that carry a body (a header and 2 bytes), in one read.
    fn small_frames() -> (usize, Vec<u8>) {
        let one = frame(FRAME_AMQP, 0, &[0x00, 0x40]).unwrap();
        let count = 64 * 1024 / one.len();
        let mut bytes = Vec::with_capacity(count * one.len());
        for _ in 0..count {
            bytes.extend_from_slice(&one);
        }
        (count, bytes)
    }

    /// Reads every frame of `bytes` as `next_frame` does; the bytes the buffer moved.
    fn read_all(count: usize, bytes: &[u8]) -> u64 {
        use crate::proto::io::testing::{Fed, wide};
        let mut stream = Fed(std::collections::VecDeque::from([bytes.to_vec()]));
        let mut io = Io::new(&mut stream, wide());
        io.poll(WAIT).unwrap();
        for _ in 0..count {
            let (n, frame) = parse_frame(io.buffered(), MAX_FRAME).unwrap().unwrap();
            io.take(n).unwrap();
            assert_eq!(frame.body.len(), 2);
        }
        assert!(io.buffered().is_empty());
        io.copied()
    }

    #[test]
    fn frames_parse_in_linear_copies() {
        let (count, bytes) = small_frames();
        let copied = read_all(count, &bytes);
        assert!(copied <= 2 * bytes.len() as u64, "copied {copied} bytes");
    }

    /// `cargo test --release -p engine --lib -- --ignored --nocapture measure_`
    #[test]
    #[ignore = "a measurement, run in release"]
    fn measure_amqp1_small_frames() {
        let (count, bytes) = small_frames();
        let (us, copied) = crate::proto::io::testing::median_us(9, || read_all(count, &bytes));
        println!(
            "amqp1: {count} frames in {} bytes: median {us} us, {copied} bytes copied",
            bytes.len()
        );
    }

    #[test]
    fn values_encode_as_the_standard_writes_them() {
        let mut out = Vec::new();
        let open = Value::described(code::OPEN, vec![Value::String("c".into())]);
        encode(&open, &mut out).unwrap();
        assert_eq!(
            out,
            [
                0x00, 0x53, 0x10, 0xd0, 0, 0, 0, 7, 0, 0, 0, 1, 0xa1, 1, b'c'
            ]
        );
        let (code, _) = decode(&out)
            .unwrap()
            .as_described_list()
            .map(|(c, f)| (c, f.len()))
            .unwrap();
        assert_eq!(code, code::OPEN);
        // A symbolic descriptor and the short forms decode alike.
        let mut sym = vec![0x00, 0xa3, 14];
        sym.extend_from_slice(b"amqp:open:list");
        sym.extend_from_slice(&[0xc0, 4, 1, 0xa1, 1, b'c']);
        assert_eq!(
            decode(&sym).unwrap().as_described_list().map(|(c, _)| c),
            Some(code::OPEN)
        );
        let names = Value::Array(vec![
            Value::Symbol("PLAIN".into()),
            Value::Symbol("EXTERNAL".into()),
        ]);
        let mut arr = Vec::new();
        encode(&names, &mut arr).unwrap();
        assert_eq!(decode(&arr).unwrap(), names);
    }

    #[test]
    fn nesting_and_zero_width_arrays_are_bounded() {
        // MAX_DEPTH + 1 lists inside each other, each list8 holding the next.
        let levels = MAX_DEPTH + 2;
        let mut deep = vec![0x40];
        for _ in 0..levels {
            let size = u8::try_from(deep.len() + 1).unwrap();
            let mut outer = vec![0xc0, size, 1];
            outer.extend_from_slice(&deep);
            deep = outer;
        }
        assert!(decode(&deep).is_err());
        // Within the bound it decodes.
        let mut shallow = vec![0x40];
        for _ in 0..4 {
            let size = u8::try_from(shallow.len() + 1).unwrap();
            let mut outer = vec![0xc0, size, 1];
            outer.extend_from_slice(&shallow);
            shallow = outer;
        }
        assert!(decode(&shallow).is_ok());
        // An array32 of 2^32 - 1 nulls in a few bytes.
        let zero_width = [0xf0, 0, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0x40];
        assert!(decode(&zero_width).is_err());
        // A list whose count is larger than its size can hold.
        assert!(decode(&[0xc0, 1, 200]).is_err());
        // A string that is not UTF-8, a symbol that is not ASCII, a boolean of 2.
        assert!(decode(&[0xa1, 1, 0xff]).is_err());
        assert!(decode(&[0xa3, 1, 0xc3]).is_err());
        assert!(decode(&[0x56, 2]).is_err());
        // A descriptor is a ulong or a short symbol: an array would repeat a long one for
        // every element.
        let mut long = vec![0xf0];
        let descriptor = [
            vec![0xb0],
            60_000u32.to_be_bytes().to_vec(),
            vec![7; 60_000],
        ]
        .concat();
        let size = u32::try_from(4 + descriptor.len() + 2 + 1).unwrap();
        long.extend_from_slice(&size.to_be_bytes());
        long.extend_from_slice(&3u32.to_be_bytes());
        long.push(0x00);
        long.extend_from_slice(&descriptor);
        long.extend_from_slice(&[0x40, 0x40, 0x40]);
        assert!(decode(&long).is_err());
        let symbol = [
            vec![0x00, 0xb3],
            300u32.to_be_bytes().to_vec(),
            vec![b's'; 300],
            vec![0x40],
        ]
        .concat();
        assert!(
            decode(&symbol).is_err(),
            "a symbol longer than MAX_DESCRIPTOR"
        );
        assert!(decode(&[0x00, 0xa3, 1, b's', 0x40]).is_ok());
        assert!(decode(&[0x00, 0x53, 0x75, 0xa0, 1, b'x']).is_ok());
        assert!(decode(&[0x00, 0x40, 0x40]).is_err(), "a null descriptor");
    }

    #[test]
    fn frames_and_performatives_are_checked() {
        let mut body = Vec::new();
        encode(&Value::described(0x30, vec![]), &mut body).unwrap();
        let f = frame(FRAME_AMQP, 0, &body).unwrap();
        let (n, parsed) = parse_frame(&f, MAX_FRAME).unwrap().unwrap();
        assert_eq!(n, f.len());
        assert!(
            performative(&parsed.body).is_err(),
            "an unknown performative"
        );
        let mut big = frame(FRAME_AMQP, 0, &[]).unwrap();
        big[..4].copy_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        assert!(parse_frame(&big, MAX_FRAME).is_err());
        let mut doff = frame(FRAME_AMQP, 0, &[]).unwrap();
        doff[4] = 1;
        assert!(parse_frame(&doff, MAX_FRAME).is_err());
        assert!(parse_frame(b"AMQP\x00\x01\x00\x00", MAX_FRAME).is_err());
        assert!(address_ok(b"queue/orders"));
        assert!(!address_ok(b"a\nb"));
        assert!(!address_ok(b""));
    }
}
