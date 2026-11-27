//! A MySQL client (client/server protocol 4.1): TLS before anything but the server's greeting,
//! `caching_sha2_password` only, and statements prepared with every parameter bound.
//!
//! What it refuses, and why:
//!
//! - a server whose greeting does not offer TLS (`CLIENT_SSL`), or that sends anything after
//!   its greeting before the handshake (it would be read as if it came over TLS); the user
//!   name, like everything else of the sign-in, goes only over TLS;
//! - every authentication plugin but `caching_sha2_password`: `mysql_native_password` is
//!   SHA-1 over a nonce the server chooses (a captured exchange is an offline dictionary
//!   attack), `mysql_clear_password` and `sha256_password` hand the server the password
//!   whatever it proved, and an auth switch to any of them is a downgrade;
//! - a request for a local file (`LOCAL INFILE`): the node never offers `CLIENT_LOCAL_FILES`;
//! - more than one statement or result set: `CLIENT_MULTI_STATEMENTS` and
//!   `CLIENT_MULTI_RESULTS` are never offered, so the SQL of a rule is one statement.
//!
//! `caching_sha2_password` proves nothing of the server: when the server has the password's
//! hash cached it checks the scramble (fast path); otherwise it asks for the password itself
//! (full authentication), which the node sends over the TLS it already verified. That is the
//! same trust as a password sent over TLS anywhere: the certificate of the destination's host
//! is what authenticates the server.

use ring::digest;
use zeroize::Zeroizing;

use super::io::Io;
use crate::{Error, Result};

/// Longest message of the server (several packets of one message together), in bytes.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// A packet of this length is continued by the next one.
const SPLIT: usize = 0xff_ffff;
/// Most columns of a result.
const MAX_COLUMNS: usize = 4096;
/// The character set the node asks for: `utf8mb4_general_ci`.
const CHARSET: u8 = 45;
/// The only authentication plugin the node answers.
pub const PLUGIN: &str = "caching_sha2_password";

// Capability flags (`CLIENT_*`).
const LONG_PASSWORD: u32 = 0x0000_0001;
const CONNECT_WITH_DB: u32 = 0x0000_0008;
const LOCAL_FILES: u32 = 0x0000_0080;
const PROTOCOL_41: u32 = 0x0000_0200;
const SSL: u32 = 0x0000_0800;
const TRANSACTIONS: u32 = 0x0000_2000;
const SECURE_CONNECTION: u32 = 0x0000_8000;
const MULTI_STATEMENTS: u32 = 0x0001_0000;
const MULTI_RESULTS: u32 = 0x0002_0000;
const PLUGIN_AUTH: u32 = 0x0008_0000;
const DEPRECATE_EOF: u32 = 0x0100_0000;

/// What every server must offer.
const REQUIRED: u32 = PROTOCOL_41 | SSL | SECURE_CONNECTION | PLUGIN_AUTH;

// Commands.
const COM_QUIT: u8 = 0x01;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_CLOSE: u8 = 0x19;

/// `SERVER_MORE_RESULTS_EXISTS` in the status of an OK or EOF packet.
const MORE_RESULTS: u16 = 0x0008;
/// `UNSIGNED_FLAG` of a column.
const UNSIGNED: u16 = 0x0020;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

/// A little-endian reader over one message.
struct Le<'a>(&'a [u8]);

impl<'a> Le<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| invalid("message truncated or malformed"))?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| invalid("message truncated"))
    }

    fn uint(&mut self, n: usize) -> Result<u64> {
        let bytes = self.take(n)?;
        Ok(bytes
            .iter()
            .rev()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn u16(&mut self) -> Result<u16> {
        u16::try_from(self.uint(2)?).map_err(|_| invalid("u16"))
    }

    fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.uint(4)?).map_err(|_| invalid("u32"))
    }

    /// A length-encoded integer; `None` for the NULL marker `0xfb`.
    fn lenenc(&mut self) -> Result<Option<u64>> {
        Ok(match self.u8()? {
            0xfb => None,
            0xfc => Some(self.uint(2)?),
            0xfd => Some(self.uint(3)?),
            0xfe => Some(self.uint(8)?),
            0xff => return Err(invalid("an error marker where a length was expected")),
            n => Some(u64::from(n)),
        })
    }

    /// A length-encoded string.
    fn lenenc_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.lenenc()?.ok_or_else(|| invalid("a NULL length"))?;
        self.take(usize::try_from(len).map_err(|_| invalid("length"))?)
    }

    /// A string ending in NUL, without it.
    fn cstring(&mut self) -> Result<&'a [u8]> {
        let end = memchr::memchr(0, self.0).ok_or_else(|| invalid("a string without its NUL"))?;
        let s = self.take(end)?;
        self.take(1)?;
        Ok(s)
    }

    fn rest(&self) -> &'a [u8] {
        self.0
    }
}

fn put_lenenc(out: &mut Vec<u8>, n: usize) {
    let n = n as u64;
    if n < 0xfb {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfc);
        out.extend_from_slice(n.to_le_bytes().get(..2).unwrap_or_default());
    } else if n <= 0xff_ffff {
        out.push(0xfd);
        out.extend_from_slice(n.to_le_bytes().get(..3).unwrap_or_default());
    } else {
        out.push(0xfe);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// What the server's greeting (protocol 10) said.
pub struct Greeting {
    /// Its capabilities.
    pub capabilities: u32,
    /// The 20-byte nonce of the scramble.
    pub nonce: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Greeting {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Greeting({:#x})", self.capabilities)
    }
}

/// Reads one packet: its sequence number and payload.
fn packet(io: &mut Io<'_>) -> Result<(u8, Zeroizing<Vec<u8>>)> {
    let head = io.take(4)?;
    let mut le = Le(&head);
    let len = usize::try_from(le.uint(3)?).map_err(|_| invalid("length"))?;
    let seq = le.u8()?;
    Ok((seq, io.take(len)?))
}

/// Parses a greeting.
pub fn parse_greeting(payload: &[u8]) -> Result<Greeting> {
    let mut p = Le(payload);
    match p.u8()? {
        10 => {}
        0xff => {
            return Err(Error::AuthRefused {
                rule: "the server refused the connection",
            });
        }
        _ => return Err(untrusted("not a protocol 10 greeting")),
    }
    p.cstring()?;
    p.u32()?;
    let first = p.take(8)?;
    p.u8()?;
    let low = u32::from(p.u16()?);
    if p.rest().is_empty() {
        return Err(untrusted("the server offers no TLS"));
    }
    p.u8()?;
    p.u16()?;
    let high = u32::from(p.u16()?);
    let capabilities = low | (high << 16);
    let data_len = usize::from(p.u8()?);
    p.take(10)?;
    let second_len = data_len.saturating_sub(8).max(13);
    let second = p.take(second_len)?;
    let mut nonce = Zeroizing::new(first.to_vec());
    nonce.extend_from_slice(second.strip_suffix(&[0]).unwrap_or(second));
    if nonce.len() != 20 {
        return Err(invalid("a scramble nonce that is not 20 bytes"));
    }
    Ok(Greeting {
        capabilities,
        nonce,
    })
}

/// The capabilities the node asks for, from what the server offers.
fn ours(server: u32, database: bool) -> u32 {
    let mut caps =
        LONG_PASSWORD | PROTOCOL_41 | SSL | TRANSACTIONS | SECURE_CONNECTION | PLUGIN_AUTH;
    if database {
        caps |= CONNECT_WITH_DB;
    }
    caps |= server & DEPRECATE_EOF;
    // Never: local files, several statements or result sets.
    caps & !(LOCAL_FILES | MULTI_STATEMENTS | MULTI_RESULTS)
}

fn header(caps: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&caps.to_le_bytes());
    out.extend_from_slice(&(MAX_MESSAGE as u32).to_le_bytes());
    out.push(CHARSET);
    out.extend_from_slice(&[0u8; 23]);
    out
}

fn frame(seq: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() >= SPLIT {
        return Err(Error::RequestInvalid {
            rule: "a MySQL message of 16 MiB or more",
        });
    }
    let len = payload.len() as u32;
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    out.extend_from_slice(len.to_le_bytes().get(..3).unwrap_or_default());
    out.push(seq);
    out.extend_from_slice(payload);
    Ok(out)
}

/// The plain prelude: reads the greeting, which must offer TLS and the protocol the node
/// speaks, and asks for TLS (`SSLRequest`). Nothing secret is written: not even the user name.
pub fn prelude(io: &mut Io<'_>, database: bool) -> Result<Greeting> {
    let (seq, payload) = packet(io)?;
    if seq != 0 {
        return Err(invalid("a greeting out of sequence"));
    }
    let greeting = parse_greeting(&payload)?;
    if greeting.capabilities & SSL == 0 {
        return Err(untrusted("the server does not take TLS"));
    }
    if greeting.capabilities & REQUIRED != REQUIRED {
        return Err(untrusted(
            "the server lacks protocol 4.1, secure connection or plugin authentication",
        ));
    }
    io.expect_empty()?;
    let request = header(ours(greeting.capabilities, database));
    io.write(&frame(1, &request)?)?;
    Ok(greeting)
}

/// The scramble of `caching_sha2_password`: `SHA256(p) XOR SHA256(SHA256(SHA256(p)) || nonce)`.
pub fn scramble(password: &[u8], nonce: &[u8]) -> Zeroizing<Vec<u8>> {
    if password.is_empty() {
        return Zeroizing::new(Vec::new());
    }
    let one = Zeroizing::new(digest::digest(&digest::SHA256, password).as_ref().to_vec());
    let two = digest::digest(&digest::SHA256, &one);
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(two.as_ref());
    ctx.update(nonce);
    let three = ctx.finish();
    Zeroizing::new(one.iter().zip(three.as_ref()).map(|(a, b)| a ^ b).collect())
}

/// What a statement gave.
pub struct Rows {
    /// `{"columns": [...], "rows": [[...]], "affected": n}`, or `{"error": {"code", "state",
    /// "message"}}`.
    pub json: Zeroizing<Vec<u8>>,
    /// True when the server answered with an error.
    pub failed: bool,
    /// The values as the server sent them, for the reflection search.
    pub raw: Zeroizing<Vec<u8>>,
}

/// A column of a result.
struct Column {
    name: String,
    kind: u8,
    flags: u16,
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
    seq: u8,
    deprecate_eof: bool,
}

impl<'s> Client<'s> {
    /// Signs in as `user` over the TLS the prelude asked for, with the greeting it read.
    pub fn connect(
        io: Io<'s>,
        greeting: &Greeting,
        user: &[u8],
        database: Option<&str>,
        password: &[u8],
    ) -> Result<Self> {
        let caps = ours(greeting.capabilities, database.is_some());
        let mut client = Client {
            io,
            seq: 2,
            deprecate_eof: caps & DEPRECATE_EOF != 0,
        };
        if user.contains(&0) || database.is_some_and(|d| d.as_bytes().contains(&0)) {
            return Err(Error::RequestInvalid {
                rule: "a MySQL user or database cannot hold a NUL byte",
            });
        }
        let mut response = Zeroizing::new(header(caps));
        response.extend_from_slice(user);
        response.push(0);
        let proof = scramble(password, &greeting.nonce);
        response.push(u8::try_from(proof.len()).map_err(|_| Error::Encoding)?);
        response.extend_from_slice(&proof);
        if let Some(database) = database {
            response.extend_from_slice(database.as_bytes());
            response.push(0);
        }
        response.extend_from_slice(PLUGIN.as_bytes());
        response.push(0);
        client.write(&response)?;
        let mut switched = false;
        loop {
            let reply = client.read()?;
            match reply.first() {
                Some(0x00) => return Ok(client),
                Some(0xff) => {
                    return Err(Error::AuthRefused {
                        rule: "the server refused the sign-in",
                    });
                }
                Some(0x01) => match reply.get(1) {
                    // Fast authentication succeeded: an OK follows.
                    Some(0x03) if reply.len() == 2 => {}
                    // Full authentication: the password itself, over the TLS already verified.
                    Some(0x04) if reply.len() == 2 => {
                        let mut clear = Zeroizing::new(password.to_vec());
                        clear.push(0);
                        client.write(&clear)?;
                    }
                    _ => return Err(invalid("an unexpected caching_sha2_password message")),
                },
                Some(0xfe) => {
                    // An auth switch: only to the same plugin, once, with a new nonce.
                    let mut p = Le(reply.get(1..).unwrap_or_default());
                    let plugin = p.cstring()?;
                    if plugin != PLUGIN.as_bytes() || switched {
                        return Err(untrusted(
                            "the server asks for another mechanism than caching_sha2_password",
                        ));
                    }
                    switched = true;
                    let data = p.rest();
                    let nonce = data.strip_suffix(&[0]).unwrap_or(data);
                    if nonce.len() != 20 {
                        return Err(invalid("a scramble nonce that is not 20 bytes"));
                    }
                    let proof = scramble(password, nonce);
                    client.write(&proof)?;
                }
                _ => return Err(invalid("an unexpected message during sign-in")),
            }
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Reads one message (the packets of a split one together), in sequence.
    fn read(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut message = Zeroizing::new(Vec::new());
        loop {
            let (seq, part) = packet(&mut self.io)?;
            if seq != self.seq {
                return Err(invalid("a packet out of sequence"));
            }
            self.seq = self.seq.wrapping_add(1);
            if message.len().saturating_add(part.len()) > MAX_MESSAGE {
                return Err(Error::transport(
                    crate::error::TransportKind::TooLarge,
                    true,
                ));
            }
            message.extend_from_slice(&part);
            if part.len() < SPLIT {
                return Ok(message);
            }
        }
    }

    fn write(&mut self, payload: &[u8]) -> Result<()> {
        let framed = frame(self.seq, payload)?;
        self.seq = self.seq.wrapping_add(1);
        self.io.write(&framed)
    }

    /// Starts a command: its sequence begins at 0.
    fn command_packet(&mut self, payload: &[u8]) -> Result<()> {
        self.seq = 0;
        self.write(payload)
    }

    /// The end of a list of column definitions: an EOF packet unless the server deprecated it.
    fn end_of_columns(&mut self) -> Result<()> {
        if self.deprecate_eof {
            return Ok(());
        }
        let eof = self.read()?;
        if eof.first() == Some(&0xfe) && eof.len() < 9 {
            Ok(())
        } else {
            Err(invalid("expected the EOF after the column definitions"))
        }
    }

    fn column(&mut self) -> Result<Column> {
        let def = self.read()?;
        let mut p = Le(&def);
        for _ in 0..4 {
            p.lenenc_bytes()?;
        }
        let name = String::from_utf8_lossy(p.lenenc_bytes()?).into_owned();
        p.lenenc_bytes()?;
        p.lenenc()?;
        p.u16()?;
        p.u32()?;
        let kind = p.u8()?;
        let flags = p.u16()?;
        Ok(Column { name, kind, flags })
    }

    /// Prepares `sql`, runs it with `params` bound as strings, and closes it; keeps only
    /// `columns` (all when empty). At most `max` bytes of values.
    pub fn query(
        &mut self,
        sql: &[u8],
        params: &[Zeroizing<Vec<u8>>],
        columns: &[String],
        max: usize,
    ) -> Result<Rows> {
        let mut prepare = Zeroizing::new(vec![COM_STMT_PREPARE]);
        prepare.extend_from_slice(sql);
        self.command_packet(&prepare)?;
        let ok = self.read()?;
        let mut raw = Zeroizing::new(Vec::new());
        match ok.first() {
            Some(0x00) => {}
            Some(0xff) => return error_rows(&ok, raw),
            _ => return Err(invalid("an unexpected answer to a prepare")),
        }
        let mut p = Le(ok.get(1..).unwrap_or_default());
        let id = p.u32()?;
        let column_count = usize::from(p.u16()?);
        let param_count = usize::from(p.u16()?);
        if param_count > 0 {
            for _ in 0..param_count {
                self.column()?;
            }
            self.end_of_columns()?;
        }
        if column_count > 0 {
            for _ in 0..column_count {
                self.column()?;
            }
            self.end_of_columns()?;
        }
        let result = if param_count != params.len() {
            Err(Error::RequestInvalid {
                rule: "the statement takes another number of parameters",
            })
        } else {
            self.execute(id, params, columns, max, &mut raw)
        };
        let mut close = vec![COM_STMT_CLOSE];
        close.extend_from_slice(&id.to_le_bytes());
        self.command_packet(&close)?;
        let (json, failed) = result?;
        Ok(Rows { json, failed, raw })
    }

    fn execute(
        &mut self,
        id: u32,
        params: &[Zeroizing<Vec<u8>>],
        keep_columns: &[String],
        max: usize,
        raw: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(Zeroizing<Vec<u8>>, bool)> {
        let mut exec = Zeroizing::new(vec![COM_STMT_EXECUTE]);
        exec.extend_from_slice(&id.to_le_bytes());
        exec.push(0);
        exec.extend_from_slice(&1u32.to_le_bytes());
        if !params.is_empty() {
            exec.extend(core::iter::repeat_n(0u8, params.len().div_ceil(8)));
            exec.push(1);
            for _ in params {
                // MYSQL_TYPE_STRING, signed: every value goes as a string the server converts.
                exec.extend_from_slice(&[0xfe, 0x00]);
            }
            for p in params {
                put_lenenc(&mut exec, p.len());
                exec.extend_from_slice(p);
            }
        }
        self.command_packet(&exec)?;
        let first = self.read()?;
        match first.first() {
            Some(0x00) => {
                let mut p = Le(first.get(1..).unwrap_or_default());
                let affected = p.lenenc()?.unwrap_or(0);
                let insert_id = p.lenenc()?.unwrap_or(0);
                let status = p.u16()?;
                if status & MORE_RESULTS != 0 {
                    return Err(invalid("more than one result"));
                }
                let json = serde_json::json!({
                    "columns": [], "rows": [], "affected": affected, "insert_id": insert_id,
                });
                return Ok((
                    Zeroizing::new(serde_json::to_vec(&json).map_err(|_| Error::Encoding)?),
                    false,
                ));
            }
            Some(0xff) => {
                let rows = error_rows(&first, core::mem::take(raw))?;
                *raw = rows.raw;
                return Ok((rows.json, true));
            }
            Some(0xfb) => return Err(untrusted("the server asks for a local file")),
            _ => {}
        }
        let count = Le(&first)
            .lenenc()?
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| (1..=MAX_COLUMNS).contains(n))
            .ok_or_else(|| invalid("a column count out of bounds"))?;
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            columns.push(self.column()?);
        }
        self.end_of_columns()?;
        let keep: Vec<usize> = (0..columns.len())
            .filter(|i| {
                keep_columns.is_empty()
                    || columns
                        .get(*i)
                        .is_some_and(|c| keep_columns.contains(&c.name))
            })
            .collect();
        let mut rows = Vec::new();
        loop {
            let row = self.read()?;
            match row.first() {
                Some(0x00) => {}
                Some(0xfe) if row.len() < SPLIT => {
                    // EOF, or the OK that replaces it: the status follows the counts.
                    let mut p = Le(row.get(1..).unwrap_or_default());
                    let status = if self.deprecate_eof {
                        p.lenenc()?;
                        p.lenenc()?;
                        p.u16()?
                    } else {
                        p.u16()?;
                        p.u16()?
                    };
                    if status & MORE_RESULTS != 0 {
                        return Err(invalid("more than one result"));
                    }
                    break;
                }
                Some(0xff) => {
                    let rows = error_rows(&row, core::mem::take(raw))?;
                    *raw = rows.raw;
                    return Ok((rows.json, true));
                }
                _ => return Err(invalid("an unexpected row")),
            }
            let values = binary_row(&row, &columns, raw)?;
            if raw.len() > max {
                return Err(Error::transport(
                    crate::error::TransportKind::TooLarge,
                    true,
                ));
            }
            rows.push(serde_json::Value::Array(
                keep.iter()
                    .map(|i| match values.get(*i) {
                        Some(Some(v)) => serde_json::Value::String(v.clone()),
                        _ => serde_json::Value::Null,
                    })
                    .collect(),
            ));
        }
        let names: Vec<&str> = keep
            .iter()
            .filter_map(|i| columns.get(*i).map(|c| c.name.as_str()))
            .collect();
        let json = serde_json::json!({"columns": names, "rows": rows});
        Ok((
            Zeroizing::new(serde_json::to_vec(&json).map_err(|_| Error::Encoding)?),
            false,
        ))
    }

    /// Says goodbye and closes.
    pub fn close(&mut self) {
        let _ = self.command_packet(&[COM_QUIT]);
        self.io.close();
    }
}

/// An error packet as the result of a statement.
fn error_rows(packet: &[u8], mut raw: Zeroizing<Vec<u8>>) -> Result<Rows> {
    let mut p = Le(packet.get(1..).unwrap_or_default());
    let code = p.u16()?;
    let mut state = String::new();
    if p.rest().first() == Some(&b'#') {
        p.take(1)?;
        state = String::from_utf8_lossy(p.take(5)?).into_owned();
    }
    let message = p.rest();
    raw.extend_from_slice(message);
    raw.push(0);
    let json = serde_json::json!({"error": {
        "code": code.to_string(),
        "state": state,
        "message": String::from_utf8_lossy(message),
    }});
    Ok(Rows {
        json: Zeroizing::new(serde_json::to_vec(&json).map_err(|_| Error::Encoding)?),
        failed: true,
        raw,
    })
}

/// The values of a row of the binary protocol, as text; `None` for NULL.
fn binary_row(row: &[u8], columns: &[Column], raw: &mut Vec<u8>) -> Result<Vec<Option<String>>> {
    let mut p = Le(row.get(1..).unwrap_or_default());
    let bitmap = p.take((columns.len() + 9) / 8)?;
    let mut out = Vec::with_capacity(columns.len());
    for (i, column) in columns.iter().enumerate() {
        let bit = i + 2;
        let null = bitmap
            .get(bit / 8)
            .is_some_and(|b| b & (1 << (bit % 8)) != 0);
        if null {
            out.push(None);
            continue;
        }
        let unsigned = column.flags & UNSIGNED != 0;
        let int = |p: &mut Le<'_>, n: usize| -> Result<String> {
            let v = p.uint(n)?;
            if unsigned {
                return Ok(v.to_string());
            }
            let shift = 64 - 8 * n as u32;
            Ok((((v << shift) as i64) >> shift).to_string())
        };
        let text = match column.kind {
            0x01 => int(&mut p, 1)?,
            0x02 | 0x0d => int(&mut p, 2)?,
            0x03 | 0x09 => int(&mut p, 4)?,
            0x08 => int(&mut p, 8)?,
            0x04 => f32::from_bits(p.u32()?).to_string(),
            0x05 => f64::from_bits(p.uint(8)?).to_string(),
            0x06 => {
                out.push(None);
                continue;
            }
            0x07 | 0x0a | 0x0c => {
                let len = usize::from(p.u8()?);
                let mut d = Le(p.take(len)?);
                let (mut y, mut mo, mut da, mut h, mut mi, mut s, mut us) = (0, 0, 0, 0, 0, 0, 0);
                if len >= 4 {
                    y = u32::from(d.u16()?);
                    mo = d.u8()?;
                    da = d.u8()?;
                }
                if len >= 7 {
                    h = d.u8()?;
                    mi = d.u8()?;
                    s = d.u8()?;
                }
                if len >= 11 {
                    us = d.u32()?;
                }
                if !matches!(len, 0 | 4 | 7 | 11) {
                    return Err(invalid("a date of another length"));
                }
                if column.kind == 0x0a {
                    format!("{y:04}-{mo:02}-{da:02}")
                } else if us > 0 {
                    format!("{y:04}-{mo:02}-{da:02} {h:02}:{mi:02}:{s:02}.{us:06}")
                } else {
                    format!("{y:04}-{mo:02}-{da:02} {h:02}:{mi:02}:{s:02}")
                }
            }
            0x0b => {
                let len = usize::from(p.u8()?);
                let mut d = Le(p.take(len)?);
                let (mut neg, mut days, mut h, mut mi, mut s, mut us) = (0, 0, 0, 0, 0, 0);
                if len >= 8 {
                    neg = d.u8()?;
                    days = d.u32()?;
                    h = d.u8()?;
                    mi = d.u8()?;
                    s = d.u8()?;
                }
                if len >= 12 {
                    us = d.u32()?;
                }
                if !matches!(len, 0 | 8 | 12) {
                    return Err(invalid("a time of another length"));
                }
                let hours = u64::from(days) * 24 + u64::from(h);
                let sign = if neg == 1 { "-" } else { "" };
                if us > 0 {
                    format!("{sign}{hours:02}:{mi:02}:{s:02}.{us:06}")
                } else {
                    format!("{sign}{hours:02}:{mi:02}:{s:02}")
                }
            }
            _ => {
                let bytes = p.lenenc_bytes()?;
                raw.extend_from_slice(bytes);
                raw.push(0);
                String::from_utf8_lossy(bytes).into_owned()
            }
        };
        out.push(Some(text));
    }
    if !p.rest().is_empty() {
        return Err(invalid("a row longer than its columns"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    /// 64 KiB of 10-byte packets (a 4-byte header, 6 bytes of payload) in one read.
    fn small_packets() -> (usize, Vec<u8>) {
        let count = 64 * 1024 / 10;
        let mut bytes = Vec::with_capacity(count * 10);
        for i in 0..count {
            bytes.extend_from_slice(&[6, 0, 0, i as u8]);
            bytes.extend_from_slice(b"abcdef");
        }
        (count, bytes)
    }

    /// Parses every packet of `bytes`; the bytes the buffer moved.
    fn parse_all(count: usize, bytes: &[u8]) -> u64 {
        use crate::proto::io::testing::{Fed, wide};
        let mut stream = Fed(std::collections::VecDeque::from([bytes.to_vec()]));
        let mut io = Io::new(&mut stream, wide());
        for _ in 0..count {
            let (_, payload) = packet(&mut io).unwrap();
            assert_eq!(payload.len(), 6);
        }
        assert!(io.buffered().is_empty());
        io.copied()
    }

    #[test]
    fn packets_parse_in_linear_copies() {
        let (count, bytes) = small_packets();
        let copied = parse_all(count, &bytes);
        // Each byte is copied out once, plus at most one compaction of the buffer.
        assert!(copied <= 2 * bytes.len() as u64, "copied {copied} bytes");
    }

    /// `cargo test --release -p engine --lib -- --ignored --nocapture measure_`
    #[test]
    #[ignore = "a measurement, run in release"]
    fn measure_mysql_small_packets() {
        let (count, bytes) = small_packets();
        let (us, copied) = crate::proto::io::testing::median_us(9, || parse_all(count, &bytes));
        println!(
            "mysql: {count} packets in {} bytes: median {us} us, {copied} bytes copied",
            bytes.len()
        );
    }

    #[test]
    fn scramble_is_the_documented_one() {
        // Computed independently: SHA256("pw") XOR SHA256(SHA256(SHA256("pw")) || nonce).
        let nonce = [7u8; 20];
        let s = scramble(b"pw", &nonce);
        assert_eq!(s.len(), 32);
        let one = digest::digest(&digest::SHA256, b"pw");
        let two = digest::digest(&digest::SHA256, one.as_ref());
        let mut both = two.as_ref().to_vec();
        both.extend_from_slice(&nonce);
        let three = digest::digest(&digest::SHA256, &both);
        let back: Vec<u8> = s.iter().zip(three.as_ref()).map(|(a, b)| a ^ b).collect();
        assert_eq!(back, one.as_ref());
        assert!(scramble(b"", &nonce).is_empty());
    }

    #[test]
    fn lenenc_round_trip() {
        for n in [0usize, 250, 251, 0xffff, 0x1_0000, 0xff_ffff, 0x100_0000] {
            let mut out = Vec::new();
            put_lenenc(&mut out, n);
            assert_eq!(Le(&out).lenenc().unwrap(), Some(n as u64));
        }
        assert_eq!(Le(&[0xfb]).lenenc().unwrap(), None);
        assert!(Le(&[0xfc, 1]).lenenc().is_err());
    }

    #[test]
    fn a_greeting_without_tls_is_refused() {
        let mut g = vec![10];
        g.extend_from_slice(b"8.0.36\0");
        g.extend_from_slice(&[1, 0, 0, 0]);
        g.extend_from_slice(&[1; 8]);
        g.push(0);
        g.extend_from_slice(&((PROTOCOL_41 | SECURE_CONNECTION) as u16).to_le_bytes());
        g.push(CHARSET);
        g.extend_from_slice(&[2, 0]);
        g.extend_from_slice(&((PLUGIN_AUTH >> 16) as u16).to_le_bytes());
        g.push(21);
        g.extend_from_slice(&[0; 10]);
        g.extend_from_slice(&[2; 12]);
        g.push(0);
        g.extend_from_slice(b"caching_sha2_password\0");
        let parsed = parse_greeting(&g).unwrap();
        assert_eq!(parsed.nonce.len(), 20);
        assert_eq!(parsed.capabilities & SSL, 0);
        assert!(parse_greeting(&g[..12]).is_err());
        assert!(parse_greeting(&[9, 0]).is_err());
    }

    #[test]
    fn binary_rows_decode_by_type() {
        let columns = [
            Column {
                name: "a".into(),
                kind: 0x03,
                flags: 0,
            },
            Column {
                name: "b".into(),
                kind: 0x08,
                flags: UNSIGNED,
            },
            Column {
                name: "c".into(),
                kind: 0xfd,
                flags: 0,
            },
            Column {
                name: "d".into(),
                kind: 0x0c,
                flags: 0,
            },
            Column {
                name: "e".into(),
                kind: 0xfd,
                flags: 0,
            },
        ];
        // The header, then a null bitmap of (5 + 9) / 8 bytes: column 4 (bit 6) is NULL.
        let mut row = vec![0x00, 0b0100_0000];
        row.extend_from_slice(&(-5i32).to_le_bytes());
        row.extend_from_slice(&u64::MAX.to_le_bytes());
        row.extend_from_slice(&[2, b'h', b'i']);
        row.extend_from_slice(&[7, 0xe8, 0x07, 11, 26, 9, 30, 5]);
        let mut raw = Vec::new();
        let values = binary_row(&row, &columns, &mut raw).unwrap();
        assert_eq!(
            values,
            [
                Some("-5".to_string()),
                Some(u64::MAX.to_string()),
                Some("hi".into()),
                Some("2024-11-26 09:30:05".into()),
                None,
            ]
        );
        assert_eq!(raw, b"hi\0");
        row.push(0);
        assert!(binary_row(&row, &columns, &mut raw).is_err());
    }
}
