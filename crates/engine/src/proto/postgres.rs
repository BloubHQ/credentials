//! A PostgreSQL client (frontend/backend protocol 3.0): TLS required, SCRAM-SHA-256 only,
//! queries by the extended protocol with every parameter bound, never spliced into the text.
//!
//! What it refuses, and why:
//!
//! - a server that does not take TLS (`SSLRequest` answered `N`), or that sends bytes after
//!   its `S` before the handshake (they would be read as if they came over TLS);
//! - every mechanism but SCRAM-SHA-256: cleartext and MD5 would hand the server the password
//!   or a replayable hash, so a server that asks for them is a downgrade;
//! - a server that says the sign-in succeeded before SCRAM proved it knows the password
//!   (`AuthenticationOk` first), and a SCRAM server signature that does not verify;
//! - fewer than 4096 or more than 1,000,000 PBKDF2 iterations (RFC 7677's floor; the ceiling
//!   bounds the work a server can make the node do).
//!
//! Channel binding is not used (`n,,`): TLS already authenticates the server by its
//! certificate for the destination's host, which is what binding would add here.

use base64::Engine as _;
use ring::{digest, hmac, pbkdf2};
use zeroize::Zeroizing;

use super::io::Io;
use super::wire::Parse;
use crate::{Error, Result};

/// Longest message of the server, in bytes.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Fewest PBKDF2 iterations a server may ask for.
pub const MIN_ITERATIONS: u32 = 4096;
/// Most PBKDF2 iterations a server may ask for.
pub const MAX_ITERATIONS: u32 = 1_000_000;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

/// The plain prelude: asks for TLS and accepts only `S` with nothing after it.
pub fn prelude(io: &mut Io<'_>) -> Result<()> {
    io.write(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])?;
    let answer = io.take(1)?;
    match answer.first() {
        Some(b'S') => io.expect_empty(),
        Some(b'N') => Err(untrusted("the server does not take TLS")),
        _ => Err(invalid("not an answer to SSLRequest")),
    }
}

/// One message of the server: its type and body.
struct Message {
    kind: u8,
    body: Zeroizing<Vec<u8>>,
}

fn read(io: &mut Io<'_>) -> Result<Message> {
    let head = io.take(5)?;
    let kind = *head.first().ok_or(invalid("short message"))?;
    let length = Parse::new(head.get(1..).unwrap_or_default()).u32()? as usize;
    if !(4..=MAX_MESSAGE).contains(&length) {
        return Err(invalid("message length out of bounds"));
    }
    let body = io.take(length - 4)?;
    Ok(Message { kind, body })
}

fn message(kind: u8, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let length = u32::try_from(body.len() + 4).map_err(|_| Error::RequestInvalid {
        rule: "a message too long for PostgreSQL",
    })?;
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 5));
    out.push(kind);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn cstring(out: &mut Vec<u8>, text: &[u8]) -> Result<()> {
    if text.contains(&0) {
        return Err(Error::RequestInvalid {
            rule: "a PostgreSQL string cannot hold a NUL byte",
        });
    }
    out.extend_from_slice(text);
    out.push(0);
    Ok(())
}

/// The fields of an `ErrorResponse`: SQLSTATE and message.
fn error_fields(body: &[u8]) -> (String, String) {
    let (mut code, mut text) = (String::new(), String::new());
    for field in body.split(|b| *b == 0) {
        match field.split_first() {
            Some((b'C', v)) => code = String::from_utf8_lossy(v).into_owned(),
            Some((b'M', v)) => text = String::from_utf8_lossy(v).into_owned(),
            _ => {}
        }
    }
    (code, text)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Zeroizing::new(hmac::sign(&key, data).as_ref().to_vec())
}

/// The attribute `name` of a SCRAM message (`r=...,s=...`).
fn attribute(message: &[u8], name: u8) -> Option<&[u8]> {
    message
        .split(|b| *b == b',')
        .find_map(|part| part.strip_prefix(&[name, b'='][..]))
}

/// The SCRAM-SHA-256 exchange of the client (RFC 5802, 7677), its messages built and checked.
pub struct Scram {
    nonce: String,
    first_bare: String,
    signature: Option<Zeroizing<Vec<u8>>>,
}

impl Scram {
    /// Starts with a fresh nonce.
    pub fn new() -> Result<Self> {
        let mut raw = [0u8; 24];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
            .map_err(|_| Error::Encoding)?;
        Ok(Self::with_nonce(
            &base64::engine::general_purpose::STANDARD.encode(raw),
        ))
    }

    /// Starts with `nonce` (tests).
    pub fn with_nonce(nonce: &str) -> Self {
        Self {
            nonce: nonce.to_string(),
            first_bare: format!("n=,r={nonce}"),
            signature: None,
        }
    }

    /// The client-first message.
    pub fn first(&self) -> String {
        format!("n,,{}", self.first_bare)
    }

    /// The client-final message for the server-first message, with the proof.
    pub fn last(&mut self, server_first: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = attribute(server_first, b'r').ok_or(invalid("SCRAM: no nonce"))?;
        if nonce.len() <= self.nonce.len() || !nonce.starts_with(self.nonce.as_bytes()) {
            return Err(untrusted(
                "SCRAM: the server nonce does not extend the node's",
            ));
        }
        let salt = attribute(server_first, b's').ok_or(invalid("SCRAM: no salt"))?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt)
            .map_err(|_| invalid("SCRAM: salt not base64"))?;
        let iterations: u32 = attribute(server_first, b'i')
            .and_then(|i| std::str::from_utf8(i).ok())
            .and_then(|i| i.parse().ok())
            .ok_or(invalid("SCRAM: no iteration count"))?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(untrusted("SCRAM: an iteration count out of bounds"));
        }
        let rounds = core::num::NonZeroU32::new(iterations).ok_or(invalid("SCRAM: zero"))?;
        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            &salt,
            password,
            salted.as_mut_slice(),
        );
        let client_key = hmac_sha256(salted.as_slice(), b"Client Key");
        let stored = digest::digest(&digest::SHA256, &client_key);
        let nonce = std::str::from_utf8(nonce).map_err(|_| invalid("SCRAM: nonce not text"))?;
        let without_proof = format!("c=biws,r={nonce}");
        let mut auth = Zeroizing::new(Vec::new());
        auth.extend_from_slice(self.first_bare.as_bytes());
        auth.push(b',');
        auth.extend_from_slice(server_first);
        auth.push(b',');
        auth.extend_from_slice(without_proof.as_bytes());
        let client_signature = hmac_sha256(stored.as_ref(), &auth);
        let proof: Zeroizing<Vec<u8>> = Zeroizing::new(
            client_key
                .iter()
                .zip(client_signature.iter())
                .map(|(a, b)| a ^ b)
                .collect(),
        );
        let server_key = hmac_sha256(salted.as_slice(), b"Server Key");
        self.signature = Some(hmac_sha256(&server_key, &auth));
        let mut out = Zeroizing::new(without_proof.into_bytes());
        out.extend_from_slice(b",p=");
        out.extend_from_slice(
            base64::engine::general_purpose::STANDARD
                .encode(proof.as_slice())
                .as_bytes(),
        );
        Ok(out)
    }

    /// Checks the server-final message.
    pub fn verify(&self, server_final: &[u8]) -> Result<()> {
        let expected = self
            .signature
            .as_ref()
            .ok_or(invalid("SCRAM: out of order"))?;
        let given = attribute(server_final, b'v')
            .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
            .ok_or(untrusted("SCRAM: no server signature"))?;
        if given.len() == expected.len()
            && given
                .iter()
                .zip(expected.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        {
            Ok(())
        } else {
            Err(untrusted("SCRAM: the server signature does not verify"))
        }
    }
}

/// What a query gave.
pub struct Rows {
    /// `{"columns": [...], "rows": [[...]], "tag": "..."}`, or `{"error": {"code", "message"}}`.
    pub json: Zeroizing<Vec<u8>>,
    /// True when the server answered with an error.
    pub failed: bool,
    /// The values as the server sent them, for the reflection search.
    pub raw: Zeroizing<Vec<u8>>,
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
}

impl<'s> Client<'s> {
    /// Starts up as `user` on `database` and signs in with SCRAM-SHA-256.
    pub fn connect(
        mut io: Io<'s>,
        user: &[u8],
        database: Option<&str>,
        password: &[u8],
    ) -> Result<Self> {
        let mut body = Zeroizing::new(Vec::new());
        body.extend_from_slice(&196_608u32.to_be_bytes());
        cstring(&mut body, b"user")?;
        cstring(&mut body, user)?;
        if let Some(database) = database {
            cstring(&mut body, b"database")?;
            cstring(&mut body, database.as_bytes())?;
        }
        body.push(0);
        let length = u32::try_from(body.len() + 4).map_err(|_| invalid("startup too long"))?;
        let mut startup = Zeroizing::new(length.to_be_bytes().to_vec());
        startup.extend_from_slice(&body);
        io.write(&startup)?;
        let mut scram = Scram::new()?;
        let mut proven = false;
        loop {
            let m = read(&mut io)?;
            match m.kind {
                b'R' => {
                    let mut p = Parse::new(&m.body);
                    match p.u32()? {
                        0 if proven => {}
                        0 => {
                            return Err(untrusted(
                                "the server signed in without SCRAM proving it knows the password",
                            ));
                        }
                        10 => {
                            let offered =
                                p.rest().split(|b| *b == 0).any(|m| m == b"SCRAM-SHA-256");
                            if !offered {
                                return Err(untrusted("the server does not offer SCRAM-SHA-256"));
                            }
                            let first = scram.first();
                            let mut body = Zeroizing::new(Vec::new());
                            cstring(&mut body, b"SCRAM-SHA-256")?;
                            let len = u32::try_from(first.len()).map_err(|_| invalid("long"))?;
                            body.extend_from_slice(&len.to_be_bytes());
                            body.extend_from_slice(first.as_bytes());
                            io.write(&message(b'p', &body)?)?;
                        }
                        11 => {
                            let last = scram.last(p.rest(), password)?;
                            io.write(&message(b'p', &last)?)?;
                        }
                        12 => {
                            scram.verify(p.rest())?;
                            proven = true;
                        }
                        _ => {
                            return Err(untrusted(
                                "the server asks for a weaker mechanism than SCRAM-SHA-256",
                            ));
                        }
                    }
                }
                b'E' => {
                    return Err(Error::AuthRefused {
                        rule: "the server refused the sign-in",
                    });
                }
                b'S' | b'K' | b'N' => {}
                b'Z' if proven => return Ok(Self { io }),
                _ => return Err(invalid("an unexpected message during sign-in")),
            }
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Runs `sql` with `params` bound as text; keeps only `columns` (all when empty). At most
    /// `max` bytes of values.
    pub fn query(
        &mut self,
        sql: &[u8],
        params: &[Zeroizing<Vec<u8>>],
        columns: &[String],
        max: usize,
    ) -> Result<Rows> {
        let count = u16::try_from(params.len()).map_err(|_| invalid("too many parameters"))?;
        let mut out = Zeroizing::new(Vec::new());
        let mut parse = Zeroizing::new(Vec::new());
        cstring(&mut parse, b"")?;
        cstring(&mut parse, sql)?;
        parse.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&message(b'P', &parse)?);
        let mut bind = Zeroizing::new(Vec::new());
        cstring(&mut bind, b"")?;
        cstring(&mut bind, b"")?;
        bind.extend_from_slice(&0u16.to_be_bytes());
        bind.extend_from_slice(&count.to_be_bytes());
        for p in params {
            if p.contains(&0) {
                return Err(Error::RequestInvalid {
                    rule: "a PostgreSQL text parameter cannot hold a NUL byte",
                });
            }
            let len = i32::try_from(p.len()).map_err(|_| invalid("parameter too long"))?;
            bind.extend_from_slice(&len.to_be_bytes());
            bind.extend_from_slice(p);
        }
        bind.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&message(b'B', &bind)?);
        out.extend_from_slice(&message(b'D', b"P\0")?);
        out.extend_from_slice(&message(b'E', b"\0\0\0\0\0")?);
        out.extend_from_slice(&message(b'S', b"")?);
        self.io.write(&out)?;

        let mut names: Vec<String> = Vec::new();
        let mut keep: Vec<usize> = Vec::new();
        let mut rows: Vec<serde_json::Value> = Vec::new();
        let mut raw = Zeroizing::new(Vec::new());
        let mut tag = String::new();
        let mut error: Option<(String, String)> = None;
        loop {
            let m = read(&mut self.io)?;
            match m.kind {
                b'1' | b'2' | b'n' | b'N' | b'S' | b'A' | b's' | b'I' => {}
                b'T' => {
                    let mut p = Parse::new(&m.body);
                    let n = p.u16()?;
                    names.clear();
                    for _ in 0..n {
                        let rest = p.rest();
                        let end = memchr::memchr(0, rest).ok_or(invalid("column name"))?;
                        names.push(String::from_utf8_lossy(p.take(end)?).into_owned());
                        p.take(1 + 4 + 2 + 4 + 2 + 4 + 2)?;
                    }
                    keep = (0..names.len())
                        .filter(|i| {
                            columns.is_empty() || names.get(*i).is_some_and(|n| columns.contains(n))
                        })
                        .collect();
                }
                b'D' => {
                    let mut p = Parse::new(&m.body);
                    let n = usize::from(p.u16()?);
                    let mut values = Vec::with_capacity(n);
                    for _ in 0..n {
                        let len = p.u32()?;
                        if len == u32::MAX {
                            values.push(None);
                        } else {
                            let v = p.take(len as usize)?;
                            raw.extend_from_slice(v);
                            raw.push(0);
                            values.push(Some(v));
                        }
                    }
                    if raw.len() > max {
                        return Err(Error::transport(
                            crate::error::TransportKind::TooLarge,
                            true,
                        ));
                    }
                    let row: Vec<serde_json::Value> = keep
                        .iter()
                        .map(|i| match values.get(*i) {
                            Some(Some(v)) => {
                                serde_json::Value::String(String::from_utf8_lossy(v).into_owned())
                            }
                            _ => serde_json::Value::Null,
                        })
                        .collect();
                    rows.push(serde_json::Value::Array(row));
                }
                b'C' => {
                    tag = String::from_utf8_lossy(
                        m.body.split(|b| *b == 0).next().unwrap_or_default(),
                    )
                    .into_owned();
                }
                b'E' => {
                    raw.extend_from_slice(&m.body);
                    error = Some(error_fields(&m.body));
                }
                b'Z' => break,
                _ => return Err(invalid("an unexpected message in a query")),
            }
        }
        let json = match &error {
            Some((code, text)) => serde_json::json!({"error": {"code": code, "message": text}}),
            None => serde_json::json!({
                "columns": keep.iter().filter_map(|i| names.get(*i)).collect::<Vec<_>>(),
                "rows": rows,
                "tag": tag,
            }),
        };
        let json = serde_json::to_vec(&json).map_err(|_| Error::Encoding)?;
        Ok(Rows {
            json: Zeroizing::new(json),
            failed: error.is_some(),
            raw,
        })
    }

    /// Says goodbye and closes.
    pub fn close(&mut self) {
        if let Ok(bye) = message(b'X', b"") {
            let _ = self.io.write(&bye);
        }
        self.io.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn scram_matches_rfc_7677() {
        // RFC 7677, section 3 (user "user", password "pencil"); PostgreSQL leaves the user
        // name empty, so the auth message differs and only the shape is checked here.
        let mut scram = Scram::with_nonce("rOprNGfwEbeRWgbNEkqO");
        assert_eq!(scram.first(), "n,,n=,r=rOprNGfwEbeRWgbNEkqO");
        let server_first =
            b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let last = scram.last(server_first, b"pencil").unwrap();
        assert!(
            last.starts_with(b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=")
        );
        assert!(scram.verify(b"v=AAAA").is_err());
    }

    #[test]
    fn scram_refuses_a_nonce_it_did_not_start_and_bad_iterations() {
        let mut scram = Scram::with_nonce("abc");
        assert!(scram.last(b"r=xyzdef,s=AAAA,i=4096", b"p").is_err());
        assert!(scram.last(b"r=abc,s=AAAA,i=4096", b"p").is_err());
        assert!(scram.last(b"r=abcd,s=AAAA,i=1", b"p").is_err());
        assert!(scram.last(b"r=abcd,s=AAAA,i=2000000", b"p").is_err());
    }
}
