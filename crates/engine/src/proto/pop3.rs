//! A POP3 client (RFC 1939): implicit TLS (port 995) or `STLS` before anything else (RFC
//! 2595, port 110), then the mechanism the policy names and only if the server offers it:
//! `USER`/`PASS`, `APOP`, or SASL `AUTH` (RFC 5034) with `PLAIN`, `LOGIN` or `XOAUTH2`.
//! Commands are verbs the policy fixes with message numbers as their only parameters, so no
//! parameter can start another command.
//!
//! `APOP` is MD5 over the server's timestamp and the password: the password does not cross
//! the connection, but MD5 is weak, so a summary flags the mechanism. After `STLS` the
//! capabilities are asked for again over TLS (RFC 2595 section 4), and the timestamp is the
//! one of the greeting before TLS, the only one the server sends.
//!
//! Status lines are bounded (4096 bytes), multi-line responses by the result limit and lines
//! of 64 KiB; a status line that goes back is scrubbed of the user name and password
//! ([`Scrub`]).

use base64::Engine as _;
use md5::Digest as _;
use zeroize::Zeroizing;

use super::io::{Io, Scrub};
use crate::error::TransportKind;
use crate::policy::Mechanism;
use crate::{Error, Result};

/// Longest status line, with its CRLF.
pub const MAX_STATUS: usize = 4096;
/// Longest line of a multi-line response.
pub const MAX_LINE: usize = 64 * 1024;
/// Longest SASL command with its initial response (RFC 5034 section 4).
const MAX_INITIAL: usize = 255;

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn rejected() -> Error {
    Error::AuthRefused {
        rule: "the server refused the sign-in",
    }
}

/// True for a message number: 1 to 10 ASCII digits.
pub fn number_ok(value: &[u8]) -> bool {
    (1..=10).contains(&value.len()) && value.iter().all(u8::is_ascii_digit)
}

/// The verbs whose `+OK` starts a multi-line response, with this many parameters.
fn multi_line(verb: &[u8], params: usize) -> bool {
    match verb {
        b"RETR" | b"TOP" => true,
        b"LIST" | b"UIDL" => params == 0,
        _ => false,
    }
}

/// True for a verb this client sends for the policy.
fn verb_ok(verb: &[u8]) -> bool {
    matches!(
        verb,
        b"STAT" | b"LIST" | b"UIDL" | b"RETR" | b"TOP" | b"DELE" | b"NOOP" | b"RSET"
    )
}

/// A status line: `Some(true)` for `+OK`, `Some(false)` for `-ERR`, `None` otherwise.
pub fn status_of(line: &[u8]) -> Option<bool> {
    let upper = line.get(..4).map(<[u8]>::to_ascii_uppercase);
    if line.starts_with(b"+OK") {
        Some(true)
    } else if upper.as_deref() == Some(b"-ERR") {
        Some(false)
    } else {
        None
    }
}

/// The timestamp of an `APOP` greeting (`<...@...>`), with its angle brackets.
pub fn timestamp(greeting: &[u8]) -> Option<&[u8]> {
    let open = memchr::memchr(b'<', greeting)?;
    let close = open + memchr::memchr(b'>', greeting.get(open..)?)?;
    let stamp = greeting.get(open..=close)?;
    let inner = stamp.get(1..stamp.len() - 1)?;
    (inner.contains(&b'@') && inner.iter().all(|b| b.is_ascii_graphic() && *b != b'<'))
        .then_some(stamp)
}

/// The `APOP` digest: lower-case hex of MD5 over the timestamp and the secret.
pub fn apop_digest(stamp: &[u8], secret: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hasher = md5::Md5::new();
    hasher.update(stamp);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut out = Zeroizing::new(Vec::with_capacity(32));
    for b in digest {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out
}

/// Reads the lines of a multi-line response up to its `.` line, dot-unstuffed (RFC 1939
/// section 3), at most `max` bytes. The response with its line ends as sent.
pub fn read_body(
    next_line: &mut dyn FnMut() -> Result<Zeroizing<Vec<u8>>>,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    loop {
        let line = next_line()?;
        if !line.ends_with(b"\r\n") {
            return Err(invalid("a POP3 line not ending in CRLF"));
        }
        if line.as_slice() == b".\r\n" {
            return Ok(out);
        }
        let line = line.strip_prefix(b".").unwrap_or(&line);
        if out.len().saturating_add(line.len()) > max {
            return Err(Error::transport(TransportKind::TooLarge, true));
        }
        out.extend_from_slice(line);
    }
}

/// What the plain prelude read: the greeting, whose `APOP` timestamp the sign-in needs.
pub struct Greeting(pub Zeroizing<Vec<u8>>);

/// The plain prelude: the greeting, then `STLS` and its `+OK`. Nothing secret is written; a
/// server that refuses `STLS`, or sends bytes after its go-ahead, fails the call.
pub fn prelude(io: &mut Io<'_>) -> Result<Greeting> {
    let greeting = io.line(MAX_STATUS)?;
    if status_of(&greeting) != Some(true) {
        return Err(untrusted("a POP3 greeting other than +OK"));
    }
    io.write(b"STLS\r\n")?;
    if status_of(&io.line(MAX_STATUS)?) != Some(true) {
        return Err(untrusted("the server does not offer STLS"));
    }
    io.expect_empty()?;
    Ok(Greeting(greeting))
}

/// The response to one command.
pub struct Response {
    /// 0 for `+OK`, 1 for `-ERR`.
    pub status: i64,
    /// The status line (scrubbed of the sign-in's values), then the body of a multi-line
    /// response.
    pub bytes: Zeroizing<Vec<u8>>,
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
    scrub: Scrub,
}

fn b64(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes(),
    )
}

fn line_of(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    for p in parts {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A value that goes in a command line: no CR, LF or NUL, not empty.
fn check_word(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(Error::RequestInvalid {
            rule: "a POP3 user name or password is not empty and holds no CR, LF or NUL",
        });
    }
    Ok(())
}

impl<'s> Client<'s> {
    fn status(&mut self) -> Result<(bool, Zeroizing<Vec<u8>>)> {
        let line = self.io.line(MAX_STATUS)?;
        let ok = status_of(&line).ok_or(invalid("a POP3 status other than +OK or -ERR"))?;
        Ok((ok, line))
    }

    /// The capabilities (`CAPA`, RFC 2449), upper case, or `None` when the server has none.
    fn capabilities(&mut self) -> Result<Option<Vec<String>>> {
        self.io.write(b"CAPA\r\n")?;
        if !self.status()?.0 {
            return Ok(None);
        }
        let body = read_body(&mut || self.io.line(MAX_STATUS), 64 * 1024)?;
        Ok(Some(
            body.split(|b| *b == b'\n')
                .map(|l| String::from_utf8_lossy(l.trim_ascii()).to_ascii_uppercase())
                .filter(|l| !l.is_empty())
                .collect(),
        ))
    }

    /// Greets (on implicit TLS; after `STLS`, `greeting` is the one before TLS), reads the
    /// capabilities and signs in with `mechanism`, which the server must offer.
    pub fn connect(
        io: Io<'s>,
        greeting: Option<&Greeting>,
        mechanism: Mechanism,
        user: &[u8],
        secret: &[u8],
    ) -> Result<Self> {
        let mut client = Self {
            io,
            scrub: Scrub::new(&[user, secret]),
        };
        let greeting = match greeting {
            Some(g) => g.0.clone(),
            None => {
                let line = client.io.line(MAX_STATUS)?;
                if status_of(&line) != Some(true) {
                    return Err(untrusted("a POP3 greeting other than +OK"));
                }
                line
            }
        };
        let caps = client.capabilities()?;
        let sasl = |name: &str| {
            caps.as_ref().is_some_and(|caps| {
                caps.iter().any(|c| {
                    c.strip_prefix("SASL ")
                        .is_some_and(|list| list.split_ascii_whitespace().any(|m| m == name))
                })
            })
        };
        let not_offered = || Error::AuthRefused {
            rule: "the server does not offer the mechanism the policy names",
        };
        match mechanism {
            Mechanism::User => {
                // A server without CAPA speaks RFC 1939, where USER is the baseline; one that
                // lists its capabilities must list USER.
                if caps
                    .as_ref()
                    .is_some_and(|c| !c.iter().any(|c| c == "USER"))
                {
                    return Err(not_offered());
                }
                check_word(user)?;
                check_word(secret)?;
                client.io.write(&line_of(&[b"USER ", user]))?;
                if !client.status()?.0 {
                    return Err(rejected());
                }
                client.io.write(&line_of(&[b"PASS ", secret]))?;
            }
            Mechanism::Apop => {
                let stamp = timestamp(&greeting).ok_or_else(not_offered)?;
                check_word(user)?;
                if user.contains(&b' ') {
                    return Err(Error::RequestInvalid {
                        rule: "an APOP user name holds no space",
                    });
                }
                let digest = apop_digest(stamp, secret);
                client
                    .io
                    .write(&line_of(&[b"APOP ", user, b" ", &digest]))?;
            }
            Mechanism::Plain | Mechanism::Login | Mechanism::Xoauth2 => {
                let name = match mechanism {
                    Mechanism::Plain => "PLAIN",
                    Mechanism::Login => "LOGIN",
                    _ => "XOAUTH2",
                };
                if !sasl(name) {
                    return Err(not_offered());
                }
                client.sasl(mechanism, name, user, secret)?;
            }
            _ => return Err(not_offered()),
        }
        loop {
            let line = client.io.line(MAX_STATUS)?;
            match status_of(&line) {
                Some(true) => return Ok(client),
                Some(false) => return Err(rejected()),
                // XOAUTH2 failures come as a challenge with details; an empty line ends it.
                None if line.starts_with(b"+ ") || line.as_slice() == b"+\r\n" => {
                    client.io.write(b"\r\n")?;
                }
                None => return Err(invalid("a POP3 status other than +OK or -ERR")),
            }
        }
    }

    /// Writes the SASL exchange of `mechanism` up to its last client message; the caller
    /// reads the outcome.
    fn sasl(&mut self, mechanism: Mechanism, name: &str, user: &[u8], secret: &[u8]) -> Result<()> {
        let challenge = |client: &mut Self| -> Result<()> {
            let line = client.io.line(MAX_STATUS)?;
            if line.starts_with(b"+ ") || line.as_slice() == b"+\r\n" {
                Ok(())
            } else {
                Err(rejected())
            }
        };
        let initial = match mechanism {
            Mechanism::Plain => super::smtp::plain(user, secret),
            Mechanism::Xoauth2 => super::smtp::xoauth2(user, secret),
            _ => {
                // LOGIN: the user name and the password, each after its challenge.
                self.io.write(b"AUTH LOGIN\r\n")?;
                challenge(self)?;
                self.io.write(&line_of(&[&b64(user)]))?;
                challenge(self)?;
                return self.io.write(&line_of(&[&b64(secret)]));
            }
        };
        let command = format!("AUTH {name} ");
        if command.len() + initial.len() + 2 <= MAX_INITIAL {
            self.io.write(&line_of(&[command.as_bytes(), &initial]))
        } else {
            // Too long to go with the command (RFC 5034 section 4): after the challenge.
            self.io.write(&line_of(&[command.trim_end().as_bytes()]))?;
            challenge(self)?;
            self.io.write(&line_of(&[&initial]))
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Runs `verb` with message numbers, at most `max` bytes of response.
    pub fn command(
        &mut self,
        verb: &[u8],
        params: &[Zeroizing<Vec<u8>>],
        max: usize,
    ) -> Result<Response> {
        if !verb_ok(verb) {
            return Err(Error::RequestInvalid {
                rule: "a POP3 command is STAT, LIST, UIDL, RETR, TOP, DELE, NOOP or RSET",
            });
        }
        if !params.iter().all(|p| number_ok(p)) {
            return Err(Error::RequestInvalid {
                rule: "a POP3 parameter is a message number of 1 to 10 digits",
            });
        }
        let mut line = Zeroizing::new(verb.to_vec());
        for p in params {
            line.push(b' ');
            line.extend_from_slice(p);
        }
        line.extend_from_slice(b"\r\n");
        self.io.write(&line)?;
        let (ok, status) = self.status()?;
        let mut bytes = self.scrub.apply(&status);
        if ok && multi_line(verb, params.len()) {
            let body = read_body(&mut || self.io.line(MAX_LINE), max)?;
            bytes.extend_from_slice(&body);
        }
        Ok(Response {
            status: i64::from(!ok),
            bytes,
        })
    }

    /// Says goodbye and closes. `QUIT` commits the deletions of the session (RFC 1939
    /// section 6).
    pub fn close(&mut self) {
        let _ = self.io.write(b"QUIT\r\n");
        let _ = self.io.line(MAX_STATUS);
        self.io.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn apop_digest_of_rfc_1939() {
        // RFC 1939 section 7.
        assert_eq!(
            apop_digest(b"<1896.697170952@dbc.mtview.ca.us>", b"tanstaaf").as_slice(),
            b"c4c9334bac560ecc979e58001b3e22fb"
        );
        assert_eq!(
            timestamp(b"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n"),
            Some(&b"<1896.697170952@dbc.mtview.ca.us>"[..])
        );
        assert_eq!(timestamp(b"+OK ready\r\n"), None);
        assert_eq!(timestamp(b"+OK <no-at>\r\n"), None);
    }

    #[test]
    fn bodies_are_dot_unstuffed_and_bounded() {
        let mut lines = vec![
            Zeroizing::new(b"..hidden\r\n".to_vec()),
            Zeroizing::new(b"line\r\n".to_vec()),
            Zeroizing::new(b".\r\n".to_vec()),
        ]
        .into_iter();
        let body = read_body(&mut || lines.next().ok_or(invalid("eof")), 1024).unwrap();
        assert_eq!(body.as_slice(), b".hidden\r\nline\r\n");
        let mut endless = || Ok(Zeroizing::new(b"aaaa\r\n".to_vec()));
        assert!(read_body(&mut endless, 100).is_err());
    }

    #[test]
    fn numbers_and_statuses() {
        assert!(number_ok(b"1"));
        assert!(number_ok(b"4294967295"));
        for bad in [
            &b""[..],
            b"12345678901",
            b"1 2",
            b"1\r\nDELE 1",
            b"-1",
            b"x",
        ] {
            assert!(!number_ok(bad));
        }
        assert_eq!(status_of(b"+OK hi\r\n"), Some(true));
        assert_eq!(status_of(b"-err no\r\n"), Some(false));
        assert_eq!(status_of(b"* hi\r\n"), None);
    }
}
