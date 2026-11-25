//! An IMAP4rev1 client (RFC 3501): implicit TLS or `STARTTLS`, `LOGIN` or `AUTHENTICATE`
//! with the mechanism the policy names, then tagged commands whose parameters go as quoted
//! strings. Responses are read whole, literals (`{n}`) included, up to the tagged completion.
//!
//! Reading a message for a code: a fixed command (`UID FETCH ... BODY[TEXT]`) followed by a
//! `receive` that captures the code into a temp; the message itself does not go back.

use zeroize::Zeroizing;

use super::io::Io;
use crate::policy::Mechanism;
use crate::{Error, Result};

/// Longest response line, without its literals.
const MAX_LINE: usize = 64 * 1024;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// `value` as a quoted string; CR, LF and NUL cannot be quoted and are refused.
pub fn quote(value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(Error::RequestInvalid {
            rule: "an IMAP string cannot hold CR, LF or NUL",
        });
    }
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() + 2));
    out.push(b'"');
    for b in value {
        if matches!(b, b'"' | b'\\') {
            out.push(b'\\');
        }
        out.push(*b);
    }
    out.push(b'"');
    Ok(out)
}

/// A whole response: every line up to and with the tagged one, literals inline.
pub struct Response {
    /// 0 for `OK`, 1 for `NO`, 2 for `BAD`.
    pub status: i64,
    /// The response as it came.
    pub bytes: Zeroizing<Vec<u8>>,
}

/// The length of the literal a line announces at its end (`... {12}\r\n`).
pub fn literal_at_end(line: &[u8]) -> Option<usize> {
    let body = line.strip_suffix(b"\r\n")?.strip_suffix(b"}")?;
    let open = body.iter().rposition(|b| *b == b'{')?;
    let digits = body.get(open + 1..)?;
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// The completion of a tagged line: `tag OK|NO|BAD ...`.
pub fn completion(line: &[u8], tag: &[u8]) -> Option<i64> {
    let rest = line.strip_prefix(tag)?.strip_prefix(b" ")?;
    let word = rest.split(|b| *b == b' ' || *b == b'\r').next()?;
    match word.to_ascii_uppercase().as_slice() {
        b"OK" => Some(0),
        b"NO" => Some(1),
        b"BAD" => Some(2),
        _ => None,
    }
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
    next: u32,
}

impl<'s> Client<'s> {
    fn tag(&mut self) -> Vec<u8> {
        self.next = self.next.wrapping_add(1);
        format!("a{}", self.next).into_bytes()
    }

    /// Reads up to the completion of `tag`, at most `max` bytes.
    fn response(&mut self, tag: &[u8], max: usize) -> Result<Response> {
        let mut bytes = Zeroizing::new(Vec::new());
        loop {
            let line = self.io.line(MAX_LINE)?;
            bytes.extend_from_slice(&line);
            if let Some(status) = completion(&line, tag) {
                return Ok(Response { status, bytes });
            }
            if let Some(n) = literal_at_end(&line) {
                if bytes.len().saturating_add(n) > max {
                    return Err(Error::transport(
                        crate::error::TransportKind::TooLarge,
                        true,
                    ));
                }
                bytes.extend_from_slice(&self.io.take(n)?);
            }
            if bytes.len() > max {
                return Err(Error::transport(
                    crate::error::TransportKind::TooLarge,
                    true,
                ));
            }
        }
    }

    /// Greets (on implicit TLS), reads the capabilities and signs in.
    pub fn connect(
        io: Io<'s>,
        after_starttls: bool,
        mechanism: Mechanism,
        user: &[u8],
        secret: &[u8],
    ) -> Result<Self> {
        let mut client = Self { io, next: 0 };
        if !after_starttls {
            let greeting = client.io.line(MAX_LINE)?;
            if !greeting.to_ascii_uppercase().starts_with(b"* OK") {
                return Err(Error::ServerUntrusted {
                    rule: "an IMAP greeting other than OK",
                });
            }
        }
        let tag = client.tag();
        let mut line = tag.clone();
        line.extend_from_slice(b" CAPABILITY\r\n");
        client.io.write(&line)?;
        let caps = client.response(&tag, MAX_LINE)?;
        let caps = String::from_utf8_lossy(&caps.bytes).to_ascii_uppercase();
        let has = |name: &str| caps.split_ascii_whitespace().any(|w| w == name);
        let refused = || Error::AuthRefused {
            rule: "the server refused the sign-in",
        };
        let tag = client.tag();
        let mut command = Zeroizing::new(tag.clone());
        match mechanism {
            Mechanism::Login => {
                if has("LOGINDISABLED") {
                    return Err(Error::AuthRefused {
                        rule: "the server does not take LOGIN",
                    });
                }
                command.extend_from_slice(b" LOGIN ");
                command.extend_from_slice(&quote(user)?);
                command.push(b' ');
                command.extend_from_slice(&quote(secret)?);
                command.extend_from_slice(b"\r\n");
                client.io.write(&command)?;
            }
            Mechanism::Plain | Mechanism::Xoauth2 => {
                let (name, initial) = if mechanism == Mechanism::Plain {
                    ("PLAIN", super::smtp::plain(user, secret))
                } else {
                    ("XOAUTH2", super::smtp::xoauth2(user, secret))
                };
                // The mechanism the policy names, or none.
                if !has(&format!("AUTH={name}")) {
                    return Err(Error::AuthRefused {
                        rule: "the server does not offer the mechanism the policy names",
                    });
                }
                command.extend_from_slice(b" AUTHENTICATE ");
                command.extend_from_slice(name.as_bytes());
                command.extend_from_slice(b"\r\n");
                client.io.write(&command)?;
                let go = client.io.line(MAX_LINE)?;
                if !go.starts_with(b"+") {
                    return Err(refused());
                }
                let mut answer = Zeroizing::new(initial.to_vec());
                answer.extend_from_slice(b"\r\n");
                client.io.write(&answer)?;
            }
            _ => return Err(refused()),
        }
        loop {
            let line = client.io.line(MAX_LINE)?;
            // XOAUTH2 failures come as a challenge with details; an empty line ends it.
            if line.starts_with(b"+") {
                client.io.write(b"\r\n")?;
                continue;
            }
            if let Some(status) = completion(&line, &tag) {
                return if status == 0 {
                    Ok(client)
                } else {
                    Err(refused())
                };
            }
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Runs `text` with `params` quoted after it.
    pub fn command(
        &mut self,
        text: &[u8],
        params: &[Zeroizing<Vec<u8>>],
        max: usize,
    ) -> Result<Response> {
        if text.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err(Error::RequestInvalid {
                rule: "an IMAP command cannot hold CR, LF or NUL",
            });
        }
        let tag = self.tag();
        let mut line = Zeroizing::new(tag.clone());
        line.push(b' ');
        line.extend_from_slice(text);
        for p in params {
            line.push(b' ');
            line.extend_from_slice(&quote(p)?);
        }
        line.extend_from_slice(b"\r\n");
        self.io.write(&line)?;
        self.response(&tag, max)
    }

    /// Logs out and closes.
    pub fn close(&mut self) {
        let tag = self.tag();
        let mut line = tag;
        line.extend_from_slice(b" LOGOUT\r\n");
        let _ = self.io.write(&line);
        self.io.close();
    }
}

/// The plain prelude: greeting, `STARTTLS`, its `OK`.
pub fn prelude(io: &mut Io<'_>) -> Result<()> {
    let greeting = io.line(MAX_LINE)?;
    if !greeting.to_ascii_uppercase().starts_with(b"* OK") {
        return Err(Error::ServerUntrusted {
            rule: "an IMAP greeting other than OK",
        });
    }
    io.write(b"a0 STARTTLS\r\n")?;
    loop {
        let line = io.line(MAX_LINE)?;
        match completion(&line, b"a0") {
            Some(0) => return io.expect_empty(),
            Some(_) => {
                return Err(Error::ServerUntrusted {
                    rule: "the server does not offer STARTTLS",
                });
            }
            None if line.starts_with(b"* ") => {}
            None => return Err(invalid("an IMAP response to STARTTLS")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote(b"a\"b\\c").unwrap().as_slice(), b"\"a\\\"b\\\\c\"");
        assert!(quote(b"a\r\nb").is_err());
        assert!(quote(b"a\0").is_err());
    }

    #[test]
    fn literals_and_completions() {
        assert_eq!(literal_at_end(b"* 1 FETCH (BODY[TEXT] {12}\r\n"), Some(12));
        assert_eq!(literal_at_end(b"* 1 FETCH (BODY[TEXT] {12+}\r\n"), Some(12));
        assert_eq!(literal_at_end(b"* OK {x}\r\n"), None);
        assert_eq!(literal_at_end(b"* OK\r\n"), None);
        assert_eq!(completion(b"a3 OK done\r\n", b"a3"), Some(0));
        assert_eq!(completion(b"a3 no\r\n", b"a3"), Some(1));
        assert_eq!(completion(b"a31 OK\r\n", b"a3"), None);
        assert_eq!(completion(b"* OK\r\n", b"a3"), None);
    }
}
