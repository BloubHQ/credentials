//! An SMTP submission client (RFC 6409): implicit TLS or `STARTTLS` before anything else,
//! `AUTH` with the mechanism the policy names and only if the server offers it, then
//! messages whose envelope the policy's mail rule allowed.
//!
//! A message travels with every line end a CRLF (bare CR or LF are refused before the call
//! runs, which closes SMTP smuggling) and dot-stuffed, so nothing in it ends the data early.

use base64::Engine as _;
use zeroize::Zeroizing;

use super::io::Io;
use crate::policy::Mechanism;
use crate::{Error, Result};

/// Longest reply line.
const MAX_LINE: usize = 4096;
/// Most lines of one reply.
const MAX_LINES: usize = 128;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// A reply: its code and its lines' text.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    /// The three-digit code.
    pub code: u16,
    /// The text of each line, after the code and separator.
    pub lines: Vec<Vec<u8>>,
}

impl Reply {
    /// The reply as the server wrote it, one line per line.
    pub fn text(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for line in &self.lines {
            out.extend_from_slice(self.code.to_string().as_bytes());
            out.push(b' ');
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

/// Reads one reply, of one line or several (`250-...` then `250 ...`).
pub fn read_reply(next_line: &mut dyn FnMut() -> Result<Zeroizing<Vec<u8>>>) -> Result<Reply> {
    let mut lines = Vec::new();
    let mut code = None;
    loop {
        let line = next_line()?;
        let line = line
            .strip_suffix(b"\r\n")
            .ok_or(invalid("an SMTP reply line not ending in CRLF"))?;
        let digits = line.get(..3).ok_or(invalid("an SMTP reply too short"))?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(invalid("an SMTP reply without a code"));
        }
        let this: u16 = digits
            .iter()
            .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
        if code.is_some_and(|c| c != this) {
            return Err(invalid("an SMTP reply whose lines differ in code"));
        }
        code = Some(this);
        let (last, text) = match line.get(3) {
            None => (true, &[][..]),
            Some(b' ') => (true, line.get(4..).unwrap_or_default()),
            Some(b'-') => (false, line.get(4..).unwrap_or_default()),
            _ => return Err(invalid("an SMTP reply separator")),
        };
        lines.push(text.to_vec());
        if last {
            return Ok(Reply { code: this, lines });
        }
        if lines.len() >= MAX_LINES {
            return Err(invalid("an SMTP reply of too many lines"));
        }
    }
}

fn reply(io: &mut Io<'_>) -> Result<Reply> {
    read_reply(&mut || io.line(MAX_LINE))
}

fn expect(io: &mut Io<'_>, codes: &[u16]) -> Result<Reply> {
    let r = reply(io)?;
    if codes.contains(&r.code) {
        Ok(r)
    } else {
        Err(Error::ResponseInvalid {
            rule: "the SMTP server refused a command",
        })
    }
}

/// `EHLO` and its capabilities, upper case. The node names itself with an address literal
/// (RFC 5321 section 4.1.4): a server with a strict HELO check refuses `localhost`, and the
/// node has no name of its own to give.
fn ehlo(io: &mut Io<'_>) -> Result<Vec<String>> {
    io.write(b"EHLO [127.0.0.1]\r\n")?;
    let r = expect(io, &[250])?;
    Ok(r.lines
        .iter()
        .skip(1)
        .map(|l| String::from_utf8_lossy(l).to_ascii_uppercase())
        .collect())
}

/// The plain prelude: greeting, `EHLO`, `STARTTLS` (which must be offered), go-ahead.
pub fn prelude(io: &mut Io<'_>) -> Result<()> {
    expect(io, &[220])?;
    let caps = ehlo(io)?;
    if !caps.iter().any(|c| c == "STARTTLS") {
        return Err(Error::ServerUntrusted {
            rule: "the server does not offer STARTTLS",
        });
    }
    io.write(b"STARTTLS\r\n")?;
    expect(io, &[220])?;
    io.expect_empty()
}

/// True when the `AUTH` capability lists `name`.
fn offers(caps: &[String], name: &str) -> bool {
    caps.iter().any(|c| {
        c.strip_prefix("AUTH ")
            .or_else(|| c.strip_prefix("AUTH="))
            .is_some_and(|list| list.split_ascii_whitespace().any(|m| m == name))
    })
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

/// The SASL `XOAUTH2` initial response.
pub fn xoauth2(user: &[u8], token: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut raw = Zeroizing::new(b"user=".to_vec());
    raw.extend_from_slice(user);
    raw.extend_from_slice(b"\x01auth=Bearer ");
    raw.extend_from_slice(token);
    raw.extend_from_slice(b"\x01\x01");
    b64(&raw)
}

/// The SASL `PLAIN` initial response.
pub fn plain(user: &[u8], password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut raw = Zeroizing::new(vec![0u8]);
    raw.extend_from_slice(user);
    raw.push(0);
    raw.extend_from_slice(password);
    b64(&raw)
}

/// Dot-stuffs `data` (whose line ends are all CRLF) and ends it with `CRLF . CRLF`.
pub fn stuff(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() + 8));
    let mut start = true;
    for b in data {
        if start && *b == b'.' {
            out.push(b'.');
        }
        out.push(*b);
        start = *b == b'\n';
    }
    if !data.is_empty() && !data.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
}

impl<'s> Client<'s> {
    /// Greets (on implicit TLS), says `EHLO` and signs in.
    pub fn connect(
        mut io: Io<'s>,
        after_starttls: bool,
        mechanism: Mechanism,
        user: &[u8],
        secret: &[u8],
    ) -> Result<Self> {
        if !after_starttls {
            expect(&mut io, &[220])?;
        }
        let caps = ehlo(&mut io)?;
        let refused = || Error::AuthRefused {
            rule: "the server refused the sign-in",
        };
        let name = match mechanism {
            Mechanism::Plain => "PLAIN",
            Mechanism::Login => "LOGIN",
            Mechanism::Xoauth2 => "XOAUTH2",
            _ => return Err(refused()),
        };
        // The mechanism the policy names, or none: never a fallback to another.
        if !offers(&caps, name) {
            return Err(Error::AuthRefused {
                rule: "the server does not offer the mechanism the policy names",
            });
        }
        let done = match mechanism {
            Mechanism::Plain => {
                io.write(&line_of(&[b"AUTH PLAIN ", &plain(user, secret)]))?;
                reply(&mut io)?
            }
            Mechanism::Login => {
                io.write(b"AUTH LOGIN\r\n")?;
                if reply(&mut io)?.code != 334 {
                    return Err(refused());
                }
                io.write(&line_of(&[&b64(user)]))?;
                if reply(&mut io)?.code != 334 {
                    return Err(refused());
                }
                io.write(&line_of(&[&b64(secret)]))?;
                reply(&mut io)?
            }
            _ => {
                io.write(&line_of(&[b"AUTH XOAUTH2 ", &xoauth2(user, secret)]))?;
                let r = reply(&mut io)?;
                if r.code == 334 {
                    // The error details; an empty line ends the exchange.
                    io.write(b"\r\n")?;
                    reply(&mut io)?
                } else {
                    r
                }
            }
        };
        if done.code == 235 {
            Ok(Self { io })
        } else {
            Err(refused())
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Sends one message; the last reply comes back.
    pub fn send(&mut self, from: &str, to: &[String], data: &[u8]) -> Result<Reply> {
        let io = &mut self.io;
        io.write(&line_of(&[b"MAIL FROM:<", from.as_bytes(), b">"]))?;
        expect(io, &[250])?;
        for rcpt in to {
            io.write(&line_of(&[b"RCPT TO:<", rcpt.as_bytes(), b">"]))?;
            expect(io, &[250, 251])?;
        }
        io.write(b"DATA\r\n")?;
        expect(io, &[354])?;
        io.write(&stuff(data))?;
        let r = reply(io)?;
        if r.code != 250 {
            let _ = io.write(b"RSET\r\n");
            let _ = reply(io);
        }
        Ok(r)
    }

    /// Says goodbye and closes.
    pub fn close(&mut self) {
        let _ = self.io.write(b"QUIT\r\n");
        self.io.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    fn parse(text: &[u8]) -> Result<Reply> {
        let mut lines = text
            .split_inclusive(|b| *b == b'\n')
            .map(|l| Zeroizing::new(l.to_vec()));
        read_reply(&mut || lines.next().ok_or(invalid("eof")))
    }

    #[test]
    fn replies_of_several_lines() {
        let r = parse(b"250-mail.example\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n").unwrap();
        assert_eq!(r.code, 250);
        assert_eq!(r.lines.len(), 3);
        assert!(parse(b"250-a\r\n251 b\r\n").is_err());
        assert!(parse(b"2x0 a\r\n").is_err());
        assert!(parse(b"250 a\n").is_err());
    }

    #[test]
    fn data_is_dot_stuffed() {
        assert_eq!(
            stuff(b".hidden\r\nline\r\n.\r\nend").as_slice(),
            b"..hidden\r\nline\r\n..\r\nend\r\n.\r\n"
        );
    }

    #[test]
    fn sasl_initial_responses() {
        assert_eq!(plain(b"u", b"p").as_slice(), b"AHUAcA==");
        assert_eq!(
            xoauth2(b"u", b"t").as_slice(),
            b"dXNlcj11AWF1dGg9QmVhcmVyIHQBAQ=="
        );
    }
}
