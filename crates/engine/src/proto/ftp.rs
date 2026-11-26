//! An FTP client over TLS (RFC 959, RFC 4217): implicit TLS (port 990) or `AUTH TLS` before
//! anything else (port 21), `USER` and `PASS`, then `PBSZ 0` and `PROT P` so every data
//! connection is TLS too, and typed operations: list, retrieve, store, delete, rename and
//! mkdir.
//!
//! Data connections are passive only (`EPSV` of RFC 2428, else `PASV`); active mode, in which
//! the server connects to the node, is never used. A data connection goes to the same server
//! the control connection reached, never to an address a reply names: a `PASV` reply naming
//! another address than the control connection's peer is refused (FTP bounce, and a server
//! steering the node at another host), and so is a data port below 1024. Over TLS the data
//! connection makes TLS to the same server name and resumes the control connection's session
//! when the server allows it (RFC 4217 section 10); it must end with a TLS `close_notify`, so
//! a cut connection is not taken for a whole file.
//!
//! A path is a parameter of one command line: it is checked before anything is sent
//! ([`check_path`]) for what could start another command or leave the pattern the policy
//! matched: CR, LF, NUL and other control bytes, `0xFF` (Telnet IAC), invalid UTF-8, a
//! relative path, an empty, `.` or `..` segment, a backslash. The user name and the password
//! may hold no CR, LF or NUL either: such a value is refused, never cut or sent.
//!
//! Replies are bounded (lines of 4096 bytes, 256 lines), listings too (8192-byte lines,
//! 10,000 entries), and what goes back of a reply is scrubbed of the user name and password
//! ([`Scrub`]).

use std::net::IpAddr;
use std::time::Duration;

use zeroize::Zeroizing;

use super::io::{Io, Scrub};
use crate::egress::{Arrived, Stream};
use crate::error::TransportKind;
use crate::{Error, Result};

/// Longest reply line, with its CRLF.
pub const MAX_LINE: usize = 4096;
/// Most lines of one reply.
pub const MAX_LINES: usize = 256;
/// Longest line of a listing.
pub const MAX_LIST_LINE: usize = 8192;
/// Most entries of a listing.
pub const MAX_ENTRIES: usize = 10_000;
/// Lowest data port a passive reply may name.
pub const MIN_DATA_PORT: u16 = 1024;
/// Longest path, in bytes.
pub const MAX_PATH: usize = 4096;
/// How long one read of a data connection waits before the bounds are looked at.
const WAIT: Duration = Duration::from_millis(50);
/// Most bytes read from a data connection at once.
const READ: usize = 64 * 1024;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

fn refused(rule: &'static str) -> Error {
    Error::RequestInvalid { rule }
}

/// A reply: its code and the text of its lines.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    /// The three-digit code.
    pub code: u16,
    /// Each line's text without its CRLF; the first and last without their code.
    pub lines: Vec<Vec<u8>>,
}

impl Reply {
    /// True for a positive completion (2xx).
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// The text of the reply, its lines joined by a line feed.
    pub fn text(&self) -> Vec<u8> {
        self.lines.join(&b'\n')
    }
}

/// The code of a reply line: three digits, the first 1 to 5 (RFC 959 section 4.2).
fn code_of(line: &[u8]) -> Option<u16> {
    let digits = line.get(..3)?;
    if !digits.iter().all(u8::is_ascii_digit)
        || digits.first().is_some_and(|d| !(b'1'..=b'5').contains(d))
    {
        return None;
    }
    Some(
        digits
            .iter()
            .fold(0u16, |n, d| n * 10 + u16::from(d - b'0')),
    )
}

/// Reads one reply (RFC 959 section 4.2): `ddd text`, or `ddd-text` then any lines up to one
/// that starts with the same `ddd ` and ends the reply.
pub fn read_reply(next_line: &mut dyn FnMut() -> Result<Zeroizing<Vec<u8>>>) -> Result<Reply> {
    let first = next_line()?;
    let line = first
        .strip_suffix(b"\r\n")
        .ok_or(invalid("an FTP reply line not ending in CRLF"))?;
    let code = code_of(line).ok_or(invalid("an FTP reply without a code"))?;
    let mut lines = vec![line.get(4..).unwrap_or_default().to_vec()];
    match line.get(3) {
        None | Some(b' ') => return Ok(Reply { code, lines }),
        Some(b'-') => {}
        _ => return Err(invalid("an FTP reply separator")),
    }
    loop {
        if lines.len() >= MAX_LINES {
            return Err(invalid("an FTP reply of too many lines"));
        }
        let next = next_line()?;
        let line = next
            .strip_suffix(b"\r\n")
            .ok_or(invalid("an FTP reply line not ending in CRLF"))?;
        if code_of(line) == Some(code) && matches!(line.get(3), None | Some(b' ')) {
            lines.push(line.get(4..).unwrap_or_default().to_vec());
            return Ok(Reply { code, lines });
        }
        lines.push(line.to_vec());
    }
}

/// Checks a path before it goes in a command: at most 4096 bytes of UTF-8 with no control
/// byte (so no CR, LF or NUL), no DEL and no `0xFF`, absolute, with no empty, `.` or `..`
/// segment, no trailing `/` and no backslash.
pub fn check_path(path: &[u8]) -> Result<()> {
    let bad = || refused("an FTP path: absolute, no empty, . or .. segment, no \\ or control byte");
    if path.len() > MAX_PATH
        || path.iter().any(|b| *b < 0x20 || *b == 0x7f || *b == 0xff)
        || core::str::from_utf8(path).is_err()
    {
        return Err(bad());
    }
    super::sftp::normalize(path).map_err(|_| bad())
}

/// Checks a value of the sign-in: it goes in a command line, so it holds no CR, LF or NUL.
fn check_word(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(refused(
            "an FTP user name or password is not empty and holds no CR, LF or NUL",
        ));
    }
    Ok(())
}

/// The port of an `EPSV` reply (RFC 2428 section 3): `(<d><d><d><port><d>)`, where `<d>` is
/// one printable delimiter.
pub fn parse_epsv(text: &[u8]) -> Option<u16> {
    let open = memchr::memchr(b'(', text)?;
    let inner = text.get(open + 1..)?;
    let close = memchr::memchr(b')', inner)?;
    let inner = inner.get(..close)?;
    let d = *inner.first()?;
    if !(33..=126).contains(&d) || d.is_ascii_digit() {
        return None;
    }
    let rest = inner.strip_prefix(&[d, d, d][..])?.strip_suffix(&[d][..])?;
    if rest.is_empty() || rest.len() > 5 || !rest.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(rest)
        .ok()?
        .parse()
        .ok()
        .filter(|p| *p > 0)
}

/// The address and port of a `PASV` reply: the first six comma-separated numbers of 0 to
/// 255 (`h1,h2,h3,h4,p1,p2`).
pub fn parse_pasv(text: &[u8]) -> Option<(std::net::Ipv4Addr, u16)> {
    let start = text.iter().position(u8::is_ascii_digit)?;
    let tail = text.get(start..)?;
    let end = tail
        .iter()
        .position(|b| !(b.is_ascii_digit() || *b == b','))
        .unwrap_or(tail.len());
    let mut numbers = [0u8; 6];
    let mut parts = tail.get(..end)?.split(|b| *b == b',');
    for n in &mut numbers {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        *n = core::str::from_utf8(part).ok()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    let [a, b, c, d, p1, p2] = numbers;
    Some((
        std::net::Ipv4Addr::new(a, b, c, d),
        u16::from(p1) << 8 | u16::from(p2),
    ))
}

/// True when the address a `PASV` reply names is the server the control connection reached.
fn same_host(named: std::net::Ipv4Addr, peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(peer) => peer == named,
        IpAddr::V6(peer) => peer.to_ipv4_mapped() == Some(named),
    }
}

/// One entry of a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The name, as the server sent it.
    pub name: Vec<u8>,
    /// `file`, `dir`, or another `type` fact of MLSD (lower case); `None` from NLST.
    pub kind: Option<String>,
    /// The `size` fact.
    pub size: Option<u64>,
    /// The `modify` fact (`YYYYMMDDHHMMSS[.sss]`).
    pub modify: Option<String>,
}

impl Entry {
    /// The entry as JSON: the name as text, or `name_base64` when it is not UTF-8.
    pub fn json(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        match core::str::from_utf8(&self.name) {
            Ok(name) => out.insert("name".into(), name.into()),
            Err(_) => {
                use base64::Engine as _;
                out.insert(
                    "name_base64".into(),
                    base64::engine::general_purpose::STANDARD
                        .encode(&self.name)
                        .into(),
                )
            }
        };
        if let Some(kind) = &self.kind {
            out.insert("type".into(), kind.as_str().into());
        }
        if let Some(size) = self.size {
            out.insert("size".into(), size.into());
        }
        if let Some(modify) = &self.modify {
            out.insert("modify".into(), modify.as_str().into());
        }
        serde_json::Value::Object(out)
    }
}

/// Parses one line of an `MLSD` listing (RFC 3659 section 7): `fact=value;...; name`. The
/// directory itself and its parent (`cdir`, `pdir`) give `None`, as does a malformed line.
pub fn parse_mlsd_line(line: &[u8]) -> Option<Entry> {
    let space = memchr::memchr(b' ', line)?;
    let (facts, name) = (line.get(..space)?, line.get(space + 1..)?);
    if name.is_empty() || name.contains(&b'/') {
        return None;
    }
    let mut entry = Entry {
        name: name.to_vec(),
        kind: None,
        size: None,
        modify: None,
    };
    for fact in facts.split(|b| *b == b';').filter(|f| !f.is_empty()) {
        let eq = memchr::memchr(b'=', fact)?;
        let key = fact.get(..eq)?.to_ascii_lowercase();
        let value = core::str::from_utf8(fact.get(eq + 1..)?).ok()?;
        if value.len() > 64 || value.bytes().any(|b| !b.is_ascii_graphic()) {
            continue;
        }
        match key.as_slice() {
            b"type" => entry.kind = Some(value.to_ascii_lowercase()),
            b"size" => entry.size = value.parse().ok(),
            b"modify" => entry.modify = Some(value.to_string()),
            _ => {}
        }
    }
    match entry.kind.as_deref() {
        Some("cdir" | "pdir") => None,
        _ => Some(entry),
    }
}

/// What one operation came to: the server's final reply (scrubbed), and what it brought.
pub struct Outcome {
    /// The final reply's code.
    pub code: u16,
    /// Its text, scrubbed of the sign-in's values.
    pub text: Zeroizing<Vec<u8>>,
    /// True when the operation completed (a 2xx final reply).
    pub ok: bool,
    /// What a retrieve brought, or the listing.
    pub data: Option<Zeroizing<Vec<u8>>>,
    /// The entries of a listing.
    pub entries: Vec<Entry>,
}

/// The plain prelude of explicit FTPS: the greeting (220), then `AUTH TLS` and its go-ahead
/// (234). Nothing secret is written; bytes after the go-ahead fail the call.
pub fn prelude(io: &mut Io<'_>) -> Result<()> {
    let greeting = reply(io)?;
    if greeting.code != 220 {
        return Err(untrusted("an FTP greeting other than 220"));
    }
    io.write(b"AUTH TLS\r\n")?;
    if reply(io)?.code != 234 {
        return Err(untrusted("the server does not take AUTH TLS"));
    }
    io.expect_empty()
}

fn reply(io: &mut Io<'_>) -> Result<Reply> {
    read_reply(&mut || io.line(MAX_LINE))
}

fn line_of(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    for p in parts {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
    /// True until the server refuses `EPSV`; then `PASV`.
    epsv: bool,
    /// True when `FEAT` lists `MLST`: listings by `MLSD`, else names by `NLST`.
    mlst: bool,
    scrub: Scrub,
}

impl<'s> Client<'s> {
    /// Greets (on implicit TLS), signs in with `USER` and `PASS`, protects data connections
    /// (`PBSZ 0`, `PROT P`), sets binary transfers and reads the features.
    pub fn connect(
        mut io: Io<'s>,
        after_auth_tls: bool,
        user: &[u8],
        secret: &[u8],
    ) -> Result<Self> {
        if !after_auth_tls && reply(&mut io)?.code != 220 {
            return Err(untrusted("an FTP greeting other than 220"));
        }
        check_word(user)?;
        check_word(secret)?;
        let rejected = || Error::AuthRefused {
            rule: "the server refused the sign-in",
        };
        io.write(&line_of(&[b"USER ", user]))?;
        let mut r = reply(&mut io)?;
        if r.code == 331 {
            io.write(&line_of(&[b"PASS ", secret]))?;
            r = reply(&mut io)?;
        }
        if !matches!(r.code, 230 | 202) {
            return Err(rejected());
        }
        io.write(b"PBSZ 0\r\n")?;
        if reply(&mut io)?.code != 200 {
            return Err(untrusted("the server does not take PBSZ 0"));
        }
        io.write(b"PROT P\r\n")?;
        if reply(&mut io)?.code != 200 {
            return Err(untrusted(
                "the server does not protect data connections (PROT P)",
            ));
        }
        io.write(b"TYPE I\r\n")?;
        if reply(&mut io)?.code != 200 {
            return Err(invalid("the server does not take binary transfers"));
        }
        io.write(b"FEAT\r\n")?;
        let features = reply(&mut io)?;
        let mlst = features.code == 211
            && features.lines.iter().any(|l| {
                l.trim_ascii()
                    .get(..4)
                    .is_some_and(|w| w.eq_ignore_ascii_case(b"MLST"))
            });
        Ok(Self {
            io,
            epsv: true,
            mlst,
            scrub: Scrub::new(&[user, secret]),
        })
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    fn reply(&mut self) -> Result<Reply> {
        reply(&mut self.io)
    }

    fn outcome(&self, reply: &Reply) -> Outcome {
        Outcome {
            code: reply.code,
            text: self.scrub.apply(&reply.text()),
            ok: reply.ok(),
            data: None,
            entries: Vec::new(),
        }
    }

    /// Asks for a passive data connection and opens it to the same server.
    fn passive(&mut self) -> Result<Box<dyn Stream>> {
        let mut port = None;
        if self.epsv {
            self.io.write(b"EPSV\r\n")?;
            let r = self.reply()?;
            match r.code {
                229 => {
                    port = Some(
                        r.lines
                            .first()
                            .and_then(|l| parse_epsv(l))
                            .ok_or(invalid("an EPSV reply without a port"))?,
                    );
                }
                500..=599 => self.epsv = false,
                _ => return Err(invalid("an unexpected answer to EPSV")),
            }
        }
        let port = match port {
            Some(port) => port,
            None => {
                self.io.write(b"PASV\r\n")?;
                let r = self.reply()?;
                if r.code != 227 {
                    return Err(invalid("the server opens no passive data connection"));
                }
                let (named, port) = r
                    .lines
                    .first()
                    .and_then(|l| parse_pasv(l))
                    .ok_or(invalid("a PASV reply without an address"))?;
                // The data connection goes to the control connection's server whatever the
                // reply names; a reply naming another host is refused outright.
                if let Some(peer) = self.io.peer_ip()
                    && !same_host(named, peer)
                {
                    return Err(untrusted(
                        "a passive reply names another host than the control connection",
                    ));
                }
                port
            }
        };
        if port < MIN_DATA_PORT {
            return Err(untrusted("a passive reply names a data port below 1024"));
        }
        self.io.open_data(port)
    }

    /// Opens a data connection and sends `command` over the control connection. The data
    /// connection when the server starts the transfer (125, 150), else the reply.
    fn start(&mut self, command: &[u8]) -> Result<core::result::Result<Box<dyn Stream>, Reply>> {
        let mut data = self.passive()?;
        self.io.write(command)?;
        let r = self.reply()?;
        if matches!(r.code, 125 | 150) {
            Ok(Ok(data))
        } else {
            let _ = data.close();
            Ok(Err(r))
        }
    }

    /// Reads a data connection to its end, at most `max` bytes, counting them against the
    /// control connection's bounds.
    fn read_all(&mut self, data: &mut dyn Stream, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        loop {
            match data.read_some(READ, WAIT)? {
                Arrived::Bytes(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    self.io.tally(bytes.len(), 0)?;
                    if out.len().saturating_add(bytes.len()) > max {
                        return Err(Error::transport(TransportKind::TooLarge, true));
                    }
                    out.extend_from_slice(&bytes);
                }
                Arrived::Nothing => self.io.tally(0, 0)?,
                Arrived::End => return Ok(out),
            }
        }
    }

    /// Ends a transfer: the final reply.
    fn finish(&mut self, data: Option<Zeroizing<Vec<u8>>>) -> Result<Outcome> {
        let r = self.reply()?;
        let mut outcome = self.outcome(&r);
        if !matches!(r.code, 226 | 250) {
            outcome.ok = false;
            return Ok(outcome);
        }
        outcome.data = data;
        Ok(outcome)
    }

    /// Reads the file at `path`, at most `max` bytes.
    pub fn retrieve(&mut self, path: &[u8], max: usize) -> Result<Outcome> {
        check_path(path)?;
        let mut data = match self.start(&line_of(&[b"RETR ", path]))? {
            Ok(data) => data,
            Err(r) => return Ok(self.outcome(&r)),
        };
        let read = self.read_all(&mut *data, max);
        let _ = data.close();
        let bytes = read?;
        self.finish(Some(bytes))
    }

    /// Writes `bytes` as the file at `path` (`STOR`: created or replaced).
    pub fn store(&mut self, path: &[u8], bytes: &[u8]) -> Result<Outcome> {
        check_path(path)?;
        let mut data = match self.start(&line_of(&[b"STOR ", path]))? {
            Ok(data) => data,
            Err(r) => return Ok(self.outcome(&r)),
        };
        for chunk in bytes.chunks(READ) {
            self.io.tally(0, chunk.len())?;
            data.write(chunk)?;
        }
        // The end of the file is the end of the connection: TLS close_notify, then FIN.
        data.close()?;
        drop(data);
        self.finish(None)
    }

    /// Lists the directory at `path` (`/` allowed): `MLSD` entries when the server lists
    /// `MLST`, else `NLST` names. At most `max` bytes and [`MAX_ENTRIES`] entries.
    pub fn list(&mut self, path: &[u8], max: usize) -> Result<Outcome> {
        if path != b"/" {
            check_path(path)?;
        }
        let verb: &[u8] = if self.mlst { b"MLSD " } else { b"NLST " };
        let mut data = match self.start(&line_of(&[verb, path]))? {
            Ok(data) => data,
            Err(r) => return Ok(self.outcome(&r)),
        };
        let read = self.read_all(&mut *data, max);
        let _ = data.close();
        let bytes = read?;
        let entries = parse_listing(&bytes, self.mlst)?;
        let mut outcome = self.finish(None)?;
        outcome.data = Some(bytes);
        outcome.entries = entries;
        Ok(outcome)
    }

    /// A command of one path that answers with one reply.
    fn simple(&mut self, verb: &[u8], path: &[u8]) -> Result<Outcome> {
        check_path(path)?;
        self.io.write(&line_of(&[verb, path]))?;
        let r = self.reply()?;
        Ok(self.outcome(&r))
    }

    /// Deletes the file at `path` (`DELE`).
    pub fn delete(&mut self, path: &[u8]) -> Result<Outcome> {
        self.simple(b"DELE ", path)
    }

    /// Makes the directory at `path` (`MKD`).
    pub fn mkdir(&mut self, path: &[u8]) -> Result<Outcome> {
        self.simple(b"MKD ", path)
    }

    /// Renames `from` to `to` (`RNFR`, then `RNTO` after 350).
    pub fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<Outcome> {
        check_path(to)?;
        let first = self.simple(b"RNFR ", from)?;
        if first.code != 350 {
            let mut first = first;
            first.ok = false;
            return Ok(first);
        }
        self.simple(b"RNTO ", to)
    }

    /// Says goodbye and closes.
    pub fn close(&mut self) {
        let _ = self.io.write(b"QUIT\r\n");
        self.io.close();
    }
}

/// The entries of a listing: one per line (CRLF or LF), each at most [`MAX_LIST_LINE`]
/// bytes, at most [`MAX_ENTRIES`].
pub fn parse_listing(bytes: &[u8], mlsd: bool) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LIST_LINE {
            return Err(invalid("a listing line too long"));
        }
        let entry = if mlsd {
            parse_mlsd_line(line)
        } else {
            Some(Entry {
                name: line.to_vec(),
                kind: None,
                size: None,
                modify: None,
            })
        };
        if let Some(entry) = entry {
            if entries.len() >= MAX_ENTRIES {
                return Err(invalid("a listing of too many entries"));
            }
            entries.push(entry);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn parse(text: &[u8]) -> Result<Reply> {
        let mut lines = text
            .split_inclusive(|b| *b == b'\n')
            .map(|l| Zeroizing::new(l.to_vec()));
        read_reply(&mut || lines.next().ok_or(invalid("eof")))
    }

    #[test]
    fn replies_of_one_or_several_lines() {
        assert_eq!(parse(b"220 ready\r\n").unwrap().code, 220);
        let r = parse(b"211-Features:\r\n MLST type*;size*;\r\n EPSV\r\n211 End\r\n").unwrap();
        assert_eq!(r.code, 211);
        assert_eq!(r.lines.len(), 4);
        // A line with another code inside a reply is text, not its end.
        let r = parse(b"230-hello\r\n220 not the end\r\n230 end\r\n").unwrap();
        assert_eq!(r.lines.len(), 3);
        assert!(parse(b"22x ready\r\n").is_err());
        assert!(parse(b"220 ready\n").is_err());
        assert!(parse(b"220_ready\r\n").is_err());
        assert!(parse(b"020 ready\r\n").is_err());
    }

    #[test]
    fn passive_replies() {
        assert_eq!(
            parse_epsv(b"Entering Extended Passive Mode (|||6446|)"),
            Some(6446)
        );
        assert_eq!(parse_epsv(b"ok (!!!2121!)"), Some(2121));
        for bad in [
            &b"(|||0|)"[..],
            b"(||1|6446|)",
            b"(|||6446)",
            b"(|||99999|)",
            b"(111611)",
        ] {
            assert_eq!(parse_epsv(bad), None);
        }
        assert_eq!(
            parse_pasv(b"Entering Passive Mode (192,0,2,10,19,137)"),
            Some((std::net::Ipv4Addr::new(192, 0, 2, 10), 5001))
        );
        assert_eq!(parse_pasv(b"Entering Passive Mode (192,0,2,10,19)"), None);
        assert_eq!(parse_pasv(b"(192,0,2,10,19,137,1)"), None);
        assert_eq!(parse_pasv(b"(192,0,2,300,19,137)"), None);
        assert!(same_host(
            std::net::Ipv4Addr::new(192, 0, 2, 10),
            "::ffff:192.0.2.10".parse().unwrap()
        ));
        assert!(!same_host(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            "192.0.2.10".parse().unwrap()
        ));
    }

    #[test]
    fn paths_that_could_inject_or_climb_are_refused() {
        assert!(check_path(b"/srv/a.csv").is_ok());
        assert!(check_path("/srv/caf\u{e9}.txt".as_bytes()).is_ok());
        for bad in [
            &b"/srv/a\r\nDELE /etc/passwd"[..],
            b"/srv/a\nx",
            b"/srv/a\0",
            b"/srv/\xff\xf4",
            b"/srv/\x7f",
            b"/srv/\x80",
            b"srv/a",
            b"/srv/../a",
            b"/srv/./a",
            b"/srv//a",
            b"/srv/a/",
            b"/srv\\a",
        ] {
            assert!(check_path(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(check_word(b"a\r\nPASS x").is_err());
        assert!(check_word(b"").is_err());
    }

    #[test]
    fn listings() {
        let entries = parse_listing(
            b"type=cdir; .\r\ntype=pdir; ..\r\ntype=file;size=12;modify=20250101120000; a b.csv\r\ntype=dir; sub\r\n",
            true,
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"a b.csv");
        assert_eq!(entries[0].size, Some(12));
        assert_eq!(entries[1].kind.as_deref(), Some("dir"));
        assert_eq!(parse_listing(b"a\nb\r\n", false).unwrap().len(), 2);
        let many = "x\n".repeat(MAX_ENTRIES + 1);
        assert!(parse_listing(many.as_bytes(), false).is_err());
        let long = vec![b'a'; MAX_LIST_LINE + 1];
        assert!(parse_listing(&long, false).is_err());
    }
}
