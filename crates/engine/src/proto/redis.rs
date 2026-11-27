//! A Redis client: TLS, `AUTH`, then commands as RESP arrays of bulk strings, so a parameter
//! is always one argument whatever bytes it holds. Replies are read as RESP2 and handed back
//! as JSON.

use base64::Engine as _;
use zeroize::Zeroizing;

use super::io::Io;
use crate::{Error, Result};

/// Deepest nesting of a reply.
const MAX_DEPTH: usize = 16;
/// Longest line of a reply.
const MAX_LINE: usize = 64 * 1024;
/// Most elements of one reply, nested ones included. Each is a [`Reply`] in memory whatever
/// its size on the wire, so the count is bounded apart from the bytes.
pub const MAX_ELEMENTS: usize = 1 << 20;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// A command as RESP: an array of bulk strings.
pub fn encode(words: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(format!("*{}\r\n", words.len()).into_bytes());
    for word in words {
        out.extend_from_slice(format!("${}\r\n", word.len()).as_bytes());
        out.extend_from_slice(word);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// A reply.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// `+...`
    Simple(Vec<u8>),
    /// `-...`
    Error(Vec<u8>),
    /// `:...`
    Integer(i64),
    /// `$...`, or `None` for the null bulk string.
    Bulk(Option<Vec<u8>>),
    /// `*...`, or `None` for the null array.
    Array(Option<Vec<Reply>>),
}

impl Reply {
    /// As JSON of at most `max` bytes: text as strings, bytes that are not UTF-8 as
    /// `{"base64": ...}`, an error as `{"error": ...}`. Written straight into the bytes, so
    /// the node holds no JSON tree beside the reply.
    pub fn json_bytes(&self, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        self.write_json(&mut out, max)?;
        Ok(out)
    }

    fn write_json(&self, out: &mut Vec<u8>, max: usize) -> Result<()> {
        fn text(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
            match std::str::from_utf8(b) {
                Ok(s) => serde_json::to_writer(&mut *out, s).map_err(|_| Error::Encoding),
                Err(_) => {
                    out.extend_from_slice(b"{\"base64\":\"");
                    out.extend_from_slice(
                        base64::engine::general_purpose::STANDARD
                            .encode(b)
                            .as_bytes(),
                    );
                    out.extend_from_slice(b"\"}");
                    Ok(())
                }
            }
        }
        match self {
            Reply::Simple(s) | Reply::Bulk(Some(s)) => text(out, s)?,
            Reply::Error(e) => {
                out.extend_from_slice(b"{\"error\":");
                text(out, e)?;
                out.push(b'}');
            }
            Reply::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
            Reply::Bulk(None) | Reply::Array(None) => out.extend_from_slice(b"null"),
            Reply::Array(Some(items)) => {
                out.push(b'[');
                for (at, item) in items.iter().enumerate() {
                    if at > 0 {
                        out.push(b',');
                    }
                    item.write_json(out, max)?;
                }
                out.push(b']');
            }
        }
        if out.len() > max {
            return Err(Error::transport(
                crate::error::TransportKind::TooLarge,
                true,
            ));
        }
        Ok(())
    }

    /// Every byte of the reply, for the reflection search.
    pub fn raw(&self, out: &mut Vec<u8>) {
        match self {
            Reply::Simple(b) | Reply::Error(b) | Reply::Bulk(Some(b)) => {
                out.extend_from_slice(b);
                out.push(0);
            }
            Reply::Array(Some(items)) => items.iter().for_each(|i| i.raw(out)),
            Reply::Integer(_) | Reply::Bulk(None) | Reply::Array(None) => {}
        }
    }
}

/// A source of reply bytes: lines and runs of bytes.
pub trait Source {
    /// One line ending in CRLF, without it.
    fn line(&mut self) -> Result<Zeroizing<Vec<u8>>>;
    /// `n` bytes and the CRLF after them.
    fn exact(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>>;
}

impl Source for Io<'_> {
    fn line(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut line = Io::line(self, MAX_LINE)?;
        if !line.ends_with(b"\r\n") {
            return Err(invalid("a RESP line not ending in CRLF"));
        }
        let len = line.len() - 2;
        line.truncate(len);
        Ok(line)
    }

    fn exact(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = self.take(n.checked_add(2).ok_or(invalid("length"))?)?;
        if !bytes.ends_with(b"\r\n") {
            return Err(invalid("a bulk string not ending in CRLF"));
        }
        bytes.truncate(n);
        Ok(bytes)
    }
}

/// Reads one reply of at most `max` bytes, counted as they arrive (each line with its CRLF,
/// each bulk string with its CRLF), and of at most [`MAX_ELEMENTS`] elements.
pub fn read(source: &mut dyn Source, max: usize) -> Result<Reply> {
    let mut budget = Budget {
        bytes: max,
        elements: MAX_ELEMENTS,
    };
    read_at(source, 0, &mut budget)
}

/// What a reply may still spend.
struct Budget {
    bytes: usize,
    elements: usize,
}

fn number(bytes: &[u8]) -> Result<i64> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(invalid("a RESP number"))
}

fn spend(left: &mut usize, n: usize) -> Result<()> {
    *left = left.checked_sub(n).ok_or(Error::transport(
        crate::error::TransportKind::TooLarge,
        true,
    ))?;
    Ok(())
}

fn read_at(source: &mut dyn Source, depth: usize, budget: &mut Budget) -> Result<Reply> {
    if depth > MAX_DEPTH {
        return Err(invalid("a RESP reply nested too deep"));
    }
    spend(&mut budget.elements, 1)?;
    let line = source.line()?;
    spend(&mut budget.bytes, line.len().saturating_add(2))?;
    let (kind, rest) = line.split_first().ok_or(invalid("an empty RESP line"))?;
    Ok(match kind {
        b'+' => Reply::Simple(rest.to_vec()),
        b'-' => Reply::Error(rest.to_vec()),
        b':' => Reply::Integer(number(rest)?),
        b'$' => match number(rest)? {
            -1 => Reply::Bulk(None),
            n if n >= 0 => {
                let n = usize::try_from(n).map_err(|_| invalid("length"))?;
                spend(&mut budget.bytes, n.saturating_add(2))?;
                Reply::Bulk(Some(source.exact(n)?.to_vec()))
            }
            _ => return Err(invalid("a negative bulk length")),
        },
        b'*' => match number(rest)? {
            -1 => Reply::Array(None),
            n if n >= 0 => {
                let n = usize::try_from(n).map_err(|_| invalid("length"))?;
                if n > budget.elements {
                    return Err(Error::transport(
                        crate::error::TransportKind::TooLarge,
                        true,
                    ));
                }
                // The header is a claim, not elements: room grows as they arrive, so nested
                // headers cannot reserve memory the bytes never pay for (#112).
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(read_at(source, depth + 1, budget)?);
                }
                Reply::Array(Some(items))
            }
            _ => return Err(invalid("a negative array length")),
        },
        _ => return Err(invalid("a RESP type the node does not read")),
    })
}

/// A signed-in connection.
pub struct Client<'s> {
    io: Io<'s>,
}

impl<'s> Client<'s> {
    /// Signs in with `AUTH [user] password`.
    pub fn connect(mut io: Io<'s>, user: &[u8], password: &[u8]) -> Result<Self> {
        let auth = if user.is_empty() {
            encode(&[b"AUTH", password])
        } else {
            encode(&[b"AUTH", user, password])
        };
        io.write(&auth)?;
        match read(&mut io, MAX_LINE)? {
            Reply::Simple(ok) if ok == b"OK" => Ok(Self { io }),
            _ => Err(Error::AuthRefused {
                rule: "the server refused AUTH",
            }),
        }
    }

    /// The connection.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Runs the command `words` (literal) with `params` after them.
    pub fn command(
        &mut self,
        words: &[u8],
        params: &[Zeroizing<Vec<u8>>],
        max: usize,
    ) -> Result<Reply> {
        let mut all: Vec<&[u8]> = words
            .split(|b| b.is_ascii_whitespace())
            .filter(|w| !w.is_empty())
            .collect();
        all.extend(params.iter().map(|p| p.as_slice()));
        if all.is_empty() {
            return Err(Error::RequestInvalid {
                rule: "an empty Redis command",
            });
        }
        self.io.write(&encode(&all))?;
        read(&mut self.io, max)
    }

    /// Says goodbye and closes.
    pub fn close(&mut self) {
        let _ = self.io.write(&encode(&[b"QUIT"]));
        self.io.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    struct Bytes(Vec<u8>);

    impl Source for Bytes {
        fn line(&mut self) -> Result<Zeroizing<Vec<u8>>> {
            let at = self
                .0
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or(invalid("eof"))?;
            let line: Vec<u8> = self.0.drain(..at + 2).collect();
            Ok(Zeroizing::new(line[..at].to_vec()))
        }
        fn exact(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>> {
            if self.0.len() < n + 2 {
                return Err(invalid("eof"));
            }
            let bytes: Vec<u8> = self.0.drain(..n + 2).collect();
            Ok(Zeroizing::new(bytes[..n].to_vec()))
        }
    }

    #[test]
    fn replies_parse_to_json() {
        let mut s = Bytes(b"*3\r\n$3\r\nfoo\r\n:42\r\n$-1\r\n".to_vec());
        let reply = read(&mut s, 1024).unwrap();
        assert_eq!(json(&reply), serde_json::json!(["foo", 42, null]));
        let mut s = Bytes(b"-ERR wrong\r\n".to_vec());
        assert_eq!(
            json(&read(&mut s, 1024).unwrap()),
            serde_json::json!({"error": "ERR wrong"})
        );
        let mut s = Bytes(b"*2\r\n$2\r\n\xff\xfe\r\n+a\"b\r\n".to_vec());
        assert_eq!(
            json(&read(&mut s, 1024).unwrap()),
            serde_json::json!([{"base64": "//4="}, "a\"b"])
        );
    }

    fn json(reply: &Reply) -> serde_json::Value {
        serde_json::from_slice(&reply.json_bytes(1024).unwrap()).unwrap()
    }

    #[test]
    fn each_element_is_charged_its_line_and_counted() {
        // `:1` is four bytes on the wire, and so four of the budget.
        let ones = |n: usize| format!("*{n}\r\n{}", ":1\r\n".repeat(n)).into_bytes();
        assert!(read(&mut Bytes(ones(10)), 5 + 10 * 4).is_ok());
        assert!(read(&mut Bytes(ones(10)), 5 + 10 * 4 - 1).is_err());
        // Nested arrays share one count of elements: `MAX_ELEMENTS / 1024` arrays of 1024
        // elements, plus the arrays themselves, are too many.
        struct Nested {
            inner: usize,
            at: usize,
        }
        impl Source for Nested {
            fn line(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                let at = self.at;
                self.at += 1;
                let line = if at == 0 {
                    format!("*{}", MAX_ELEMENTS / self.inner)
                } else if (at - 1).is_multiple_of(self.inner + 1) {
                    format!("*{}", self.inner)
                } else {
                    ":1".to_string()
                };
                Ok(Zeroizing::new(line.into_bytes()))
            }
            fn exact(&mut self, _: usize) -> Result<Zeroizing<Vec<u8>>> {
                Err(invalid("no bulk strings here"))
            }
        }
        assert_eq!(
            read(&mut Nested { inner: 1024, at: 0 }, usize::MAX).err(),
            Some(Error::transport(
                crate::error::TransportKind::TooLarge,
                true
            ))
        );
    }

    #[test]
    fn the_json_is_held_to_its_limit() {
        let mut s = Bytes(b"*3\r\n:1\r\n:2\r\n:3\r\n".to_vec());
        let reply = read(&mut s, 1024).unwrap();
        assert_eq!(reply.json_bytes(7).unwrap().as_slice(), b"[1,2,3]");
        assert!(reply.json_bytes(6).is_err());
    }

    #[test]
    fn hostile_replies_are_refused() {
        let deep = "*1\r\n".repeat(40);
        assert!(read(&mut Bytes(deep.into_bytes()), 1024).is_err());
        assert!(read(&mut Bytes(b"$100\r\nshort\r\n".to_vec()), 1024).is_err());
        assert!(read(&mut Bytes(b"$5\r\nhello\r\n".to_vec()), 3).is_err());
        assert!(read(&mut Bytes(b"*-5\r\n".to_vec()), 1024).is_err());
        assert!(read(&mut Bytes(b"%1\r\n".to_vec()), 1024).is_err());
    }

    #[test]
    fn a_parameter_is_one_bulk_string() {
        assert_eq!(
            encode(&[b"GET", b"a b\r\nFLUSHALL"]).as_slice(),
            b"*2\r\n$3\r\nGET\r\n$13\r\na b\r\nFLUSHALL\r\n"
        );
    }
}
