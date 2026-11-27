//! SFTP version 3 (draft-ietf-secsh-filexfer-02, the version OpenSSH speaks) on an SSH
//! session channel: reading and writing whole files, listing a directory, the status of a
//! path, renaming, deleting a file, making and removing a directory, at paths the policy
//! fixes or shapes.
//!
//! A path is checked twice. Before anything is sent, [`normalize`] refuses what could leave the
//! pattern the policy matched: a relative path, an empty, `.` or `..` segment, a backslash, a
//! NUL. On the server, the node follows no symbolic link: it asks for the canonical form of
//! the path (`SSH_FXP_REALPATH`, which resolves links), or of its directory for a file a write
//! may create, and refuses the path unless that form is the path itself; the file must then be
//! a regular file, or absent for a write. What remains is a race on the server between that
//! check and the open: whoever can replace a directory or the file with a link in between
//! (the server, or another account on it) can redirect the open. The check holds against a
//! link planted beforehand, which is how a caller could reach a file outside the pattern.
//!
//! The other operations hold to the same rule: a listing, a status or `rmdir` asks that the
//! path itself resolves to itself; `rename`, `delete` and `mkdir` that the directories they
//! change resolve to themselves, and act on the entry itself (`LSTAT`): a file for `delete`,
//! a file or a directory for `rename`, nothing yet at a new name. A listing holds at most
//! [`MAX_ENTRIES`] entries.

use std::time::Duration;

use zeroize::Zeroizing;

use super::ssh::{Client, Event};
use super::wire::{Parse, Put};
use crate::readbuf::ReadBuf;
use crate::{Error, Result};

/// Longest SFTP packet accepted, in bytes.
const MAX_PACKET: usize = 256 * 1024;
/// Bytes asked for by one read and written by one write.
const CHUNK: usize = 32 * 1024;
/// Longest path, in bytes.
pub const MAX_PATH: usize = 4096;
/// Longest wait for one read.
const WAIT: Duration = Duration::from_millis(50);

const INIT: u8 = 1;
const VERSION: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const LSTAT: u8 = 7;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const REALPATH: u8 = 16;
const RENAME: u8 = 18;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;
const ATTRS: u8 = 105;

const FX_OK: u32 = 0;
const FX_EOF: u32 = 1;
const FX_NO_SUCH_FILE: u32 = 2;

const READ_FLAG: u32 = 0x01;
const WRITE_FLAG: u32 = 0x02;
const CREAT: u32 = 0x08;
const TRUNC: u32 = 0x10;

const ATTR_SIZE: u32 = 0x01;
const ATTR_UIDGID: u32 = 0x02;
const ATTR_PERMISSIONS: u32 = 0x04;
const ATTR_ACMODTIME: u32 = 0x08;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// Most entries of a listing.
pub const MAX_ENTRIES: usize = 10_000;
/// Longest name in a listing, in bytes.
const MAX_NAME: usize = 4096;

/// What `LSTAT` (or a listing) tells of a file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    /// Its size.
    pub size: Option<u64>,
    /// Its permission and type bits.
    pub mode: Option<u32>,
    /// Its modification time (seconds since 1970).
    pub mtime: Option<u32>,
}

impl Attrs {
    /// Reads the attributes of draft-ietf-secsh-filexfer-02 section 5.
    fn parse(p: &mut Parse<'_>) -> Result<Self> {
        let flags = p.u32()?;
        let mut out = Attrs::default();
        if flags & ATTR_SIZE != 0 {
            out.size = Some(p.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            p.u32()?;
            p.u32()?;
        }
        if flags & ATTR_PERMISSIONS != 0 {
            out.mode = Some(p.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            p.u32()?;
            out.mtime = Some(p.u32()?);
        }
        if flags & ATTR_EXTENDED != 0 {
            let n = p.u32()?;
            if n > 64 {
                return Err(invalid("more than 64 extended SFTP attributes"));
            }
            for _ in 0..n {
                p.string()?;
                p.string()?;
            }
        }
        Ok(out)
    }

    /// The file type bits, when the server gave the mode.
    pub fn kind(&self) -> Option<u32> {
        self.mode.map(|m| m & S_IFMT)
    }

    /// The type as a word: `file`, `dir`, `link` or `other`.
    pub fn kind_name(&self) -> &'static str {
        match self.kind() {
            Some(S_IFREG) => "file",
            Some(S_IFDIR) => "dir",
            Some(S_IFLNK) => "link",
            _ => "other",
        }
    }

    /// The attributes as JSON members.
    pub fn json(&self, out: &mut serde_json::Map<String, serde_json::Value>) {
        out.insert("type".into(), self.kind_name().into());
        if let Some(size) = self.size {
            out.insert("size".into(), size.into());
        }
        if let Some(mode) = self.mode {
            out.insert("mode".into(), format!("{:o}", mode & 0o7777).into());
        }
        if let Some(mtime) = self.mtime {
            out.insert("mtime".into(), mtime.into());
        }
    }
}

/// One entry of a listing: its name (no `/`, never `.` or `..`) and attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The name, as the server sent it.
    pub name: Vec<u8>,
    /// What the server said of it, without following a link.
    pub attrs: Attrs,
}

impl Entry {
    /// The entry as JSON: the name as text, or `name_base64` when it is not UTF-8.
    pub fn json(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        match core::str::from_utf8(&self.name) {
            Ok(name) => {
                out.insert("name".into(), name.into());
            }
            Err(_) => {
                use base64::Engine as _;
                out.insert(
                    "name_base64".into(),
                    base64::engine::general_purpose::STANDARD
                        .encode(&self.name)
                        .into(),
                );
            }
        }
        self.attrs.json(&mut out);
        serde_json::Value::Object(out)
    }
}

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

fn refused(rule: &'static str) -> Error {
    Error::RequestInvalid { rule }
}

/// Checks that `path` names one file without leaving the place its text says: absolute, at
/// most 4096 bytes, no empty, `.` or `..` segment, no trailing `/`, no backslash, no NUL.
pub fn normalize(path: &[u8]) -> Result<()> {
    let bad = || refused("an SFTP path: absolute, no empty, . or .. segment, no \\ or NUL");
    if path.len() > MAX_PATH || path.contains(&0) || path.contains(&b'\\') {
        return Err(bad());
    }
    let rest = path.strip_prefix(b"/").ok_or_else(bad)?;
    if rest
        .split(|b| *b == b'/')
        .any(|segment| matches!(segment, b"" | b"." | b".."))
    {
        return Err(bad());
    }
    Ok(())
}

/// [`normalize`], or the root `/` itself where `root` allows it (a listing, a status).
pub fn normalize_or_root(path: &[u8], root: bool) -> Result<()> {
    if root && path == b"/" {
        Ok(())
    } else {
        normalize(path)
    }
}

/// The directory of a normalized path (`/` for a file at the root).
fn parent(path: &[u8]) -> &[u8] {
    match memchr::memrchr(b'/', path) {
        Some(0) | None => b"/",
        Some(at) => path.get(..at).unwrap_or(b"/"),
    }
}

/// Takes the first whole packet out of `buf`: its type and the bytes after it.
fn split(buf: &mut ReadBuf) -> Result<Option<(u8, Zeroizing<Vec<u8>>)>> {
    let pending = buf.pending();
    let Some(head) = pending.get(..4) else {
        return Ok(None);
    };
    let len = usize::try_from(Parse::new(head).u32()?).map_err(|_| invalid("len"))?;
    if !(1..=MAX_PACKET).contains(&len) {
        return Err(invalid("an SFTP packet length out of bounds"));
    }
    if pending.len() < 4 + len {
        return Ok(None);
    }
    let kind = pending.get(4).copied().unwrap_or(0);
    buf.skip(5);
    Ok(Some((kind, buf.take(len - 1))))
}

/// An SFTP session on its own channel.
pub struct Sftp<'c, 's> {
    ssh: &'c mut Client<'s>,
    buf: ReadBuf,
    next_id: u32,
}

impl<'c, 's> Sftp<'c, 's> {
    /// Starts the `sftp` subsystem and agrees on version 3.
    pub fn start(ssh: &'c mut Client<'s>) -> Result<Self> {
        ssh.subsystem(b"sftp")?;
        let mut sftp = Sftp {
            ssh,
            buf: ReadBuf::new(),
            next_id: 1,
        };
        let mut init = Put::new();
        init.u8(INIT).u32(3);
        sftp.send(init.bytes())?;
        let (kind, body) = sftp.packet()?;
        let mut p = Parse::new(&body);
        if kind != VERSION || p.u32()? != 3 {
            return Err(invalid("the server speaks no SFTP version 3"));
        }
        Ok(sftp)
    }

    fn send(&mut self, payload: &[u8]) -> Result<()> {
        let mut out = Put::new();
        out.string(payload);
        self.ssh.write_data(out.bytes())
    }

    /// The next packet: its type and the bytes after it.
    fn packet(&mut self) -> Result<(u8, Zeroizing<Vec<u8>>)> {
        loop {
            if let Some(packet) = split(&mut self.buf)? {
                return Ok(packet);
            }
            match self.ssh.poll_event(WAIT)? {
                Some(Event::Data(data)) => self.buf.push(&data),
                Some(Event::Stderr(_) | Event::Exit(_) | Event::Forwarded { .. }) | None => {}
                Some(Event::Closed) => {
                    return Err(Error::transport(crate::error::TransportKind::Closed, true));
                }
            }
        }
    }

    /// Sends a request of `kind` with `body` and returns the answer to it.
    fn request(&mut self, kind: u8, body: &[u8]) -> Result<(u8, Zeroizing<Vec<u8>>)> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut out = Put::new();
        out.u8(kind).u32(id).raw(body);
        self.send(out.bytes())?;
        let (answer, rest) = self.packet()?;
        let mut p = Parse::new(&rest);
        if p.u32()? != id {
            return Err(invalid("an SFTP answer to another request"));
        }
        Ok((answer, Zeroizing::new(p.rest().to_vec())))
    }

    fn status(body: &[u8]) -> Result<u32> {
        Parse::new(body).u32()
    }

    fn expect_ok(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        match self.request(kind, body)? {
            (STATUS, s) if Self::status(&s)? == FX_OK => Ok(()),
            (STATUS, _) => Err(refused("the SFTP server refused the request")),
            _ => Err(invalid("an unexpected SFTP answer")),
        }
    }

    /// The server's canonical form of `path`.
    fn realpath(&mut self, path: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut body = Put::new();
        body.string(path);
        match self.request(REALPATH, body.bytes())? {
            (NAME, rest) => {
                let mut p = Parse::new(&rest);
                if p.u32()? != 1 {
                    return Err(invalid("REALPATH answered with another number of names"));
                }
                Ok(Some(Zeroizing::new(p.string()?.to_vec())))
            }
            (STATUS, _) => Ok(None),
            _ => Err(invalid("an unexpected answer to REALPATH")),
        }
    }

    /// Refuses `path` unless the server's canonical form of it is itself: no link on the way.
    fn no_link(&mut self, path: &[u8]) -> Result<()> {
        match self.realpath(path)? {
            Some(real) if real.as_slice() == path => Ok(()),
            Some(_) => Err(refused(
                "the SFTP path resolves elsewhere: a symbolic link, which the node does not follow",
            )),
            None => Err(refused("the SFTP path does not exist")),
        }
    }

    /// The attributes of the file at `path` without following a link; `None` when absent.
    fn lstat_attrs(&mut self, path: &[u8]) -> Result<Option<Attrs>> {
        let mut body = Put::new();
        body.string(path);
        match self.request(LSTAT, body.bytes())? {
            (ATTRS, rest) => {
                let attrs = Attrs::parse(&mut Parse::new(&rest))?;
                if attrs.mode.is_none() {
                    return Err(invalid("LSTAT gave no file type"));
                }
                Ok(Some(attrs))
            }
            (STATUS, s) if Self::status(&s)? == FX_NO_SUCH_FILE => Ok(None),
            (STATUS, _) => Err(refused("the SFTP server refused LSTAT")),
            _ => Err(invalid("an unexpected answer to LSTAT")),
        }
    }

    /// The type bits of the file at `path` without following a link; `None` when absent.
    fn lstat(&mut self, path: &[u8]) -> Result<Option<u32>> {
        Ok(self.lstat_attrs(path)?.and_then(|a| a.kind()))
    }

    /// The status of `path` (`/` allowed), which must resolve to itself.
    pub fn stat(&mut self, path: &[u8]) -> Result<Attrs> {
        normalize_or_root(path, true)?;
        self.no_link(path)?;
        self.lstat_attrs(path)?
            .ok_or_else(|| refused("the SFTP path does not exist"))
    }

    /// Lists the directory at `path` (`/` allowed), which must resolve to itself: at most
    /// [`MAX_ENTRIES`] entries, without `.` and `..`.
    pub fn list(&mut self, path: &[u8]) -> Result<Vec<Entry>> {
        normalize_or_root(path, true)?;
        self.no_link(path)?;
        if self.lstat(path)? != Some(S_IFDIR) {
            return Err(refused("the SFTP path is not a directory"));
        }
        let mut body = Put::new();
        body.string(path);
        let handle = match self.request(OPENDIR, body.bytes())? {
            (HANDLE, rest) => {
                let handle = Parse::new(&rest).string()?.to_vec();
                if handle.len() > 256 {
                    return Err(invalid("an SFTP handle longer than 256 bytes"));
                }
                Zeroizing::new(handle)
            }
            (STATUS, _) => return Err(refused("the SFTP server refused to open the directory")),
            _ => return Err(invalid("an unexpected answer to OPENDIR")),
        };
        let mut entries = Vec::new();
        loop {
            let mut body = Put::new();
            body.string(&handle);
            match self.request(READDIR, body.bytes())? {
                (NAME, rest) => {
                    let mut p = Parse::new(&rest);
                    let count = p.u32()?;
                    if count == 0 {
                        return Err(invalid("an SFTP listing of no names"));
                    }
                    for _ in 0..count {
                        let name = p.string()?.to_vec();
                        p.string()?;
                        let attrs = Attrs::parse(&mut p)?;
                        if name.is_empty()
                            || name.len() > MAX_NAME
                            || name.contains(&b'/')
                            || name.contains(&0)
                        {
                            return Err(invalid("an SFTP listing name with / or NUL"));
                        }
                        if name == b"." || name == b".." {
                            continue;
                        }
                        if entries.len() >= MAX_ENTRIES {
                            let _ = self.close_handle(&handle);
                            return Err(invalid("an SFTP listing of too many entries"));
                        }
                        entries.push(Entry { name, attrs });
                    }
                }
                (STATUS, s) if Self::status(&s)? == FX_EOF => break,
                (STATUS, _) => return Err(refused("the SFTP server refused a listing")),
                _ => return Err(invalid("an unexpected answer to READDIR")),
            }
        }
        self.close_handle(&handle)?;
        Ok(entries)
    }

    /// Renames the file or directory `from` to `to`, where nothing is yet; the directories
    /// of both must resolve to themselves.
    pub fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<()> {
        normalize(from)?;
        normalize(to)?;
        self.no_link(parent(from))?;
        self.no_link(parent(to))?;
        match self.lstat(from)? {
            Some(S_IFREG | S_IFDIR) => {}
            _ => return Err(refused("the SFTP path is not a file or a directory")),
        }
        if self.lstat(to)?.is_some() {
            return Err(refused("the SFTP path to rename to exists"));
        }
        let mut body = Put::new();
        body.string(from).string(to);
        self.expect_ok(RENAME, body.bytes())
    }

    /// Deletes the regular file at `path`, whose directory must resolve to itself.
    pub fn delete(&mut self, path: &[u8]) -> Result<()> {
        normalize(path)?;
        self.no_link(parent(path))?;
        if self.lstat(path)? != Some(S_IFREG) {
            return Err(refused("the SFTP path is not a regular file"));
        }
        let mut body = Put::new();
        body.string(path);
        self.expect_ok(REMOVE, body.bytes())
    }

    /// Makes the directory `path`, where nothing is yet; its parent must resolve to itself.
    pub fn mkdir(&mut self, path: &[u8]) -> Result<()> {
        normalize(path)?;
        self.no_link(parent(path))?;
        if self.lstat(path)?.is_some() {
            return Err(refused("the SFTP path exists"));
        }
        let mut body = Put::new();
        body.string(path).u32(0);
        self.expect_ok(MKDIR, body.bytes())
    }

    /// Removes the empty directory `path`, which must resolve to itself.
    pub fn rmdir(&mut self, path: &[u8]) -> Result<()> {
        normalize(path)?;
        self.no_link(path)?;
        if self.lstat(path)? != Some(S_IFDIR) {
            return Err(refused("the SFTP path is not a directory"));
        }
        let mut body = Put::new();
        body.string(path);
        self.expect_ok(RMDIR, body.bytes())
    }

    fn open(&mut self, path: &[u8], flags: u32) -> Result<Zeroizing<Vec<u8>>> {
        let mut body = Put::new();
        body.string(path).u32(flags).u32(0);
        match self.request(OPEN, body.bytes())? {
            (HANDLE, rest) => {
                let mut p = Parse::new(&rest);
                let handle = p.string()?;
                if handle.len() > 256 {
                    return Err(invalid("an SFTP handle longer than 256 bytes"));
                }
                Ok(Zeroizing::new(handle.to_vec()))
            }
            (STATUS, _) => Err(refused("the SFTP server refused to open the file")),
            _ => Err(invalid("an unexpected answer to OPEN")),
        }
    }

    fn close_handle(&mut self, handle: &[u8]) -> Result<()> {
        let mut body = Put::new();
        body.string(handle);
        self.expect_ok(CLOSE, body.bytes())
    }

    /// Reads the regular file at `path`, at most `max` bytes.
    pub fn read_file(&mut self, path: &[u8], max: usize) -> Result<Zeroizing<Vec<u8>>> {
        normalize(path)?;
        self.no_link(path)?;
        if self.lstat(path)? != Some(S_IFREG) {
            return Err(refused("the SFTP path is not a regular file"));
        }
        let handle = self.open(path, READ_FLAG)?;
        let mut out = Zeroizing::new(Vec::new());
        loop {
            let mut body = Put::new();
            body.string(&handle);
            body.raw(&(out.len() as u64).to_be_bytes());
            body.u32(CHUNK as u32);
            match self.request(READ, body.bytes())? {
                (DATA, rest) => {
                    let mut p = Parse::new(&rest);
                    let data = p.string()?;
                    if data.is_empty() || data.len() > CHUNK {
                        return Err(invalid("an SFTP read of another size than asked"));
                    }
                    if out.len().saturating_add(data.len()) > max {
                        let _ = self.close_handle(&handle);
                        return Err(Error::transport(
                            crate::error::TransportKind::TooLarge,
                            true,
                        ));
                    }
                    out.extend_from_slice(data);
                }
                (STATUS, s) if Self::status(&s)? == FX_EOF => break,
                (STATUS, _) => return Err(refused("the SFTP server refused a read")),
                _ => return Err(invalid("an unexpected answer to READ")),
            }
        }
        self.close_handle(&handle)?;
        Ok(out)
    }

    /// Writes `data` as the whole file at `path`, creating it or truncating a regular file.
    pub fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<()> {
        normalize(path)?;
        self.no_link(parent(path))?;
        match self.lstat(path)? {
            None | Some(S_IFREG) => {}
            Some(_) => {
                return Err(refused(
                    "the SFTP path is a link or not a regular file, which the node does not write",
                ));
            }
        }
        let handle = self.open(path, WRITE_FLAG | CREAT | TRUNC)?;
        for (i, chunk) in data.chunks(CHUNK).enumerate() {
            let mut body = Put::new();
            body.string(&handle);
            body.raw(&((i * CHUNK) as u64).to_be_bytes());
            body.string(chunk);
            self.expect_ok(WRITE, body.bytes())?;
        }
        self.close_handle(&handle)
    }

    /// Ends the session: closes its channel.
    pub fn finish(self) -> Result<()> {
        self.ssh.close_channel()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn packets_are_split_in_linear_time() {
        // 64 KiB of the smallest packets (10 bytes), arriving 16 KiB at a time and split
        // across reads: each byte is copied a bounded number of times (#46).
        let unit = [0u8, 0, 0, 6, 101, 1, 2, 3, 4, 5];
        let wire: Vec<u8> = unit
            .iter()
            .copied()
            .cycle()
            .take(64 * 1024 / 10 * 10)
            .collect();
        let mut buf = ReadBuf::new();
        let mut packets = 0;
        for chunk in wire.chunks(16 * 1024) {
            buf.push(chunk);
            while let Some((kind, body)) = split(&mut buf).unwrap() {
                assert_eq!((kind, body.as_slice()), (101, &[1u8, 2, 3, 4, 5][..]));
                packets += 1;
            }
        }
        assert_eq!(packets, wire.len() / 10);
        assert!(buf.pending().is_empty());
        assert!(buf.copied < 2 * wire.len() as u64, "copied {}", buf.copied);
        // A length out of bounds is refused before the packet arrives.
        let mut bad = ReadBuf::new();
        bad.push(&[0, 0, 0, 0]);
        assert!(split(&mut bad).is_err());
    }

    #[test]
    fn traversal_is_refused_before_anything_is_sent() {
        assert!(normalize(b"/srv/reports/a.csv").is_ok());
        for bad in [
            &b"srv/a"[..],
            b"/srv/../etc/passwd",
            b"/srv/./a",
            b"/srv//a",
            b"/srv/a/",
            b"/srv/a\\..\\b",
            b"/srv/a\0b",
            b"/..",
            b"/",
        ] {
            assert!(normalize(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert_eq!(parent(b"/srv/a.csv"), b"/srv");
        assert_eq!(parent(b"/a.csv"), b"/");
    }
}
