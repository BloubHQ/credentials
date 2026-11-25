//! A node log kept in files: an append-only JSONL file of signed entries ([`FileSink`]) and
//! its latest checkpoint next to it ([`HeadFile`], [`head_path`]). `credentials serve` keeps
//! its log this way, and `credentials host` keeps the log of each enclave node the same way.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use engine::Error as EngineError;
use engine::log::{LogSink, SignedEntry, SignedHead};
use serde::Serialize;

use crate::{Hooks, Sink};

/// Why a log file or a checkpoint could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file operation failed; `context` names the file and what was done.
    #[error("{context}: {source}")]
    Io {
        /// The file, and what was done with it.
        context: String,
        /// The failure.
        source: io::Error,
    },
    /// A line of the log is not a signed entry.
    #[error("{path}: line {line}: {source}")]
    Entry {
        /// The log file.
        path: String,
        /// The line number, from 1.
        line: usize,
        /// Why it is not an entry.
        source: serde_json::Error,
    },
    /// A document could not be encoded as JSON.
    #[error("cannot encode JSON: {0}")]
    Encode(#[source] serde_json::Error),
}

/// An append-only JSONL file of signed entries. `append` returns `Ok` only after the line is
/// written and `sync_data` returned.
pub struct FileSink {
    file: File,
    len: u64,
    /// The last entry in the file (`Some(None)` for an empty file), or `None` when a write
    /// failed and the file could not be cut back, so its end is unknown.
    stored: Option<Option<SignedEntry>>,
}

impl FileSink {
    /// Opens the log at `path` (created when missing) and reads every entry in it. A last
    /// line without its newline is an entry whose write never completed, so never confirmed:
    /// it is cut off.
    pub fn open(path: &Path) -> Result<(Self, Vec<SignedEntry>), Error> {
        let io = |source: io::Error| Error::Io {
            context: path.display().to_string(),
            source,
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io)?;
        let complete = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i.saturating_add(1));
        if complete < bytes.len() {
            eprintln!(
                "warning: {}: cutting an incomplete last line ({} bytes); its entry was never confirmed",
                path.display(),
                bytes.len().saturating_sub(complete)
            );
            file.set_len(complete as u64)
                .and_then(|()| file.sync_data())
                .map_err(io)?;
        }
        let mut entries = Vec::new();
        let lines = bytes.get(..complete).unwrap_or(&[]).split(|b| *b == b'\n');
        for (i, line) in lines.enumerate() {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let entry: SignedEntry =
                serde_json::from_slice(line).map_err(|source| Error::Entry {
                    path: path.display().to_string(),
                    line: i.saturating_add(1),
                    source,
                })?;
            entries.push(entry);
        }
        let sink = Self {
            file,
            len: complete as u64,
            stored: Some(entries.last().cloned()),
        };
        Ok((sink, entries))
    }
}

impl LogSink for FileSink {
    fn append(&mut self, entry: &SignedEntry) -> engine::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(|_| EngineError::LogUnconfirmed)?;
        line.push(b'\n');
        let written = self
            .file
            .seek(SeekFrom::Start(self.len))
            .and_then(|_| self.file.write_all(&line))
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data());
        match written {
            Ok(()) => {
                self.len = self.len.saturating_add(line.len() as u64);
                self.stored = Some(Some(entry.clone()));
                Ok(())
            }
            Err(e) => {
                eprintln!("error: log write failed: {e}");
                // Cut what may have been written, so the file ends with the last confirmed
                // entry again.
                let cut = self
                    .file
                    .set_len(self.len)
                    .and_then(|()| self.file.sync_data());
                if cut.is_err() {
                    self.stored = None;
                }
                Err(EngineError::LogUnconfirmed)
            }
        }
    }
}

impl Sink for FileSink {
    fn confirmed(&self) -> u64 {
        self.len
    }

    fn stored(&mut self) -> Option<Option<SignedEntry>> {
        self.stored.clone()
    }
}

/// Keeps the checkpoint in a file next to the log. A real deployment keeps it where the
/// operator cannot roll it back (TEE sealed storage or a monotonic counter) and restarts with
/// `--anchor`.
pub struct HeadFile(pub PathBuf);

impl Hooks for HeadFile {
    fn checkpoint(&self, head: &SignedHead) {
        if let Err(e) = write_json_atomic(&self.0, head) {
            eprintln!("warning: {e}");
        }
    }
}

/// The path of the checkpoint written next to the log.
pub fn head_path(log: &Path) -> PathBuf {
    let mut path = log.as_os_str().to_owned();
    path.push(".head.json");
    PathBuf::from(path)
}

/// Writes a JSON document (pretty, with a final newline) through a temporary file and a
/// rename, so a reader never sees half of it.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut text = serde_json::to_string_pretty(value).map_err(Error::Encode)?;
    text.push('\n');
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut file = File::create(&tmp).map_err(|source| Error::Io {
        context: format!("cannot create {}", tmp.display()),
        source,
    })?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| Error::Io {
            context: format!("cannot write {}", tmp.display()),
            source,
        })?;
    drop(file);
    fs::rename(&tmp, path).map_err(|source| Error::Io {
        context: format!("cannot replace {}", path.display()),
        source,
    })
}
