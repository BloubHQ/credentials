//! A node log kept in files: an append-only JSONL file of signed entries ([`FileSink`]) and
//! its latest checkpoint next to it ([`HeadFile`], [`head_path`]). `credentials serve` keeps
//! its log this way, and `credentials host` keeps the log of each enclave node the same way.
//!
//! One writer per log: a [`FileSink`] holds an exclusive lock on its file while it lives
//! (`flock` on Unix; on Windows the file is opened sharing reads only), so a second
//! `credentials serve` on the same `--log` fails at start instead of writing over the first
//! one's confirmed entries. A reader (`credentials verify`) can still read the file. On Unix
//! the lock is advisory (it stops only processes that take it), and on a network filesystem
//! its behaviour depends on the server and client: a log belongs on a local filesystem.
//!
//! Durability: every entry is `sync_data`'d before `append` returns. On Unix the directory is
//! synced as well after the log file is created and after a checkpoint is renamed into place,
//! so a power loss cannot lose the new file or the new name. Windows has no directory sync;
//! there a new log file and a renamed checkpoint are as durable as the filesystem makes a
//! rename (NTFS journals it).

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
    /// Another process holds the log: two nodes would write over each other's entries.
    #[error("{path}: the log is in use by another process (another `credentials serve` on it?)")]
    InUse {
        /// The log file.
        path: String,
    },
}

/// True for the error of a lock or an open that another holder of the file refused.
fn held_elsewhere(e: &io::Error) -> bool {
    // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION on Windows.
    let windows_sharing = cfg!(windows) && matches!(e.raw_os_error(), Some(32 | 33));
    e.kind() == io::ErrorKind::WouldBlock || windows_sharing
}

/// Opens the log file for reading and writing, created when missing, and takes the one
/// writer's lock on it.
fn open_exclusive(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_SHARE_READ: readers may open it, no other writer may.
        options.share_mode(0x0000_0001);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(io::Error::from)?;
    Ok(file)
}

/// Syncs the directory that holds `path`, so a file created or renamed in it keeps its name
/// across a power loss. Nothing to do on Windows, which has no directory sync.
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
        let existed = path.exists();
        let mut file = open_exclusive(path).map_err(|e| {
            if held_elsewhere(&e) {
                Error::InUse {
                    path: path.display().to_string(),
                }
            } else {
                io(e)
            }
        })?;
        if !existed {
            sync_parent(path).map_err(io)?;
        }
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
    })?;
    sync_parent(path).map_err(|source| Error::Io {
        context: format!("cannot sync the directory of {}", path.display()),
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A new, empty directory of its own under the system temp directory.
    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "credentials-logfile-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_second_sink_on_the_same_log_is_refused_while_the_first_lives() {
        let dir = scratch("lock");
        let log = dir.join("node.log");
        let (first, entries) = FileSink::open(&log).unwrap();
        assert!(entries.is_empty());
        match FileSink::open(&log) {
            Err(Error::InUse { path }) => assert_eq!(path, log.display().to_string()),
            Err(other) => panic!("expected InUse, got {other}"),
            Ok(_) => panic!("a second writer opened a log in use"),
        }
        // A reader still can: `credentials verify` reads the live file.
        assert!(fs::read(&log).is_ok());
        drop(first);
        assert!(FileSink::open(&log).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_checkpoint_written_atomically_replaces_the_old_one() {
        let dir = scratch("head");
        let head = dir.join("node.head");
        write_json_atomic(&head, &serde_json::json!({"size": 1})).unwrap();
        write_json_atomic(&head, &serde_json::json!({"size": 2})).unwrap();
        let text = fs::read_to_string(&head).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value, serde_json::json!({"size": 2}));
        assert!(!dir.join("node.head.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
