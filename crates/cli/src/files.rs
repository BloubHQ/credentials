//! Files: keys as base64url text, JSON documents, and secret values read from files or the
//! environment.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// Exit codes of the tool (`credentials verify` keeps its own 0, 1, 2).
pub mod exit {
    /// Any other failure: an invalid document, a value the engine refuses.
    pub const OTHER: u8 = 1;
    /// The command line is wrong (clap uses the same code).
    pub const USAGE: u8 = 2;
    /// The node refused the request (HTTP 400, 403 or 404).
    pub const REFUSED: u8 = 3;
    /// The node rate limited the request (HTTP 429).
    pub const RATE_LIMITED: u8 = 4;
    /// Connection, transport, log or file I/O failure.
    pub const IO: u8 = 5;
}

/// Why a command failed: a message for the user and the exit code.
#[derive(Debug)]
pub struct Failure {
    /// The exit code, one of [`exit`].
    pub code: u8,
    /// The message.
    pub message: String,
}

impl Failure {
    /// A failure with this exit code.
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// A usage error.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, message)
    }

    /// A connection, transport, log or file I/O failure.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(exit::IO, message)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::new(exit::OTHER, message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self::new(exit::OTHER, message)
    }
}

/// The result type of the tool: errors are messages for the user, with an exit code.
pub type Res<T> = Result<T, Failure>;

/// Reads a whole file into a buffer that is erased when dropped.
pub fn read_secret_file(path: &Path) -> Res<Zeroizing<Vec<u8>>> {
    let mut file = File::open(path)
        .map_err(|e| Failure::io(format!("cannot open {}: {e}", path.display())))?;
    // Sized up front so the buffer is not reallocated (and copied) while it grows.
    let len = file
        .metadata()
        .map(|m| usize::try_from(m.len()).unwrap_or(0))
        .unwrap_or(0);
    let mut out = Zeroizing::new(Vec::with_capacity(len.saturating_add(1)));
    file.read_to_end(&mut out)
        .map_err(|e| Failure::io(format!("cannot read {}: {e}", path.display())))?;
    Ok(out)
}

/// Reads a 32-byte key written as base64url text.
pub fn read_key32(path: &Path) -> Res<Zeroizing<[u8; 32]>> {
    let bad = || {
        format!(
            "{} does not hold a key (32 bytes as base64url)",
            path.display()
        )
    };
    let text = read_secret_file(path)?;
    warn_if_shared(path);
    let text = std::str::from_utf8(&text).map_err(|_| Failure::from(bad()))?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    let written = URL_SAFE_NO_PAD
        .decode_slice(text.trim(), bytes.as_mut_slice())
        .map_err(|_| Failure::from(bad()))?;
    if written != 32 {
        return Err(bad().into());
    }
    Ok(bytes)
}

/// Warns on stderr when a key file can be read by the group or by other users (Unix only;
/// on Windows the file has the access list of its directory, see the README of the CLI).
#[cfg(unix)]
fn warn_if_shared(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {} can be read by other users (mode {mode:03o}); run `chmod 600 {}`",
                path.display(),
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_shared(_path: &Path) {}

/// A 32-byte key as base64url text with a final newline, in an erased buffer.
pub fn key_text(bytes: &[u8; 32]) -> Zeroizing<String> {
    // Straight into a buffer of its own, which is erased: `encode_string` goes through a
    // 1 KiB buffer on the stack that keeps the text after it returns.
    let mut raw = Zeroizing::new([0u8; 43]);
    let written = URL_SAFE_NO_PAD
        .encode_slice(bytes, raw.as_mut_slice())
        .unwrap_or(0);
    let mut text = Zeroizing::new(String::with_capacity(44));
    text.push_str(std::str::from_utf8(raw.get(..written).unwrap_or_default()).unwrap_or_default());
    text.push('\n');
    text
}

/// Writes a new secret file. It must not exist yet; on Unix only the owner can read it. On
/// Windows the file inherits the access list of its directory (see the README of the CLI).
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Res<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        Failure::io(format!(
            "cannot create {} (a key file is never overwritten): {e}",
            path.display()
        ))
    })?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|e| Failure::io(format!("cannot write {}: {e}", path.display())))
}

/// Reads a JSON document.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Res<T> {
    from_json_value(path, read_json_value(path)?)
}

/// A JSON value of the document at `path` as `T`. An error names where in the document it is
/// (`operations[0].steps[0]: missing field ...`), in the path style of the semantic checks.
pub fn from_json_value<T: DeserializeOwned>(path: &Path, value: serde_json::Value) -> Res<T> {
    serde_path_to_error::deserialize(value).map_err(|e| {
        let at = e.path().to_string();
        let inner = e.into_inner();
        if at == "." {
            Failure::from(format!("{}: {inner}", path.display()))
        } else {
            Failure::from(format!("{}: {at}: {inner}", path.display()))
        }
    })
}

/// Reads a JSON document as a value.
pub fn read_json_value(path: &Path) -> Res<serde_json::Value> {
    let text =
        fs::read(path).map_err(|e| Failure::io(format!("cannot read {}: {e}", path.display())))?;
    serde_json::from_slice(json_text(path, &text)?)
        .map_err(|e| Failure::from(format!("{}: {e}", path.display())))
}

/// The UTF-8 text of a document read from `path`, without a UTF-8 byte order mark (as
/// `Set-Content -Encoding utf8` writes it on Windows). UTF-16, which `>` writes in Windows
/// PowerShell 5.1, is refused with what to do instead.
pub fn json_text<'a>(path: &Path, bytes: &'a [u8]) -> Res<&'a [u8]> {
    let utf16 = bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0xFE, 0xFF])
        || matches!(bytes, [a, 0, ..] | [0, a, ..] if *a != 0);
    if utf16 {
        return Err(Failure::from(format!(
            "{}: the file is UTF-16 (what `>` writes in Windows PowerShell); write it with \
             `--out <file>` instead, or save it as UTF-8",
            path.display()
        )));
    }
    Ok(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes))
}

/// A value as pretty JSON with a final newline.
pub fn to_json<T: Serialize>(value: &T) -> Res<String> {
    let mut text =
        serde_json::to_string_pretty(value).map_err(|e| format!("cannot encode JSON: {e}"))?;
    text.push('\n');
    Ok(text)
}

/// Writes a JSON document, replacing the file.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Res<()> {
    fs::write(path, to_json(value)?)
        .map_err(|e| Failure::io(format!("cannot write {}: {e}", path.display())))
}

/// A secret value: `@path` (the bytes of the file, as they are) or `env:VAR` (the value of an
/// environment variable). Never a literal, so secrets stay out of shell history.
pub fn secret_value(spec: &str) -> Res<Zeroizing<Vec<u8>>> {
    if let Some(path) = spec.strip_prefix('@') {
        return read_secret_file(Path::new(path));
    }
    if let Some(name) = spec.strip_prefix("env:") {
        let value = std::env::var_os(name)
            .ok_or_else(|| Failure::usage(format!("environment variable {name} is not set")))?;
        return Ok(Zeroizing::new(value.into_encoded_bytes()));
    }
    Err(Failure::usage(format!(
        "a secret value is @path or env:VAR, never literal text (got a value starting {:?})",
        spec.chars().next().unwrap_or(' ')
    )))
}

/// A value that is not a secret of the owner: `@path`, `env:VAR`, or the literal text.
pub fn data_value(spec: &str) -> Res<Vec<u8>> {
    if spec.starts_with('@') || spec.starts_with("env:") {
        return secret_value(spec).map(|v| v.to_vec());
    }
    Ok(spec.as_bytes().to_vec())
}
