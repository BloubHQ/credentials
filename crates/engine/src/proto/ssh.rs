//! A minimal synchronous SSH client (RFC 4253 transport, RFC 4252 authentication, RFC 4254
//! session channels), written for the node: modern algorithms only, the server's host key
//! pinned by the policy, the client key held as an item field and used only here.
//!
//! | Part | Accepted |
//! | --- | --- |
//! | Key exchange | `curve25519-sha256` (and its `@libssh.org` name), `ecdh-sha2-nistp256`, `-nistp384`, `-nistp521`; strict key exchange (`kex-strict-*-v00@openssh.com`) whenever the server offers it |
//! | Host key | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-512`, `rsa-sha2-256`: only the types of the pinned keys are offered, and the key must equal a pinned one |
//! | Cipher | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `chacha20-poly1305@openssh.com` (the last only with strict key exchange: Terrapin) |
//! | MAC | none: every cipher is an AEAD |
//! | Compression | `none` |
//! | Authentication | `password`, `publickey` (Ed25519, ECDSA P-256/P-384, RSA with SHA-2), `keyboard-interactive` with answers matched to prompts |
//!
//! SHA-1 (`diffie-hellman-group*-sha1`, `ssh-rsa` signatures, `hmac-sha1`) and CBC are never
//! offered, so a server that offers only them is refused before anything secret is sent. A
//! key re-exchange the server starts (RFC 4253, 9: servers rekey after a volume or a time) is
//! carried out: the server must prove the same host key as in the first exchange, the
//! session identifier stays the first exchange hash, and strict key exchange, when it was
//! agreed, resets the sequence numbers again. At most [`MAX_REKEYS`] per connection.
//!
//! A channel the server opens is refused (`SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`), unless it
//! is the `forwarded-tcpip` channel of the one remote forward the node asked for
//! ([`Client::tcpip_forward`]), for exactly the address and port it asked for, while no other
//! channel is open: then the caller of the client decides ([`Event::Forwarded`]). More than
//! [`MAX_REFUSED_OPENS`] refused opens end the connection.

use std::collections::VecDeque;
use std::time::Duration;

use ring::rand::SystemRandom;
use ring::signature::{self as rsig, KeyPair as _};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use super::io::Io;
use super::wire::{Parse, Put};
use crate::error::TransportKind;
use crate::{Error, Result};

/// The identification string of the node.
const VERSION: &[u8] = b"SSH-2.0-credentials\r\n";

/// Key exchange methods, in order of preference.
const KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
];
const STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
/// Ciphers, in order of preference. AES-GCM first: ChaCha20-Poly1305 is taken only when the
/// server has no AES-GCM, and then only with strict key exchange.
const CIPHERS: &[&str] = &[
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
];
/// Named so that servers that insist on a common MAC agree; never used, as every cipher of
/// [`CIPHERS`] is an AEAD.
const MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
];

// Message numbers (RFC 4250, 4.1.2).
const DISCONNECT: u8 = 1;
const IGNORE: u8 = 2;
const UNIMPLEMENTED: u8 = 3;
const DEBUG: u8 = 4;
const SERVICE_REQUEST: u8 = 5;
const SERVICE_ACCEPT: u8 = 6;
const EXT_INFO: u8 = 7;
const KEXINIT: u8 = 20;
const NEWKEYS: u8 = 21;
const KEX_ECDH_INIT: u8 = 30;
const KEX_ECDH_REPLY: u8 = 31;
const USERAUTH_REQUEST: u8 = 50;
const USERAUTH_FAILURE: u8 = 51;
const USERAUTH_SUCCESS: u8 = 52;
const USERAUTH_BANNER: u8 = 53;
const USERAUTH_INFO_REQUEST: u8 = 60;
const USERAUTH_INFO_RESPONSE: u8 = 61;
const GLOBAL_REQUEST: u8 = 80;
const REQUEST_SUCCESS: u8 = 81;
const REQUEST_FAILURE: u8 = 82;
const CHANNEL_OPEN: u8 = 90;
const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const CHANNEL_OPEN_FAILURE: u8 = 92;
const CHANNEL_WINDOW_ADJUST: u8 = 93;
const CHANNEL_DATA: u8 = 94;
const CHANNEL_EXTENDED_DATA: u8 = 95;
const CHANNEL_EOF: u8 = 96;
const CHANNEL_CLOSE: u8 = 97;
const CHANNEL_REQUEST: u8 = 98;
const CHANNEL_SUCCESS: u8 = 99;
const CHANNEL_FAILURE: u8 = 100;

/// Longest packet accepted (RFC 4253 asks for 35,000 at least).
const MAX_PACKET: usize = 256 * 1024;
/// The window the node gives the server on a channel.
const WINDOW: u32 = 2 * 1024 * 1024;
/// The largest data packet the node accepts on a channel.
const CHANNEL_PACKET: u32 = 32 * 1024;
/// Most rounds of keyboard-interactive prompts.
const MAX_ROUNDS: usize = 8;
/// Longest wait for one packet in a blocking read.
const WAIT: Duration = Duration::from_millis(50);
/// Most channels the server may open that the node refuses before the connection ends.
pub const MAX_REFUSED_OPENS: usize = 16;
/// Most key re-exchanges the server may start on one connection. Servers rekey after a
/// volume (OpenSSH `RekeyLimit`, Dropbear at 1 GiB) or a time (an hour, 8 hours); past this
/// count the server is taken to burn the node's CPU and the connection ends.
pub const MAX_REKEYS: u32 = 256;
/// Most bytes of output kept for later reads while a write waits for the server's window.
const MAX_QUEUED_BYTES: usize = WINDOW as usize;
/// Most events kept for later reads while a write waits for the server's window (output of
/// one kind that follows output of the same kind joins it).
const MAX_QUEUED_EVENTS: usize = 256;
/// Longest originator address of a `forwarded-tcpip` channel the node takes.
const MAX_ORIGINATOR: usize = 255;

fn untrusted(rule: &'static str) -> Error {
    Error::ServerUntrusted { rule }
}

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// A host key the policy pins, as an algorithm name and the key blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    /// The key type: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521` or
    /// `ssh-rsa`.
    pub kind: String,
    /// The public key blob (RFC 4253, 6.6).
    pub blob: Vec<u8>,
}

/// Key types the node accepts as host keys.
const HOST_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

impl HostKey {
    /// Parses `type base64 [comment]`, the form of `known_hosts` and `.pub` files; the type
    /// must be one the node accepts and agree with the blob.
    pub fn parse(text: &str) -> Option<Self> {
        use base64::Engine as _;
        let mut parts = text.split_ascii_whitespace();
        let kind = parts.next()?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(parts.next()?)
            .ok()?;
        if !HOST_KEY_TYPES.contains(&kind) || blob.len() > 4096 {
            return None;
        }
        let mut parse = Parse::new(&blob);
        if parse.text().ok()? != kind {
            return None;
        }
        Some(Self {
            kind: kind.to_string(),
            blob,
        })
    }

    /// The signature algorithms this key may sign with, as offered in the key exchange.
    fn algorithms(&self) -> &'static [&'static str] {
        match self.kind.as_str() {
            "ssh-ed25519" => &["ssh-ed25519"],
            "ecdsa-sha2-nistp256" => &["ecdsa-sha2-nistp256"],
            "ecdsa-sha2-nistp384" => &["ecdsa-sha2-nistp384"],
            "ecdsa-sha2-nistp521" => &["ecdsa-sha2-nistp521"],
            "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256"],
            _ => &[],
        }
    }
}

/// The SHA-2 hash of a key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        fn run<D: sha2::Digest>(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            Zeroizing::new(d.finalize().to_vec())
        }
        match self {
            Hash::Sha256 => run::<Sha256>(parts),
            Hash::Sha384 => run::<Sha384>(parts),
            Hash::Sha512 => run::<Sha512>(parts),
        }
    }
}

/// The cipher of one direction.
enum Cipher {
    /// Before the first `NEWKEYS`.
    Clear,
    /// AES-GCM (RFC 5647 as OpenSSH names it): the length is in the clear and authenticated,
    /// the nonce a fixed part and a 64-bit counter.
    Gcm {
        key: Box<ring::aead::LessSafeKey>,
        nonce: [u8; 12],
    },
    /// ChaCha20-Poly1305 as OpenSSH defines it (`PROTOCOL.chacha20poly1305`).
    Chacha {
        seal: Box<ring::aead::chacha20_poly1305_openssh::SealingKey>,
        open: Box<ring::aead::chacha20_poly1305_openssh::OpeningKey>,
    },
}

impl Cipher {
    fn block(&self) -> usize {
        match self {
            Cipher::Gcm { .. } => 16,
            Cipher::Clear | Cipher::Chacha { .. } => 8,
        }
    }

    fn tag(&self) -> usize {
        match self {
            Cipher::Clear => 0,
            Cipher::Gcm { .. } | Cipher::Chacha { .. } => 16,
        }
    }
}

fn next_nonce(nonce: &mut [u8; 12]) {
    let mut counter = [0u8; 8];
    if let Some(tail) = nonce.get(4..) {
        counter.copy_from_slice(tail);
    }
    let next = u64::from_be_bytes(counter).wrapping_add(1).to_be_bytes();
    if let Some(tail) = nonce.get_mut(4..) {
        tail.copy_from_slice(&next);
    }
}

/// One direction of the packet layer.
struct Direction {
    cipher: Cipher,
    seq: u32,
}

impl Direction {
    fn clear() -> Self {
        Self {
            cipher: Cipher::Clear,
            seq: 0,
        }
    }
}

/// The negotiated algorithms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreed {
    /// Key exchange.
    pub kex: &'static str,
    /// Host key signature algorithm.
    pub host_key: &'static str,
    /// Cipher, client to server.
    pub cipher_out: &'static str,
    /// Cipher, server to client.
    pub cipher_in: &'static str,
    /// True when both sides do strict key exchange.
    pub strict: bool,
}

/// The first algorithm of `ours` that `theirs` has (RFC 4253, 7.1).
fn choose(ours: &[&'static str], theirs: &[&str]) -> Option<&'static str> {
    ours.iter().copied().find(|a| theirs.contains(a))
}

/// What the server's `KEXINIT` offered.
#[derive(Debug)]
pub struct ServerInit<'a> {
    /// Key exchange methods.
    pub kex: Vec<&'a str>,
    /// Host key algorithms.
    pub host_key: Vec<&'a str>,
    /// Ciphers, client to server.
    pub cipher_out: Vec<&'a str>,
    /// Ciphers, server to client.
    pub cipher_in: Vec<&'a str>,
    /// Compression, both ways.
    pub compression: (Vec<&'a str>, Vec<&'a str>),
    /// True when a guessed key exchange packet follows.
    pub follows: bool,
}

/// Parses a `KEXINIT` payload (with its message number).
pub fn parse_kexinit(payload: &[u8]) -> Result<ServerInit<'_>> {
    let mut p = Parse::new(payload);
    if p.u8()? != KEXINIT {
        return Err(invalid("expected KEXINIT"));
    }
    p.take(16)?;
    let kex = p.names()?;
    let host_key = p.names()?;
    let cipher_out = p.names()?;
    let cipher_in = p.names()?;
    let _macs = (p.names()?, p.names()?);
    let compression = (p.names()?, p.names()?);
    let _languages = (p.names()?, p.names()?);
    let follows = p.bool()?;
    p.u32()?;
    p.end()?;
    Ok(ServerInit {
        kex,
        host_key,
        cipher_out,
        cipher_in,
        compression,
        follows,
    })
}

/// Agrees on the algorithms from the server's offer and the pinned host keys. Fails when the
/// server offers nothing the node accepts: the node never falls back to a weaker one.
pub fn negotiate(server: &ServerInit<'_>, pinned: &[HostKey]) -> Result<Agreed> {
    let host_algs: Vec<&'static str> = pinned
        .iter()
        .flat_map(|k| k.algorithms().iter().copied())
        .collect();
    let kex =
        choose(KEX, &server.kex).ok_or_else(|| untrusted("no key exchange the node accepts"))?;
    let host_key = choose(&host_algs, &server.host_key)
        .ok_or_else(|| untrusted("no host key algorithm of a pinned key"))?;
    let cipher_out = choose(CIPHERS, &server.cipher_out)
        .ok_or_else(|| untrusted("no cipher the node accepts"))?;
    let cipher_in = choose(CIPHERS, &server.cipher_in)
        .ok_or_else(|| untrusted("no cipher the node accepts"))?;
    if !server.compression.0.contains(&"none") || !server.compression.1.contains(&"none") {
        return Err(untrusted("the server insists on compression"));
    }
    let strict = server.kex.contains(&STRICT_SERVER);
    let chacha = "chacha20-poly1305@openssh.com";
    if !strict && (cipher_out == chacha || cipher_in == chacha) {
        return Err(untrusted(
            "chacha20-poly1305 without strict key exchange (prefix truncation)",
        ));
    }
    Ok(Agreed {
        kex,
        host_key,
        cipher_out,
        cipher_in,
        strict,
    })
}

/// A private key of the client, from an item field.
pub enum ClientKey {
    /// Ed25519.
    Ed25519(rsig::Ed25519KeyPair),
    /// ECDSA over P-256 or P-384.
    Ecdsa(rsig::EcdsaKeyPair, &'static str, &'static str),
    /// RSA, signing with SHA-256.
    Rsa(rsig::RsaKeyPair),
}

impl core::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientKey(<redacted>)")
    }
}

fn key_invalid() -> Error {
    Error::KeyInvalid
}

/// The body of the first PEM block of `text` with this label.
fn pem(text: &[u8], label: &str) -> Option<Zeroizing<Vec<u8>>> {
    use base64::Engine as _;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = memchr::memmem::find(text, begin.as_bytes())? + begin.len();
    let stop = start + memchr::memmem::find(text.get(start..)?, end.as_bytes())?;
    let body: Zeroizing<Vec<u8>> = Zeroizing::new(
        text.get(start..stop)?
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect(),
    );
    base64::engine::general_purpose::STANDARD
        .decode(body.as_slice())
        .ok()
        .map(Zeroizing::new)
}

impl ClientKey {
    /// A key from the bytes a template rendered: PEM (`PRIVATE KEY`, `RSA PRIVATE KEY`, or an
    /// unencrypted `OPENSSH PRIVATE KEY` of Ed25519 or ECDSA), or DER (PKCS#8, PKCS#1).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if let Some(der) = pem(bytes, "PRIVATE KEY") {
            return Self::pkcs8(&der);
        }
        if let Some(der) = pem(bytes, "RSA PRIVATE KEY") {
            return rsig::RsaKeyPair::from_der(&der)
                .map(ClientKey::Rsa)
                .map_err(|_| key_invalid());
        }
        if let Some(raw) = pem(bytes, "OPENSSH PRIVATE KEY") {
            return Self::openssh(&raw);
        }
        Self::pkcs8(bytes).or_else(|_| {
            rsig::RsaKeyPair::from_der(bytes)
                .map(ClientKey::Rsa)
                .map_err(|_| key_invalid())
        })
    }

    fn pkcs8(der: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        if let Ok(key) = rsig::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
            return Ok(ClientKey::Ed25519(key));
        }
        if let Ok(key) =
            rsig::EcdsaKeyPair::from_pkcs8(&rsig::ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
        {
            return Ok(ClientKey::Ecdsa(key, "ecdsa-sha2-nistp256", "nistp256"));
        }
        if let Ok(key) =
            rsig::EcdsaKeyPair::from_pkcs8(&rsig::ECDSA_P384_SHA384_FIXED_SIGNING, der, &rng)
        {
            return Ok(ClientKey::Ecdsa(key, "ecdsa-sha2-nistp384", "nistp384"));
        }
        rsig::RsaKeyPair::from_pkcs8(der)
            .map(ClientKey::Rsa)
            .map_err(|_| key_invalid())
    }

    /// An unencrypted `openssh-key-v1` file (OpenSSH's `PROTOCOL.key`) with one key.
    fn openssh(raw: &[u8]) -> Result<Self> {
        let bad = |_| key_invalid();
        let body = raw
            .strip_prefix(b"openssh-key-v1\0".as_slice())
            .ok_or_else(key_invalid)?;
        let mut p = Parse::new(body);
        let (cipher, kdf) = (p.string().map_err(bad)?, p.string().map_err(bad)?);
        if cipher != b"none" || kdf != b"none" {
            // An encrypted key would need its passphrase in the node too; store it decrypted
            // in the item instead.
            return Err(key_invalid());
        }
        p.string().map_err(bad)?;
        if p.u32().map_err(bad)? != 1 {
            return Err(key_invalid());
        }
        p.string().map_err(bad)?;
        let private = p.string().map_err(bad)?;
        let mut k = Parse::new(private);
        if k.u32().map_err(bad)? != k.u32().map_err(bad)? {
            return Err(key_invalid());
        }
        let rng = SystemRandom::new();
        match k.text().map_err(bad)? {
            "ssh-ed25519" => {
                let public = k.string().map_err(bad)?;
                let pair = k.string().map_err(bad)?;
                let seed = pair.get(..32).ok_or_else(key_invalid)?;
                rsig::Ed25519KeyPair::from_seed_and_public_key(seed, public)
                    .map(ClientKey::Ed25519)
                    .map_err(|_| key_invalid())
            }
            kind @ ("ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384") => {
                let (alg, curve) = if kind == "ecdsa-sha2-nistp256" {
                    (&rsig::ECDSA_P256_SHA256_FIXED_SIGNING, "nistp256")
                } else {
                    (&rsig::ECDSA_P384_SHA384_FIXED_SIGNING, "nistp384")
                };
                if k.text().map_err(bad)? != curve {
                    return Err(key_invalid());
                }
                let public = k.string().map_err(bad)?;
                let scalar = k.mpint().map_err(bad)?;
                let width: usize = if curve == "nistp256" { 32 } else { 48 };
                let pad = width.checked_sub(scalar.len()).ok_or_else(key_invalid)?;
                let mut d = Zeroizing::new(vec![0u8; pad]);
                d.extend_from_slice(scalar);
                let kind = if curve == "nistp256" {
                    "ecdsa-sha2-nistp256"
                } else {
                    "ecdsa-sha2-nistp384"
                };
                rsig::EcdsaKeyPair::from_private_key_and_public_key(alg, &d, public, &rng)
                    .map(|key| ClientKey::Ecdsa(key, kind, curve))
                    .map_err(|_| key_invalid())
            }
            _ => Err(key_invalid()),
        }
    }

    /// The signature algorithm the node uses with this key.
    pub fn algorithm(&self) -> &'static str {
        match self {
            ClientKey::Ed25519(_) => "ssh-ed25519",
            ClientKey::Ecdsa(_, alg, _) => alg,
            ClientKey::Rsa(_) => "rsa-sha2-256",
        }
    }

    /// The public key blob.
    pub fn public_blob(&self) -> Vec<u8> {
        let mut put = Put::new();
        match self {
            ClientKey::Ed25519(key) => {
                put.string(b"ssh-ed25519").string(key.public_key().as_ref());
            }
            ClientKey::Ecdsa(key, alg, curve) => {
                put.string(alg.as_bytes())
                    .string(curve.as_bytes())
                    .string(key.public_key().as_ref());
            }
            ClientKey::Rsa(key) => {
                let parts: ring::rsa::PublicKeyComponents<Vec<u8>> = key.public().into();
                put.string(b"ssh-rsa").mpint(&parts.e).mpint(&parts.n);
            }
        }
        put.bytes().to_vec()
    }

    /// The signature blob over `data`.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut put = Put::new();
        match self {
            ClientKey::Ed25519(key) => {
                put.string(b"ssh-ed25519").string(key.sign(data).as_ref());
            }
            ClientKey::Ecdsa(key, alg, _) => {
                let sig = key.sign(&rng, data).map_err(|_| key_invalid())?;
                let (r, s) = sig.as_ref().split_at(sig.as_ref().len() / 2);
                let mut inner = Put::new();
                inner.mpint(r).mpint(s);
                put.string(alg.as_bytes()).string(inner.bytes());
            }
            ClientKey::Rsa(key) => {
                let mut sig = vec![0u8; key.public().modulus_len()];
                key.sign(&rsig::RSA_PKCS1_SHA256, &rng, data, &mut sig)
                    .map_err(|_| key_invalid())?;
                put.string(b"rsa-sha2-256").string(&sig);
            }
        }
        Ok(put.bytes().to_vec())
    }
}

/// Verifies the server's signature `sig` (a signature blob) over `data` with the host key
/// `blob`, for the negotiated algorithm `alg`.
pub fn verify_host_signature(alg: &str, blob: &[u8], data: &[u8], sig: &[u8]) -> Result<()> {
    let bad = || untrusted("host key signature does not verify");
    let mut k = Parse::new(blob);
    let mut s = Parse::new(sig);
    let kind = k.text()?;
    if s.text()? != alg {
        return Err(untrusted("host key signature of another algorithm"));
    }
    let signature = s.string()?;
    s.end()?;
    match alg {
        "ssh-ed25519" => {
            if kind != "ssh-ed25519" {
                return Err(bad());
            }
            let public = k.string()?;
            k.end()?;
            rsig::UnparsedPublicKey::new(&rsig::ED25519, public)
                .verify(data, signature)
                .map_err(|_| bad())
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let curve = alg.strip_prefix("ecdsa-sha2-").unwrap_or_default();
            if kind != alg || k.text()? != curve {
                return Err(bad());
            }
            let point = k.string()?;
            k.end()?;
            let mut rs = Parse::new(signature);
            let (r, sv) = (rs.mpint()?, rs.mpint()?);
            rs.end()?;
            let width = match curve {
                "nistp256" => 32,
                "nistp384" => 48,
                _ => 66,
            };
            let mut fixed = vec![0u8; width * 2];
            let place = |fixed: &mut Vec<u8>, at: usize, v: &[u8]| -> Result<()> {
                let start = (at + width).checked_sub(v.len()).ok_or_else(bad)?;
                if start < at {
                    return Err(bad());
                }
                fixed
                    .get_mut(start..at + width)
                    .ok_or_else(bad)?
                    .copy_from_slice(v);
                Ok(())
            };
            place(&mut fixed, 0, r)?;
            place(&mut fixed, width, sv)?;
            match curve {
                "nistp256" => rsig::UnparsedPublicKey::new(&rsig::ECDSA_P256_SHA256_FIXED, point)
                    .verify(data, &fixed)
                    .map_err(|_| bad()),
                "nistp384" => rsig::UnparsedPublicKey::new(&rsig::ECDSA_P384_SHA384_FIXED, point)
                    .verify(data, &fixed)
                    .map_err(|_| bad()),
                _ => {
                    use p521::ecdsa::signature::Verifier as _;
                    let key =
                        p521::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| bad())?;
                    let sig = p521::ecdsa::Signature::from_slice(&fixed).map_err(|_| bad())?;
                    key.verify(data, &sig).map_err(|_| bad())
                }
            }
        }
        "rsa-sha2-256" | "rsa-sha2-512" => {
            if kind != "ssh-rsa" {
                return Err(bad());
            }
            let (e, n) = (k.mpint()?, k.mpint()?);
            k.end()?;
            let params = if alg == "rsa-sha2-256" {
                &rsig::RSA_PKCS1_2048_8192_SHA256
            } else {
                &rsig::RSA_PKCS1_2048_8192_SHA512
            };
            rsig::RsaPublicKeyComponents { n, e }
                .verify(params, data, signature)
                .map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

/// The ephemeral key of an ECDH key exchange.
enum Ephemeral {
    Ring(ring::agreement::EphemeralPrivateKey),
    P521(p521::SecretKey),
}

impl Ephemeral {
    fn new(kex: &str) -> Result<(Self, Vec<u8>, Hash)> {
        use ring::agreement;
        let rng = SystemRandom::new();
        let ring_key = |alg: &'static agreement::Algorithm| {
            let key =
                agreement::EphemeralPrivateKey::generate(alg, &rng).map_err(|_| Error::Encoding)?;
            let public = key
                .compute_public_key()
                .map_err(|_| Error::Encoding)?
                .as_ref()
                .to_vec();
            Ok::<_, Error>((Ephemeral::Ring(key), public))
        };
        Ok(match kex {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
                let (k, p) = ring_key(&agreement::X25519)?;
                (k, p, Hash::Sha256)
            }
            "ecdh-sha2-nistp256" => {
                let (k, p) = ring_key(&agreement::ECDH_P256)?;
                (k, p, Hash::Sha256)
            }
            "ecdh-sha2-nistp384" => {
                let (k, p) = ring_key(&agreement::ECDH_P384)?;
                (k, p, Hash::Sha384)
            }
            _ => {
                use getrandom::SysRng;
                use getrandom::rand_core::UnwrapErr;
                use p521::elliptic_curve::Generate as _;
                use p521::elliptic_curve::sec1::ToSec1Point as _;
                let key = p521::SecretKey::generate_from_rng(&mut UnwrapErr(SysRng));
                let public = key.public_key().to_sec1_point(false).as_bytes().to_vec();
                (Ephemeral::P521(key), public, Hash::Sha512)
            }
        })
    }

    /// The shared secret with the server's key, as the magnitude of the `mpint` K.
    fn agree(self, kex: &str, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        use ring::agreement;
        let bad = || untrusted("invalid key exchange value");
        match self {
            Ephemeral::Ring(key) => {
                let alg = match kex {
                    "ecdh-sha2-nistp256" => &agreement::ECDH_P256,
                    "ecdh-sha2-nistp384" => &agreement::ECDH_P384,
                    _ => &agreement::X25519,
                };
                agreement::agree_ephemeral(
                    key,
                    &agreement::UnparsedPublicKey::new(alg, peer),
                    |k| Zeroizing::new(k.to_vec()),
                )
                .map_err(|_| bad())
            }
            Ephemeral::P521(key) => {
                let peer = p521::PublicKey::from_sec1_bytes(peer).map_err(|_| bad())?;
                let shared = p521::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
                Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
            }
        }
    }
}

fn mpint_bytes(magnitude: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut put = Put::new();
    put.mpint(magnitude);
    put.into_bytes()
}

fn string_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut put = Put::new();
    put.string(bytes);
    put.bytes().to_vec()
}

/// Derives `len` bytes of key material for `letter` (RFC 4253, 7.2).
fn derive(
    hash: Hash,
    k: &[u8],
    h: &[u8],
    letter: u8,
    session: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut out = hash.digest(&[k, h, &[letter], session]);
    while out.len() < len {
        let more = hash.digest(&[k, h, &out]);
        out.extend_from_slice(&more);
    }
    out.truncate(len);
    out
}

fn cipher_of(name: &str, key: &[u8], iv: &[u8]) -> Result<Cipher> {
    use ring::aead;
    match name {
        "aes256-gcm@openssh.com" | "aes128-gcm@openssh.com" => {
            let alg = if name.starts_with("aes256") {
                &aead::AES_256_GCM
            } else {
                &aead::AES_128_GCM
            };
            let key = aead::UnboundKey::new(alg, key).map_err(|_| Error::Encoding)?;
            let nonce: [u8; 12] = iv.try_into().map_err(|_| Error::Encoding)?;
            Ok(Cipher::Gcm {
                key: Box::new(aead::LessSafeKey::new(key)),
                nonce,
            })
        }
        _ => {
            let material: &[u8; 64] = key.try_into().map_err(|_| Error::Encoding)?;
            Ok(Cipher::Chacha {
                seal: Box::new(aead::chacha20_poly1305_openssh::SealingKey::new(material)),
                open: Box::new(aead::chacha20_poly1305_openssh::OpeningKey::new(material)),
            })
        }
    }
}

fn key_sizes(cipher: &str) -> (usize, usize) {
    match cipher {
        "aes256-gcm@openssh.com" => (32, 12),
        "aes128-gcm@openssh.com" => (16, 12),
        _ => (64, 0),
    }
}

/// What happened on a channel.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Output (`stdout`).
    Data(Zeroizing<Vec<u8>>),
    /// Error output (`stderr`).
    Stderr(Zeroizing<Vec<u8>>),
    /// The command exited with this status.
    Exit(u32),
    /// The server closed the channel.
    Closed,
    /// The server opened the `forwarded-tcpip` channel of the remote forward: a connection to
    /// the address and port the node asked it to listen on, from this originator. The caller
    /// of the client accepts it ([`Client::accept_forwarded`]) or refuses it
    /// ([`Client::refuse_forwarded`]).
    Forwarded {
        /// The address the connection came from, as the server says.
        originator: Vec<u8>,
        /// Its port.
        port: u32,
    },
}

/// A `forwarded-tcpip` channel the server opened, not yet accepted or refused.
#[derive(Debug)]
struct PendingOpen {
    sender: u32,
    window: u32,
    max_packet: u32,
    originator: Vec<u8>,
    port: u32,
    reported: bool,
}

/// What a command printed and how it ended.
#[derive(Debug, Default)]
pub struct Output {
    /// Its output.
    pub stdout: Zeroizing<Vec<u8>>,
    /// Its error output.
    pub stderr: Zeroizing<Vec<u8>>,
    /// Its exit status, when the server sent one.
    pub exit: Option<u32>,
}

/// How the node signs in.
pub enum Auth<'a> {
    /// `password`.
    Password(&'a [u8]),
    /// `publickey`, with a key from the item.
    Key(&'a ClientKey),
    /// `keyboard-interactive`: each prompt must match one of the patterns, and gets its answer.
    Answers(&'a [(regex::bytes::Regex, Zeroizing<Vec<u8>>)]),
}

/// An open channel.
#[derive(Debug)]
struct Channel {
    ours: u32,
    theirs: u32,
    /// What the server lets the node send.
    window: u64,
    max_packet: usize,
    /// What the node consumed of its own window since the last adjustment.
    consumed: u32,
    closed: bool,
    sent_close: bool,
}

/// An SSH connection after the key exchange.
pub struct Client<'s> {
    io: Io<'s>,
    out: Direction,
    inn: Direction,
    session: Zeroizing<Vec<u8>>,
    /// The negotiated algorithms.
    pub agreed: Agreed,
    next_channel: u32,
    channel: Option<Channel>,
    /// The remote forward the server agreed to: the address and port it listens on.
    forward: Option<(Vec<u8>, u16)>,
    /// True once a forwarded channel was accepted: a forward serves one connection.
    forward_used: bool,
    pending: Option<PendingOpen>,
    refused_opens: usize,
    /// Events that came while a write waited for the server's window, in order: every read
    /// ([`Client::poll_event`]) takes them before it reads the connection again.
    queued: VecDeque<Event>,
    /// Bytes of channel data each way: to the server, from it.
    pub data: (u64, u64),
    /// The server's identification line and the pinned host keys, for a key re-exchange.
    server_version: Vec<u8>,
    pinned: Vec<HostKey>,
    /// The host key blob the server proved in the first exchange.
    host_key: Vec<u8>,
    /// Key re-exchanges the server started.
    pub rekeys: u32,
}

impl<'s> Client<'s> {
    /// Exchanges versions and keys with the server, which must prove it holds one of the
    /// pinned host keys.
    pub fn connect(io: Io<'s>, pinned: &[HostKey]) -> Result<Self> {
        if pinned.is_empty() {
            return Err(untrusted("no host key is pinned"));
        }
        let mut client = Client {
            io,
            out: Direction::clear(),
            inn: Direction::clear(),
            session: Zeroizing::new(Vec::new()),
            agreed: Agreed {
                kex: "",
                host_key: "",
                cipher_out: "",
                cipher_in: "",
                strict: false,
            },
            next_channel: 0,
            channel: None,
            forward: None,
            forward_used: false,
            pending: None,
            refused_opens: 0,
            queued: VecDeque::new(),
            data: (0, 0),
            server_version: Vec::new(),
            pinned: pinned.to_vec(),
            host_key: Vec::new(),
            rekeys: 0,
        };
        client.io.write(VERSION)?;
        client.server_version = client.read_version()?;
        client.exchange(None)?;
        Ok(client)
    }

    /// The bytes read from and written to the server so far.
    pub fn io(&self) -> &Io<'s> {
        &self.io
    }

    /// Reads the server's identification line, skipping the lines before it (RFC 4253, 4.2).
    fn read_version(&mut self) -> Result<Vec<u8>> {
        for _ in 0..64 {
            let line = self.io.line(255)?;
            let line = line.strip_suffix(b"\n").unwrap_or(&line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.starts_with(b"SSH-") {
                if !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
                    return Err(untrusted("the server speaks no SSH 2.0"));
                }
                if line.iter().any(|b| !(b' '..0x7f).contains(b)) {
                    return Err(invalid("identification line holds a control byte"));
                }
                return Ok(line.to_vec());
            }
        }
        Err(invalid("no SSH identification line"))
    }

    /// The node's KEXINIT, offering `host` as host key algorithms.
    fn kexinit(host: &[&str]) -> Result<Zeroizing<Vec<u8>>> {
        let mut cookie = [0u8; 16];
        ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut cookie)
            .map_err(|_| Error::Encoding)?;
        let mut kex: Vec<&str> = KEX.to_vec();
        kex.push(STRICT_CLIENT);
        let mut put = Put::message(KEXINIT);
        put.raw(&cookie)
            .names(&kex)
            .names(host)
            .names(CIPHERS)
            .names(CIPHERS)
            .names(MACS)
            .names(MACS)
            .names(&["none"])
            .names(&["none"])
            .names(&[])
            .names(&[])
            .bool(false)
            .u32(0);
        Ok(put.into_bytes())
    }

    /// A key exchange (RFC 4253, 7 and 8; RFC 5656 and RFC 8731 for ECDH): the first one, or
    /// a re-exchange the server started with `rekey`, its KEXINIT (RFC 4253, 9).
    fn exchange(&mut self, rekey: Option<Zeroizing<Vec<u8>>>) -> Result<()> {
        let first = rekey.is_none();
        let pinned = self.pinned.clone();
        let host_algs: Vec<&str> = pinned
            .iter()
            .flat_map(|k| k.algorithms().iter().copied())
            .collect();
        let ours = Self::kexinit(&host_algs)?;
        self.send(&ours)?;
        // Before the server's first KEXINIT, only messages that strict key exchange forbids
        // may come; they are counted and refused once strict mode is known.
        let mut early = 0usize;
        let theirs = match rekey {
            Some(theirs) => theirs,
            None => loop {
                let packet = self.recv_raw()?;
                match packet.first() {
                    Some(&KEXINIT) => break packet,
                    Some(&IGNORE | &DEBUG) => early += 1,
                    Some(&DISCONNECT) => {
                        return Err(Error::transport(TransportKind::Closed, true));
                    }
                    _ => return Err(invalid("expected KEXINIT")),
                }
            },
        };
        let server = parse_kexinit(&theirs)?;
        let mut agreed = negotiate(&server, &pinned)?;
        if !first {
            // Strict key exchange is agreed in the first exchange and holds for the connection
            // (it resets the sequence numbers at every NEWKEYS); its markers are not looked at
            // again.
            agreed.strict = self.agreed.strict;
        }
        if agreed.strict && early > 0 {
            return Err(untrusted("strict key exchange: a message before KEXINIT"));
        }
        // Only the first exchange forbids stray messages; a re-exchange takes IGNORE and DEBUG.
        let strict_kex = first && agreed.strict;
        // A guess the server sent for another method is skipped (RFC 4253, 7).
        let skip_guess = server.follows
            && (server.kex.first() != Some(&agreed.kex)
                || server.host_key.first() != Some(&agreed.host_key));
        let (ephemeral, q_c, hash) = Ephemeral::new(agreed.kex)?;
        let mut init = Put::message(KEX_ECDH_INIT);
        init.string(&q_c);
        self.send(init.bytes())?;
        if skip_guess {
            self.recv_kex(strict_kex)?;
        }
        let reply = self.recv_kex(strict_kex)?;
        let mut p = Parse::new(&reply);
        if p.u8()? != KEX_ECDH_REPLY {
            return Err(invalid("expected the key exchange reply"));
        }
        let host_key = p.string()?;
        let q_s = p.string()?;
        let signature = p.string()?;
        p.end()?;
        // The host key must be pinned, and of the type negotiated.
        if !pinned.iter().any(|k| k.blob == host_key) {
            return Err(untrusted("host key not pinned by the policy"));
        }
        // In a re-exchange, the host key must be the one the server proved first.
        if !first && host_key != self.host_key.as_slice() {
            return Err(untrusted("a key re-exchange with another host key"));
        }
        let k = ephemeral.agree(agreed.kex, q_s)?;
        let k_mpint = mpint_bytes(&k);
        let h = hash.digest(&[
            &string_bytes(b"SSH-2.0-credentials"),
            &string_bytes(&self.server_version),
            &string_bytes(&ours),
            &string_bytes(&theirs),
            &string_bytes(host_key),
            &string_bytes(&q_c),
            &string_bytes(q_s),
            &k_mpint,
        ]);
        verify_host_signature(agreed.host_key, host_key, &h, signature)?;
        // The session identifier is the hash of the first exchange, for the whole connection.
        if first {
            self.session = h.clone();
            self.host_key = host_key.to_vec();
        }
        self.send(&[NEWKEYS])?;
        let (out_key, out_iv) = key_sizes(agreed.cipher_out);
        let (in_key, in_iv) = key_sizes(agreed.cipher_in);
        let iv_c = derive(hash, &k_mpint, &h, b'A', &self.session, out_iv);
        let iv_s = derive(hash, &k_mpint, &h, b'B', &self.session, in_iv);
        let key_c = derive(hash, &k_mpint, &h, b'C', &self.session, out_key);
        let key_s = derive(hash, &k_mpint, &h, b'D', &self.session, in_key);
        self.out.cipher = cipher_of(agreed.cipher_out, &key_c, &iv_c)?;
        if agreed.strict {
            self.out.seq = 0;
        }
        let newkeys = self.recv_kex(strict_kex)?;
        if newkeys.as_slice() != [NEWKEYS] {
            return Err(invalid("expected NEWKEYS"));
        }
        self.inn.cipher = cipher_of(agreed.cipher_in, &key_s, &iv_s)?;
        if agreed.strict {
            self.inn.seq = 0;
        }
        self.agreed = agreed;
        Ok(())
    }

    /// A packet during the key exchange: with strict key exchange nothing else may come.
    fn recv_kex(&mut self, strict: bool) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let packet = self.recv_raw()?;
            match packet.first() {
                Some(&DISCONNECT) => return Err(Error::transport(TransportKind::Closed, true)),
                Some(&IGNORE | &DEBUG | &UNIMPLEMENTED) if !strict => {}
                Some(&IGNORE | &DEBUG | &UNIMPLEMENTED) => {
                    return Err(untrusted("strict key exchange: an unexpected message"));
                }
                _ => return Ok(packet),
            }
        }
    }

    /// Sends one packet.
    fn send(&mut self, payload: &[u8]) -> Result<()> {
        let dir = &mut self.out;
        let block = dir.cipher.block();
        // AES-GCM leaves the length out of the blocks; the others count it.
        let counted = match dir.cipher {
            Cipher::Gcm { .. } => 1 + payload.len(),
            _ => 4 + 1 + payload.len(),
        };
        let mut padding = block - counted % block;
        if padding < 4 {
            padding += block;
        }
        let length = 1 + payload.len() + padding;
        let mut packet = Zeroizing::new(Vec::with_capacity(4 + length + 16));
        packet.extend_from_slice(
            &u32::try_from(length)
                .map_err(|_| Error::Encoding)?
                .to_be_bytes(),
        );
        packet.push(u8::try_from(padding).map_err(|_| Error::Encoding)?);
        packet.extend_from_slice(payload);
        let mut pad = vec![0u8; padding];
        ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut pad)
            .map_err(|_| Error::Encoding)?;
        packet.extend_from_slice(&pad);
        match &mut dir.cipher {
            Cipher::Clear => {}
            Cipher::Gcm { key, nonce } => {
                let (len, body) = packet.split_at_mut(4);
                let tag = key
                    .seal_in_place_separate_tag(
                        ring::aead::Nonce::assume_unique_for_key(*nonce),
                        ring::aead::Aad::from(&*len),
                        body,
                    )
                    .map_err(|_| Error::Encoding)?;
                packet.extend_from_slice(tag.as_ref());
                next_nonce(nonce);
            }
            Cipher::Chacha { seal, .. } => {
                let mut tag = [0u8; 16];
                seal.seal_in_place(dir.seq, &mut packet, &mut tag);
                packet.extend_from_slice(&tag);
            }
        }
        dir.seq = dir.seq.wrapping_add(1);
        self.io.write(&packet)
    }

    /// A whole packet when one is buffered.
    fn try_recv(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let dir = &mut self.inn;
        let Some(head) = self.io.buffered().get(..4) else {
            return Ok(None);
        };
        let head: [u8; 4] = head.try_into().map_err(|_| Error::Encoding)?;
        let length = match &dir.cipher {
            Cipher::Chacha { open, .. } => open.decrypt_packet_length(dir.seq, head),
            _ => head,
        };
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Error::Encoding)?;
        let block = dir.cipher.block();
        let counted = match dir.cipher {
            Cipher::Gcm { .. } => length,
            _ => length + 4,
        };
        if !(5..=MAX_PACKET).contains(&length) || counted % block != 0 {
            return Err(invalid("packet length invalid"));
        }
        let total = 4 + length + dir.cipher.tag();
        if self.io.buffered().len() < total {
            return Ok(None);
        }
        let mut packet = self.io.take(total)?;
        let body: &[u8] = match &mut dir.cipher {
            Cipher::Clear => packet.get(4..).unwrap_or_default(),
            Cipher::Gcm { key, nonce } => {
                let (len, body) = packet.split_at_mut(4);
                let opened = key
                    .open_in_place(
                        ring::aead::Nonce::assume_unique_for_key(*nonce),
                        ring::aead::Aad::from(&*len),
                        body,
                    )
                    .map_err(|_| invalid("packet authentication failed"))?;
                next_nonce(nonce);
                opened
            }
            Cipher::Chacha { open, .. } => {
                let split = 4 + length;
                let (data, tag) = packet.split_at_mut(split);
                let tag: [u8; 16] = (&*tag).try_into().map_err(|_| Error::Encoding)?;
                open.open_in_place(dir.seq, data, &tag)
                    .map_err(|_| invalid("packet authentication failed"))?
            }
        };
        let mut p = Parse::new(body);
        let padding = usize::from(p.u8()?);
        let payload_len = body
            .len()
            .checked_sub(1 + padding)
            .filter(|_| padding >= 4)
            .ok_or_else(|| invalid("packet padding invalid"))?;
        let payload = Zeroizing::new(p.take(payload_len)?.to_vec());
        dir.seq = dir.seq.wrapping_add(1);
        if payload.is_empty() {
            return Err(invalid("empty packet"));
        }
        Ok(Some(payload))
    }

    /// The next packet, waiting for it.
    fn recv_raw(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(packet) = self.try_recv()? {
                return Ok(packet);
            }
            self.io.poll(WAIT)?;
        }
    }

    /// Handles the messages any state may see; true when `packet` was one of them.
    fn transport_message(&mut self, packet: &[u8]) -> Result<bool> {
        match packet.first() {
            Some(&IGNORE | &DEBUG | &UNIMPLEMENTED | &EXT_INFO) => Ok(true),
            Some(&DISCONNECT) => Err(Error::transport(TransportKind::Closed, true)),
            Some(&KEXINIT) => {
                self.rekeys = self.rekeys.saturating_add(1);
                if self.rekeys > MAX_REKEYS {
                    return Err(untrusted("too many key re-exchanges"));
                }
                self.exchange(Some(Zeroizing::new(packet.to_vec())))?;
                Ok(true)
            }
            Some(&GLOBAL_REQUEST) => {
                let mut p = Parse::new(packet);
                p.u8()?;
                p.string()?;
                if p.bool()? {
                    self.send(&[REQUEST_FAILURE])?;
                }
                Ok(true)
            }
            Some(&CHANNEL_OPEN) => {
                self.server_open(packet)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// A channel the server opens: kept for the caller when it is the `forwarded-tcpip`
    /// channel of the node's remote forward, to exactly its address and port, while nothing
    /// else is open or waiting; refused otherwise.
    fn server_open(&mut self, packet: &[u8]) -> Result<()> {
        let mut p = Parse::new(packet);
        p.u8()?;
        let kind = p.string()?;
        let sender = p.u32()?;
        let window = p.u32()?;
        let max_packet = p.u32()?;
        let wanted = kind == b"forwarded-tcpip"
            && self.channel.is_none()
            && self.pending.is_none()
            && !self.forward_used;
        if wanted && let Some((address, port)) = self.forward.as_ref() {
            let connected = p.string()?;
            let connected_port = p.u32()?;
            let originator = p.string()?;
            let originator_port = p.u32()?;
            p.end()?;
            let matches = connected == address.as_slice() && connected_port == u32::from(*port);
            let originator_ok =
                originator.len() <= MAX_ORIGINATOR && originator.iter().all(u8::is_ascii_graphic);
            if matches && originator_ok {
                self.pending = Some(PendingOpen {
                    sender,
                    window,
                    max_packet,
                    originator: originator.to_vec(),
                    port: originator_port,
                    reported: false,
                });
                return Ok(());
            }
        }
        self.refuse_open(sender, 1)
    }

    /// Answers a channel open of the server with a failure (`reason` 1: administratively
    /// prohibited; 4: resource shortage), and counts it.
    fn refuse_open(&mut self, sender: u32, reason: u32) -> Result<()> {
        self.refused_opens += 1;
        if self.refused_opens > MAX_REFUSED_OPENS {
            return Err(untrusted(
                "the server opened more channels than the node refuses",
            ));
        }
        let mut put = Put::message(CHANNEL_OPEN_FAILURE);
        put.u32(sender).u32(reason).string(b"refused").string(b"");
        self.send(put.bytes())
    }

    /// Asks the server to listen on `address` and `port` and forward what connects there
    /// (RFC 4254 section 7.1, `tcpip-forward`). The node asks once per connection, never for
    /// port 0 (a port the server would choose).
    pub fn tcpip_forward(&mut self, address: &[u8], port: u16) -> Result<()> {
        if self.forward.is_some() || port == 0 {
            return Err(invalid("one remote forward, to a port the policy fixes"));
        }
        let mut put = Put::message(GLOBAL_REQUEST);
        put.string(b"tcpip-forward")
            .bool(true)
            .string(address)
            .u32(u32::from(port));
        self.send(put.bytes())?;
        // Transport messages are taken on the way (a channel the server opens before it
        // answers is refused: no forward is set yet).
        let packet = self.recv()?;
        match packet.first() {
            // With a port the node fixed, the answer carries nothing else (a port is there
            // only when port 0 was asked).
            Some(&REQUEST_SUCCESS) => {
                self.forward = Some((address.to_vec(), port));
                Ok(())
            }
            Some(&REQUEST_FAILURE) => Err(invalid("the server refused the remote forward")),
            _ => Err(invalid("unexpected answer to a remote forward")),
        }
    }

    /// Accepts the `forwarded-tcpip` channel reported by [`Event::Forwarded`]: it becomes the
    /// open channel.
    pub fn accept_forwarded(&mut self) -> Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| invalid("no forwarded channel waits"))?;
        let ours = self.next_channel;
        self.next_channel = self.next_channel.wrapping_add(1);
        let mut put = Put::message(CHANNEL_OPEN_CONFIRMATION);
        put.u32(pending.sender)
            .u32(ours)
            .u32(WINDOW)
            .u32(CHANNEL_PACKET);
        self.send(put.bytes())?;
        self.channel = Some(Channel {
            ours,
            theirs: pending.sender,
            window: u64::from(pending.window),
            max_packet: usize::try_from(pending.max_packet)
                .unwrap_or(0)
                .clamp(1, MAX_PACKET),
            consumed: 0,
            closed: false,
            sent_close: false,
        });
        self.forward_used = true;
        Ok(())
    }

    /// Refuses the `forwarded-tcpip` channel reported by [`Event::Forwarded`] (a resource
    /// shortage: the node's limits on open connections).
    pub fn refuse_forwarded(&mut self) -> Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| invalid("no forwarded channel waits"))?;
        self.refuse_open(pending.sender, 4)
    }

    /// The next message that is not a transport message.
    fn recv(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let packet = self.recv_raw()?;
            if !self.transport_message(&packet)? {
                return Ok(packet);
            }
        }
    }

    /// Signs in as `user` (RFC 4252; RFC 4256 for keyboard-interactive).
    pub fn authenticate(&mut self, user: &[u8], auth: &Auth<'_>) -> Result<()> {
        let mut request = Put::message(SERVICE_REQUEST);
        request.string(b"ssh-userauth");
        self.send(request.bytes())?;
        let accept = self.recv()?;
        let mut p = Parse::new(&accept);
        if p.u8()? != SERVICE_ACCEPT || p.string()? != b"ssh-userauth" {
            return Err(invalid("expected the user authentication service"));
        }
        let mut put = Put::message(USERAUTH_REQUEST);
        put.string(user).string(b"ssh-connection");
        match auth {
            Auth::Password(password) => {
                put.string(b"password").bool(false).string(password);
            }
            Auth::Key(key) => {
                let alg = key.algorithm();
                let blob = key.public_blob();
                let mut signed = Put::new();
                signed
                    .string(&self.session)
                    .u8(USERAUTH_REQUEST)
                    .string(user)
                    .string(b"ssh-connection")
                    .string(b"publickey")
                    .bool(true)
                    .string(alg.as_bytes())
                    .string(&blob);
                let signature = key.sign(signed.bytes())?;
                put.string(b"publickey")
                    .bool(true)
                    .string(alg.as_bytes())
                    .string(&blob)
                    .string(&signature);
            }
            Auth::Answers(_) => {
                put.string(b"keyboard-interactive").string(b"").string(b"");
            }
        }
        self.send(put.bytes())?;
        let mut rounds = 0usize;
        loop {
            let reply = self.recv()?;
            match reply.first() {
                Some(&USERAUTH_SUCCESS) => return Ok(()),
                Some(&USERAUTH_BANNER) => {}
                Some(&USERAUTH_FAILURE) => {
                    return Err(Error::AuthRefused {
                        rule: "the server refused the credentials",
                    });
                }
                Some(&USERAUTH_INFO_REQUEST) => {
                    let Auth::Answers(answers) = auth else {
                        // For a password, 60 is a request to change it.
                        return Err(Error::AuthRefused {
                            rule: "the server asks for a new password",
                        });
                    };
                    rounds += 1;
                    if rounds > MAX_ROUNDS {
                        return Err(Error::AuthRefused {
                            rule: "too many rounds of prompts",
                        });
                    }
                    let response = respond(&reply, answers)?;
                    self.send(response.bytes())?;
                }
                _ => return Err(invalid("unexpected message during authentication")),
            }
        }
    }

    /// Opens a session channel.
    fn open_session(&mut self) -> Result<()> {
        self.open_channel(b"session", &[])
    }

    /// Opens a channel of `kind`, with `extra` after the window and packet size.
    fn open_channel(&mut self, kind: &[u8], extra: &[u8]) -> Result<()> {
        if self.channel.is_some() {
            return Err(invalid("a channel is already open"));
        }
        let ours = self.next_channel;
        self.next_channel = self.next_channel.wrapping_add(1);
        let mut put = Put::message(CHANNEL_OPEN);
        put.string(kind)
            .u32(ours)
            .u32(WINDOW)
            .u32(CHANNEL_PACKET)
            .raw(extra);
        self.send(put.bytes())?;
        let reply = self.recv()?;
        let mut p = Parse::new(&reply);
        match p.u8()? {
            CHANNEL_OPEN_CONFIRMATION => {
                if p.u32()? != ours {
                    return Err(invalid("confirmation of another channel"));
                }
                let theirs = p.u32()?;
                let window = u64::from(p.u32()?);
                let max_packet = usize::try_from(p.u32()?).unwrap_or(0).clamp(1, MAX_PACKET);
                self.channel = Some(Channel {
                    ours,
                    theirs,
                    window,
                    max_packet,
                    consumed: 0,
                    closed: false,
                    sent_close: false,
                });
                Ok(())
            }
            CHANNEL_OPEN_FAILURE => Err(invalid("the server refused to open a channel")),
            _ => Err(invalid("unexpected answer to a channel open")),
        }
    }

    fn theirs(&self) -> Result<u32> {
        self.channel
            .as_ref()
            .map(|c| c.theirs)
            .ok_or_else(|| invalid("no channel open"))
    }

    /// Sends a channel request that wants a reply, and waits for it.
    fn request(&mut self, kind: &[u8], body: &[u8]) -> Result<()> {
        let mut put = Put::message(CHANNEL_REQUEST);
        put.u32(self.theirs()?).string(kind).bool(true).raw(body);
        self.send(put.bytes())?;
        loop {
            let packet = self.recv()?;
            match packet.first() {
                Some(&CHANNEL_SUCCESS) => return Ok(()),
                Some(&CHANNEL_FAILURE) => {
                    return Err(invalid("the server refused a channel request"));
                }
                Some(&CHANNEL_WINDOW_ADJUST) => {
                    self.channel_message(&packet)?;
                }
                _ => return Err(invalid("unexpected answer to a channel request")),
            }
        }
    }

    /// Handles a channel message; the event it carries, if any.
    fn channel_message(&mut self, packet: &[u8]) -> Result<Option<Event>> {
        let mut p = Parse::new(packet);
        let kind = p.u8()?;
        let recipient = p.u32()?;
        let channel = self
            .channel
            .as_mut()
            .filter(|c| c.ours == recipient)
            .ok_or_else(|| invalid("message for an unknown channel"))?;
        let event = match kind {
            CHANNEL_WINDOW_ADJUST => {
                channel.window = channel
                    .window
                    .saturating_add(u64::from(p.u32()?))
                    .min(u64::from(u32::MAX));
                None
            }
            CHANNEL_DATA | CHANNEL_EXTENDED_DATA => {
                let stderr = if kind == CHANNEL_EXTENDED_DATA {
                    p.u32()? == 1
                } else {
                    false
                };
                let data = p.string()?;
                p.end()?;
                let len = u32::try_from(data.len()).map_err(|_| Error::Encoding)?;
                if data.len() > CHANNEL_PACKET as usize
                    || channel.consumed.saturating_add(len) > WINDOW
                {
                    return Err(invalid("the server overran the channel window"));
                }
                channel.consumed += len;
                self.data.1 = self.data.1.saturating_add(data.len() as u64);
                let data = Zeroizing::new(data.to_vec());
                Some(if stderr {
                    Event::Stderr(data)
                } else {
                    Event::Data(data)
                })
            }
            CHANNEL_EOF => None,
            CHANNEL_CLOSE => {
                channel.closed = true;
                Some(Event::Closed)
            }
            CHANNEL_REQUEST => {
                let name = p.string()?;
                let want = p.bool()?;
                let event = if name == b"exit-status" {
                    Some(Event::Exit(p.u32()?))
                } else {
                    None
                };
                if want {
                    let mut put = Put::message(CHANNEL_FAILURE);
                    put.u32(channel.theirs);
                    self.send(put.bytes())?;
                }
                event
            }
            CHANNEL_SUCCESS | CHANNEL_FAILURE => None,
            _ => return Err(invalid("unexpected channel message")),
        };
        self.adjust()?;
        Ok(event)
    }

    /// Gives the server more window once half of it is used.
    fn adjust(&mut self) -> Result<()> {
        let Some(channel) = self.channel.as_mut() else {
            return Ok(());
        };
        if channel.consumed < WINDOW / 2 || channel.closed {
            return Ok(());
        }
        let mut put = Put::message(CHANNEL_WINDOW_ADJUST);
        put.u32(channel.theirs).u32(channel.consumed);
        channel.consumed = 0;
        self.send(put.bytes())
    }

    /// The next channel event, within `wait`; `None` when nothing came. Events that came
    /// while a write waited for window come first, in the order they came.
    pub fn poll_event(&mut self, wait: Duration) -> Result<Option<Event>> {
        if let Some(event) = self.queued.pop_front() {
            return Ok(Some(event));
        }
        self.read_event(wait)
    }

    /// Keeps an event for the next reads. Output of the same kind as the last event kept
    /// joins it; past [`MAX_QUEUED_BYTES`] of output or [`MAX_QUEUED_EVENTS`] events the
    /// channel fails rather than drop what the server sent.
    fn queue(&mut self, event: Event) -> Result<()> {
        let held: usize = self
            .queued
            .iter()
            .map(|e| match e {
                Event::Data(d) | Event::Stderr(d) => d.len(),
                _ => 0,
            })
            .fold(0, usize::saturating_add);
        let adds = match &event {
            Event::Data(d) | Event::Stderr(d) => d.len(),
            _ => 0,
        };
        if held.saturating_add(adds) > MAX_QUEUED_BYTES {
            return Err(Error::transport(TransportKind::TooLarge, true));
        }
        if let (Some(Event::Data(last)), Event::Data(more))
        | (Some(Event::Stderr(last)), Event::Stderr(more)) = (self.queued.back_mut(), &event)
        {
            last.extend_from_slice(more);
            return Ok(());
        }
        if self.queued.len() >= MAX_QUEUED_EVENTS {
            return Err(Error::transport(TransportKind::TooLarge, true));
        }
        self.queued.push_back(event);
        Ok(())
    }

    /// The next channel event read from the connection, within `wait`.
    fn read_event(&mut self, wait: Duration) -> Result<Option<Event>> {
        loop {
            if let Some(pending) = self.pending.as_mut().filter(|p| !p.reported) {
                pending.reported = true;
                return Ok(Some(Event::Forwarded {
                    originator: pending.originator.clone(),
                    port: pending.port,
                }));
            }
            if let Some(packet) = self.try_recv()? {
                if self.transport_message(&packet)? {
                    continue;
                }
                if let Some(event) = self.channel_message(&packet)? {
                    return Ok(Some(event));
                }
                continue;
            }
            if !self.io.poll(wait)? {
                return Ok(None);
            }
        }
    }

    /// Writes data on the open channel, within the server's window.
    pub fn write_data(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let (theirs, room) = {
                let channel = self
                    .channel
                    .as_ref()
                    .ok_or_else(|| invalid("no channel open"))?;
                if channel.closed {
                    return Err(Error::transport(TransportKind::Closed, true));
                }
                let room = usize::try_from(channel.window)
                    .unwrap_or(usize::MAX)
                    .min(channel.max_packet);
                (channel.theirs, room)
            };
            if room == 0 {
                // Wait for the server to open its window. What comes meanwhile (output, an
                // exit status, a forwarded channel the caller must accept or refuse, the
                // close) is kept for the next reads.
                match self.read_event(WAIT)? {
                    Some(Event::Closed) => {
                        self.queue(Event::Closed)?;
                        return Err(Error::transport(TransportKind::Closed, true));
                    }
                    Some(event) => self.queue(event)?,
                    None => {}
                }
                continue;
            }
            let (chunk, rest) = data.split_at(room.min(data.len()));
            let mut put = Put::message(CHANNEL_DATA);
            put.u32(theirs).string(chunk);
            self.send(put.bytes())?;
            if let Some(channel) = self.channel.as_mut() {
                channel.window = channel.window.saturating_sub(chunk.len() as u64);
            }
            self.data.0 = self.data.0.saturating_add(chunk.len() as u64);
            data = rest;
        }
        Ok(())
    }

    /// Closes the open channel, waits for the server to close it too, and forgets it.
    pub fn close_channel(&mut self) -> Result<()> {
        self.end_channel(true)
    }

    /// Closes the open channel; with `wait`, after the server closes it too.
    fn end_channel(&mut self, wait: bool) -> Result<()> {
        let Some(channel) = self.channel.as_mut() else {
            return Ok(());
        };
        let closed = channel.closed;
        if !channel.sent_close {
            channel.sent_close = true;
            let mut put = Put::message(CHANNEL_CLOSE);
            put.u32(channel.theirs);
            self.send(put.bytes())?;
        }
        // The server answers with its own close (RFC 4254, 5.3); until it does, the channel
        // number is still its, and what it sends on it belongs to this channel. The wait is
        // within the connection's bounds.
        if wait && !closed {
            loop {
                match self.poll_event(WAIT)? {
                    Some(Event::Closed) => break,
                    // A forwarded channel is answered, never left waiting.
                    Some(Event::Forwarded { .. }) => self.refuse_forwarded()?,
                    _ => {}
                }
            }
        }
        self.channel = None;
        // What was kept belongs to the channel that ended, except a forwarded channel the
        // caller still has to accept or refuse.
        self.queued
            .retain(|event| matches!(event, Event::Forwarded { .. }));
        Ok(())
    }

    /// Runs `command` on a new session channel and collects what it prints, at most `max`
    /// bytes.
    pub fn exec(&mut self, command: &[u8], max: usize) -> Result<Output> {
        self.open_session()?;
        let mut body = Put::new();
        body.string(command);
        self.request(b"exec", body.bytes())?;
        let mut output = Output::default();
        loop {
            match self.poll_event(WAIT)? {
                None => {}
                Some(Event::Data(data)) => output.stdout.extend_from_slice(&data),
                Some(Event::Stderr(data)) => output.stderr.extend_from_slice(&data),
                Some(Event::Exit(status)) => output.exit = Some(status),
                Some(Event::Closed) => break,
                Some(Event::Forwarded { .. }) => self.refuse_forwarded()?,
            }
            if output.stdout.len().saturating_add(output.stderr.len()) > max {
                let _ = self.end_channel(false);
                return Err(Error::transport(TransportKind::TooLarge, true));
            }
        }
        self.close_channel()?;
        Ok(output)
    }

    /// Opens an interactive shell on a new session channel, with a pseudo-terminal.
    pub fn shell(&mut self) -> Result<()> {
        self.open_session()?;
        let mut pty = Put::new();
        // TERM, 80 columns, 24 rows, no pixel sizes, no terminal modes (TTY_OP_END).
        pty.string(b"xterm")
            .u32(80)
            .u32(24)
            .u32(0)
            .u32(0)
            .string(&[0]);
        self.request(b"pty-req", pty.bytes())?;
        self.request(b"shell", &[])
    }

    /// Starts the subsystem `name` (`sftp`) on a new session channel.
    pub fn subsystem(&mut self, name: &[u8]) -> Result<()> {
        self.open_session()?;
        let mut body = Put::new();
        body.string(name);
        self.request(b"subsystem", body.bytes())
    }

    /// Opens a `direct-tcpip` channel (RFC 4254, 7.2): the server connects to `host` and
    /// `port` and relays that connection over the channel. The node names itself as the
    /// originator `127.0.0.1` port 0: it forwards no local socket.
    pub fn direct_tcpip(&mut self, host: &[u8], port: u16) -> Result<()> {
        let mut extra = Put::new();
        extra
            .string(host)
            .u32(u32::from(port))
            .string(b"127.0.0.1")
            .u32(0);
        self.open_channel(b"direct-tcpip", extra.bytes())
    }

    /// Ends the connection.
    pub fn disconnect(&mut self) {
        let _ = self.end_channel(false);
        if let Some((address, port)) = self.forward.take() {
            let mut put = Put::message(GLOBAL_REQUEST);
            put.string(b"cancel-tcpip-forward")
                .bool(false)
                .string(&address)
                .u32(u32::from(port));
            let _ = self.send(put.bytes());
        }
        let mut put = Put::message(DISCONNECT);
        // 11: SSH_DISCONNECT_BY_APPLICATION.
        put.u32(11).string(b"").string(b"");
        let _ = self.send(put.bytes());
        self.io.close();
    }
}

/// The answer to one keyboard-interactive request: each prompt must match an answer's
/// pattern; one that matches none ends the authentication.
fn respond(request: &[u8], answers: &[(regex::bytes::Regex, Zeroizing<Vec<u8>>)]) -> Result<Put> {
    let mut p = Parse::new(request);
    p.u8()?;
    p.string()?;
    p.string()?;
    p.string()?;
    let count = p.u32()?;
    if count > 16 {
        return Err(invalid("too many prompts"));
    }
    let mut put = Put::message(USERAUTH_INFO_RESPONSE);
    put.u32(count);
    for _ in 0..count {
        let prompt = p.string()?;
        p.bool()?;
        let answer = answers
            .iter()
            .find(|(pattern, _)| pattern.is_match(prompt))
            .ok_or(Error::AuthRefused {
                rule: "a prompt the policy has no answer for",
            })?;
        put.string(&answer.1);
    }
    p.end()?;
    Ok(put)
}

/// Quotes `word` for a POSIX shell: in single quotes, each `'` written `'\''`. The result is
/// one word whatever `word` holds; the node refuses a NUL, which no command line can carry.
pub fn shell_quote(word: &[u8]) -> Result<Vec<u8>> {
    if word.contains(&0) {
        return Err(Error::RequestInvalid {
            rule: "a parameter holds a NUL byte",
        });
    }
    let mut out = Vec::with_capacity(word.len() + 2);
    out.push(b'\'');
    for b in word {
        if *b == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(*b);
        }
    }
    out.push(b'\'');
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn quoting_makes_one_word() {
        assert_eq!(shell_quote(b"a b").unwrap(), b"'a b'");
        assert_eq!(
            shell_quote(b"x'; rm -rf /; '").unwrap(),
            b"'x'\\''; rm -rf /; '\\'''"
        );
        assert!(shell_quote(b"a\0b").is_err());
    }

    #[test]
    fn host_keys_parse() {
        let key = HostKey::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl comment",
        )
        .unwrap();
        assert_eq!(key.kind, "ssh-ed25519");
        assert_eq!(key.blob.len(), 51);
        // The type must agree with the blob, and be one the node accepts.
        assert!(
            HostKey::parse(
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
            )
            .is_none()
        );
        assert!(HostKey::parse("ssh-dss AAAAB3NzaC1kc3M=").is_none());
    }

    fn server_init(kex: &str, host: &str, cipher: &str) -> Vec<u8> {
        let mut put = Put::message(KEXINIT);
        put.raw(&[0; 16])
            .names(&kex.split(',').collect::<Vec<_>>())
            .names(&[host])
            .names(&cipher.split(',').collect::<Vec<_>>())
            .names(&cipher.split(',').collect::<Vec<_>>())
            .names(&["hmac-sha1"])
            .names(&["hmac-sha1"])
            .names(&["none"])
            .names(&["none"])
            .names(&[])
            .names(&[])
            .bool(false)
            .u32(0);
        put.bytes().to_vec()
    }

    fn pinned() -> Vec<HostKey> {
        vec![HostKey {
            kind: "ssh-ed25519".into(),
            blob: vec![],
        }]
    }

    #[test]
    fn weak_algorithms_are_refused() {
        // SHA-1 key exchange only.
        let init = server_init(
            "diffie-hellman-group14-sha1",
            "ssh-ed25519",
            "aes128-gcm@openssh.com",
        );
        let offer = parse_kexinit(&init).unwrap();
        assert!(matches!(
            negotiate(&offer, &pinned()),
            Err(Error::ServerUntrusted { .. })
        ));
        // CBC only.
        let init = server_init("curve25519-sha256", "ssh-ed25519", "aes128-cbc,3des-cbc");
        let offer = parse_kexinit(&init).unwrap();
        assert!(matches!(
            negotiate(&offer, &pinned()),
            Err(Error::ServerUntrusted { .. })
        ));
        // An `ssh-rsa` (SHA-1) host key signature only.
        let init = server_init("curve25519-sha256", "ssh-rsa", "aes128-gcm@openssh.com");
        let offer = parse_kexinit(&init).unwrap();
        let rsa = vec![HostKey {
            kind: "ssh-rsa".into(),
            blob: vec![],
        }];
        assert!(matches!(
            negotiate(&offer, &rsa),
            Err(Error::ServerUntrusted { .. })
        ));
        // ChaCha20-Poly1305 without strict key exchange (Terrapin).
        let init = server_init(
            "curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
        );
        let offer = parse_kexinit(&init).unwrap();
        assert!(matches!(
            negotiate(&offer, &pinned()),
            Err(Error::ServerUntrusted { .. })
        ));
        // With strict key exchange, it is taken.
        let init = server_init(
            "curve25519-sha256,kex-strict-s-v00@openssh.com",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
        );
        let offer = parse_kexinit(&init).unwrap();
        let agreed = negotiate(&offer, &pinned()).unwrap();
        assert!(agreed.strict);
        assert_eq!(agreed.cipher_in, "chacha20-poly1305@openssh.com");
        // AES-GCM is preferred.
        let init = server_init(
            "ecdh-sha2-nistp256,curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com",
        );
        let agreed = negotiate(&parse_kexinit(&init).unwrap(), &pinned()).unwrap();
        assert_eq!(agreed.kex, "curve25519-sha256");
        assert_eq!(agreed.cipher_out, "aes128-gcm@openssh.com");
    }

    #[test]
    fn nonce_counter_increments_big_endian() {
        let mut nonce = [0u8; 12];
        nonce[11] = 0xff;
        next_nonce(&mut nonce);
        assert_eq!(&nonce[4..], &[0, 0, 0, 0, 0, 0, 1, 0]);
    }
}
