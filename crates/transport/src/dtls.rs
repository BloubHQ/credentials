//! DTLS 1.2 and 1.3 (RFC 6347, RFC 9147) over the datagram sockets of [`crate::udp`]: the
//! exchanges of a `dtls` operation (CoAP over DTLS, LwM2M and other request and response
//! protocols that protect their messages with DTLS).
//!
//! The protocol is the Sans-IO state machine of the `dimpl` crate, built without any of its
//! crypto backends: its [`CryptoProvider`] is filled by [`provider`] with ring (the
//! primitives the `tls` connection uses through rustls) and rustls-webpki. `dimpl` leaves the
//! server certificate to the caller; [`DtlsStream::connect`] checks it with the same verifier
//! as a `tls` connection (rustls' `WebPkiServerVerifier`: the chain to the transport's roots,
//! the validity period, the server-authentication usage and the destination's host name),
//! and, when the policy pins keys, that the certificate's key is one of them. A pinned key
//! also lets a self-signed certificate through, which is then its own trust anchor: it must
//! still be in its validity period and name the host. Nothing is written on the connection
//! before the handshake is complete and the certificate accepted.
//!
//! `dimpl` hands over the server's leaf certificate only, not the intermediates the server
//! sent: a certificate must be issued by one of the roots directly, or be pinned and
//! self-signed. A certificate under an intermediate is refused (it fails closed).
//!
//! The record layer of `dimpl` drops records that fail authentication or that replay one
//! within the window of RFC 6347 section 4.1.2.6 (RFC 9147 section 4.5.1); the handshake
//! flights are sent again on its timers. A request sent after the handshake that gets no
//! answer is sent again, as a new record, like a datagram of [`crate::udp::DatagramStream`].
//!
//! Each call into `dimpl` runs under [`std::panic::catch_unwind`]: a panic in it ends the
//! connection with an error instead of the node.

use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::crypto::{
    Aad, ActiveKeyExchange, Buf, Cipher, CryptoProvider, Dtls12CipherSuite, Dtls13CipherSuite,
    HashAlgorithm, HashContext, HashProvider, HmacProvider, KeyProvider, NamedGroup, Nonce,
    SecureRandom, SignatureAlgorithm, SignatureVerifier, SigningKey, SupportedDtls12CipherSuite,
    SupportedDtls13CipherSuite, SupportedKxGroup, TmpBuf,
};
use dimpl::{Config, CryptoError, CryptoOperation, Dtls, DtlsCertificate, Output};
use engine::egress::{Arrived, Stream};
use engine::error::TransportKind;
use ring::rand::SecureRandom as _;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use zeroize::{Zeroize, Zeroizing};

use crate::udp::{DatagramSocket, MAX_RETRIES, RETRY_FIRST};

/// Largest plaintext of one record, sent or received: 2^14 bytes (RFC 6347 section 4.1,
/// RFC 9147 section 4). A `send` of the policy or the caller is one record.
pub const MAX_RECORD: usize = 16_384;
/// Most records received and not yet read.
pub const MAX_PENDING: usize = 64;
/// Longest wait for the handshake, its resent flights included.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// Most pins of one operation.
pub const MAX_PINS: usize = 16;
/// The buffer the records are written into: a datagram, or the server's leaf certificate.
const POLL_BUFFER: usize = 1 << 17;
/// The largest datagram `dimpl` writes during the handshake (its default).
const MTU: usize = 1150;

/// Why a DTLS connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DtlsError {
    /// The server's certificate was refused: no chain to the roots, outside its validity
    /// period, not for the host, or its key not among the pins.
    #[error("the server certificate was refused")]
    Certificate,
    /// The handshake failed (a protocol error, an alert, an unsupported or unsigned
    /// algorithm, a request for a client certificate).
    #[error("the DTLS handshake failed")]
    Handshake,
    /// A deadline passed.
    #[error("a DTLS deadline passed")]
    Timeout,
    /// The socket failed.
    #[error("the datagram socket failed")]
    Io,
    /// A record, or the records waiting, went over the limits.
    #[error("a DTLS record is too large")]
    TooLarge,
    /// The server ended the connection (`close_notify`), or it ended already.
    #[error("the DTLS connection is closed")]
    Closed,
    /// The protocol state machine failed: the connection ended.
    #[error("the DTLS state machine failed")]
    Internal,
}

impl DtlsError {
    /// The engine's error for it; `sent` when the request may have reached the server.
    pub fn into_engine(self, sent: bool) -> engine::Error {
        let kind = match self {
            DtlsError::Certificate | DtlsError::Handshake | DtlsError::Internal => {
                TransportKind::Tls
            }
            DtlsError::Timeout => TransportKind::Timeout,
            DtlsError::Io => TransportKind::Io,
            DtlsError::TooLarge => TransportKind::TooLarge,
            DtlsError::Closed => TransportKind::Closed,
        };
        engine::Error::transport(kind, sent)
    }
}

/// Runs one call into `dimpl`, turning a panic into an error.
fn guarded<T>(call: impl FnOnce() -> T) -> Result<T, DtlsError> {
    catch_unwind(AssertUnwindSafe(call)).map_err(|_| DtlsError::Internal)
}

/// What the certificate of the server must satisfy.
#[derive(Clone)]
pub struct Trust {
    roots: Arc<RootCertStore>,
    host: String,
    pins: Vec<[u8; 32]>,
}

impl fmt::Debug for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trust")
            .field("roots", &self.roots.len())
            .field("host", &self.host)
            .field("pins", &self.pins.len())
            .finish()
    }
}

impl Trust {
    /// A certificate for `host` that chains to `roots` directly, and, when `pins` is not
    /// empty, whose key's SHA-256 (of its DER `SubjectPublicKeyInfo`) is one of them; a
    /// self-signed certificate with a pinned key is accepted as its own root.
    pub fn new(roots: Arc<RootCertStore>, host: &str, pins: &[[u8; 32]]) -> Self {
        Self {
            roots,
            host: host.to_string(),
            pins: pins.to_vec(),
        }
    }

    /// Checks the server's leaf certificate (DER).
    pub fn check(&self, leaf: &[u8]) -> Result<(), DtlsError> {
        let name = ServerName::try_from(self.host.clone()).map_err(|_| DtlsError::Certificate)?;
        let leaf = CertificateDer::from(leaf.to_vec());
        let now = UnixTime::now();
        let pinned = if self.pins.is_empty() {
            false
        } else {
            let cert =
                webpki::EndEntityCert::try_from(&leaf).map_err(|_| DtlsError::Certificate)?;
            let spki = cert.subject_public_key_info();
            let hash = ring::digest::digest(&ring::digest::SHA256, spki.as_ref());
            // The pins are public (the policy names them); the comparison need not be
            // constant-time.
            if !self.pins.iter().any(|pin| pin.as_slice() == hash.as_ref()) {
                return Err(DtlsError::Certificate);
            }
            true
        };
        if verify(self.roots.clone(), &leaf, &name, now).is_ok() {
            return Ok(());
        }
        if pinned {
            // A pinned key: a self-signed certificate is its own root. One issued by a CA
            // that is not a root names another issuer and fails here too.
            let anchor = webpki::anchor_from_trusted_cert(&leaf)
                .map_err(|_| DtlsError::Certificate)?
                .to_owned();
            let own = RootCertStore {
                roots: vec![anchor],
            };
            return verify(Arc::new(own), &leaf, &name, now);
        }
        Err(DtlsError::Certificate)
    }
}

/// The verifier of a `tls` connection: rustls' WebPKI server verifier with the ring
/// provider, no intermediates, no OCSP.
fn verify(
    roots: Arc<RootCertStore>,
    leaf: &CertificateDer<'_>,
    name: &ServerName<'_>,
    now: UnixTime,
) -> Result<(), DtlsError> {
    let verifier = WebPkiServerVerifier::builder_with_provider(
        roots,
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| DtlsError::Certificate)?;
    verifier
        .verify_server_cert(leaf, &[], name, &[], now)
        .map(|_| ())
        .map_err(|_| DtlsError::Certificate)
}

/// What a round of [`Dtls::poll_output`] found.
#[derive(Default)]
struct Polled {
    connected: bool,
    verified: bool,
    closed: bool,
    timer: Option<Instant>,
}

/// A DTLS client connection over a datagram socket: a write sends one record, a read returns
/// the plaintext of the next record.
pub struct DtlsStream {
    dtls: Dtls,
    socket: Box<dyn DatagramSocket>,
    trust: Trust,
    buffer: Zeroizing<Vec<u8>>,
    received: VecDeque<Zeroizing<Vec<u8>>>,
    polled: Polled,
    last: Zeroizing<Vec<u8>>,
    io_timeout: Duration,
    deadline: Instant,
    failed: bool,
}

impl fmt::Debug for DtlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsStream")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

/// The client's configuration: the provider of [`provider`], `dimpl`'s defaults otherwise.
fn config(handshake: Duration) -> Result<Arc<Config>, DtlsError> {
    let config = Config::builder()
        .with_crypto_provider(provider())
        .mtu(MTU)
        .handshake_timeout(handshake.max(Duration::from_millis(1)))
        .build()
        .map_err(|_| DtlsError::Internal)?;
    Ok(Arc::new(config))
}

impl DtlsStream {
    /// Makes DTLS (1.3, or 1.2 when the server takes only that) over `socket` and checks the
    /// server's certificate with `trust`. Each read waits at most `io_timeout`, and nothing
    /// happens after `deadline`; the handshake takes at most [`HANDSHAKE_WAIT`] of it.
    pub fn connect(
        socket: Box<dyn DatagramSocket>,
        trust: Trust,
        io_timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, DtlsError> {
        let start = Instant::now();
        let end = start
            .checked_add(HANDSHAKE_WAIT)
            .map_or(deadline, |end| end.min(deadline));
        let config = config(end.saturating_duration_since(start))?;
        // The client presents no certificate: the key provider loads an empty key as one
        // that refuses to sign, so a server that asks for a certificate fails the handshake.
        let identity = DtlsCertificate {
            certificate: NO_CERTIFICATE.to_vec(),
            private_key: Vec::new(),
        };
        let dtls = guarded(|| {
            let mut dtls = Dtls::new_auto(config, identity, start);
            dtls.set_active(true);
            dtls
        })?;
        let mut stream = Self {
            dtls,
            socket,
            trust,
            buffer: Zeroizing::new(vec![0u8; POLL_BUFFER]),
            received: VecDeque::new(),
            polled: Polled::default(),
            last: Zeroizing::new(Vec::new()),
            io_timeout,
            deadline,
            failed: false,
        };
        stream
            .handshake(end)
            .inspect_err(|_| stream.failed = true)?;
        Ok(stream)
    }

    /// The protocol version the handshake agreed on: `"1.2"` or `"1.3"`.
    pub fn version(&self) -> Option<&'static str> {
        match self.dtls.protocol_version()? {
            dimpl::ProtocolVersion::DTLS1_2 => Some("1.2"),
            dimpl::ProtocolVersion::DTLS1_3 => Some("1.3"),
            _ => None,
        }
    }

    fn handshake(&mut self, end: Instant) -> Result<(), DtlsError> {
        let now = Instant::now();
        let dtls = &mut self.dtls;
        guarded(|| dtls.handle_timeout(now))?.map_err(|_| DtlsError::Handshake)?;
        loop {
            self.poll()?;
            if self.polled.connected {
                // A handshake that never showed a certificate is not accepted.
                return if self.polled.verified {
                    Ok(())
                } else {
                    Err(DtlsError::Certificate)
                };
            }
            if self.polled.closed {
                return Err(DtlsError::Handshake);
            }
            self.step(end, DtlsError::Handshake)?;
        }
    }

    /// Waits for one datagram until the timer of `dimpl` or `end`, and hands it over (or the
    /// time). Fails with [`DtlsError::Timeout`] at `end`.
    fn step(&mut self, end: Instant, refused: DtlsError) -> Result<(), DtlsError> {
        let now = Instant::now();
        if now >= end {
            return Err(DtlsError::Timeout);
        }
        let until = self.polled.timer.map_or(end, |t| t.min(end));
        let wait = until
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        let datagram = self.socket.recv(wait).map_err(|_| DtlsError::Io)?;
        let now = Instant::now();
        let dtls = &mut self.dtls;
        guarded(|| dtls.handle_timeout(now))?.map_err(|_| refused)?;
        if let Some(mut datagram) = datagram {
            let dtls = &mut self.dtls;
            let handled = guarded(|| dtls.handle_packet(&datagram));
            datagram.zeroize();
            handled?.map_err(|_| refused)?;
        }
        Ok(())
    }

    /// Drains what `dimpl` has to send and to say, until its next timer.
    fn poll(&mut self) -> Result<(), DtlsError> {
        let Self {
            dtls,
            socket,
            trust,
            buffer,
            received,
            polled,
            ..
        } = self;
        loop {
            let done = guarded(|| -> Result<bool, DtlsError> {
                match dtls.poll_output(buffer.as_mut_slice()) {
                    Output::Packet(packet) => {
                        socket.send(packet).map_err(|_| DtlsError::Io)?;
                    }
                    Output::BufferTooSmall { .. } => return Err(DtlsError::TooLarge),
                    Output::Timeout(at) => {
                        polled.timer = Some(at);
                        return Ok(true);
                    }
                    Output::Connected => polled.connected = true,
                    Output::PeerCert(leaf) => {
                        // A second certificate (a renegotiation) is checked again.
                        polled.verified = false;
                        trust.check(leaf)?;
                        polled.verified = true;
                    }
                    Output::ApplicationData(data) => {
                        if !polled.verified {
                            return Err(DtlsError::Certificate);
                        }
                        if data.len() > MAX_RECORD || received.len() >= MAX_PENDING {
                            return Err(DtlsError::TooLarge);
                        }
                        received.push_back(Zeroizing::new(data.to_vec()));
                    }
                    Output::CloseNotify => polled.closed = true,
                    // DTLS-SRTP keys: no SRTP profile is offered, none is used.
                    Output::KeyingMaterial(..) => {}
                    _ => {}
                }
                Ok(false)
            })??;
            if done {
                return Ok(());
            }
        }
    }

    /// The next record within `wait`, sending the last one again at growing intervals while
    /// none comes; `None` when none came.
    fn next(
        &mut self,
        wait: Duration,
        max: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DtlsError> {
        let start = Instant::now();
        let end = start
            .checked_add(wait)
            .map_or(self.deadline, |end| end.min(self.deadline));
        let mut resend_at = start.checked_add(RETRY_FIRST);
        let mut interval = RETRY_FIRST;
        let mut retries = 0;
        loop {
            if let Some(record) = self.received.pop_front() {
                if record.len() > max {
                    return Err(DtlsError::TooLarge);
                }
                return Ok(Some(record));
            }
            if self.polled.closed {
                return Err(DtlsError::Closed);
            }
            let now = Instant::now();
            if now >= end {
                return Ok(None);
            }
            let resend = !self.last.is_empty() && retries < MAX_RETRIES;
            let slice_end = match resend_at {
                Some(at) if resend => at.min(end),
                _ => end,
            };
            match self.step(slice_end, DtlsError::Internal) {
                Ok(()) => {}
                Err(DtlsError::Timeout) if Instant::now() < end => {}
                Err(DtlsError::Timeout) => return Ok(None),
                Err(error) => return Err(error),
            }
            self.poll()?;
            if resend
                && self.received.is_empty()
                && resend_at.is_some_and(|at| Instant::now() >= at)
            {
                let dtls = &mut self.dtls;
                let last = &self.last;
                guarded(|| dtls.send_application_data(last))?.map_err(|_| DtlsError::Internal)?;
                self.poll()?;
                retries += 1;
                interval = interval.saturating_mul(2);
                resend_at = Instant::now().checked_add(interval);
            }
        }
    }

    fn usable(&self) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Closed);
        }
        if Instant::now() >= self.deadline {
            return Err(DtlsError::Timeout);
        }
        Ok(())
    }

    /// Sends `bytes` as one record.
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), DtlsError> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD {
            return Err(DtlsError::TooLarge);
        }
        self.usable()?;
        if self.polled.closed {
            return Err(DtlsError::Closed);
        }
        let dtls = &mut self.dtls;
        let sent = guarded(|| dtls.send_application_data(bytes))?;
        sent.map_err(|_| DtlsError::Internal)
            .and_then(|_| self.poll())
            .inspect_err(|_| self.failed = true)?;
        self.last.zeroize();
        *self.last = bytes.to_vec();
        Ok(())
    }

    /// The plaintext of the next record within `wait` (at most the stream's read timeout);
    /// `None` when none came.
    pub fn receive(
        &mut self,
        wait: Duration,
        max: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DtlsError> {
        self.usable()?;
        let record = self
            .next(wait.min(self.io_timeout), max)
            .inspect_err(|_| self.failed = true)?;
        if record.is_some() {
            // An answer ends the resends of the record it answers.
            self.last.zeroize();
        }
        Ok(record)
    }

    /// Sends `close_notify`.
    pub fn shutdown(&mut self) {
        if self.failed {
            return;
        }
        let dtls = &mut self.dtls;
        if matches!(guarded(|| dtls.close()), Ok(Ok(()))) {
            let _ = self.poll();
        }
        self.failed = true;
    }
}

impl Stream for DtlsStream {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.send(bytes).map_err(|e| e.into_engine(true))
    }

    /// Reads one record; delimiters do not apply to records and must be empty.
    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> engine::Result<Vec<u8>> {
        if !delimiters.is_empty() {
            return Err(engine::Error::transport(TransportKind::Unsupported, true));
        }
        match self.receive(self.io_timeout, max) {
            Ok(Some(mut record)) => Ok(core::mem::take(&mut *record)),
            Ok(None) => Err(engine::Error::transport(TransportKind::Timeout, true)),
            Err(error) => Err(error.into_engine(true)),
        }
    }

    fn read_some(&mut self, max: usize, wait: Duration) -> engine::Result<Arrived> {
        match self.receive(wait, max) {
            Ok(Some(mut record)) => Ok(Arrived::Bytes(core::mem::take(&mut *record))),
            Ok(None) => Ok(Arrived::Nothing),
            Err(DtlsError::Closed) => Ok(Arrived::End),
            Err(error) => Err(error.into_engine(true)),
        }
    }

    fn close(&mut self) -> engine::Result<()> {
        self.shutdown();
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// The crypto provider: ring for every primitive, rustls-webpki for signatures under a
// certificate.
// ---------------------------------------------------------------------------------------

/// What the client hands `dimpl` as its own certificate: never sent, since the key that goes
/// with it signs nothing (an empty DER `SEQUENCE`).
const NO_CERTIFICATE: &[u8] = &[0x30, 0x00];

/// The crypto provider of the DTLS connections: ECDHE over X25519, P-256 and P-384; AES-GCM
/// and ChaCha20-Poly1305 (DTLS 1.2 with ECDSA, and DTLS 1.3); SHA-256 and SHA-384; ECDSA
/// P-256 with SHA-256 and P-384 with SHA-384 under the server's certificate. No PSK suite.
///
/// The key provider loads a PKCS#8 ECDSA key (P-256 or P-384) to sign with, as a server
/// does; an empty key loads as one that signs nothing (the client's).
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: KX_GROUPS,
        signature_verification: &VERIFIER,
        key_provider: &KEYS,
        secure_random: &RANDOM,
        hash_provider: &HASHES,
        hmac_provider: &HMACS,
        cipher_suites: DTLS12_SUITES,
        dtls13_cipher_suites: DTLS13_SUITES,
    }
}

fn failed(operation: CryptoOperation) -> CryptoError {
    CryptoError::OperationFailed(operation)
}

/// The system random source of ring.
#[derive(Debug)]
struct Random;

static RANDOM: Random = Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        ring::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| failed(CryptoOperation::FillRandom))
    }
}

/// SHA-256 and SHA-384.
#[derive(Debug)]
struct Hashes;

static HASHES: Hashes = Hashes;

/// A running hash; `None` for an algorithm the provider does not have, which hashes to
/// nothing (the handshake then fails on its `Finished`).
struct Hash(Option<ring::digest::Context>);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash")
    }
}

fn digest_of(algorithm: HashAlgorithm) -> Option<&'static ring::digest::Algorithm> {
    match algorithm {
        HashAlgorithm::SHA256 => Some(&ring::digest::SHA256),
        HashAlgorithm::SHA384 => Some(&ring::digest::SHA384),
        _ => None,
    }
}

impl HashContext for Hash {
    fn update(&mut self, data: &[u8]) {
        if let Some(context) = &mut self.0 {
            context.update(data);
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        out.clear();
        if let Some(context) = &self.0 {
            out.extend_from_slice(context.clone().finish().as_ref());
        }
    }
}

impl HashProvider for Hashes {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        Box::new(Hash(digest_of(algorithm).map(ring::digest::Context::new)))
    }
}

/// HMAC with SHA-256 and SHA-384 (the PRF of DTLS 1.2, HKDF of DTLS 1.3).
#[derive(Debug)]
struct Hmacs;

static HMACS: Hmacs = Hmacs;

impl HmacProvider for Hmacs {
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let algorithm = match hash {
            HashAlgorithm::SHA256 => ring::hmac::HMAC_SHA256,
            HashAlgorithm::SHA384 => ring::hmac::HMAC_SHA384,
            _ => return Err(CryptoError::UnsupportedHmacHash(hash)),
        };
        let tag = ring::hmac::sign(&ring::hmac::Key::new(algorithm, key), data);
        let tag = tag.as_ref();
        let slot = out
            .get_mut(..tag.len())
            .ok_or(failed(CryptoOperation::ComputeHmac))?;
        slot.copy_from_slice(tag);
        Ok(tag.len())
    }
}

/// An AEAD of ring under one key.
struct Aead(ring::aead::LessSafeKey);

impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aead")
    }
}

impl Aead {
    fn boxed(
        algorithm: &'static ring::aead::Algorithm,
        key: &[u8],
    ) -> Result<Box<dyn Cipher>, CryptoError> {
        let key = ring::aead::UnboundKey::new(algorithm, key)
            .map_err(|_| failed(CryptoOperation::CreateCipher))?;
        Ok(Box::new(Aead(ring::aead::LessSafeKey::new(key))))
    }
}

fn nonce_of(nonce: &Nonce) -> Result<ring::aead::Nonce, CryptoError> {
    ring::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonce)
}

impl Cipher for Aead {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let tag = self
            .0
            .seal_in_place_separate_tag(
                nonce_of(&nonce)?,
                ring::aead::Aad::from(&*aad),
                plaintext.as_mut(),
            )
            .map_err(|_| failed(CryptoOperation::Encrypt))?;
        plaintext.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        let length = self
            .0
            .open_in_place(
                nonce_of(&nonce)?,
                ring::aead::Aad::from(&*aad),
                ciphertext.as_mut(),
            )
            .map_err(|_| failed(CryptoOperation::Decrypt))?
            .len();
        ciphertext.truncate(length);
        Ok(())
    }
}

/// A DTLS 1.2 suite with ECDHE and ECDSA.
#[derive(Debug)]
struct Dtls12 {
    suite: Dtls12CipherSuite,
    hash: HashAlgorithm,
    aead: &'static ring::aead::Algorithm,
    explicit_nonce: usize,
}

impl SupportedDtls12CipherSuite for Dtls12 {
    fn suite(&self) -> Dtls12CipherSuite {
        self.suite
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }

    /// No MAC key; the key; the fixed part of the nonce (4 bytes for AES-GCM, RFC 5288; the
    /// whole 12 for ChaCha20-Poly1305, RFC 7905).
    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, self.aead.key_len(), 12 - self.explicit_nonce)
    }

    fn explicit_nonce_len(&self) -> usize {
        self.explicit_nonce
    }

    fn tag_len(&self) -> usize {
        self.aead.tag_len()
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Aead::boxed(self.aead, key)
    }
}

static ECDHE_ECDSA_AES128_GCM_SHA256: Dtls12 = Dtls12 {
    suite: Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
    hash: HashAlgorithm::SHA256,
    aead: &ring::aead::AES_128_GCM,
    explicit_nonce: 8,
};
static ECDHE_ECDSA_AES256_GCM_SHA384: Dtls12 = Dtls12 {
    suite: Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
    hash: HashAlgorithm::SHA384,
    aead: &ring::aead::AES_256_GCM,
    explicit_nonce: 8,
};
static ECDHE_ECDSA_CHACHA20_POLY1305_SHA256: Dtls12 = Dtls12 {
    suite: Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
    hash: HashAlgorithm::SHA256,
    aead: &ring::aead::CHACHA20_POLY1305,
    explicit_nonce: 0,
};

static DTLS12_SUITES: &[&dyn SupportedDtls12CipherSuite] = &[
    &ECDHE_ECDSA_AES128_GCM_SHA256,
    &ECDHE_ECDSA_AES256_GCM_SHA384,
    &ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
];

/// A DTLS 1.3 suite.
#[derive(Debug)]
struct Dtls13 {
    suite: Dtls13CipherSuite,
    hash: HashAlgorithm,
    aead: &'static ring::aead::Algorithm,
    /// The record number mask (RFC 9147 section 4.2.3).
    mask: Mask,
}

/// How a DTLS 1.3 suite masks record numbers.
#[derive(Debug, Clone, Copy)]
enum Mask {
    /// AES-ECB of the sample under the key (16 or 32 bytes).
    Aes,
    /// ChaCha20 with the counter and nonce of the sample: the header protection of QUIC
    /// (RFC 9001 section 5.4.4), of which ring gives the first five bytes.
    ChaCha20,
}

/// AES-ECB of one block; `None` for a key of another length.
fn aes_block(key: &[u8], sample: &[u8; 16]) -> Option<[u8; 16]> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let mut block = aes::Block::from(*sample);
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .ok()?
            .encrypt_block(&mut block),
        32 => aes::Aes256::new_from_slice(key)
            .ok()?
            .encrypt_block(&mut block),
        _ => return None,
    }
    Some(block.into())
}

impl SupportedDtls13CipherSuite for Dtls13 {
    fn suite(&self) -> Dtls13CipherSuite {
        self.suite
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }

    fn key_len(&self) -> usize {
        self.aead.key_len()
    }

    fn iv_len(&self) -> usize {
        self.aead.nonce_len()
    }

    fn tag_len(&self) -> usize {
        self.aead.tag_len()
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Aead::boxed(self.aead, key)
    }

    /// The whole block for AES; for ChaCha20 the first five bytes, the rest zero (a record
    /// number takes at most two, RFC 9147 section 4). A key of the wrong length gives a zero
    /// mask, and the record then fails authentication.
    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        match self.mask {
            Mask::Aes => {
                if let Some(block) = aes_block(sn_key, sample) {
                    out = block;
                }
            }
            Mask::ChaCha20 => {
                if let Ok(key) =
                    ring::aead::quic::HeaderProtectionKey::new(&ring::aead::quic::CHACHA20, sn_key)
                    && let Ok(mask) = key.new_mask(sample)
                    && let Some(head) = out.get_mut(..mask.len())
                {
                    head.copy_from_slice(&mask);
                }
            }
        }
        out
    }
}

static TLS_AES_128_GCM_SHA256: Dtls13 = Dtls13 {
    suite: Dtls13CipherSuite::AES_128_GCM_SHA256,
    hash: HashAlgorithm::SHA256,
    aead: &ring::aead::AES_128_GCM,
    mask: Mask::Aes,
};
static TLS_AES_256_GCM_SHA384: Dtls13 = Dtls13 {
    suite: Dtls13CipherSuite::AES_256_GCM_SHA384,
    hash: HashAlgorithm::SHA384,
    aead: &ring::aead::AES_256_GCM,
    mask: Mask::Aes,
};
static TLS_CHACHA20_POLY1305_SHA256: Dtls13 = Dtls13 {
    suite: Dtls13CipherSuite::CHACHA20_POLY1305_SHA256,
    hash: HashAlgorithm::SHA256,
    aead: &ring::aead::CHACHA20_POLY1305,
    mask: Mask::ChaCha20,
};

static DTLS13_SUITES: &[&dyn SupportedDtls13CipherSuite] = &[
    &TLS_AES_128_GCM_SHA256,
    &TLS_AES_256_GCM_SHA384,
    &TLS_CHACHA20_POLY1305_SHA256,
];

/// An ECDHE group of ring.
#[derive(Debug)]
struct Group {
    name: NamedGroup,
    algorithm: &'static ring::agreement::Algorithm,
}

impl SupportedKxGroup for Group {
    fn name(&self) -> NamedGroup {
        self.name
    }

    fn start_exchange(&self, mut buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let rng = ring::rand::SystemRandom::new();
        let private = ring::agreement::EphemeralPrivateKey::generate(self.algorithm, &rng)
            .map_err(|_| failed(CryptoOperation::GenerateEphemeralKey))?;
        let public = private
            .compute_public_key()
            .map_err(|_| failed(CryptoOperation::ComputePublicKey))?;
        buf.clear();
        buf.extend_from_slice(public.as_ref());
        Ok(Box::new(Exchange {
            group: self.name,
            algorithm: self.algorithm,
            private,
            public: buf,
        }))
    }
}

/// One ephemeral key pair.
struct Exchange {
    group: NamedGroup,
    algorithm: &'static ring::agreement::Algorithm,
    private: ring::agreement::EphemeralPrivateKey,
    public: Buf,
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl ActiveKeyExchange for Exchange {
    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    /// ring checks the peer's point (on the curve; for X25519, a shared secret that is not
    /// all zero).
    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), CryptoError> {
        let peer = ring::agreement::UnparsedPublicKey::new(self.algorithm, peer_pub);
        out.clear();
        ring::agreement::agree_ephemeral(self.private, &peer, |secret| {
            out.extend_from_slice(secret)
        })
        .map_err(|_| CryptoError::InvalidPublicKey(self.group))
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

static X25519: Group = Group {
    name: NamedGroup::X25519,
    algorithm: &ring::agreement::X25519,
};
static P256: Group = Group {
    name: NamedGroup::Secp256r1,
    algorithm: &ring::agreement::ECDH_P256,
};
static P384: Group = Group {
    name: NamedGroup::Secp384r1,
    algorithm: &ring::agreement::ECDH_P384,
};

static KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &P256, &P384];

/// Signatures under the server's certificate, checked by rustls-webpki: ECDSA P-256 with
/// SHA-256 and P-384 with SHA-384, each curve with its own hash (the pairs of TLS 1.3).
#[derive(Debug)]
struct Verifier;

static VERIFIER: Verifier = Verifier;

impl SignatureVerifier for Verifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
    ) -> Result<(), CryptoError> {
        if sig_alg != SignatureAlgorithm::ECDSA {
            return Err(CryptoError::UnsupportedSignatureAlgorithm(sig_alg));
        }
        let algorithm: &dyn rustls::pki_types::SignatureVerificationAlgorithm = match hash_alg {
            HashAlgorithm::SHA256 => webpki::ring::ECDSA_P256_SHA256,
            HashAlgorithm::SHA384 => webpki::ring::ECDSA_P384_SHA384,
            _ => {
                return Err(CryptoError::UnsupportedSignaturePair {
                    signature: sig_alg,
                    hash: hash_alg,
                });
            }
        };
        let der = CertificateDer::from(cert_der);
        let cert = webpki::EndEntityCert::try_from(&der)
            .map_err(|_| CryptoError::CertificateParseFailed)?;
        // webpki refuses a key of another curve than the algorithm's.
        cert.verify_signature(algorithm, data, signature)
            .map_err(|_| failed(CryptoOperation::VerifySignature))
    }
}

/// PKCS#8 ECDSA keys.
#[derive(Debug)]
struct Keys;

static KEYS: Keys = Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKey>, CryptoError> {
        if key_der.is_empty() {
            return Ok(Box::new(NoKey));
        }
        let rng = ring::rand::SystemRandom::new();
        for (algorithm, hash) in [
            (
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                HashAlgorithm::SHA256,
            ),
            (
                &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                HashAlgorithm::SHA384,
            ),
        ] {
            if let Ok(pair) = ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, key_der, &rng) {
                return Ok(Box::new(Key { pair, hash: [hash] }));
            }
        }
        Err(CryptoError::InvalidPrivateKey)
    }
}

/// An ECDSA key, with the one hash it signs with.
struct Key {
    pair: ring::signature::EcdsaKeyPair,
    hash: [HashAlgorithm; 1],
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl SigningKey for Key {
    fn sign(
        &mut self,
        data: &[u8],
        hash_alg: HashAlgorithm,
        out: &mut Buf,
    ) -> Result<(), CryptoError> {
        if !self.hash.contains(&hash_alg) {
            return Err(failed(CryptoOperation::Sign));
        }
        let signature = self
            .pair
            .sign(&ring::rand::SystemRandom::new(), data)
            .map_err(|_| failed(CryptoOperation::Sign))?;
        out.clear();
        out.extend_from_slice(signature.as_ref());
        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash.first().copied().unwrap_or(HashAlgorithm::SHA256)
    }

    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        &self.hash
    }
}

/// The client's key: it signs nothing.
#[derive(Debug)]
struct NoKey;

impl SigningKey for NoKey {
    fn sign(&mut self, _: &[u8], _: HashAlgorithm, _: &mut Buf) -> Result<(), CryptoError> {
        Err(failed(CryptoOperation::Sign))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA256]
    }
}
