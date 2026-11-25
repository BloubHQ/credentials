//! HPKE (RFC 9180): every DHKEM of the registry (P-256, P-384, P-521, X25519, X448), every
//! HKDF (SHA-256, SHA-384, SHA-512), every AEAD (AES-128-GCM, AES-256-GCM,
//! ChaCha20-Poly1305) and export-only, in the four modes (base, psk, auth, auth_psk), with
//! single-shot seal, open and secret export on either side.
//!
//! Written over the primitives of the engine rather than the `hpke` crate, which has no X448
//! KEM. The key agreement is [`super::ecdh`]; the KDF is the `hkdf` crate; the AEADs are
//! `aes-gcm` and `chacha20poly1305`.

use hmac::Hmac;
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroize as _;
use zeroize::Zeroizing;

use super::{bad, ecdh, ecdh_public, generate};
use crate::template::Bytes;
use crate::{Error, Result};

/// Most bytes one export derives.
pub(crate) const MAX_EXPORT: usize = super::MAX_DERIVED;

/// A DHKEM of the registry, named by its curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kem {
    P256,
    P384,
    P521,
    X25519,
    X448,
}

impl Kem {
    fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"p256" => Kem::P256,
            b"p384" => Kem::P384,
            b"p521" => Kem::P521,
            b"x25519" => Kem::X25519,
            b"x448" => Kem::X448,
            _ => return Err(bad("unknown hpke kem")),
        })
    }

    fn id(self) -> u16 {
        match self {
            Kem::P256 => 0x0010,
            Kem::P384 => 0x0011,
            Kem::P521 => 0x0012,
            Kem::X25519 => 0x0020,
            Kem::X448 => 0x0021,
        }
    }

    /// The curve name of [`super::ecdh`].
    fn curve(self) -> &'static str {
        match self {
            Kem::P256 => "p256",
            Kem::P384 => "p384",
            Kem::P521 => "p521",
            Kem::X25519 => "x25519",
            Kem::X448 => "x448",
        }
    }

    /// The KDF of the KEM itself.
    fn kdf(self) -> Kdf {
        match self {
            Kem::P256 | Kem::X25519 => Kdf::Sha256,
            Kem::P384 => Kdf::Sha384,
            Kem::P521 | Kem::X448 => Kdf::Sha512,
        }
    }

    /// `Nsecret`.
    fn secret_len(self) -> usize {
        match self {
            Kem::P256 | Kem::X25519 => 32,
            Kem::P384 => 48,
            Kem::P521 | Kem::X448 => 64,
        }
    }

    /// `Npk` and `Nenc`.
    pub(crate) fn public_len(self) -> usize {
        match self {
            Kem::P256 => 65,
            Kem::P384 => 97,
            Kem::P521 => 133,
            Kem::X25519 => 32,
            Kem::X448 => 56,
        }
    }

    /// `Nsk`.
    fn private_len(self) -> usize {
        match self {
            Kem::P256 | Kem::X25519 => 32,
            Kem::P384 => 48,
            Kem::P521 => 66,
            Kem::X448 => 56,
        }
    }

    fn nist(self) -> bool {
        matches!(self, Kem::P256 | Kem::P384 | Kem::P521)
    }

    fn suite_id(self) -> [u8; 5] {
        let [hi, lo] = self.id().to_be_bytes();
        [b'K', b'E', b'M', hi, lo]
    }

    /// A public key as the KEM serializes it: uncompressed SEC1 for NIST curves.
    fn check_public(self, key: &[u8]) -> Result<()> {
        if key.len() != self.public_len() || (self.nist() && key.first() != Some(&4)) {
            return Err(Error::KeyInvalid);
        }
        Ok(())
    }

    /// A private key of `Nsk` bytes; NIST curves also take PKCS#8 DER.
    fn check_private(self, key: &[u8]) -> Result<()> {
        if key.len() != self.private_len() && !(self.nist() && key.len() > self.private_len()) {
            return Err(Error::KeyInvalid);
        }
        Ok(())
    }

    fn public(self, private: &[u8]) -> Result<Bytes> {
        self.check_private(private)?;
        ecdh_public(self.curve(), private)
    }

    fn dh(self, private: &[u8], public: &[u8]) -> Result<Bytes> {
        self.check_private(private)?;
        self.check_public(public)?;
        ecdh(self.curve(), public, private)
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 section 7.1.3): the private key.
    pub(crate) fn derive_private(self, ikm: &[u8]) -> Result<Bytes> {
        let suite = self.suite_id();
        let kdf = self.kdf();
        let prk = kdf.labeled_extract(&suite, b"", b"dkp_prk", &[ikm]);
        if !self.nist() {
            return kdf.labeled_expand(&suite, &prk, b"sk", &[], self.private_len());
        }
        let mask = if self == Kem::P521 { 0x01 } else { 0xff };
        for counter in 0u8..=255 {
            let mut candidate = kdf.labeled_expand(
                &suite,
                &prk,
                b"candidate",
                &[&[counter]],
                self.private_len(),
            )?;
            if let Some(first) = candidate.first_mut() {
                *first &= mask;
            }
            // Zero and values not below the order are refused by the public key computation.
            if self.public(&candidate).is_ok() {
                return Ok(candidate);
            }
        }
        Err(bad("hpke key derivation failed"))
    }

    fn extract_and_expand(self, dh: &[u8], context: &[&[u8]]) -> Result<Bytes> {
        let suite = self.suite_id();
        let kdf = self.kdf();
        let prk = kdf.labeled_extract(&suite, b"", b"eae_prk", &[dh]);
        kdf.labeled_expand(&suite, &prk, b"shared_secret", context, self.secret_len())
    }

    /// `Encap` or `AuthEncap` with the ephemeral private key `ephemeral`: the shared secret
    /// and `enc`.
    fn encap(
        self,
        recipient: &[u8],
        sender: Option<&[u8]>,
        ephemeral: &[u8],
    ) -> Result<(Bytes, Bytes)> {
        self.check_public(recipient)?;
        let enc = self.public(ephemeral)?;
        let mut dh = self.dh(ephemeral, recipient)?;
        let sender_public = match sender {
            Some(sender) => {
                let second = self.dh(sender, recipient)?;
                dh = concat(&[&dh, &second]);
                Some(self.public(sender)?)
            }
            None => None,
        };
        let shared = match &sender_public {
            Some(sender_public) => {
                self.extract_and_expand(&dh, &[&enc, recipient, sender_public])?
            }
            None => self.extract_and_expand(&dh, &[&enc, recipient])?,
        };
        Ok((shared, enc))
    }

    /// `Decap` or `AuthDecap`: the shared secret.
    fn decap(self, enc: &[u8], recipient: &[u8], sender: Option<&[u8]>) -> Result<Bytes> {
        self.check_public(enc)?;
        let recipient_public = self.public(recipient)?;
        let mut dh = self.dh(recipient, enc)?;
        if let Some(sender) = sender {
            let second = self.dh(recipient, sender)?;
            dh = concat(&[&dh, &second]);
            return self.extract_and_expand(&dh, &[enc, &recipient_public, sender]);
        }
        self.extract_and_expand(&dh, &[enc, &recipient_public])
    }
}

fn concat(parts: &[&[u8]]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
    parts.iter().for_each(|p| out.extend_from_slice(p));
    out
}

/// An HKDF of the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kdf {
    Sha256,
    Sha384,
    Sha512,
}

/// HKDF-Extract of the input key material given in parts.
fn extract<M: hkdf::HmacImpl>(salt: &[u8], parts: &[&[u8]]) -> Bytes {
    let mut extract = hkdf::GenericHkdfExtract::<M>::new(Some(salt));
    parts.iter().for_each(|p| extract.input_ikm(p));
    let (mut prk, _) = extract.finalize();
    let out = Zeroizing::new(prk.to_vec());
    prk.as_mut_slice().zeroize();
    out
}

/// HKDF-Expand of the info given in parts.
fn expand<M: hkdf::HmacImpl>(prk: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<()> {
    hkdf::GenericHkdf::<M>::from_prk(prk)
        .map_err(|_| Error::KeyInvalid)?
        .expand_multi_info(parts, out)
        .map_err(|_| bad("hpke length out of range"))
}

impl Kdf {
    fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"sha256" => Kdf::Sha256,
            b"sha384" => Kdf::Sha384,
            b"sha512" => Kdf::Sha512,
            _ => return Err(bad("unknown hpke kdf")),
        })
    }

    fn id(self) -> u16 {
        match self {
            Kdf::Sha256 => 1,
            Kdf::Sha384 => 2,
            Kdf::Sha512 => 3,
        }
    }

    /// `Nh`.
    fn len(self) -> usize {
        match self {
            Kdf::Sha256 => 32,
            Kdf::Sha384 => 48,
            Kdf::Sha512 => 64,
        }
    }

    /// `LabeledExtract(salt, label, ikm)`, the input key material given in parts.
    fn labeled_extract(self, suite: &[u8], salt: &[u8], label: &[u8], ikm: &[&[u8]]) -> Bytes {
        let mut parts: Vec<&[u8]> = vec![b"HPKE-v1", suite, label];
        parts.extend_from_slice(ikm);
        match self {
            Kdf::Sha256 => extract::<Hmac<Sha256>>(salt, &parts),
            Kdf::Sha384 => extract::<Hmac<Sha384>>(salt, &parts),
            Kdf::Sha512 => extract::<Hmac<Sha512>>(salt, &parts),
        }
    }

    /// `LabeledExpand(prk, label, info, length)`, the info given in parts.
    fn labeled_expand(
        self,
        suite: &[u8],
        prk: &[u8],
        label: &[u8],
        info: &[&[u8]],
        length: usize,
    ) -> Result<Bytes> {
        let size = u16::try_from(length).map_err(|_| bad("hpke length out of range"))?;
        let size = size.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&size, b"HPKE-v1", suite, label];
        parts.extend_from_slice(info);
        let mut out = Zeroizing::new(vec![0u8; length]);
        match self {
            Kdf::Sha256 => expand::<Hmac<Sha256>>(prk, &parts, &mut out)?,
            Kdf::Sha384 => expand::<Hmac<Sha384>>(prk, &parts, &mut out)?,
            Kdf::Sha512 => expand::<Hmac<Sha512>>(prk, &parts, &mut out)?,
        }
        Ok(out)
    }
}

/// An AEAD of the registry, or export-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    ExportOnly,
}

impl Aead {
    fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"aes128gcm" => Aead::Aes128Gcm,
            b"aes256gcm" => Aead::Aes256Gcm,
            b"chacha20poly1305" => Aead::ChaCha20Poly1305,
            b"export" => Aead::ExportOnly,
            _ => return Err(bad("unknown hpke aead")),
        })
    }

    fn id(self) -> u16 {
        match self {
            Aead::Aes128Gcm => 1,
            Aead::Aes256Gcm => 2,
            Aead::ChaCha20Poly1305 => 3,
            Aead::ExportOnly => 0xffff,
        }
    }

    /// `Nk`.
    fn key_len(self) -> usize {
        match self {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 32,
            Aead::ExportOnly => 0,
        }
    }

    /// `Nn`.
    fn nonce_len(self) -> usize {
        match self {
            Aead::ExportOnly => 0,
            _ => 12,
        }
    }

    fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Bytes> {
        match self {
            Aead::Aes128Gcm | Aead::Aes256Gcm => super::aes_gcm(key, nonce, plaintext, aad),
            Aead::ChaCha20Poly1305 => super::chacha20_poly1305(key, nonce, plaintext, aad),
            Aead::ExportOnly => Err(bad("hpke seal or open with the export-only aead")),
        }
    }

    fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Bytes> {
        use aes_gcm::aead::{Aead as _, KeyInit, Payload};
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let failed = |_| bad("hpke open failed");
        let out = match self {
            Aead::Aes128Gcm => {
                let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(nonce)
                    .map_err(|_| Error::KeyInvalid)?;
                aes_gcm::Aes128Gcm::new_from_slice(key)
                    .map_err(|_| Error::KeyInvalid)?
                    .decrypt(&nonce, payload)
                    .map_err(failed)?
            }
            Aead::Aes256Gcm => {
                let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(nonce)
                    .map_err(|_| Error::KeyInvalid)?;
                aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|_| Error::KeyInvalid)?
                    .decrypt(&nonce, payload)
                    .map_err(failed)?
            }
            Aead::ChaCha20Poly1305 => {
                use chacha20poly1305::aead::{Aead as _, KeyInit as _};
                let nonce =
                    chacha20poly1305::Nonce::try_from(nonce).map_err(|_| Error::KeyInvalid)?;
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| Error::KeyInvalid)?
                    .decrypt(
                        &nonce,
                        chacha20poly1305::aead::Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(failed)?
            }
            Aead::ExportOnly => return Err(bad("hpke seal or open with the export-only aead")),
        };
        Ok(Zeroizing::new(out))
    }
}

/// A cipher suite: `kem,kdf,aead`, as `x25519,sha256,chacha20poly1305`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suite {
    pub(crate) kem: Kem,
    kdf: Kdf,
    aead: Aead,
}

impl Suite {
    pub(crate) fn parse(text: &[u8]) -> Result<Self> {
        let mut parts = text.split(|b| *b == b',').map(<[u8]>::trim_ascii);
        let (Some(kem), Some(kdf), Some(aead), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("hpke suite is kem,kdf,aead"));
        };
        Ok(Self {
            kem: Kem::parse(kem)?,
            kdf: Kdf::parse(kdf)?,
            aead: Aead::parse(aead)?,
        })
    }

    fn id(self) -> [u8; 10] {
        let [k1, k2] = self.kem.id().to_be_bytes();
        let [d1, d2] = self.kdf.id().to_be_bytes();
        let [a1, a2] = self.aead.id().to_be_bytes();
        [b'H', b'P', b'K', b'E', k1, k2, d1, d2, a1, a2]
    }
}

/// The mode of a key schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Base,
    Psk,
    Auth,
    AuthPsk,
}

impl Mode {
    pub(crate) fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"base" => Mode::Base,
            b"psk" => Mode::Psk,
            b"auth" => Mode::Auth,
            b"auth_psk" => Mode::AuthPsk,
            _ => return Err(bad("unknown hpke mode")),
        })
    }

    fn id(self) -> u8 {
        match self {
            Mode::Base => 0,
            Mode::Psk => 1,
            Mode::Auth => 2,
            Mode::AuthPsk => 3,
        }
    }

    fn psk(self) -> bool {
        matches!(self, Mode::Psk | Mode::AuthPsk)
    }

    fn auth(self) -> bool {
        matches!(self, Mode::Auth | Mode::AuthPsk)
    }

    /// How many arguments follow the fixed ones: the PSK and its id, then the sender's key.
    pub(crate) fn extras(self) -> usize {
        usize::from(self.psk()) * 2 + usize::from(self.auth())
    }
}

/// What the mode adds: a PSK with its id, and the sender's key (private on the sending side,
/// public on the receiving side).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Extras<'a> {
    pub(crate) psk: Option<(&'a [u8], &'a [u8])>,
    pub(crate) sender: Option<&'a [u8]>,
}

impl<'a> Extras<'a> {
    /// The extras of `mode` from the arguments after the fixed ones.
    pub(crate) fn of(mode: Mode, rest: &'a [Bytes]) -> Result<Self> {
        if rest.len() != mode.extras() {
            return Err(bad("hpke arguments do not match the mode"));
        }
        let at = |i: usize| rest.get(i).map(|v| v.as_slice());
        let psk = if mode.psk() {
            match (at(0), at(1)) {
                (Some(psk), Some(id)) => Some((psk, id)),
                _ => return Err(bad("hpke arguments do not match the mode")),
            }
        } else {
            None
        };
        let sender = if mode.auth() {
            Some(at(mode.extras() - 1).ok_or(bad("hpke arguments do not match the mode"))?)
        } else {
            None
        };
        Ok(Self { psk, sender })
    }
}

/// The context of one side after the key schedule.
pub(crate) struct Context {
    suite: Suite,
    key: Bytes,
    base_nonce: Bytes,
    exporter_secret: Bytes,
    seq: u64,
}

/// `KeySchedule` (RFC 9180 section 5.1).
fn key_schedule(
    suite: Suite,
    mode: Mode,
    shared: &[u8],
    info: &[u8],
    psk: Option<(&[u8], &[u8])>,
) -> Result<Context> {
    let (psk, psk_id) = psk.unwrap_or((b"", b""));
    // RFC 9180 VerifyPSKInputs: a PSK and its id both or neither, as the mode says. A PSK
    // shorter than 32 bytes is refused (section 9.5 asks for at least 32 bytes of entropy).
    if mode.psk() && (psk.len() < 32 || psk_id.is_empty()) {
        return Err(bad("hpke psk of at least 32 bytes and a psk id"));
    }
    let id = suite.id();
    let kdf = suite.kdf;
    let psk_id_hash = kdf.labeled_extract(&id, b"", b"psk_id_hash", &[psk_id]);
    let info_hash = kdf.labeled_extract(&id, b"", b"info_hash", &[info]);
    let mode_byte = [mode.id()];
    let context: [&[u8]; 3] = [&mode_byte, &psk_id_hash, &info_hash];
    let secret = kdf.labeled_extract(&id, shared, b"secret", &[psk]);
    let key = kdf.labeled_expand(&id, &secret, b"key", &context, suite.aead.key_len())?;
    let base_nonce = kdf.labeled_expand(
        &id,
        &secret,
        b"base_nonce",
        &context,
        suite.aead.nonce_len(),
    )?;
    let exporter_secret = kdf.labeled_expand(&id, &secret, b"exp", &context, kdf.len())?;
    Ok(Context {
        suite,
        key,
        base_nonce,
        exporter_secret,
        seq: 0,
    })
}

impl Context {
    /// The sending side, with the ephemeral key `ephemeral` (fresh for each use but in the
    /// known-answer tests): the context and `enc`.
    pub(crate) fn sender(
        suite: Suite,
        mode: Mode,
        recipient: &[u8],
        info: &[u8],
        extras: Extras<'_>,
        ephemeral: &[u8],
    ) -> Result<(Self, Bytes)> {
        let (shared, enc) = suite.kem.encap(recipient, extras.sender, ephemeral)?;
        Ok((key_schedule(suite, mode, &shared, info, extras.psk)?, enc))
    }

    /// The sending side with a fresh ephemeral key.
    pub(crate) fn sender_fresh(
        suite: Suite,
        mode: Mode,
        recipient: &[u8],
        info: &[u8],
        extras: Extras<'_>,
    ) -> Result<(Self, Bytes)> {
        let ephemeral = generate(suite.kem.curve())?;
        Self::sender(suite, mode, recipient, info, extras, &ephemeral)
    }

    /// The receiving side.
    pub(crate) fn receiver(
        suite: Suite,
        mode: Mode,
        recipient: &[u8],
        enc: &[u8],
        info: &[u8],
        extras: Extras<'_>,
    ) -> Result<Self> {
        let shared = suite.kem.decap(enc, recipient, extras.sender)?;
        key_schedule(suite, mode, &shared, info, extras.psk)
    }

    fn nonce(&self) -> Result<Bytes> {
        let mut nonce = self.base_nonce.clone();
        let seq = self.seq.to_be_bytes();
        let offset = nonce
            .len()
            .checked_sub(seq.len())
            .ok_or(bad("hpke nonce"))?;
        for (n, s) in nonce.iter_mut().skip(offset).zip(seq) {
            *n ^= s;
        }
        Ok(nonce)
    }

    fn next(&mut self) -> Result<()> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(bad("hpke sequence overflow"))?;
        Ok(())
    }

    /// `ContextS.Seal(aad, pt)`.
    pub(crate) fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Bytes> {
        let out = self
            .suite
            .aead
            .seal(&self.key, &self.nonce()?, aad, plaintext)?;
        self.next()?;
        Ok(out)
    }

    /// `ContextR.Open(aad, ct)`.
    pub(crate) fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Bytes> {
        let out = self
            .suite
            .aead
            .open(&self.key, &self.nonce()?, aad, ciphertext)?;
        self.next()?;
        Ok(out)
    }

    /// `Context.Export(exporter_context, L)`.
    pub(crate) fn export(&self, context: &[u8], length: usize) -> Result<Bytes> {
        let id = self.suite.id();
        if length == 0 || length > MAX_EXPORT.min(255 * self.suite.kdf.len()) {
            return Err(bad("hpke length out of range"));
        }
        self.suite
            .kdf
            .labeled_expand(&id, &self.exporter_secret, b"sec", &[context], length)
    }

    /// The key, base nonce and exporter secret, for the known-answer tests.
    #[cfg(test)]
    pub(crate) fn secrets(&self) -> (&[u8], &[u8], &[u8]) {
        (&self.key, &self.base_nonce, &self.exporter_secret)
    }

    /// Sets the sequence number, for the known-answer tests.
    #[cfg(test)]
    pub(crate) fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }
}

/// The template functions. `args` start with the suite and the mode.
pub(super) fn seal(args: &[Bytes]) -> Result<Bytes> {
    let (suite, mode, rest) = head(args, 6)?;
    let [recipient, info, aad, plaintext] = fixed(rest)?;
    let extras = Extras::of(mode, rest.get(4..).unwrap_or_default())?;
    let (mut context, enc) = Context::sender_fresh(suite, mode, recipient, info, extras)?;
    let sealed = context.seal(aad, plaintext)?;
    Ok(concat(&[&enc, &sealed]))
}

pub(super) fn open(args: &[Bytes]) -> Result<Bytes> {
    let (suite, mode, rest) = head(args, 7)?;
    let [recipient, enc, info, aad, ciphertext] = fixed(rest)?;
    let extras = Extras::of(mode, rest.get(5..).unwrap_or_default())?;
    Context::receiver(suite, mode, recipient, enc, info, extras)?.open(aad, ciphertext)
}

pub(super) fn export(args: &[Bytes]) -> Result<Bytes> {
    let (suite, mode, rest) = head(args, 6)?;
    let [recipient, info, context, length] = fixed(rest)?;
    let extras = Extras::of(mode, rest.get(4..).unwrap_or_default())?;
    let length = super::kdf::length(length, MAX_EXPORT)?;
    let (sender, enc) = Context::sender_fresh(suite, mode, recipient, info, extras)?;
    let secret = sender.export(context, length)?;
    Ok(concat(&[&enc, &secret]))
}

pub(super) fn receiver_export(args: &[Bytes]) -> Result<Bytes> {
    let (suite, mode, rest) = head(args, 7)?;
    let [recipient, enc, info, context, length] = fixed(rest)?;
    let extras = Extras::of(mode, rest.get(5..).unwrap_or_default())?;
    let length = super::kdf::length(length, MAX_EXPORT)?;
    Context::receiver(suite, mode, recipient, enc, info, extras)?.export(context, length)
}

/// The suite, the mode and the arguments after them; at least `min` arguments in all.
fn head(args: &[Bytes], min: usize) -> Result<(Suite, Mode, &[Bytes])> {
    if args.len() < min {
        return Err(bad("missing argument"));
    }
    let (Some(suite), Some(mode), Some(rest)) = (args.first(), args.get(1), args.get(2..)) else {
        return Err(bad("missing argument"));
    };
    Ok((Suite::parse(suite)?, Mode::parse(mode)?, rest))
}

/// The first `N` arguments of `rest`.
fn fixed<const N: usize>(rest: &[Bytes]) -> Result<[&[u8]; N]> {
    let mut out = [&[][..]; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = rest.get(i).ok_or(bad("missing argument"))?.as_slice();
    }
    Ok(out)
}

/// `hpke_public(kem, private_key)`: the serialized public key of a KEM private key.
pub(super) fn public(kem: &[u8], private: &[u8]) -> Result<Bytes> {
    Kem::parse(kem)?.public(private)
}

/// `hpke_derive_key(kem, ikm)`: the private key of `DeriveKeyPair` (RFC 9180 section 7.1.3).
pub(super) fn derive_key(kem: &[u8], ikm: &[u8]) -> Result<Bytes> {
    // RFC 9180 section 7.1.3: the key material should hold at least Nsk bytes of entropy.
    if ikm.len() < 32 {
        return Err(bad(
            "hpke_derive_key needs at least 32 bytes of key material",
        ));
    }
    Kem::parse(kem)?.derive_private(ikm)
}
