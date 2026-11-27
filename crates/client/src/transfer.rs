//! Device transfer with a 6-digit code: the old phone shows a code, the person types it on
//! the new phone, and the keys move from one to the other through any relay (the app's
//! server, a QR code, a local link) that cannot read or change them.
//!
//! A 6-digit code is a million guesses, so it must not be testable offline. The two devices
//! run SPAKE2 (RustCrypto `spake2`, Ed25519 group) on the code: someone who records every
//! message learns nothing they can test a guess against, and someone who takes part guesses
//! once per run. Key confirmation follows SPAKE2 (which has none), with HMAC-SHA256 over the
//! transcript under keys derived from its shared secret by HKDF-SHA256:
//!
//! 1. old device: [`start_transfer`], shows [`TransferSender::code`], sends
//!    [`TransferSender::offer`] (`{session, message}`);
//! 2. new device: [`join_transfer`] with the code typed and the offer, sends
//!    [`TransferReceiver::answer`] (`{session, message, confirm}`);
//! 3. old device: [`TransferSender::seal`] checks the confirmation (a wrong code or a changed
//!    message fails it) and sends the keys sealed under the shared key
//!    (`{session, confirm, nonce, ciphertext}`, XChaCha20-Poly1305 with the transcript as
//!    additional data);
//! 4. new device: [`TransferReceiver::open`] checks the old device's confirmation and opens
//!    the keys.
//!
//! Limits: a code allows [`MAX_ATTEMPTS`] failed confirmations, then the old device refuses
//! until a new transfer (a new code) starts; a transfer lasts [`TRANSFER_TTL_MS`]; each side
//! seals or opens once. An attacker who takes part therefore wins with a chance of at most
//! 3 in a million per code shown.

use std::sync::{Arc, Mutex, PoisonError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::backup::{BackedUpKey, PlainKey, encode_keys, from_plain};
use crate::error::{ClientError, Result};
use crate::time::now_ms;

/// Failed confirmations one code allows.
pub const MAX_ATTEMPTS: u32 = 3;
/// How long a transfer lasts: five minutes.
pub const TRANSFER_TTL_MS: u64 = 5 * 60 * 1000;
/// The largest message read, in bytes.
pub const MAX_TRANSFER_MESSAGE: usize = 64 * 1024;

const ID_OLD: &[u8] = b"credentials transfer/v1 old device";
const ID_NEW: &[u8] = b"credentials transfer/v1 new device";
const KEYS_INFO: &[u8] = b"credentials transfer/v1 keys";
const SESSION_LEN: usize = 16;

fn refused(detail: impl Into<String>) -> ClientError {
    ClientError::TransferRefused {
        detail: detail.into(),
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| ClientError::Refused {
        detail: format!("no random source: {e}"),
    })?;
    Ok(bytes)
}

/// A uniform 6-digit code.
fn new_code() -> Result<Zeroizing<String>> {
    loop {
        let n = u32::from_be_bytes(random::<4>()?);
        // 4_294_000_000 is the largest multiple of 10^6 below 2^32: no bias.
        if n < 4_294_000_000 {
            return Ok(Zeroizing::new(format!("{:06}", n % 1_000_000)));
        }
    }
}

fn check_code(code: &str) -> Result<()> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ClientError::input("the code is 6 digits"));
    }
    Ok(())
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(super) fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::URL_SAFE_NO_PAD.encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        super::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| de::Error::custom("invalid base64url"))
    }
}

/// Message 1.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Offer {
    #[serde(with = "b64")]
    session: Vec<u8>,
    #[serde(with = "b64")]
    message: Vec<u8>,
}

/// Message 2.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Answer {
    #[serde(with = "b64")]
    session: Vec<u8>,
    #[serde(with = "b64")]
    message: Vec<u8>,
    #[serde(with = "b64")]
    confirm: Vec<u8>,
}

/// Message 3.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sealed {
    #[serde(with = "b64")]
    session: Vec<u8>,
    #[serde(with = "b64")]
    confirm: Vec<u8>,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    owner: String,
    keys: Vec<PlainKey>,
}

fn parse<T: serde::de::DeserializeOwned>(json: &str, what: &str) -> Result<T> {
    if json.len() > MAX_TRANSFER_MESSAGE {
        return Err(ClientError::input(format!("{what}: too long")));
    }
    serde_json::from_str(json).map_err(ClientError::json(what))
}

/// What both sides derive from the run.
struct Keys {
    transcript: [u8; 32],
    confirm_new: Zeroizing<[u8; 32]>,
    confirm_old: Zeroizing<[u8; 32]>,
    seal: Zeroizing<[u8; 32]>,
}

impl Keys {
    fn derive(shared: &[u8], session: &[u8], offer: &[u8], answer: &[u8]) -> Result<Self> {
        let mut hash = Sha256::new();
        for part in [
            b"credentials transfer/v1".as_slice(),
            session,
            offer,
            answer,
        ] {
            hash.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            hash.update(part);
        }
        let transcript: [u8; 32] = hash.finalize().into();
        let mut okm = Zeroizing::new([0u8; 96]);
        hkdf::Hkdf::<Sha256>::new(Some(&transcript), shared)
            .expand(KEYS_INFO, okm.as_mut_slice())
            .map_err(|_| refused("cannot derive the transfer keys"))?;
        let mut keys = Self {
            transcript,
            confirm_new: Zeroizing::new([0; 32]),
            confirm_old: Zeroizing::new([0; 32]),
            seal: Zeroizing::new([0; 32]),
        };
        for (i, slot) in [&mut keys.confirm_new, &mut keys.confirm_old, &mut keys.seal]
            .into_iter()
            .enumerate()
        {
            let part = okm
                .get(i * 32..i * 32 + 32)
                .ok_or_else(|| refused("cannot derive the transfer keys"))?;
            slot.copy_from_slice(part);
        }
        Ok(keys)
    }

    fn mac(key: &[u8; 32], role: &[u8], transcript: &[u8; 32]) -> Result<Hmac<Sha256>> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
            .map_err(|_| refused("cannot derive the transfer keys"))?;
        mac.update(role);
        mac.update(transcript);
        Ok(mac)
    }

    fn confirm(&self, new_device: bool) -> Result<Vec<u8>> {
        let (key, role) = if new_device {
            (&self.confirm_new, ID_NEW)
        } else {
            (&self.confirm_old, ID_OLD)
        };
        Ok(Self::mac(key, role, &self.transcript)?
            .finalize()
            .into_bytes()
            .to_vec())
    }

    /// Checks a confirmation in constant time.
    fn check(&self, new_device: bool, confirm: &[u8]) -> bool {
        let (key, role) = if new_device {
            (&self.confirm_new, ID_NEW)
        } else {
            (&self.confirm_old, ID_OLD)
        };
        Self::mac(key, role, &self.transcript).is_ok_and(|mac| mac.verify_slice(confirm).is_ok())
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.seal.as_slice())
            .map_err(|_| refused("cannot derive the transfer keys"))
    }
}

struct SenderState {
    attempts: u32,
    run: Option<(Spake2<Ed25519Group>, Vec<u8>)>,
    done: bool,
}

/// The old device's side of a transfer. See the module documentation.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Object))]
pub struct TransferSender {
    code: Zeroizing<String>,
    session: [u8; SESSION_LEN],
    created_ms: u64,
    state: Mutex<SenderState>,
}

impl std::fmt::Debug for TransferSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferSender").finish_non_exhaustive()
    }
}

/// Starts a transfer on the old device, with a new random code.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn start_transfer() -> Result<Arc<TransferSender>> {
    TransferSender::new(now_ms()).map(Arc::new)
}

impl TransferSender {
    pub(crate) fn new(now: u64) -> Result<Self> {
        Ok(Self {
            code: new_code()?,
            session: random()?,
            created_ms: now,
            state: Mutex::new(SenderState {
                attempts: 0,
                run: None,
                done: false,
            }),
        })
    }

    fn usable(&self, state: &SenderState, now: u64) -> Result<()> {
        if state.done {
            return Err(refused("this transfer is done: start a new one"));
        }
        if state.attempts >= MAX_ATTEMPTS {
            return Err(refused(
                "too many wrong codes: start a new transfer, with a new code",
            ));
        }
        if now.saturating_sub(self.created_ms) > TRANSFER_TTL_MS {
            return Err(refused(
                "the transfer is older than five minutes: start a new one",
            ));
        }
        Ok(())
    }

    pub(crate) fn offer_at(&self, now: u64) -> Result<String> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.usable(&state, now)?;
        let (spake, message) = Spake2::<Ed25519Group>::start_a(
            &Password::new(self.code.as_bytes()),
            &Identity::new(ID_OLD),
            &Identity::new(ID_NEW),
        );
        state.run = Some((spake, message.clone()));
        crate::owner::to_json(&Offer {
            session: self.session.to_vec(),
            message,
        })
    }

    pub(crate) fn seal_at(
        &self,
        answer_json: &str,
        owner: &str,
        keys: Vec<BackedUpKey>,
        now: u64,
    ) -> Result<String> {
        let plain_keys = encode_keys(keys)?;
        let answer: Answer = parse(answer_json, "transfer answer")?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.usable(&state, now)?;
        let (spake, offer) = state
            .run
            .take()
            .ok_or_else(|| refused("no offer is waiting for this answer: send an offer"))?;
        // Counted before it is checked: every answer is a guess.
        state.attempts = state.attempts.saturating_add(1);
        let left = MAX_ATTEMPTS.saturating_sub(state.attempts);
        let wrong = || {
            refused(format!(
                "the code was wrong, or a message was changed on the way ({left} attempts left)"
            ))
        };
        if answer.session != self.session {
            return Err(wrong());
        }
        let shared = Zeroizing::new(spake.finish(&answer.message).map_err(|_| wrong())?);
        let derived = Keys::derive(&shared, &self.session, &offer, &answer.message)?;
        if !derived.check(true, &answer.confirm) {
            return Err(wrong());
        }
        state.done = true;
        drop(state);
        // {"owner": <owner>, "keys": <the keys, as a backup holds them>}
        // Sized up front: a buffer that grew would free a copy of the keys before it, unwiped.
        let owner_json =
            serde_json::to_vec(owner).map_err(|_| refused("cannot encode the owner"))?;
        let mut contents = Zeroizing::new(Vec::with_capacity(
            owner_json
                .len()
                .saturating_add(plain_keys.len())
                .saturating_add(32),
        ));
        contents.extend_from_slice(b"{\"owner\":");
        contents.extend_from_slice(&owner_json);
        contents.extend_from_slice(b",\"keys\":");
        contents.extend_from_slice(&plain_keys);
        contents.push(b'}');
        let nonce: [u8; 24] = random()?;
        let ciphertext = derived
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &contents,
                    aad: &derived.transcript,
                },
            )
            .map_err(|_| refused("cannot encrypt the keys"))?;
        crate::owner::to_json(&Sealed {
            session: self.session.to_vec(),
            confirm: derived.confirm(false)?,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
impl TransferSender {
    /// The code to show on the old device, for the person to type on the new one.
    pub fn code(&self) -> String {
        String::from(self.code.as_str())
    }

    /// Message 1, to send to the new device. Each call starts a new run on the same code (to
    /// try again after a wrong code); an answer is checked against the latest offer only.
    pub fn offer(&self) -> Result<String> {
        self.offer_at(now_ms())
    }

    /// Message 3: checks the new device's answer and seals `keys` of `owner` to it. A wrong
    /// code counts against [`MAX_ATTEMPTS`]. The keys are erased.
    pub fn seal(
        &self,
        answer_json: String,
        owner: String,
        keys: Vec<BackedUpKey>,
    ) -> Result<String> {
        self.seal_at(&answer_json, &owner, keys, now_ms())
    }

    /// Failed confirmations left for this code.
    pub fn attempts_left(&self) -> u32 {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        MAX_ATTEMPTS.saturating_sub(state.attempts)
    }
}

/// The keys a transfer brought.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
#[derive(Debug)]
pub struct TransferredKeys {
    /// The owner they belong to.
    pub owner: String,
    /// The keys: put them in protected storage.
    pub keys: Vec<BackedUpKey>,
}

struct ReceiverState {
    keys: Option<Keys>,
}

/// The new device's side of a transfer. See the module documentation.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Object))]
pub struct TransferReceiver {
    session: Vec<u8>,
    answer: String,
    created_ms: u64,
    state: Mutex<ReceiverState>,
}

impl std::fmt::Debug for TransferReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferReceiver").finish_non_exhaustive()
    }
}

/// Joins a transfer on the new device with the `code` the person typed and the old device's
/// offer. The code is erased.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn join_transfer(code: String, offer_json: String) -> Result<Arc<TransferReceiver>> {
    TransferReceiver::join(code, &offer_json, now_ms()).map(Arc::new)
}

impl TransferReceiver {
    pub(crate) fn join(mut code: String, offer_json: &str, now: u64) -> Result<Self> {
        let checked = check_code(&code);
        let code = Zeroizing::new(std::mem::take(&mut code));
        checked?;
        let offer: Offer = parse(offer_json, "transfer offer")?;
        if offer.session.len() != SESSION_LEN {
            return Err(ClientError::input(
                "transfer offer: the session is not 16 bytes",
            ));
        }
        let (spake, message) = Spake2::<Ed25519Group>::start_b(
            &Password::new(code.as_bytes()),
            &Identity::new(ID_OLD),
            &Identity::new(ID_NEW),
        );
        let shared = Zeroizing::new(
            spake
                .finish(&offer.message)
                .map_err(|_| refused("the offer is not a transfer message"))?,
        );
        let keys = Keys::derive(&shared, &offer.session, &offer.message, &message)?;
        let answer = crate::owner::to_json(&Answer {
            session: offer.session.clone(),
            message,
            confirm: keys.confirm(true)?,
        })?;
        Ok(Self {
            session: offer.session,
            answer,
            created_ms: now,
            state: Mutex::new(ReceiverState { keys: Some(keys) }),
        })
    }

    pub(crate) fn open_at(&self, sealed_json: &str, now: u64) -> Result<TransferredKeys> {
        let sealed: Sealed = parse(sealed_json, "sealed transfer")?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if now.saturating_sub(self.created_ms) > TRANSFER_TTL_MS {
            state.keys = None;
            return Err(refused(
                "the transfer is older than five minutes: start again",
            ));
        }
        // One try: whatever happens, this run is spent.
        let keys = state
            .keys
            .take()
            .ok_or_else(|| refused("this transfer was already opened, or failed: start again"))?;
        drop(state);
        if sealed.session != self.session || !keys.check(false, &sealed.confirm) {
            return Err(refused(
                "the old device's confirmation does not match: a wrong code or a changed message",
            ));
        }
        let nonce: [u8; 24] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::input("sealed transfer: the nonce is not 24 bytes"))?;
        let plain = keys
            .cipher()?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &keys.transcript,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| refused("the keys were changed on the way"))?;
        let contents: Contents = serde_json::from_slice(&plain)
            .map_err(|_| refused("the transfer does not hold keys"))?;
        Ok(TransferredKeys {
            keys: from_plain(&contents.keys)?,
            owner: contents.owner,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
impl TransferReceiver {
    /// Message 2, to send back to the old device.
    pub fn answer(&self) -> String {
        self.answer.clone()
    }

    /// Message 4: checks the old device's confirmation and opens the keys. Once.
    pub fn open(&self, sealed_json: String) -> Result<TransferredKeys> {
        self.open_at(&sealed_json, now_ms())
    }
}
