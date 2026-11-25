//! The 12-round Keccak family of RFC 9861: TurboSHAKE128 and TurboSHAKE256 (the
//! Keccak-p[1600, 12] sponge with a domain separation byte), and KangarooTwelve (KT128 and
//! KT256, with a customization string).
//!
//! TurboSHAKE is written here over the permutation of the `keccak` crate because its domain
//! byte is a run-time argument (the `turboshake` crate takes it as a type parameter);
//! KangarooTwelve is the `k12` crate, which builds its tree over the same permutation.

use k12::digest::{ExtendableOutput as _, Update as _, XofReader as _};
use zeroize::Zeroizing;

use super::bad;
use crate::Result;
use crate::template::Bytes;

/// Rounds of Keccak-p[1600, n_r] in TurboSHAKE.
const ROUNDS: usize = 12;
/// Lanes of the Keccak state.
const LANES: usize = 25;

/// The rate in bytes of a security level: 168 for 128-bit, 136 for 256-bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    /// TurboSHAKE128, KT128.
    L128,
    /// TurboSHAKE256, KT256.
    L256,
}

impl Level {
    fn rate(self) -> usize {
        match self {
            Level::L128 => 168,
            Level::L256 => 136,
        }
    }
}

/// XORs a block of the rate into the first lanes of the state.
fn absorb(state: &mut [u64; LANES], block: &[u8]) {
    for (lane, bytes) in state.iter_mut().zip(block.chunks(8)) {
        let mut word = [0u8; 8];
        for (w, b) in word.iter_mut().zip(bytes) {
            *w = *b;
        }
        *lane ^= u64::from_le_bytes(word);
    }
}

/// Copies the first lanes of the state into `out` (at most the rate).
fn squeeze(state: &[u64; LANES], out: &mut [u8]) {
    for (bytes, lane) in out.chunks_mut(8).zip(state.iter()) {
        for (o, b) in bytes.iter_mut().zip(lane.to_le_bytes()) {
            *o = b;
        }
    }
}

/// TurboSHAKE (RFC 9861 section 2.2) of `message` with domain byte `domain` (0x01 to 0x7F)
/// into `out`.
pub(crate) fn turboshake_into(level: Level, message: &[u8], domain: u8, out: &mut [u8]) {
    let rate = level.rate();
    let mut state = Zeroizing::new([0u64; LANES]);
    let mut last = Zeroizing::new([0u8; 168]);
    keccak::Keccak::new().with_p1600::<ROUNDS>(|permute| {
        let mut blocks = message.chunks_exact(rate);
        for block in &mut blocks {
            absorb(&mut state, block);
            permute(&mut state);
        }
        let rest = blocks.remainder();
        for (l, b) in last.iter_mut().zip(rest) {
            *l = *b;
        }
        if let Some(byte) = last.get_mut(rest.len()) {
            *byte ^= domain;
        }
        if let Some(byte) = last.get_mut(rate - 1) {
            *byte ^= 0x80;
        }
        absorb(&mut state, last.get(..rate).unwrap_or_default());
        permute(&mut state);
        let mut chunks = out.chunks_mut(rate);
        if let Some(first) = chunks.next() {
            squeeze(&state, first);
        }
        for chunk in chunks {
            permute(&mut state);
            squeeze(&state, chunk);
        }
    });
}

/// KangarooTwelve (RFC 9861 section 3.2) of `message` with customization `custom` into
/// `out`.
pub(crate) fn kt_into(level: Level, message: &[u8], custom: &[u8], out: &mut [u8]) {
    match level {
        Level::L128 => {
            let mut hasher = k12::CustomRefKt128::new_customized(custom);
            hasher.update(message);
            hasher.finalize_xof().read(out);
        }
        Level::L256 => {
            let mut hasher = k12::CustomRefKt256::new_customized(custom);
            hasher.update(message);
            hasher.finalize_xof().read(out);
        }
    }
}

/// A domain byte argument: decimal, 1 to 127.
fn domain(text: &[u8]) -> Result<u8> {
    core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .filter(|d| (1..=0x7f).contains(d))
        .ok_or(bad("turboshake domain byte of 1 to 127"))
}

/// `turboshake128(message, domain, length)` and `turboshake256(...)`.
pub(super) fn turboshake(
    level: Level,
    message: &[u8],
    domain_byte: &[u8],
    len: &[u8],
) -> Result<Bytes> {
    let domain = domain(domain_byte)?;
    let len = super::kdf::length(len, super::MAX_DERIVED)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    turboshake_into(level, message, domain, &mut out);
    Ok(out)
}

/// `kt128(message, customization, length)` and `kt256(...)`.
pub(super) fn kt(level: Level, message: &[u8], custom: &[u8], len: &[u8]) -> Result<Bytes> {
    let len = super::kdf::length(len, super::MAX_DERIVED)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    kt_into(level, message, custom, &mut out);
    Ok(out)
}
