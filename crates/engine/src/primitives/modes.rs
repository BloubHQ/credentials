//! AES modes beyond GCM and CBC: key wrapping (RFC 3394, RFC 5649), AES-CBC with
//! HMAC-SHA-2 (RFC 7518 section 5.2), CCM (NIST SP 800-38C, RFC 3610), EAX, CBC-MAC, CMAC
//! (RFC 4493), ciphertext stealing as Kerberos uses it (RFC 3962), and the Kerberos key
//! derivation of RFC 3961 (n-fold and DK) over AES.
//!
//! Key wrapping, EAX, CMAC and ciphertext stealing are the RustCrypto crates. CCM and CBC-MAC
//! are written here over the `aes` block cipher, so that every tag and nonce size of
//! SP 800-38C is one function instead of 49 instances of the `ccm` crate's types per key size;
//! the tests compare it with the `ccm` crate on every size.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};

use super::bad;
use crate::template::Bytes;
use crate::{Error, Result};

const BLOCK: usize = 16;

/// AES with a key size chosen at run time.
pub(super) enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    /// AES under a 16-, 24- or 32-byte key.
    pub(super) fn new(key: &[u8]) -> Result<Self> {
        let invalid = |_| Error::KeyInvalid;
        Ok(match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).map_err(invalid)?),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).map_err(invalid)?),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).map_err(invalid)?),
            _ => return Err(Error::KeyInvalid),
        })
    }

    /// Encrypts one block in place.
    fn encrypt(&self, block: &mut [u8; BLOCK]) {
        let mut b = aes::Block::from(*block);
        match self {
            Aes::A128(c) => c.encrypt_block(&mut b),
            Aes::A192(c) => c.encrypt_block(&mut b),
            Aes::A256(c) => c.encrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
        b.as_mut_slice().zeroize();
    }
}

fn xor_into(block: &mut [u8; BLOCK], bytes: &[u8]) {
    block.iter_mut().zip(bytes).for_each(|(b, x)| *b ^= x);
}

/// CBC-MAC with a zero IV over `parts` as one message, each part padded with zero bytes to a
/// whole block; the last block of the chain.
fn cbc_mac_blocks(aes: &Aes, parts: &[&[u8]]) -> [u8; BLOCK] {
    let mut state = [0u8; BLOCK];
    for part in parts {
        for chunk in part.chunks(BLOCK) {
            xor_into(&mut state, chunk);
            aes.encrypt(&mut state);
        }
    }
    state
}

/// `aes_cbc_mac(key, message)`: CBC-MAC with a zero IV, the message padded with zero bytes
/// to a whole block (an empty message is one zero block), as COSE AES-MAC (RFC 9053 section
/// 3.2) computes it. The full 16-byte tag; COSE's 64-bit tags are its first 8 bytes.
pub(super) fn cbc_mac(key: &[u8], message: &[u8]) -> Result<Bytes> {
    let aes = Aes::new(key)?;
    let zero = [0u8; BLOCK];
    let parts: [&[u8]; 1] = [if message.is_empty() { &zero } else { message }];
    let mut tag = cbc_mac_blocks(&aes, &parts);
    let out = Zeroizing::new(tag.to_vec());
    tag.zeroize();
    Ok(out)
}

/// `aes_cmac(key, message)`: CMAC (NIST SP 800-38B, RFC 4493), 16 bytes.
pub(super) fn cmac(key: &[u8], message: &[u8]) -> Result<Bytes> {
    use cmac::Cmac;
    match key.len() {
        16 => super::mac::<Cmac<aes::Aes128>>(key, message),
        24 => super::mac::<Cmac<aes::Aes192>>(key, message),
        32 => super::mac::<Cmac<aes::Aes256>>(key, message),
        _ => Err(Error::KeyInvalid),
    }
}

/// `aes_ccm_encrypt(key, nonce, tag_length, message[, aad])`: CCM (NIST SP 800-38C). The
/// nonce is 7 to 13 bytes, which sets the length field to 15 minus its length; the tag 4 to
/// 16 bytes, even. The ciphertext, then the tag.
pub(super) fn ccm(
    key: &[u8],
    nonce: &[u8],
    tag_len: usize,
    message: &[u8],
    aad: &[u8],
) -> Result<Bytes> {
    if !(7..=13).contains(&nonce.len()) {
        return Err(bad("aes_ccm_encrypt takes a nonce of 7 to 13 bytes"));
    }
    if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) {
        return Err(bad("aes_ccm_encrypt takes a tag of 4 to 16 bytes, even"));
    }
    let aes = Aes::new(key)?;
    let q = 15 - nonce.len();
    // The message length must fit the length field of q bytes.
    let length = u64::try_from(message.len()).map_err(|_| bad("aes_ccm_encrypt length"))?;
    if q < 8 && length >> (8 * q) != 0 {
        return Err(bad("aes_ccm_encrypt of a message too long for the nonce"));
    }
    // B0: flags, nonce, message length.
    let mut b0 = [0u8; BLOCK];
    let tag_bits = u8::try_from((tag_len - 2) / 2).map_err(|_| bad("tag"))?;
    let q_bits = u8::try_from(q - 1).map_err(|_| bad("nonce"))?;
    b0[0] = (u8::from(!aad.is_empty()) << 6) | (tag_bits << 3) | q_bits;
    b0.get_mut(1..1 + nonce.len())
        .ok_or(bad("nonce"))?
        .copy_from_slice(nonce);
    let be = length.to_be_bytes();
    b0.get_mut(BLOCK - q..)
        .ok_or(bad("nonce"))?
        .copy_from_slice(be.get(8 - q..).ok_or(bad("nonce"))?);
    // The associated data, after its encoded length.
    let aad_len = u64::try_from(aad.len()).map_err(|_| bad("aes_ccm_encrypt length"))?;
    let mut prefixed = Zeroizing::new(Vec::with_capacity(aad.len() + 10));
    if aad_len == 0 {
    } else if aad_len < 0xff00 {
        prefixed.extend_from_slice(&aad_len.to_be_bytes()[6..]);
    } else if aad_len <= u64::from(u32::MAX) {
        prefixed.extend_from_slice(&[0xff, 0xfe]);
        prefixed.extend_from_slice(&aad_len.to_be_bytes()[4..]);
    } else {
        prefixed.extend_from_slice(&[0xff, 0xff]);
        prefixed.extend_from_slice(&aad_len.to_be_bytes());
    }
    prefixed.extend_from_slice(aad);
    let mut mac = cbc_mac_blocks(&aes, &[&b0, &prefixed, message]);
    // Counter blocks: flags q - 1, nonce, counter. Block 0 encrypts the tag.
    let counter = |i: u64| -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[0] = q_bits;
        block
            .iter_mut()
            .skip(1)
            .zip(nonce)
            .for_each(|(b, n)| *b = *n);
        let i = i.to_be_bytes();
        block
            .iter_mut()
            .skip(BLOCK - q)
            .zip(i.iter().skip(8 - q))
            .for_each(|(b, c)| *b = *c);
        block
    };
    let mut out = Zeroizing::new(Vec::with_capacity(message.len() + tag_len));
    for (i, chunk) in (1u64..).zip(message.chunks(BLOCK)) {
        let mut stream = counter(i);
        aes.encrypt(&mut stream);
        out.extend(chunk.iter().zip(stream.iter()).map(|(m, s)| m ^ s));
        stream.zeroize();
    }
    let mut s0 = counter(0);
    aes.encrypt(&mut s0);
    out.extend(mac.iter().zip(s0.iter()).take(tag_len).map(|(t, s)| t ^ s));
    mac.zeroize();
    s0.zeroize();
    Ok(out)
}

/// `aes_eax_encrypt(key, nonce16, message[, aad])`: EAX with a 16-byte nonce and a 16-byte
/// tag. The ciphertext, then the tag.
pub(super) fn eax(key: &[u8], nonce: &[u8], message: &[u8], aad: &[u8]) -> Result<Bytes> {
    use eax::aead::{Aead, Payload};
    let nonce = &eax::Nonce::<eax::aead::consts::U16>::try_from(nonce)
        .map_err(|_| bad("aes_eax_encrypt takes a nonce of 16 bytes"))?;
    let payload = Payload { msg: message, aad };
    let invalid = |_| Error::KeyInvalid;
    let out = match key.len() {
        16 => eax::Eax::<aes::Aes128>::new_from_slice(key)
            .map_err(invalid)?
            .encrypt(nonce, payload),
        24 => eax::Eax::<aes::Aes192>::new_from_slice(key)
            .map_err(invalid)?
            .encrypt(nonce, payload),
        32 => eax::Eax::<aes::Aes256>::new_from_slice(key)
            .map_err(invalid)?
            .encrypt(nonce, payload),
        _ => return Err(Error::KeyInvalid),
    };
    out.map(Zeroizing::new).map_err(|_| Error::Encoding)
}

/// `aes_kw_wrap(kek, key)` (RFC 3394) and `aes_kwp_wrap(kek, key)` (RFC 5649, with padding).
pub(super) fn key_wrap(kek: &[u8], key: &[u8], padded: bool) -> Result<Bytes> {
    use aes_kw::{KwAes128, KwAes192, KwAes256, KwpAes128, KwpAes192, KwpAes256};
    if padded {
        if key.is_empty() || key.len() > 1 << 20 {
            return Err(bad("aes_kwp_wrap of 1 byte to 1 MiB"));
        }
    } else if key.len() < 16 || !key.len().is_multiple_of(8) {
        return Err(bad("aes_kw_wrap of a multiple of 8 bytes, at least 16"));
    }
    let mut buf = Zeroizing::new(vec![0u8; key.len().div_ceil(8) * 8 + 8]);
    let invalid = |_| Error::KeyInvalid;
    let failed = |_| bad("key wrap failed");
    let len = match (kek.len(), padded) {
        (16, false) => KwAes128::new_from_slice(kek)
            .map_err(invalid)?
            .wrap_key(key, &mut buf)
            .map_err(failed)?
            .len(),
        (24, false) => KwAes192::new_from_slice(kek)
            .map_err(invalid)?
            .wrap_key(key, &mut buf)
            .map_err(failed)?
            .len(),
        (32, false) => KwAes256::new_from_slice(kek)
            .map_err(invalid)?
            .wrap_key(key, &mut buf)
            .map_err(failed)?
            .len(),
        (16, true) => KwpAes128::new_from_slice(kek)
            .map_err(invalid)?
            .wrap_key(key, &mut buf)
            .map_err(failed)?
            .len(),
        (24, true) => KwpAes192::new_from_slice(kek)
            .map_err(invalid)?
            .wrap_key(key, &mut buf)
            .map_err(failed)?
            .len(),
        (32, true) => KwpAes256::new_from_slice(kek)
            .map_err(invalid)?
            .wrap_key(key, &mut buf)
            .map_err(failed)?
            .len(),
        _ => return Err(Error::KeyInvalid),
    };
    buf.truncate(len);
    Ok(buf)
}

/// `aes_cts_encrypt(key, iv16, message)`: CBC with ciphertext stealing, the last two blocks
/// swapped (CBC-CS3), as Kerberos uses it (RFC 3962 section 5). The message is at least one
/// block; exactly one block is plain CBC.
pub(super) fn cts(key: &[u8], iv: &[u8], message: &[u8]) -> Result<Bytes> {
    use cts::cipher::InnerIvInit;
    use cts::{CbcCs3, Encrypt};
    if message.len() < BLOCK {
        return Err(bad("aes_cts_encrypt of at least 16 bytes"));
    }
    let iv = aes::Block::try_from(iv).map_err(|_| Error::KeyInvalid)?;
    let mut out = Zeroizing::new(vec![0u8; message.len()]);
    let failed = |_| bad("aes_cts_encrypt failed");
    match Aes::new(key)? {
        Aes::A128(c) => CbcCs3::inner_iv_init(c, &iv).encrypt_b2b(message, &mut out),
        Aes::A192(c) => CbcCs3::inner_iv_init(c, &iv).encrypt_b2b(message, &mut out),
        Aes::A256(c) => CbcCs3::inner_iv_init(c, &iv).encrypt_b2b(message, &mut out),
    }
    .map_err(failed)?;
    Ok(out)
}

/// `aes_cbc_hmac_encrypt(key, iv16, message[, aad])`: AES-CBC with HMAC-SHA-2 (RFC 7518
/// section 5.2). The key is 32, 48 or 64 bytes (A128CBC-HS256, A192CBC-HS384,
/// A256CBC-HS512): its first half is the MAC key, its second the encryption key. The
/// ciphertext, then the tag of half the key length.
pub(super) fn cbc_hmac(key: &[u8], iv: &[u8], message: &[u8], aad: &[u8]) -> Result<Bytes> {
    let half = key.len() / 2;
    if !matches!(key.len(), 32 | 48 | 64) {
        return Err(Error::KeyInvalid);
    }
    let (mac_key, enc_key) = key.split_at(half);
    let ciphertext = super::aes_cbc(enc_key, iv, message)?;
    let aad_bits = u64::try_from(aad.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(bad("aes_cbc_hmac_encrypt length"))?
        .to_be_bytes();
    macro_rules! tag {
        ($hash:ty) => {{
            let mut mac = <Hmac<$hash> as hmac::KeyInit>::new_from_slice(mac_key)
                .map_err(|_| Error::KeyInvalid)?;
            mac.update(aad);
            mac.update(iv);
            mac.update(&ciphertext);
            mac.update(&aad_bits);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }
    let full = match half {
        16 => tag!(Sha256),
        24 => tag!(Sha384),
        _ => tag!(Sha512),
    };
    let mut out = Zeroizing::new(Vec::with_capacity(ciphertext.len() + half));
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(full.get(..half).ok_or(Error::KeyInvalid)?);
    Ok(out)
}

/// Most bits of one `nfold`.
const MAX_NFOLD_BITS: usize = 8192;

/// `nfold(value, bits)`: the n-fold of RFC 3961 section 5.1, for a multiple of 8 bits.
pub(super) fn nfold(input: &[u8], bits: usize) -> Result<Bytes> {
    if input.is_empty() || bits == 0 || !bits.is_multiple_of(8) || bits > MAX_NFOLD_BITS {
        return Err(bad("nfold of a value to 8 to 8192 bits, a multiple of 8"));
    }
    let out_len = bits / 8;
    let in_len = input.len();
    // The input is repeated, each copy rotated 13 bits right more than the one before, to
    // the least common multiple of both lengths; the result is the one's-complement sum of
    // its blocks of `out_len` bytes.
    let lcm = lcm(in_len, out_len).ok_or(bad("nfold too long"))?;
    if lcm > 1 << 20 {
        return Err(bad("nfold too long"));
    }
    let in_bits = in_len * 8;
    let byte_of = |k: usize| -> u8 {
        // Byte k of the repeated, rotated input.
        let copy = k / in_len;
        let rotation = (13 * copy) % in_bits;
        let at = (k % in_len) * 8;
        let mut byte = 0u8;
        for bit in 0..8 {
            // Bit (at + bit) of the copy rotated right by `rotation` is bit
            // (at + bit - rotation) of the input, counted from the most significant.
            let source = (at + bit + in_bits - rotation) % in_bits;
            let value = input
                .get(source / 8)
                .map_or(0, |b| (b >> (7 - source % 8)) & 1);
            byte |= value << (7 - bit);
        }
        byte
    };
    let mut sum = Zeroizing::new(vec![0u32; out_len]);
    for block in 0..lcm / out_len {
        for (i, s) in sum.iter_mut().enumerate() {
            *s += u32::from(byte_of(block * out_len + i));
        }
    }
    // Carry from the last byte to the first, around, until no carry is left.
    loop {
        let mut carry = 0u32;
        for s in sum.iter_mut().rev() {
            let v = *s + carry;
            *s = v & 0xff;
            carry = v >> 8;
        }
        if carry == 0 {
            break;
        }
        if let Some(last) = sum.last_mut() {
            *last += carry;
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(out_len));
    out.extend(sum.iter().map(|s| u8::try_from(*s).unwrap_or_default()));
    Ok(out)
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn lcm(a: usize, b: usize) -> Option<usize> {
    (a / gcd(a, b)).checked_mul(b)
}

/// `kerberos_dk(key, constant)`: DK of RFC 3961 section 5.1 for the AES encryption types of
/// RFC 3962 (16- or 32-byte keys): the constant n-folded to one block, encrypted under the
/// key, and each block encrypted again, until the key length; random-to-key is the identity.
pub(super) fn kerberos_dk(key: &[u8], constant: &[u8]) -> Result<Bytes> {
    if !matches!(key.len(), 16 | 32) {
        return Err(Error::KeyInvalid);
    }
    let aes = Aes::new(key)?;
    let mut block = [0u8; BLOCK];
    if constant.len() == BLOCK {
        block.copy_from_slice(constant);
    } else {
        block.copy_from_slice(&nfold(constant, BLOCK * 8)?);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(key.len()));
    while out.len() < key.len() {
        aes.encrypt(&mut block);
        out.extend_from_slice(&block);
    }
    block.zeroize();
    out.truncate(key.len());
    Ok(out)
}
