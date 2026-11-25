//! Templates: how values are used, written as data.
//!
//! A template is text with expressions in `{{ }}`:
//!
//! ```text
//! Basic {{ b64(username + ":" + password) }}
//! {{ hex(hmac_sha256(secret, $query)) }}
//! {{ totp(b32decode(seed)) }}
//! ```
//!
//! An expression is a name (a field of the record, or a value captured by an earlier step), a
//! variable (`$method`, `$host`, `$path`, `$pathname`, `$query`, `$body`, `$unix`, `$unix_ms`,
//! `$boundary`, `$nonce`, `$input`), a string literal, a call of a function of [`Func`], or
//! several of them joined by `+`. There is no branch and no loop: a policy reads as what it
//! does. Text outside `{{ }}` is copied as it is, `}}` included.
//!
//! # Analysis
//!
//! Before a policy is signed, [`Template::analyze`] follows every value:
//!
//! - **tainted**: it holds a secret in a form that can be turned back. Encodings keep the
//!   taint; one-way functions (hashes, MACs, signatures, TOTP, `len`) drop it. An encryption
//!   drops it only under a key that is a secret field (or a hash of one), with a nonce that is
//!   not secret, and, when the caller chooses part of the message, with `$nonce` in the nonce.
//! - **controlled**: the caller or a server chooses part of it (`$input`, `$body`, `$query`,
//!   `$path`, `$pathname`, `$method`, captured values).
//!
//! A value both tainted and controlled must not reach a function whose output or failure
//! tells how the two relate: `replace` and `xor` with a secret on one side and a chosen value
//! on the other, a decoder, `json_set`, `time`, number arguments, or a key argument. Such a
//! template is refused: it would be an oracle that gives the secret back piece by piece.
//! A value handed back to the caller must be untainted.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::fields::Fields;
use crate::primitives;
use crate::{Error, Result};

pub use crate::primitives::MAX_PBKDF2_ROUNDS;

/// Longest template, in bytes.
pub const MAX_TEMPLATE: usize = 8192;
const MAX_DEPTH: usize = 24;
const MAX_NODES: usize = 512;
/// Most bytes all renderings of one operation may produce.
pub const MAX_RENDER_BYTES: usize = 128 * 1024 * 1024;
/// Most PBKDF2 rounds of one operation.
pub const MAX_RENDER_ROUNDS: u64 = 1_000_000;
/// Most signatures of one operation.
pub const MAX_RENDER_SIGNATURES: u32 = 32;

/// A variable a template can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Var {
    /// Request method.
    Method,
    /// Destination host.
    Host,
    /// Path and query of the request, before path parameters are filled.
    Path,
    /// The path without its query.
    PathName,
    /// The query, without `?`.
    Query,
    /// The body of the request.
    Body,
    /// Unix seconds.
    Unix,
    /// Unix milliseconds.
    UnixMs,
    /// A random multipart boundary.
    Boundary,
    /// 32 random hex characters.
    Nonce,
    /// The input of a derivation.
    Input,
}

impl Var {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "method" => Var::Method,
            "host" => Var::Host,
            "path" => Var::Path,
            "pathname" => Var::PathName,
            "query" => Var::Query,
            "body" => Var::Body,
            "unix" => Var::Unix,
            "unix_ms" => Var::UnixMs,
            "boundary" => Var::Boundary,
            "nonce" => Var::Nonce,
            "input" => Var::Input,
            _ => return None,
        })
    }

    /// True when a request template may read the variable.
    pub fn in_request(self) -> bool {
        self != Var::Input
    }

    /// True when a stream script or a client identity may read the variable.
    pub fn in_stream(self) -> bool {
        matches!(self, Var::Host | Var::Unix | Var::UnixMs | Var::Nonce)
    }

    /// True when a derivation (a `compute` or the `return` template of an operation with no
    /// connection) may read the variable.
    pub fn in_derive(self) -> bool {
        matches!(self, Var::Input | Var::Unix | Var::UnixMs | Var::Nonce)
    }

    /// True when a `compute` step of an operation with a connection may read the variable.
    pub fn in_compute(self) -> bool {
        matches!(self, Var::Unix | Var::UnixMs | Var::Nonce)
    }

    /// True when the caller chooses the value.
    fn controlled(self) -> bool {
        matches!(
            self,
            Var::Method | Var::Path | Var::PathName | Var::Query | Var::Body | Var::Input
        )
    }
}

macro_rules! funcs {
    ($( $variant:ident = $name:literal ($min:literal, $max:literal) : $doc:literal ),* $(,)?) => {
        /// The functions of the template language. Adding a primitive is the only change that
        /// needs code; using primitives in a new way needs none.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Func {
            $( #[doc = $doc] $variant, )*
        }

        impl Func {
            /// Every function with its name.
            pub const ALL: &[(&str, Func)] = &[ $( ($name, Func::$variant), )* ];

            fn arity(self) -> (usize, usize) {
                match self { $( Func::$variant => ($min, $max), )* }
            }
        }
    };
}

funcs! {
    B64 = "b64"(1, 1): "Standard base64 with padding.",
    B64Raw = "b64raw"(1, 1): "Standard base64 without padding.",
    B64Url = "b64url"(1, 1): "URL-safe base64 with padding.",
    B64UrlRaw = "b64urlraw"(1, 1): "URL-safe base64 without padding.",
    B64Decode = "b64decode"(1, 1): "Base64 decoding (either alphabet; padding, whitespace and trailing bits accepted).",
    B32Decode = "b32decode"(1, 1): "Base32 decoding (RFC 4648; case, whitespace, `-` and padding ignored).",
    Hex = "hex"(1, 1): "Lowercase hex.",
    HexDecode = "hexdecode"(1, 1): "Hex decoding.",
    Pct = "pct"(1, 1): "Percent encoding of everything but unreserved characters.",
    PctDecode = "pctdecode"(1, 1): "Percent decoding.",
    Json = "json"(1, 1): "JSON string escaping (without the quotes).",
    Upper = "upper"(1, 1): "ASCII uppercase.",
    Lower = "lower"(1, 1): "ASCII lowercase.",
    Trim = "trim"(1, 1): "ASCII whitespace removed at both ends.",
    Replace = "replace"(3, 3): "`replace(text, from, to)`: every `from` replaced.",
    Pem = "pem"(1, 1): "The binary body of a PEM block of any label (RFC 7468).",
    JsonSet = "json_set"(3, 3): "`json_set(object, key, value)`: the object with the string member added.",
    CanonicalQuery = "canonical_query"(1, 1): "A query with its pairs decoded, encoded again and sorted.",
    Time = "time"(2, 2): "`time(unix, format)`: UTC time with `%Y %m %d %H %M %S %a %b %s %%`.",
    Len = "len"(1, 1): "The length in bytes, as decimal text (one-way).",
    Be16 = "be16"(1, 1): "A decimal number as 2 big-endian bytes.",
    Be32 = "be32"(1, 1): "A decimal number as 4 big-endian bytes.",
    Be64 = "be64"(1, 1): "A decimal number as 8 big-endian bytes.",
    Le16 = "le16"(1, 1): "A decimal number as 2 little-endian bytes.",
    Le32 = "le32"(1, 1): "A decimal number as 4 little-endian bytes.",
    Le64 = "le64"(1, 1): "A decimal number as 8 little-endian bytes.",
    U8 = "u8"(1, 1): "A decimal number from 0 to 255 as one byte.",
    Add = "add"(2, 2): "`add(a, b)`: the sum of two signed 64-bit decimal integers, as decimal text.",
    Slice = "slice"(3, 3): "`slice(value, start, length)`: `length` bytes from byte `start`.",
    Between = "between"(3, 3): "`between(value, start, end)`: the bytes after the first `start` and before the next `end`; an empty `start` is the beginning, an empty `end` the end.",
    JsonSetNumber = "json_set_number"(3, 3): "`json_set_number(object, key, integer)`: the object with the integer member added.",
    Random = "random"(1, 1): "`random(n)`: n fresh random bytes, 1 to 1024.",
    Xor = "xor"(2, 2): "`xor(a, b)` of two values of one length.",
    Md5 = "md5"(1, 1): "MD5 digest, for protocols that require it (one-way).",
    Sha1 = "sha1"(1, 1): "SHA-1 digest (one-way).",
    Sha256 = "sha256"(1, 1): "SHA-256 digest (one-way).",
    Sha384 = "sha384"(1, 1): "SHA-384 digest (one-way).",
    Sha512 = "sha512"(1, 1): "SHA-512 digest (one-way).",
    Sha512_256 = "sha512_256"(1, 1): "SHA-512/256 digest (one-way).",
    Md4 = "md4"(1, 1): "MD4 digest, for protocols that require it (one-way).",
    Keccak256 = "keccak256"(1, 1): "Keccak-256 digest as Ethereum uses it (one-way).",
    HmacSha1 = "hmac_sha1"(2, 2): "`hmac_sha1(key, message)` (one-way).",
    HmacSha256 = "hmac_sha256"(2, 2): "`hmac_sha256(key, message)` (one-way).",
    HmacSha384 = "hmac_sha384"(2, 2): "`hmac_sha384(key, message)` (one-way).",
    HmacSha512 = "hmac_sha512"(2, 2): "`hmac_sha512(key, message)` (one-way).",
    HmacMd5 = "hmac_md5"(2, 2): "`hmac_md5(key, message)` (one-way).",
    Pbkdf2Sha256 = "pbkdf2_sha256"(3, 4): "`pbkdf2_sha256(password, salt, rounds[, length])`, 32 bytes by default (one-way).",
    Pbkdf2 = "pbkdf2"(4, 5): "`pbkdf2(hash, password, salt, rounds[, length])` with `sha1`, `sha256`, `sha384` or `sha512`; the digest length by default (one-way).",
    Totp = "totp"(1, 3): "`totp(seed[, digits[, period]])`, 6 digits and 30 s by default (one-way).",
    Ed25519Sign = "ed25519_sign"(2, 2): "`ed25519_sign(key, message)`; key raw 32 bytes or PKCS#8 DER (one-way).",
    P256Sign = "p256_sign"(2, 2): "ECDSA P-256 SHA-256, `r || s`; key raw 32 bytes or PKCS#8 DER (one-way).",
    P256SignDer = "p256_sign_der"(2, 2): "ECDSA P-256 SHA-256, DER (one-way).",
    P384Sign = "p384_sign"(2, 2): "ECDSA P-384 SHA-384, `r || s`; key raw 48 bytes or PKCS#8 DER (one-way).",
    P521Sign = "p521_sign"(2, 2): "ECDSA P-521 SHA-512, `r || s`; key raw 66 bytes or PKCS#8 DER (one-way).",
    K256Sign = "k256_sign"(2, 2): "ECDSA secp256k1 SHA-256, `r || s` with low s; key raw 32 bytes or PKCS#8 DER (one-way).",
    K256SignRecoverable = "k256_sign_recoverable"(2, 2): "`k256_sign_recoverable(key, digest32)`: `r || s || v`, v = 27 + recovery id (one-way).",
    RsaSignPkcs1Sha256 = "rsa_sign_pkcs1_sha256"(2, 2): "RSASSA-PKCS1-v1_5 SHA-256 (RS256); key PKCS#8 or PKCS#1 DER (one-way).",
    RsaSignPssSha256 = "rsa_sign_pss_sha256"(2, 2): "RSASSA-PSS SHA-256 (PS256); key PKCS#8 or PKCS#1 DER (one-way).",
    RsaSignPkcs1 = "rsa_sign_pkcs1"(3, 3): "`rsa_sign_pkcs1(hash, key, message)`: RSASSA-PKCS1-v1_5 with `sha1`, `sha256`, `sha384` or `sha512` (one-way).",
    RsaSignPss = "rsa_sign_pss"(3, 3): "`rsa_sign_pss(hash, key, message)`: RSASSA-PSS with `sha256`, `sha384` or `sha512`, salt of the digest length (one-way).",
    RsaEncryptOaep = "rsa_encrypt_oaep"(3, 3): "`rsa_encrypt_oaep(hash, public_key, message)`: RSAES-OAEP, MGF1 with the same hash, empty label; key SPKI or PKCS#1 DER.",
    RsaEncryptPkcs1 = "rsa_encrypt_pkcs1"(2, 2): "`rsa_encrypt_pkcs1(public_key, message)`: RSAES-PKCS1-v1_5; key SPKI or PKCS#1 DER.",
    Ecdh = "ecdh"(2, 3): "`ecdh(curve, peer_public[, private])`: the shared secret (x-coordinate) on `p256`, `p384`, `p521` or `x25519`; without `private`, with the ephemeral key of the operation.",
    EcdhPublic = "ecdh_public"(1, 1): "`ecdh_public(curve)`: the public key of the ephemeral key of the operation (SEC1 uncompressed, or 32 bytes for X25519).",
    AesGcmEncrypt = "aes_gcm_encrypt"(3, 4): "`aes_gcm_encrypt(key, nonce12, message[, aad])`: ciphertext and tag; key 16, 24 or 32 bytes.",
    AesCbcEncrypt = "aes_cbc_encrypt"(3, 3): "`aes_cbc_encrypt(key, iv16, message)` with PKCS#7 padding; key 16, 24 or 32 bytes.",
    ChaCha20Poly1305Encrypt = "chacha20_poly1305_encrypt"(3, 4): "`chacha20_poly1305_encrypt(key32, nonce12, message[, aad])`: ciphertext and tag (RFC 8439).",
    Sha3_224 = "sha3_224"(1, 1): "SHA3-224 digest (FIPS 202; one-way).",
    Sha3_256 = "sha3_256"(1, 1): "SHA3-256 digest (FIPS 202; one-way).",
    Sha3_384 = "sha3_384"(1, 1): "SHA3-384 digest (FIPS 202; one-way).",
    Sha3_512 = "sha3_512"(1, 1): "SHA3-512 digest (FIPS 202; one-way).",
    Shake128 = "shake128"(2, 2): "`shake128(message, length)`: `length` bytes of SHAKE128 (FIPS 202), 1 to 8192 (one-way).",
    Shake256 = "shake256"(2, 2): "`shake256(message, length)`: `length` bytes of SHAKE256 (FIPS 202), 1 to 8192 (one-way).",
    Hkdf = "hkdf"(5, 5): "`hkdf(hash, ikm, salt, info, length)`: HKDF (RFC 5869) with `sha256`, `sha384` or `sha512`; a secret when the input is.",
    HkdfExpand = "hkdf_expand"(4, 4): "`hkdf_expand(hash, prk, info, length)`: the expand step of HKDF alone; a secret when the input is.",
    ConcatKdf = "concat_kdf"(4, 4): "`concat_kdf(hash, z, other_info, length)`: the single-step KDF of NIST SP 800-56A with a SHA-2 hash; a secret when the input is.",
    KbkdfCounter = "kbkdf_counter"(4, 4): "`kbkdf_counter(hash, key, fixed_input, length)`: the counter-mode KDF of NIST SP 800-108 with HMAC-SHA-2 and a 32-bit counter before the fixed input; a secret when the input is.",
    AesCmac = "aes_cmac"(2, 2): "`aes_cmac(key, message)`: AES-CMAC (RFC 4493), 16 bytes; key 16, 24 or 32 bytes.",
    AesCbcMac = "aes_cbc_mac"(2, 2): "`aes_cbc_mac(key, message)`: AES CBC-MAC, zero IV, zero padding, 16 bytes; key 16, 24 or 32 bytes.",
    AesKwWrap = "aes_kw_wrap"(2, 2): "`aes_kw_wrap(kek, key)`: AES key wrap (RFC 3394); kek 16, 24 or 32 bytes, key a multiple of 8 bytes, at least 16.",
    AesKwpWrap = "aes_kwp_wrap"(2, 2): "`aes_kwp_wrap(kek, key)`: AES key wrap with padding (RFC 5649); kek 16, 24 or 32 bytes.",
    AesCbcHmacEncrypt = "aes_cbc_hmac_encrypt"(3, 4): "`aes_cbc_hmac_encrypt(key, iv16, message[, aad])`: AES-CBC with HMAC-SHA-2 (RFC 7518 section 5.2), ciphertext and tag; key 32, 48 or 64 bytes.",
    AesCcmEncrypt = "aes_ccm_encrypt"(4, 5): "`aes_ccm_encrypt(key, nonce, tag_length, message[, aad])`: AES-CCM (NIST SP 800-38C), ciphertext and tag; nonce 7 to 13 bytes, tag 4 to 16, even.",
    AesEaxEncrypt = "aes_eax_encrypt"(3, 4): "`aes_eax_encrypt(key, nonce16, message[, aad])`: AES-EAX, ciphertext and 16-byte tag.",
    AesCtsEncrypt = "aes_cts_encrypt"(3, 3): "`aes_cts_encrypt(key, iv16, message)`: AES-CBC with ciphertext stealing, CBC-CS3 as Kerberos uses it (RFC 3962); message at least 16 bytes.",
    Nfold = "nfold"(2, 2): "`nfold(value, bits)`: the n-fold of RFC 3961, to a multiple of 8 bits up to 8192.",
    KerberosDk = "kerberos_dk"(2, 2): "`kerberos_dk(key, constant)`: DK of RFC 3961 for the AES encryption types of RFC 3962; key 16 or 32 bytes; a secret when the input is.",
    Ed448Sign = "ed448_sign"(2, 3): "`ed448_sign(key, message[, context])`: Ed448 (RFC 8032); key raw 57 bytes or PKCS#8 DER (one-way).",
    EcdsaSignPrehash = "ecdsa_sign_prehash"(3, 3): "`ecdsa_sign_prehash(curve, key, digest)`: ECDSA of a given digest on `p256`, `p384`, `p521` or `k256`, `r || s` (one-way).",
    DsaSign = "dsa_sign"(3, 3): "`dsa_sign(hash, key, message)`: DSA (FIPS 186-4, RFC 6979 nonce) with `sha1`, `sha256`, `sha384` or `sha512`, `r || s`; key PKCS#8 DER (one-way).",
    DsaSignDer = "dsa_sign_der"(3, 3): "`dsa_sign_der(hash, key, message)`: DSA as `dsa_sign`, DER (one-way).",
    CborInt = "cbor_int"(1, 1): "`cbor_int(n)`: a CBOR integer from -2^64 to 2^64-1 (RFC 8949, deterministic).",
    CborBytes = "cbor_bytes"(1, 1): "`cbor_bytes(value)`: a CBOR byte string.",
    CborText = "cbor_text"(1, 1): "`cbor_text(value)`: a CBOR text string of UTF-8 bytes.",
    CborArray = "cbor_array"(0, 32): "`cbor_array(item, ...)`: a CBOR array of up to 32 encoded items.",
    CborMap = "cbor_map"(0, 32): "`cbor_map(key, value, ...)`: a CBOR map of up to 16 pairs of encoded items, keys sorted (RFC 8949 section 4.2.1).",
    CborTag = "cbor_tag"(2, 2): "`cbor_tag(number, item)`: a CBOR tag around one encoded item.",
}

impl Func {
    fn parse(name: &str) -> Option<Self> {
        Func::ALL.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
    }

    fn one_way(self) -> bool {
        matches!(
            self,
            Func::Len
                | Func::Md5
                | Func::Md4
                | Func::Sha1
                | Func::Sha256
                | Func::Sha384
                | Func::Sha512
                | Func::Sha512_256
                | Func::Keccak256
                | Func::Sha3_224
                | Func::Sha3_256
                | Func::Sha3_384
                | Func::Sha3_512
                | Func::Shake128
                | Func::Shake256
                | Func::HmacSha1
                | Func::HmacSha256
                | Func::HmacSha384
                | Func::HmacSha512
                | Func::HmacMd5
                | Func::Pbkdf2Sha256
                | Func::Pbkdf2
                | Func::Totp
        ) || self.signs()
    }

    /// A plain hash: one-way, but a hash of secret bytes alone stays tainted (rule 3).
    fn plain_hash(self) -> bool {
        matches!(
            self,
            Func::Md5
                | Func::Md4
                | Func::Sha1
                | Func::Sha256
                | Func::Sha384
                | Func::Sha512
                | Func::Sha512_256
                | Func::Keccak256
                | Func::Sha3_224
                | Func::Sha3_256
                | Func::Sha3_384
                | Func::Sha3_512
                | Func::Shake128
                | Func::Shake256
        )
    }

    /// A key derivation: its output is a key, a secret whenever an input is (rule 8).
    fn derives_key(self) -> bool {
        matches!(
            self,
            Func::Hkdf | Func::HkdfExpand | Func::ConcatKdf | Func::KbkdfCounter | Func::KerberosDk
        )
    }

    /// A MAC built on a block cipher: one-way only under a secret key. Under a known key
    /// it is reversible (a one-block CBC-MAC is the block encrypted).
    fn block_mac(self) -> bool {
        matches!(self, Func::AesCmac | Func::AesCbcMac)
    }

    /// The indices of the key, nonce, message and AAD of a symmetric encryption.
    fn cipher_args(self) -> Option<(usize, Option<usize>, usize, Option<usize>)> {
        match self {
            Func::AesGcmEncrypt
            | Func::ChaCha20Poly1305Encrypt
            | Func::AesCbcHmacEncrypt
            | Func::AesEaxEncrypt => Some((0, Some(1), 2, Some(3))),
            Func::AesCbcEncrypt | Func::AesCtsEncrypt => Some((0, Some(1), 2, None)),
            Func::AesCcmEncrypt => Some((0, Some(1), 3, Some(4))),
            Func::AesKwWrap | Func::AesKwpWrap => Some((0, None, 1, None)),
            _ => None,
        }
    }

    /// The arguments that set how long the output is, or where a cut falls: they may not
    /// depend on a secret, since `len` of the output (or whether it fails) would give it back.
    fn length_args(self) -> &'static [usize] {
        match self {
            Func::Random => &[0],
            Func::Shake128 | Func::Shake256 | Func::Nfold => &[1],
            Func::Slice | Func::Between => &[1, 2],
            Func::Replace => &[1],
            Func::AesCcmEncrypt => &[2],
            Func::Pbkdf2Sha256 | Func::HkdfExpand | Func::ConcatKdf | Func::KbkdfCounter => &[3],
            Func::Pbkdf2 | Func::Hkdf => &[4],
            _ => &[],
        }
    }

    fn signs(self) -> bool {
        matches!(
            self,
            Func::Ed25519Sign
                | Func::P256Sign
                | Func::P256SignDer
                | Func::P384Sign
                | Func::P521Sign
                | Func::K256Sign
                | Func::K256SignRecoverable
                | Func::RsaSignPkcs1Sha256
                | Func::RsaSignPssSha256
                | Func::RsaSignPkcs1
                | Func::RsaSignPss
                | Func::Ed448Sign
                | Func::EcdsaSignPrehash
                | Func::DsaSign
                | Func::DsaSignDer
        )
    }

    /// The index of an argument that names a hash or a curve: it must be fixed by the policy.
    fn algorithm_arg(self) -> Option<usize> {
        match self {
            Func::Pbkdf2
            | Func::RsaSignPkcs1
            | Func::RsaSignPss
            | Func::RsaEncryptOaep
            | Func::Ecdh
            | Func::EcdhPublic
            | Func::Hkdf
            | Func::HkdfExpand
            | Func::ConcatKdf
            | Func::KbkdfCounter
            | Func::EcdsaSignPrehash
            | Func::DsaSign
            | Func::DsaSignDer => Some(0),
            _ => None,
        }
    }

    /// The index of the public key argument of an encryption to a public key.
    fn public_key_arg(self) -> Option<usize> {
        match self {
            Func::RsaEncryptOaep => Some(1),
            Func::RsaEncryptPkcs1 => Some(0),
            _ => None,
        }
    }

    /// Functions where a tainted and a controlled value may not meet in any argument: the
    /// controlled value would pick which part of the secret comes out, or whether it fails.
    fn no_mixing(self) -> bool {
        matches!(
            self,
            Func::Replace
                | Func::Xor
                | Func::Slice
                | Func::Between
                | Func::Add
                | Func::JsonSetNumber
        )
    }

    /// The arguments whose value, when it mixes a secret with a chosen value, makes the
    /// function an oracle (by failing or not, or by how it compares them).
    fn sensitive_args(self) -> core::ops::Range<usize> {
        match self {
            Func::B64Decode
            | Func::B32Decode
            | Func::HexDecode
            | Func::PctDecode
            | Func::Pem
            | Func::CanonicalQuery
            | Func::Be16
            | Func::Be32
            | Func::Be64
            | Func::Le16
            | Func::Le32
            | Func::Le64
            | Func::U8
            | Func::Random
            | Func::CborInt
            | Func::CborText
            | Func::AesCmac
            | Func::AesCbcMac
            | Func::AesKwWrap
            | Func::AesKwpWrap
            | Func::KerberosDk => 0..1,
            Func::Shake128 | Func::Shake256 | Func::Nfold => 1..2,
            Func::HkdfExpand | Func::ConcatKdf | Func::KbkdfCounter => 3..4,
            Func::Hkdf => 4..5,
            Func::AesCbcHmacEncrypt | Func::AesEaxEncrypt | Func::AesCtsEncrypt => 0..2,
            Func::AesCcmEncrypt => 0..3,
            // The key; the curve or hash name is fixed (rule 6).
            Func::EcdsaSignPrehash | Func::DsaSign | Func::DsaSignDer => 1..2,
            // Every item is checked for well-formedness.
            Func::CborArray | Func::CborMap => 0..32,
            Func::CborTag => 0..2,
            Func::Time => 0..2,
            Func::Totp => 1..3,
            Func::Pbkdf2Sha256 => 2..4,
            Func::Pbkdf2 => 3..5,
            Func::AesGcmEncrypt | Func::AesCbcEncrypt | Func::ChaCha20Poly1305Encrypt => 0..2,
            Func::RsaSignPkcs1 | Func::RsaSignPss | Func::RsaEncryptOaep => 1..2,
            Func::RsaEncryptPkcs1 => 0..1,
            // The peer key and the static private key.
            Func::Ecdh => 1..3,
            f if f.signs() => 0..1,
            _ => 0..0,
        }
    }
}

/// What a name is, for the analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    /// A secret field.
    SecretField,
    /// A secret field with few possible values (a PIN, a password): anything computed from
    /// it without a strong secret key can be found by trying values.
    GuessableField,
    /// A public field.
    PublicField,
    /// A captured value marked secret.
    SecretTemp,
    /// A captured value not marked secret.
    PublicTemp,
    /// A value a `compute` step rendered. It has exactly the properties of its template, so
    /// for the analysis naming it is the same as writing its template in its place.
    Computed(Props),
}

/// The properties the analysis gives the output of a template (taint, control, key strength,
/// guessability), kept for a name a `compute` step defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Props(Info);

impl Props {
    /// The most a value can be: tainted, chosen by the caller and guessable, never a secret
    /// key. Given to a computed name that cannot be analysed (its template does not parse or
    /// breaks a rule), so nothing built on it is ever handed back.
    pub fn unknown() -> Self {
        Props(Info {
            tainted: true,
            controlled: true,
            caller: true,
            secret_key: false,
            guessable: true,
        })
    }

    /// True when the value can hold a secret in reversible form.
    pub fn tainted(self) -> bool {
        self.0.tainted
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Info {
    tainted: bool,
    controlled: bool,
    /// The caller (not only a server) chooses part of it: a request or input variable.
    caller: bool,
    secret_key: bool,
    guessable: bool,
}

impl Info {
    fn mixed(self) -> bool {
        self.tainted && self.controlled
    }
}

#[derive(Clone, Debug)]
enum Expr {
    Lit(Vec<u8>),
    Name(String),
    Var(Var),
    Call(Func, Vec<Expr>),
    Concat(Vec<Expr>),
}

#[derive(Clone, Debug)]
enum Segment {
    Text(Vec<u8>),
    Expr(Expr),
}

/// A parsed template.
#[derive(Clone, Debug)]
pub struct Template {
    segments: Vec<Segment>,
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Var(String),
    Str(Vec<u8>),
    LParen,
    RParen,
    Comma,
    Plus,
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn lex(src: &str) -> core::result::Result<Vec<Tok>, usize> {
    let mut toks = Vec::new();
    let mut chars = src.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            c if c.is_whitespace() => {}
            '(' => toks.push(Tok::LParen),
            ')' => toks.push(Tok::RParen),
            ',' => toks.push(Tok::Comma),
            '+' => toks.push(Tok::Plus),
            '"' => {
                let mut s = String::new();
                loop {
                    let (_, c) = chars.next().ok_or(at)?;
                    match c {
                        '"' => break,
                        '\\' => s.push(match chars.next().ok_or(at)?.1 {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '0' => '\0',
                            '"' => '"',
                            '\\' => '\\',
                            _ => return Err(at),
                        }),
                        other => s.push(other),
                    }
                }
                toks.push(Tok::Str(s.into_bytes()));
            }
            c if c == '$' || is_name_char(c) => {
                let mut name = String::new();
                if c != '$' {
                    name.push(c);
                }
                while let Some(&(_, n)) = chars.peek() {
                    if is_name_char(n) {
                        name.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                toks.push(if c == '$' {
                    Tok::Var(name)
                } else {
                    Tok::Ident(name)
                });
            }
            _ => return Err(at),
        }
    }
    Ok(toks)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    nodes: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let tok = self.toks.get(self.pos).cloned()?;
        self.pos += 1;
        Some(tok)
    }

    fn expr(&mut self, depth: usize) -> Option<Expr> {
        let mut parts = vec![self.term(depth)?];
        while self.peek() == Some(&Tok::Plus) {
            self.pos += 1;
            parts.push(self.term(depth)?);
        }
        Some(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expr::Concat(parts)
        })
    }

    fn term(&mut self, depth: usize) -> Option<Expr> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return None;
        }
        match self.next()? {
            Tok::Str(s) => Some(Expr::Lit(s)),
            Tok::Var(name) => Var::parse(&name).map(Expr::Var),
            Tok::Ident(name) if self.peek() == Some(&Tok::LParen) => {
                let func = Func::parse(&name)?;
                self.pos += 1;
                let mut args = Vec::new();
                if self.peek() != Some(&Tok::RParen) {
                    args.push(self.expr(depth + 1)?);
                    while self.peek() == Some(&Tok::Comma) {
                        self.pos += 1;
                        args.push(self.expr(depth + 1)?);
                    }
                }
                if self.next()? != Tok::RParen {
                    return None;
                }
                let (min, max) = func.arity();
                (min..=max)
                    .contains(&args.len())
                    .then_some(Expr::Call(func, args))
            }
            Tok::Ident(name) if crate::policy::is_token(&name) => Some(Expr::Name(name)),
            _ => None,
        }
    }
}

fn walk<'e>(expr: &'e Expr, visit: &mut dyn FnMut(&'e Expr)) {
    visit(expr);
    if let Expr::Call(_, args) | Expr::Concat(args) = expr {
        args.iter().for_each(|a| walk(a, visit));
    }
}

type Rule = &'static str;

fn analyze(expr: &Expr, kind: &dyn Fn(&str) -> NameKind) -> core::result::Result<Info, Rule> {
    Ok(match expr {
        Expr::Lit(_) => Info::default(),
        Expr::Name(name) => match kind(name) {
            NameKind::SecretField => Info {
                tainted: true,
                secret_key: true,
                ..Info::default()
            },
            NameKind::GuessableField => Info {
                tainted: true,
                guessable: true,
                ..Info::default()
            },
            NameKind::PublicField => Info::default(),
            NameKind::SecretTemp => Info {
                tainted: true,
                controlled: true,
                ..Info::default()
            },
            NameKind::PublicTemp => Info {
                controlled: true,
                ..Info::default()
            },
            NameKind::Computed(props) => props.0,
        },
        Expr::Var(v) => Info {
            controlled: v.controlled(),
            caller: v.controlled(),
            ..Info::default()
        },
        Expr::Concat(parts) => {
            let infos = parts
                .iter()
                .map(|p| analyze(p, kind))
                .collect::<core::result::Result<Vec<_>, _>>()?;
            Info {
                tainted: infos.iter().any(|i| i.tainted),
                controlled: infos.iter().any(|i| i.controlled),
                caller: infos.iter().any(|i| i.caller),
                secret_key: false,
                guessable: infos.iter().any(|i| i.guessable),
            }
        }
        Expr::Call(func, args) => {
            let infos = args
                .iter()
                .map(|a| analyze(a, kind))
                .collect::<core::result::Result<Vec<_>, _>>()?;
            call_info(*func, &infos)?
        }
    })
}

fn call_info(func: Func, args: &[Info]) -> core::result::Result<Info, Rule> {
    let at = |i: usize| args.get(i).copied().unwrap_or_default();
    let any_tainted = args.iter().any(|i| i.tainted);
    let any_controlled = args.iter().any(|i| i.controlled);
    if let Some(i) = func.algorithm_arg()
        && (at(i).tainted || at(i).controlled)
    {
        return Err("a hash or curve name must be fixed by the policy");
    }
    if let Some(i) = func.public_key_arg()
        && at(i).caller
    {
        return Err(
            "an encryption key must come from the policy or the destination, not the caller",
        );
    }
    if func.no_mixing() && any_tainted && any_controlled {
        return Err("a secret and a chosen value meet in a function that compares or cuts them");
    }
    // `json_set` compares its object and its key (a member present makes it fail); the value
    // is only escaped and appended.
    if func == Func::JsonSet && (at(0).tainted || at(1).tainted) && any_controlled {
        return Err("a secret and a chosen value meet in a function that compares or cuts them");
    }
    if func.sensitive_args().any(|i| at(i).mixed()) {
        return Err("a secret mixed with a chosen value reaches a decoder, number or key");
    }
    if func.length_args().iter().any(|&i| at(i).tainted) {
        return Err("a length must not depend on a secret");
    }
    // The order of a map's pairs, and whether two keys are equal, compare the keys: a secret
    // key and a chosen key may not meet.
    if func == Func::CborMap
        && args.iter().step_by(2).any(|k| k.tainted)
        && args.iter().step_by(2).any(|k| k.controlled)
    {
        return Err("a secret and a chosen value meet in a function that compares or cuts them");
    }
    // A secret in one number argument and a chosen value in another is the same oracle as
    // both in one: `time(secret, $input)` picks which digits of the secret come out.
    if matches!(
        func,
        Func::Time | Func::Totp | Func::Pbkdf2Sha256 | Func::Pbkdf2
    ) && func.sensitive_args().any(|i| at(i).tainted)
        && func.sensitive_args().any(|i| at(i).controlled)
    {
        return Err("a secret and a chosen value meet in the number arguments of a function");
    }
    let tainted = if func.plain_hash() {
        // A hash of nothing but secret bytes is as good as the secret where the secret is
        // hashed first: an HMAC key longer than its block, an Ed25519 seed, a password hash.
        // Only a hash that also covers bytes the caller or server chooses hides the secret.
        at(0).tainted && !at(0).controlled
    } else if func.one_way() {
        false
    } else if func == Func::Ecdh {
        // A shared secret is known to the node and the peer only: a secret, whatever the
        // arguments.
        true
    } else if func.derives_key() {
        // A key derived from a secret is a secret (rule 8), whatever else went in.
        any_tainted
    } else if func.block_mac() {
        // One-way under a key nobody else knows; under a known key, a short message can be
        // decrypted back out of the tag.
        !at(0).secret_key && any_tainted
    } else if let Some((key, nonce, message, aad)) = func.cipher_args() {
        let opt = |i: Option<usize>| i.map(at).unwrap_or_default();
        let (key, nonce, message, aad) = (at(key), opt(nonce), at(message), opt(aad));
        if key.secret_key {
            // A secret key hides only itself. A secret in the message stays readable: another
            // operation of the policy may encrypt chosen bytes under the same key and a chosen
            // nonce (an encryption oracle), which gives back the keystream of any nonce the
            // caller has seen, and a nonce that only looks fresh may be constant.
            nonce.tainted || message.tainted || aad.tainted
        } else {
            any_tainted
        }
    } else {
        // Encryption to a public key included: whoever holds the private key reads it.
        any_tainted
    };
    // The shared secret depends on a private key nobody but the node holds; the peer, who
    // chose its public key, learns it, but nothing the caller chooses reaches it. Treating it
    // as not controlled keeps a hash of it tainted (rule 3), so a key derived from it is never
    // handed back.
    // A key derived from a secret is in the same position: the caller may choose its other
    // inputs, but not one byte of the output. A key derived from nothing secret is as
    // controlled as its inputs.
    let controlled = func != Func::Ecdh && !(func.derives_key() && any_tainted) && any_controlled;
    // Only a secret field itself, or a decoding or a fixed part of it, is a key nobody else
    // knows. A hash or MAC of it is a new value that some operation may hand back, after
    // which it hides nothing.
    let secret_key = match func {
        Func::B64Decode
        | Func::B32Decode
        | Func::HexDecode
        | Func::Pem
        | Func::Trim
        | Func::Slice => at(0).secret_key,
        _ => false,
    };
    // A guessable value stays guessable through every function but `len`. A signature or a
    // hash lets anyone check a guess, and a keyed MAC or an encryption does too as soon as
    // another operation of the policy computes it on chosen input under the same key.
    let guessable = func != Func::Len && args.iter().any(|i| i.guessable);
    Ok(Info {
        tainted,
        controlled,
        caller: controlled && args.iter().any(|i| i.caller),
        secret_key,
        guessable,
    })
}

impl Template {
    /// Parses a template.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_TEMPLATE {
            return Err(Error::TemplateSyntax {
                offset: MAX_TEMPLATE,
            });
        }
        let mut segments = Vec::new();
        let mut rest = text;
        let mut nodes = 0;
        while let Some(open) = rest.find("{{") {
            let offset = text.len() - rest.len() + open;
            let syntax = |at: usize| Error::TemplateSyntax {
                offset: offset + at,
            };
            let (before, after) = rest.split_at(open);
            if !before.is_empty() {
                segments.push(Segment::Text(before.as_bytes().to_vec()));
            }
            let after = after.get(2..).ok_or(syntax(0))?;
            let close = after.find("}}").ok_or(syntax(0))?;
            let (inner, tail) = after.split_at(close);
            let toks = lex(inner).map_err(|at| syntax(at + 2))?;
            let mut parser = Parser {
                toks,
                pos: 0,
                nodes,
            };
            let expr = parser.expr(0).ok_or(syntax(2))?;
            if parser.pos != parser.toks.len() {
                return Err(syntax(2));
            }
            nodes = parser.nodes;
            segments.push(Segment::Expr(expr));
            rest = tail.get(2..).ok_or(syntax(0))?;
        }
        if !rest.is_empty() {
            segments.push(Segment::Text(rest.as_bytes().to_vec()));
        }
        Ok(Self { segments })
    }

    fn exprs(&self) -> impl Iterator<Item = &Expr> {
        self.segments.iter().filter_map(|s| match s {
            Segment::Expr(e) => Some(e),
            Segment::Text(_) => None,
        })
    }

    /// The names (fields and captured values) the template reads.
    pub fn names(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for expr in self.exprs() {
            walk(expr, &mut |e| {
                if let Expr::Name(name) = e {
                    out.push(name.as_str());
                }
            });
        }
        out
    }

    /// The variables the template reads.
    pub fn vars(&self) -> Vec<Var> {
        let mut out = Vec::new();
        for expr in self.exprs() {
            walk(expr, &mut |e| {
                if let Expr::Var(v) = e {
                    out.push(*v);
                }
            });
        }
        out
    }

    /// Checks the rules of the analysis and returns true when the output can give a secret
    /// back. `kind` says what each name is.
    pub fn analyze(&self, kind: &dyn Fn(&str) -> NameKind) -> core::result::Result<bool, Rule> {
        let mut tainted = false;
        for expr in self.exprs() {
            tainted |= analyze(expr, kind)?.tainted;
        }
        Ok(tainted)
    }

    /// The properties of the whole output: what a name a `compute` step defines from this
    /// template is. Text around the expressions is fixed by the policy; the output is a
    /// secret key only when it is one expression and nothing else.
    pub fn props(&self, kind: &dyn Fn(&str) -> NameKind) -> core::result::Result<Props, Rule> {
        let infos = self
            .exprs()
            .map(|e| analyze(e, kind))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let single = self.segments.len() == 1 && infos.len() == 1;
        Ok(Props(Info {
            tainted: infos.iter().any(|i| i.tainted),
            controlled: infos.iter().any(|i| i.controlled),
            caller: infos.iter().any(|i| i.caller),
            secret_key: single && infos.first().is_some_and(|i| i.secret_key),
            guessable: infos.iter().any(|i| i.guessable),
        }))
    }

    /// True when the output depends on a guessable field in a way a guess can be checked
    /// against (a template that breaks a rule counts as guessable).
    pub fn guessable(&self, kind: &dyn Fn(&str) -> NameKind) -> bool {
        let mut guessable = false;
        for expr in self.exprs() {
            match analyze(expr, kind) {
                Ok(info) => guessable |= info.guessable,
                Err(_) => return true,
            }
        }
        guessable
    }

    /// True when the output can give a secret back (a template that breaks a rule counts as
    /// tainted).
    pub fn tainted(&self, kind: &dyn Fn(&str) -> NameKind) -> bool {
        self.analyze(kind).unwrap_or(true)
    }

    pub(crate) fn render(&self, ctx: &Context<'_>) -> Result<Bytes> {
        let mut parts = Vec::with_capacity(self.segments.len());
        for segment in &self.segments {
            parts.push(match segment {
                Segment::Text(t) => {
                    ctx.budget.bytes(t.len())?;
                    Zeroizing::new(t.clone())
                }
                Segment::Expr(e) => eval(e, ctx)?,
            });
        }
        concat(&parts, ctx.budget)
    }
}

fn concat(parts: &[Bytes], budget: &Budget) -> Result<Bytes> {
    let len = parts.iter().map(|p| p.len()).sum();
    budget.bytes(len)?;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    parts.iter().for_each(|p| out.extend_from_slice(p));
    Ok(out)
}

/// Values captured by earlier steps of an operation.
pub(crate) type Temps = HashMap<String, Zeroizing<Vec<u8>>>;

/// An ephemeral key agreement key: its curve and its raw private scalar.
pub(crate) type Ephemeral = (&'static str, Zeroizing<Vec<u8>>);

/// The limits of one operation: bytes produced, PBKDF2 rounds and signatures. It also holds
/// the ephemeral key agreement keys of the operation, one per curve, made when first used and
/// erased when the operation ends; they never leave the node.
pub(crate) struct Budget {
    bytes: Cell<usize>,
    rounds: Cell<u64>,
    signatures: Cell<u32>,
    pub(crate) ephemeral: RefCell<Vec<Ephemeral>>,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            bytes: Cell::new(MAX_RENDER_BYTES),
            rounds: Cell::new(MAX_RENDER_ROUNDS),
            signatures: Cell::new(MAX_RENDER_SIGNATURES),
            ephemeral: RefCell::new(Vec::new()),
        }
    }
}

impl Budget {
    /// Fails when fewer than `n` bytes are left; does not spend them.
    fn room(&self, n: usize) -> Result<()> {
        if n > self.bytes.get() {
            return Err(Error::Budget { what: "bytes" });
        }
        Ok(())
    }

    /// Spends `n` bytes.
    pub(crate) fn bytes(&self, n: usize) -> Result<()> {
        self.room(n)?;
        self.bytes.set(self.bytes.get() - n);
        Ok(())
    }

    /// Spends `n` PBKDF2 rounds.
    pub(crate) fn rounds(&self, n: u64) -> Result<()> {
        let left = self.rounds.get().checked_sub(n).ok_or(Error::Budget {
            what: "pbkdf2 rounds",
        })?;
        self.rounds.set(left);
        Ok(())
    }

    /// Spends one signature or key agreement.
    pub(crate) fn signature(&self) -> Result<()> {
        let left = self
            .signatures
            .get()
            .checked_sub(1)
            .ok_or(Error::Budget { what: "signatures" })?;
        self.signatures.set(left);
        Ok(())
    }
}

/// What a rendering reads.
pub(crate) struct Context<'a> {
    pub fields: &'a Fields,
    pub temps: &'a Temps,
    pub vars: HashMap<Var, Vec<u8>>,
    pub unix: u64,
    pub budget: &'a Budget,
}

pub(crate) type Bytes = Zeroizing<Vec<u8>>;

fn eval(expr: &Expr, ctx: &Context<'_>) -> Result<Bytes> {
    Ok(match expr {
        Expr::Lit(b) => {
            ctx.budget.bytes(b.len())?;
            Zeroizing::new(b.clone())
        }
        Expr::Name(name) => {
            let value = ctx
                .fields
                .get(name)
                .or_else(|| ctx.temps.get(name).map(|v| v.as_slice()))
                .ok_or_else(|| Error::FieldMissing {
                    field: name.clone(),
                })?;
            ctx.budget.bytes(value.len())?;
            Zeroizing::new(value.to_vec())
        }
        Expr::Var(v) => {
            let value = ctx.vars.get(v).ok_or(Error::TemplateInvalid {
                rule: "variable not available here",
            })?;
            ctx.budget.bytes(value.len())?;
            Zeroizing::new(value.clone())
        }
        Expr::Concat(parts) => {
            let values = parts
                .iter()
                .map(|p| eval(p, ctx))
                .collect::<Result<Vec<_>>>()?;
            concat(&values, ctx.budget)?
        }
        Expr::Call(func, args) => {
            let args = args
                .iter()
                .map(|a| eval(a, ctx))
                .collect::<Result<Vec<_>>>()?;
            ctx.budget.room(primitives::output_bound(*func, &args))?;
            let out = primitives::call(*func, &args, ctx.unix, ctx.budget)?;
            ctx.budget.bytes(out.len())?;
            out
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn render(text: &str, fields: &Fields) -> Vec<u8> {
        let temps = Temps::new();
        let budget = Budget::default();
        let ctx = Context {
            fields,
            temps: &temps,
            vars: HashMap::from([(Var::Input, b"in".to_vec())]),
            unix: 59,
            budget: &budget,
        };
        Template::parse(text)
            .unwrap()
            .render(&ctx)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn renders_expressions() {
        let mut fields = Fields::new();
        fields.insert("user", b"bot".to_vec()).unwrap();
        fields.insert("password", b"p@ss word".to_vec()).unwrap();
        fields
            .insert("seed", b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_vec())
            .unwrap();
        fields.insert("api-key", b"k-1".to_vec()).unwrap();
        let cases: [(&str, &[u8]); 18] = [
            (
                r#"Basic {{ b64(user + ":" + password) }}"#,
                b"Basic Ym90OnBAc3Mgd29yZA==",
            ),
            ("{{pct(password)}}", b"p%40ss%20word"),
            ("{{ totp(b32decode(seed), \"8\") }}", b"94287082"),
            (
                "{{json_set(\"{\\\"a\\\":1}\", \"k\", password)}}",
                br#"{"a":1,"k":"p@ss word"}"#,
            ),
            (r#"{{ json_set("{}", "k", user) }}"#, br#"{"k":"bot"}"#),
            (
                r#"{{ time("784111777", "%a, %d %b %Y %H:%M:%S GMT") }}"#,
                b"Sun, 06 Nov 1994 08:49:37 GMT",
            ),
            (r#"{{ time("951782400", "%Y-%m-%d") }}"#, b"2000-02-29"),
            (r#"{{ time("-86400", "%Y-%m-%d") }}"#, b"1969-12-31"),
            (
                r#"{{ canonical_query("b=2&a=x%2Fy&a=1&c") }}"#,
                b"a=1&a=x%2Fy&b=2&c=",
            ),
            (
                r#"{{ hex(be32("258")) + hex(be16("1")) }}"#,
                b"000001020001",
            ),
            (r#"{{ hex(xor("ab", "AB")) }}"#, b"2020"),
            (r#"{{ replace(trim("  a-b-c "), "-", "+") }}"#, b"a+b+c"),
            // RFC 7914 section 11, PBKDF2-HMAC-SHA256 with c = 1, dkLen = 64 (first 32 bytes).
            (
                r#"{{ hex(pbkdf2_sha256("passwd", "salt", "1")) }}"#,
                b"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
            ),
            (
                r#"{{ hex(keccak256("")) }}"#,
                b"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ),
            (r#"{{ hex(md5("")) }}"#, b"d41d8cd98f00b204e9800998ecf8427e"),
            // Text after the last expression may hold `}}`: a nested JSON body.
            (r#"{"o":{"u":"{{user}}"}}"#, br#"{"o":{"u":"bot"}}"#),
            ("{{ api-key }}", b"k-1"),
            (r#"{{ b64decode("YWJj=") + b64decode("YWJk") }}"#, b"abcabd"),
        ];
        for (template, expected) in cases {
            assert_eq!(render(template, &fields), expected, "{template}");
        }
    }

    #[test]
    fn rejects_bad_templates() {
        for text in [
            "{{",
            "{{ nope( }}",
            "{{ b64() }}",
            "{{ unknown(x) }}",
            "{{ $nope }}",
            "{{ \"x }}",
        ] {
            assert!(
                matches!(Template::parse(text), Err(Error::TemplateSyntax { .. })),
                "{text}"
            );
        }
    }

    #[test]
    fn budget_stops_runaway_templates() {
        let mut fields = Fields::new();
        fields.insert("k", vec![b'a'; 1024]).unwrap();
        let temps = Temps::new();
        let budget = Budget {
            bytes: Cell::new(1 << 20),
            ..Budget::default()
        };
        let ctx = Context {
            fields: &fields,
            temps: &temps,
            vars: HashMap::new(),
            unix: 0,
            budget: &budget,
        };
        let nested = format!("{{{{ {}k{} }}}}", "hex(".repeat(20), ")".repeat(20));
        assert_eq!(
            Template::parse(&nested).unwrap().render(&ctx).map(|_| ()),
            Err(Error::Budget { what: "bytes" })
        );
        let budget = Budget {
            rounds: Cell::new(10),
            ..Budget::default()
        };
        let ctx = Context {
            budget: &budget,
            ..ctx
        };
        let rounds = r#"{{ pbkdf2_sha256(k, "s", "6") + pbkdf2_sha256(k, "s", "5") }}"#;
        assert_eq!(
            Template::parse(rounds).unwrap().render(&ctx).map(|_| ()),
            Err(Error::Budget {
                what: "pbkdf2 rounds"
            })
        );
    }

    fn kind(name: &str) -> NameKind {
        match name {
            "key" | "msg" => NameKind::SecretField,
            "session" => NameKind::SecretTemp,
            "nonce_t" => NameKind::PublicTemp,
            _ => NameKind::PublicField,
        }
    }

    #[test]
    fn taint_follows_reversible_functions_only() {
        let tainted = |t: &str| Template::parse(t).unwrap().analyze(&kind).unwrap();
        assert!(tainted("{{key}}"));
        assert!(tainted("{{ b64(hexdecode(hex(key))) }}"));
        assert!(tainted("x{{ \"a\" + key }}"));
        assert!(tainted("{{ xor(key, \"0123456789\") }}"));
        assert!(tainted(
            r#"{{ aes_gcm_encrypt("0123456789abcdef", "000000000000", msg) }}"#
        ));
        // A key that is not a secret field in substance.
        assert!(tainted(
            r#"{{ aes_gcm_encrypt(xor(key, key), "000000000000", key) }}"#
        ));
        assert!(tainted(
            r#"{{ aes_cbc_encrypt("0123456789abcdef", key, "x") }}"#
        ));
        assert!(tainted(
            r#"{{ aes_gcm_encrypt(key, "000000000000", "x", msg) }}"#
        ));
        // A secret key hides only itself: a secret message stays readable.
        assert!(tainted(
            r#"{{ aes_gcm_encrypt(key, "000000000000", msg) }}"#
        ));
        assert!(tainted(
            r#"{{ aes_gcm_encrypt(key, hexdecode(replace($nonce, "00000000", "")), msg) }}"#
        ));
        // A hash of a secret is not a secret key: some operation may hand it back.
        assert!(tainted(
            r#"{{ hex(sha256(key)) + aes_cbc_encrypt(sha256(key), $input, msg) }}"#
        ));
        assert!(!tainted(
            r#"{{ aes_gcm_encrypt(b64decode(key), hexdecode(replace($nonce, "00000000", "")), $input) }}"#
        ));
        assert!(!tainted("{{ hex(hmac_sha256(key, $input)) }}"));
        assert!(!tainted("{{ b64(rsa_sign_pkcs1_sha256(key, $input)) }}"));
        assert!(!tainted("{{ len(key) }}"));
        assert!(!tainted("{{ user }}"));
    }

    #[test]
    fn oracles_are_refused() {
        let refused = |t: &str| Template::parse(t).unwrap().analyze(&kind).is_err();
        for template in [
            r#"{{ len(replace(key, $input, "")) }}"#,
            r#"{{ sha256(xor(key, $input)) }}"#,
            r#"{{ sha256(b64decode(key + $input)) }}"#,
            r#"{{ json_set(key, $input, "x") }}"#,
            r#"{{ hmac_sha256(sha256(b64decode(session + "x")), "m") }}"#,
            r#"{{ ed25519_sign(key + $input, "m") }}"#,
            r#"{{ aes_gcm_encrypt(key, "000000000000", msg + $input) }}"#,
            r#"{{ totp(key, key + $input) }}"#,
        ] {
            let result = Template::parse(template).unwrap().analyze(&kind);
            if template.contains("aes_gcm_encrypt") {
                // Not refused, but tainted: a fixed nonce with a chosen message.
                assert_eq!(result, Ok(true), "{template}");
            } else {
                assert!(refused(template), "{template}");
            }
        }
        assert!(!refused(r#"{{ sha256(key + $input) }}"#));
        assert!(!refused(r#"{{ replace($body, "a", "b") }}"#));
        assert!(!refused(r#"{{ pbkdf2_sha256(key, $input, "1000") }}"#));
    }

    fn try_render(text: &str) -> Result<Vec<u8>> {
        let fields = Fields::new();
        let temps = Temps::new();
        let budget = Budget::default();
        let ctx = Context {
            fields: &fields,
            temps: &temps,
            vars: HashMap::from([(Var::Input, b"in".to_vec())]),
            unix: 59,
            budget: &budget,
        };
        Template::parse(text)?.render(&ctx).map(|v| v.to_vec())
    }

    #[test]
    fn renders_structure_functions() {
        let cases: [(&str, &[u8]); 16] = [
            (r#"{{ add("1700000000", "300") }}"#, b"1700000300"),
            (r#"{{ add("-5", "3") }}"#, b"-2"),
            (r#"{{ slice("abcdef", "1", "3") }}"#, b"bcd"),
            (r#"{{ slice("abcdef", "6", "0") }}"#, b""),
            (r#"{{ between("k=v1&x=2", "k=", "&") }}"#, b"v1"),
            (r#"{{ between("sess,04ab", "", ",") }}"#, b"sess"),
            (r#"{{ between("sess,04ab", ",", "") }}"#, b"04ab"),
            (r#"{{ hex(u8("255")) }}"#, b"ff"),
            (r#"{{ hex(be64("258")) }}"#, b"0000000000000102"),
            (r#"{{ hex(le16("258")) }}"#, b"0201"),
            (r#"{{ hex(le32("258")) }}"#, b"02010000"),
            (r#"{{ hex(le64("1")) }}"#, b"0100000000000000"),
            (
                r#"{{ json_set_number("{\"a\":\"x\"}", "exp", "1800000300") }}"#,
                br#"{"a":"x","exp":1800000300}"#,
            ),
            (r#"{{ json_set_number("", "n", "-0") }}"#, br#"{"n":-0}"#),
            (r#"{{ json_set_number("{}", "n", "0") }}"#, br#"{"n":0}"#),
            (r#"{{ len(random("24")) }}"#, b"24"),
        ];
        for (template, expected) in cases {
            assert_eq!(try_render(template).unwrap(), expected, "{template}");
        }
        assert_ne!(
            try_render(r#"{{ random("16") }}"#).unwrap(),
            try_render(r#"{{ random("16") }}"#).unwrap()
        );
        for (template, rule) in [
            (r#"{{ add("9223372036854775807", "1") }}"#, "add overflows"),
            (
                r#"{{ add("1.5", "1") }}"#,
                "argument is not a signed 64-bit integer",
            ),
            (r#"{{ slice("abc", "2", "2") }}"#, "slice out of range"),
            (
                r#"{{ slice("abc", "18446744073709551615", "2") }}"#,
                "slice out of range",
            ),
            (
                r#"{{ between("abc", "x", "") }}"#,
                "between delimiter not found",
            ),
            (
                r#"{{ between("abc", "a", "x") }}"#,
                "between delimiter not found",
            ),
            (r#"{{ u8("256") }}"#, "number too large"),
            (
                r#"{{ json_set_number("{}", "n", "01") }}"#,
                "json_set_number of a value that is not an integer",
            ),
            (
                r#"{{ json_set_number("{}", "n", "1e3") }}"#,
                "json_set_number of a value that is not an integer",
            ),
            (
                r#"{{ json_set_number("{\"n\":1}", "n", "2") }}"#,
                "json_set of a member the object has",
            ),
            (r#"{{ random("0") }}"#, "random of 1 to 1024 bytes"),
            (r#"{{ random("1025") }}"#, "random of 1 to 1024 bytes"),
            (r#"{{ pbkdf2("md5", "p", "s", "1") }}"#, "unknown hash name"),
            (r#"{{ ecdh_public("p224") }}"#, "unknown curve name"),
        ] {
            assert_eq!(
                try_render(template),
                Err(Error::TemplateInvalid { rule }),
                "{template}"
            );
        }
    }

    #[test]
    fn taint_of_the_new_functions() {
        let tainted = |t: &str| Template::parse(t).unwrap().analyze(&kind).unwrap();
        let refused = |t: &str| Template::parse(t).unwrap().analyze(&kind).is_err();
        // Structure keeps the taint.
        assert!(tainted(r#"{{ slice(key, "0", "16") }}"#));
        assert!(tainted(r#"{{ between(key, "", "x") }}"#));
        assert!(tainted(r#"{{ add(key, "1") }}"#));
        assert!(tainted(r#"{{ u8(key) + le64(key) }}"#));
        assert!(tainted(r#"{{ json_set_number("{}", "n", key) }}"#));
        // A fixed part of a secret field is still a secret key.
        assert!(!tainted(
            r#"{{ aes_gcm_encrypt(slice(key, "0", "16"), hexdecode(replace($nonce, "00000000", "")), $input) }}"#
        ));
        // ...but a part the caller chooses is an oracle, and so is a cut secret temp.
        for t in [
            r#"{{ slice(key, $input, "1") }}"#,
            r#"{{ slice(key, "0", len($input)) }}"#,
            r#"{{ between(key, $input, "") }}"#,
            r#"{{ between(session, "a", "b") }}"#,
            r#"{{ add(key, $input) }}"#,
            r#"{{ json_set_number($input, "n", key) }}"#,
            r#"{{ u8(key + $input) }}"#,
        ] {
            assert!(refused(t), "{t}");
        }
        // Algorithm names are fixed by the policy.
        for t in [
            r#"{{ pbkdf2($input, key, "s", "1") }}"#,
            r#"{{ pbkdf2(nonce_t, key, "s", "1") }}"#,
            r#"{{ rsa_sign_pss(key, key, "m") }}"#,
            r#"{{ ecdh(nonce_t, "x") }}"#,
        ] {
            assert!(refused(t), "{t}");
        }
        // Public-key encryption: a server-sent key is accepted, a caller-sent one is not.
        assert!(!refused(r#"{{ rsa_encrypt_pkcs1(nonce_t, key) }}"#));
        assert!(tainted(r#"{{ rsa_encrypt_pkcs1(nonce_t, key) }}"#));
        assert!(!tainted(
            r#"{{ rsa_encrypt_oaep("sha256", nonce_t, $input) }}"#
        ));
        assert!(refused(r#"{{ rsa_encrypt_pkcs1($body, key) }}"#));
        assert!(refused(
            r#"{{ rsa_encrypt_oaep("sha1", "k" + $query, key) }}"#
        ));
        // Key agreement: the shared secret is a secret that a plain hash does not hide, the
        // ephemeral public key is public.
        assert!(tainted(r#"{{ ecdh("p256", nonce_t) }}"#));
        assert!(tainted(r#"{{ hex(sha256(hex(ecdh("p256", nonce_t)))) }}"#));
        assert!(!tainted(r#"{{ hex(ecdh_public("x25519")) }}"#));
        assert!(!tainted(
            r#"{{ hex(hmac_sha256(ecdh("p256", nonce_t), $input)) }}"#
        ));
        assert!(refused(r#"{{ ecdh("p256", nonce_t, key + $input) }}"#));
        // One-way functions drop it; plain hashes of the secret alone keep it.
        assert!(!tainted(
            r#"{{ hex(hmac_sha384(key, $input)) + hex(hmac_md5(key, "x")) }}"#
        ));
        assert!(!tainted(r#"{{ hex(pbkdf2("sha1", key, "s", "1")) }}"#));
        assert!(!tainted(r#"{{ hex(p521_sign(key, $input)) }}"#));
        assert!(tainted(r#"{{ hex(md4(key)) }}"#));
        assert!(!tainted(r#"{{ hex(sha512_256(key + $input)) }}"#));
        assert!(!tainted(r#"{{ hex(random("16")) }}"#));
        assert!(tainted(
            r#"{{ chacha20_poly1305_encrypt(key, hexdecode($nonce + $nonce), key) }}"#
        ));
    }

    #[test]
    fn taint_of_the_families() {
        let analyze = |t: &str| Template::parse(t).unwrap().analyze(&kind);
        const LENGTH: Rule = "a length must not depend on a secret";
        const ALGORITHM: Rule = "a hash or curve name must be fixed by the policy";
        const MIXED: Rule = "a secret mixed with a chosen value reaches a decoder, number or key";
        const MEET: Rule =
            "a secret and a chosen value meet in a function that compares or cuts them";
        for (template, expected) in [
            // A key derived from a secret is a secret; the caller's salt does not make it
            // controlled, so a plain hash of it stays a secret too.
            (r#"{{ hkdf("sha256", key, $input, "", "32") }}"#, Ok(true)),
            (
                r#"{{ sha256(hkdf("sha256", key, $input, "", "32")) }}"#,
                Ok(true),
            ),
            (
                r#"{{ hmac_sha256(kbkdf_counter("sha384", key, "x", "16"), $input) }}"#,
                Ok(false),
            ),
            (r#"{{ concat_kdf("sha512", $input, "", "16") }}"#, Ok(false)),
            (r#"{{ kerberos_dk(key, "kerberos") }}"#, Ok(true)),
            // ...so it may key an encryption, whose output then stays a secret.
            (
                r#"{{ aes_gcm_encrypt(hkdf("sha256", key, $input, "", "16"), "000000000000", $input) }}"#,
                Ok(true),
            ),
            (r#"{{ hkdf("sha256", $input, "", "", key) }}"#, Err(LENGTH)),
            // The older functions follow the same rule.
            (r#"{{ len(random(key)) }}"#, Err(LENGTH)),
            (
                r#"{{ len(pbkdf2_sha256("p", "s", "1", key)) }}"#,
                Err(LENGTH),
            ),
            (
                r#"{{ len(pbkdf2("sha256", "p", "s", "1", key)) }}"#,
                Err(LENGTH),
            ),
            (
                r#"{{ len(slice("0123456789abcdef", "0", key)) }}"#,
                Err(LENGTH),
            ),
            (
                r#"{{ len(slice("0123456789abcdef", key, "1")) }}"#,
                Err(LENGTH),
            ),
            (r#"{{ len(between("0123456789", key, "")) }}"#, Err(LENGTH)),
            (r#"{{ len(replace("aaaa", key, "")) }}"#, Err(LENGTH)),
            (r#"{{ slice(key, "0", "4") }}"#, Ok(true)),
            (r#"{{ replace("{k}", "{k}", key) }}"#, Ok(true)),
            (r#"{{ shake128($input, key) }}"#, Err(LENGTH)),
            (r#"{{ nfold($input, key) }}"#, Err(LENGTH)),
            (
                r#"{{ aes_ccm_encrypt(key, "0123456", msg, $input) }}"#,
                Err(LENGTH),
            ),
            (r#"{{ hkdf(nonce_t, key, "", "", "16") }}"#, Err(ALGORITHM)),
            (r#"{{ dsa_sign($input, key, "m") }}"#, Err(ALGORITHM)),
            (
                r#"{{ ecdsa_sign_prehash(nonce_t, key, "0123456789abcdef") }}"#,
                Err(ALGORITHM),
            ),
            (r#"{{ shake256(key, "64") }}"#, Ok(true)),
            (r#"{{ shake256(key + $input, "64") }}"#, Ok(false)),
            (r#"{{ sha3_384(session) }}"#, Ok(false)),
            // Block-cipher MACs: one-way under a secret key only.
            (r#"{{ aes_cmac(key, msg) }}"#, Ok(false)),
            (r#"{{ aes_cbc_mac("0123456789abcdef", msg) }}"#, Ok(true)),
            (r#"{{ aes_cmac(key + $input, "m") }}"#, Err(MIXED)),
            // Encryption: the rule of the first group, with each function's arguments.
            (r#"{{ aes_kw_wrap(key, random("16")) }}"#, Ok(false)),
            (r#"{{ aes_kw_wrap(key, msg) }}"#, Ok(true)),
            (r#"{{ aes_kwp_wrap(nonce_t, msg) }}"#, Ok(true)),
            (
                r#"{{ aes_ccm_encrypt(key, "0123456", "8", $input, msg) }}"#,
                Ok(true),
            ),
            (
                r#"{{ aes_ccm_encrypt(key, "0123456", "8", $input, "aad") }}"#,
                Ok(false),
            ),
            (
                r#"{{ aes_cbc_hmac_encrypt(key, "0123456789abcdef", msg) }}"#,
                Ok(true),
            ),
            (
                r#"{{ aes_eax_encrypt(key, session + $input, "m") }}"#,
                Err(MIXED),
            ),
            (r#"{{ aes_cts_encrypt(key, $nonce, $input) }}"#, Ok(false)),
            // Signatures drop the taint; their keys may not mix.
            (r#"{{ ed448_sign(key, msg, "ctx") }}"#, Ok(false)),
            (
                r#"{{ dsa_sign_der("sha1", key + $input, "m") }}"#,
                Err(MIXED),
            ),
            (r#"{{ ecdh("x448", nonce_t) }}"#, Ok(true)),
            // CBOR keeps the taint; its checks and its key order are oracles.
            (
                r#"{{ cbor_array(cbor_bytes(key), cbor_int("1")) }}"#,
                Ok(true),
            ),
            (r#"{{ cbor_array(key + $input) }}"#, Err(MIXED)),
            (r#"{{ cbor_tag("18", session) }}"#, Err(MIXED)),
            (
                r#"{{ cbor_map(cbor_bytes(key), cbor_int("1"), cbor_bytes($input), cbor_int("2")) }}"#,
                Err(MEET),
            ),
            (
                r#"{{ cbor_map(cbor_int("1"), cbor_bytes(key), cbor_int("2"), cbor_bytes($input)) }}"#,
                Ok(true),
            ),
            (r#"{{ cbor_array() + cbor_map() }}"#, Ok(false)),
        ] {
            assert_eq!(analyze(template), expected, "{template}");
        }
    }
}
