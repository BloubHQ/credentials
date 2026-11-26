//! SRP-6a, the client side (RFC 2945, RFC 5054): the public value `A`, `x`, `u`, the
//! premaster secret `S`, the proof `M1` and the check of the server's proof `M2`, over the
//! groups of RFC 5054 appendix A.
//!
//! # Side channels
//!
//! Every operation that touches a secret (the private exponent, `x`, the exponent
//! `a + u * x` and the premaster secret) runs on `crypto-bigint`'s `BoxedUint` and
//! `BoxedMontyForm`, at a precision set by the group and by the lengths of the inputs, which
//! are public: Montgomery multiplication, and an exponentiation that walks every bit of the
//! exponent's precision with a fixed window and selects table entries in constant time, with
//! no branch or memory index that depends on a secret. Public values (`N`, `g`, `k`, `A`, `B`,
//! `u`) are checked in variable time (that `B` is below `N`, that `u` is not zero). What a
//! timing measurement on real hardware would show was not measured; the claim rests on the
//! library's design and on this code's review. Big integers that held a secret are zeroized
//! before they are dropped.

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Limb};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};

use super::{Hash, arg, bad, hex_decode};
use crate::Result;
use crate::template::{Budget, Bytes, Func};

/// The longest modulus, in bytes (RFC 5054 appendix A, 8192 bits).
const MAX_MODULUS: usize = 1024;

/// A group of RFC 5054 appendix A: the safe prime `N` and the generator `g`.
struct Group {
    modulus: &'static str,
    generator: u8,
}

/// RFC 5054 appendix A, 1024-bit group.
const N1024: &str = concat!(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576",
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1",
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC",
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
);

/// RFC 5054 appendix A, 1536-bit group.
const N1536: &str = concat!(
    "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D",
    "5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DC",
    "DF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC",
    "764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C486",
    "65772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E",
    "5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
);

/// RFC 5054 appendix A, 2048-bit group.
const N2048: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B",
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);

/// RFC 5054 appendix A, 3072-bit group (RFC 3526 group 15).
const N3072: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

/// RFC 5054 appendix A, 4096-bit group (RFC 3526 group 16).
const N4096: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

/// RFC 5054 appendix A, 6144-bit group (RFC 3526 group 17).
const N6144: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026",
    "C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE",
    "B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B",
    "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC",
    "F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E",
    "59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA",
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76",
    "F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468",
    "043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
);

/// RFC 5054 appendix A, 8192-bit group (RFC 3526 group 18).
const N8192: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026",
    "C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE",
    "B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B",
    "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC",
    "F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E",
    "59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA",
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76",
    "F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468",
    "043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4",
    "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED",
    "2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652D",
    "E3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B",
    "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6",
    "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851D",
    "F9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92",
    "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA",
    "9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF",
);

impl Group {
    fn parse(name: &[u8]) -> Result<Self> {
        let (modulus, generator) = match name {
            b"rfc5054_1024" => (N1024, 2),
            b"rfc5054_1536" => (N1536, 2),
            b"rfc5054_2048" => (N2048, 2),
            b"rfc5054_3072" => (N3072, 5),
            b"rfc5054_4096" => (N4096, 5),
            b"rfc5054_6144" => (N6144, 5),
            b"rfc5054_8192" => (N8192, 19),
            _ => return Err(bad("unknown SRP group")),
        };
        Ok(Group { modulus, generator })
    }
}

/// A group ready for arithmetic: `N` as bytes and in Montgomery form, `g`.
struct Ring {
    modulus: Vec<u8>,
    params: BoxedMontyParams,
    bits: u32,
    generator: u8,
}

impl Ring {
    fn new(name: &[u8]) -> Result<Self> {
        let group = Group::parse(name)?;
        let modulus = hex_decode(group.modulus.as_bytes())?.to_vec();
        let bits = u32::try_from(modulus.len() * 8).map_err(|_| bad("SRP group"))?;
        let n = BoxedUint::from_be_slice(&modulus, bits).map_err(|_| bad("SRP group"))?;
        let odd = Option::from(n.to_odd()).ok_or(bad("SRP group"))?;
        Ok(Ring {
            params: BoxedMontyParams::new(odd),
            modulus,
            bits,
            generator: group.generator,
        })
    }

    fn len(&self) -> usize {
        self.modulus.len()
    }

    /// `value` left-padded with zeros to the length of `N` (RFC 5054 `PAD`).
    fn pad(&self, value: &[u8]) -> Result<Bytes> {
        let skip = value.len().saturating_sub(self.len());
        let (high, low) = value.split_at(skip);
        if high.iter().any(|&b| b != 0) {
            return Err(bad("an SRP value longer than the modulus"));
        }
        let mut out = Zeroizing::new(vec![0u8; self.len()]);
        let start = self.len() - low.len();
        out.get_mut(start..)
            .ok_or(bad("an SRP value longer than the modulus"))?
            .copy_from_slice(low);
        Ok(out)
    }

    /// A public value of the group as an integer below `N`: `B`, `k`, `g`.
    fn public(&self, value: &[u8]) -> Result<BoxedUint> {
        let padded = self.pad(value)?;
        let n = BoxedUint::from_be_slice(&self.modulus, self.bits).map_err(|_| bad("SRP group"))?;
        let v = BoxedUint::from_be_slice(&padded, self.bits).map_err(|_| bad("SRP value"))?;
        if v.cmp_vartime(&n) != core::cmp::Ordering::Less {
            return Err(bad("an SRP value not below the modulus"));
        }
        Ok(v)
    }

    fn form(&self, value: BoxedUint) -> BoxedMontyForm {
        BoxedMontyForm::new(value, &self.params)
    }

    fn generator(&self) -> Result<BoxedMontyForm> {
        Ok(self.form(self.public(&[self.generator])?))
    }

    /// `g^exponent mod N` for a secret exponent of any length up to `N`'s.
    fn pow_g(&self, exponent: &[u8]) -> Result<BoxedMontyForm> {
        let mut e = secret_uint(exponent, self.len())?;
        let out = self.generator()?.pow(&e);
        e.zeroize();
        Ok(out)
    }

    /// The integer as bytes padded to the length of `N`.
    fn bytes(&self, value: &BoxedMontyForm) -> Result<Bytes> {
        let mut integer = value.retrieve();
        let mut be = integer.to_be_bytes();
        integer.zeroize();
        // Every modulus is a multiple of 64 bits, so the encoding is exactly as long as `N`.
        let out = (be.len() == self.len()).then(|| Zeroizing::new(be.to_vec()));
        be.zeroize();
        out.ok_or(bad("SRP encoding"))
    }
}

/// Bits of precision for `len` bytes, in whole limbs, at least one.
fn precision(len: usize) -> Result<u32> {
    let limb = usize::try_from(Limb::BITS).map_err(|_| bad("precision"))?;
    let bits = (len * 8).div_ceil(limb).max(1) * limb;
    u32::try_from(bits).map_err(|_| bad("precision"))
}

/// A secret integer of at most `max` bytes, at the precision its length gives (public).
fn secret_uint(bytes: &[u8], max: usize) -> Result<BoxedUint> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(bad(
            "an SRP exponent of 1 byte to the length of the modulus",
        ));
    }
    BoxedUint::from_be_slice(bytes, precision(bytes.len())?).map_err(|_| bad("SRP exponent"))
}

fn digest(hash: Hash, parts: &[&[u8]]) -> Bytes {
    fn run<D: Digest>(parts: &[&[u8]]) -> Bytes {
        let mut d = D::new();
        for p in parts {
            d.update(p);
        }
        Zeroizing::new(d.finalize().to_vec())
    }
    match hash {
        Hash::Sha1 => run::<Sha1>(parts),
        Hash::Sha256 => run::<Sha256>(parts),
        Hash::Sha384 => run::<Sha384>(parts),
        Hash::Sha512 => run::<Sha512>(parts),
    }
}

/// `srp_public(group, private)`: `g^private mod N`, padded to the length of `N`.
pub(super) fn public(group: &[u8], private: &[u8]) -> Result<Bytes> {
    let ring = Ring::new(group)?;
    let mut a = ring.pow_g(private)?;
    let out = ring.bytes(&a)?;
    a.zeroize();
    if out.iter().all(|&b| b == 0) {
        return Err(bad("an SRP private value that gives zero"));
    }
    Ok(out)
}

/// `srp_x(hash, salt, identity, password)`: `H(salt | H(identity | ":" | password))`.
pub(super) fn x(hash: &[u8], salt: &[u8], identity: &[u8], password: &[u8]) -> Result<Bytes> {
    let hash = Hash::parse(hash)?;
    let inner = digest(hash, &[identity, b":", password]);
    Ok(digest(hash, &[salt, &inner]))
}

/// `u = H(PAD(A) | PAD(B))`.
fn u_of(ring: &Ring, hash: Hash, a_pub: &[u8], b_pub: &[u8]) -> Result<Bytes> {
    Ok(digest(hash, &[&ring.pad(a_pub)?, &ring.pad(b_pub)?]))
}

/// `srp_u(group, hash, A, B)`.
pub(super) fn u(group: &[u8], hash: &[u8], a_pub: &[u8], b_pub: &[u8]) -> Result<Bytes> {
    u_of(&Ring::new(group)?, Hash::parse(hash)?, a_pub, b_pub)
}

/// `srp_premaster(group, hash, x, private, B)`: `(B - k * g^x)^(private + u * x) mod N`.
pub(super) fn premaster(
    group: &[u8],
    hash: &[u8],
    x: &[u8],
    private: &[u8],
    b_pub: &[u8],
) -> Result<Bytes> {
    let ring = Ring::new(group)?;
    let hash = Hash::parse(hash)?;
    // RFC 5054 section 2.6: the client aborts when B % N is zero; B is refused unless it is
    // below N, which an honest server's always is.
    let b = ring.public(b_pub)?;
    if bool::from(b.is_zero()) {
        return Err(bad("an SRP server value that is zero modulo N"));
    }
    let mut a_form = ring.pow_g(private)?;
    let a_pub = ring.bytes(&a_form)?;
    a_form.zeroize();
    let u = u_of(&ring, hash, &a_pub, b_pub)?;
    if u.iter().all(|&b| b == 0) {
        return Err(bad("an SRP scrambling parameter u of zero"));
    }
    // k = H(N | PAD(g)), shorter than N.
    let k = digest(hash, &[&ring.modulus, &ring.pad(&[ring.generator])?]);
    let k = ring.form(ring.public(&k)?);
    let mut v = ring.pow_g(x)?;
    let mut kv = k.mul(&v);
    let mut base = ring.form(b).sub(&kv);
    // The exponent a + u * x at a precision its inputs' lengths fix, so it never wraps.
    if x.is_empty() || x.len() > ring.len() {
        return Err(bad("an SRP x of 1 byte to the length of the modulus"));
    }
    let width = precision(private.len().max(u.len() + x.len()) + 8)?;
    let mut a = BoxedUint::from_be_slice(private, width).map_err(|_| bad("SRP exponent"))?;
    let mut xw = BoxedUint::from_be_slice(x, width).map_err(|_| bad("SRP exponent"))?;
    let uw = BoxedUint::from_be_slice(&u, width).map_err(|_| bad("SRP exponent"))?;
    let mut ux = uw.wrapping_mul(&xw);
    let mut e = a.wrapping_add(&ux);
    let mut s = base.pow(&e);
    let out = ring.bytes(&s)?;
    for secret in [&mut a, &mut xw, &mut ux, &mut e] {
        secret.zeroize();
    }
    for secret in [&mut v, &mut kv, &mut base, &mut s] {
        secret.zeroize();
    }
    Ok(out)
}

/// `srp_m1(group, hash, identity, salt, A, B, K)`:
/// `H(H(N) xor H(g) | H(identity) | salt | A | B | K)` (RFC 2945 section 3), with `N` and `g`
/// as big-endian bytes without leading zeros, and `A` and `B` as given.
pub(super) fn m1(group: &[u8], hash: &[u8], parts: [&[u8]; 5]) -> Result<Bytes> {
    let ring = Ring::new(group)?;
    let hash = Hash::parse(hash)?;
    let [identity, salt, a_pub, b_pub, key] = parts;
    let hn = digest(hash, &[&ring.modulus]);
    let hg = digest(hash, &[&[ring.generator]]);
    let mixed: Vec<u8> = hn.iter().zip(hg.iter()).map(|(n, g)| n ^ g).collect();
    let hi = digest(hash, &[identity]);
    Ok(digest(hash, &[&mixed, &hi, salt, a_pub, b_pub, key]))
}

/// `srp_verify(hash, A, M1, K, M2)`: empty when `M2 = H(A | M1 | K)`, compared in constant
/// time; an error otherwise.
pub(super) fn verify(hash: &[u8], a_pub: &[u8], m1: &[u8], key: &[u8], m2: &[u8]) -> Result<Bytes> {
    let expected = digest(Hash::parse(hash)?, &[a_pub, m1, key]);
    let differ = expected.len() != m2.len()
        || core::hint::black_box(
            expected
                .iter()
                .zip(m2)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b)),
        ) != 0;
    if differ {
        return Err(bad("the SRP server proof M2 does not match"));
    }
    Ok(Zeroizing::new(Vec::new()))
}

/// The SRP functions of the template language; `None` for any other.
pub(super) fn call(func: Func, args: &[Bytes], budget: &Budget) -> Result<Option<Bytes>> {
    let at = |i: usize| arg(args, i);
    Ok(Some(match func {
        // An exponentiation modulo N counts as a signature in the budget, like a key
        // agreement; the premaster secret takes three.
        Func::SrpPublic => {
            budget.signature()?;
            public(at(0)?, at(1)?)?
        }
        Func::SrpX => x(at(0)?, at(1)?, at(2)?, at(3)?)?,
        Func::SrpU => u(at(0)?, at(1)?, at(2)?, at(3)?)?,
        Func::SrpPremaster => {
            for _ in 0..3 {
                budget.signature()?;
            }
            premaster(at(0)?, at(1)?, at(2)?, at(3)?, at(4)?)?
        }
        Func::SrpM1 => m1(at(0)?, at(1)?, [at(2)?, at(3)?, at(4)?, at(5)?, at(6)?])?,
        Func::SrpVerify => verify(at(0)?, at(1)?, at(2)?, at(3)?, at(4)?)?,
        _ => return Ok(None),
    }))
}

/// The most bytes an SRP function writes: a value modulo N, or a digest.
pub(super) fn output_bound(func: Func) -> Option<usize> {
    match func {
        Func::SrpPublic | Func::SrpPremaster => Some(MAX_MODULUS),
        Func::SrpX | Func::SrpU | Func::SrpM1 => Some(64),
        Func::SrpVerify => Some(0),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    //! RFC 5054 appendix B, byte for byte, and the groups of appendix A checked to be safe
    //! primes.

    use super::*;

    fn h(text: &str) -> Vec<u8> {
        let clean: String = text.split_whitespace().collect();
        hex_decode(clean.as_bytes()).unwrap().to_vec()
    }

    const SALT: &str = "BEB25379 D1A8581E B5A72767 3A2441EE";
    const K: &str = "7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F";
    const X: &str = "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124";
    const V: &str = "7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
        9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A
        48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51
        CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB";
    const A_PRIV: &str = "60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393";
    const A_PUB: &str = "61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
        4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E
        42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073
        CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B";
    const B_PUB: &str = "BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
        BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610
        D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33
        1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58";
    const U: &str = "CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019";
    const S: &str = "B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
        233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C 41BB59B6 D5979B5C
        00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F 3499B200 210DCC1F 10EB3394 3CD67FC8
        8A2F39A4 BE5BEC4E C0A3212D C346D7E4 74B29EDE 8A469FFE CA686E5A";

    #[test]
    fn rfc5054_appendix_b() {
        let g = b"rfc5054_1024";
        let ring = Ring::new(g).unwrap();
        let k = digest(Hash::Sha1, &[&ring.modulus, &ring.pad(&[2]).unwrap()]);
        assert_eq!(k.as_slice(), h(K), "k");
        let x = x(b"sha1", &h(SALT), b"alice", b"password123").unwrap();
        assert!(x.as_slice() == h(X), "x");
        assert_eq!(public(g, &x).unwrap().as_slice(), h(V), "v");
        assert_eq!(public(g, &h(A_PRIV)).unwrap().as_slice(), h(A_PUB), "A");
        let u = u(g, b"sha1", &h(A_PUB), &h(B_PUB)).unwrap();
        assert_eq!(u.as_slice(), h(U), "u");
        let s = premaster(g, b"sha1", &x, &h(A_PRIV), &h(B_PUB)).unwrap();
        assert!(s.as_slice() == h(S), "premaster secret");
    }

    #[test]
    fn refuses_degenerate_values() {
        let g = b"rfc5054_1024";
        let ring = Ring::new(g).unwrap();
        let (x, a, b) = (h(X), h(A_PRIV), h(B_PUB));
        // B = 0 (one byte and padded), B = N, B = N + 1, B longer than N.
        let mut above = ring.modulus.clone();
        above[127] = above[127].wrapping_add(1);
        let mut longer = vec![1u8];
        longer.extend_from_slice(&b);
        for bad_b in [
            vec![0u8; 128],
            vec![0u8],
            ring.modulus.clone(),
            above,
            longer,
        ] {
            assert!(premaster(g, b"sha1", &x, &a, &bad_b).is_err());
        }
        assert!(premaster(g, b"sha1", &x, &[], &b).is_err());
        assert!(premaster(g, b"sha1", &[], &a, &b).is_err());
        assert!(premaster(g, b"sha1", &x, &[1u8; 129], &b).is_err());
        assert!(premaster(b"rfc5054_512", b"sha1", &x, &a, &b).is_err());
        assert!(premaster(g, b"md5", &x, &a, &b).is_err());
        assert!(public(g, &[]).is_err());
        // A leading zero byte in B is the same B.
        let mut padded = vec![0u8];
        padded.extend_from_slice(&b);
        assert!(premaster(g, b"sha1", &x, &a, &padded).unwrap().as_slice() == h(S));
        // The server's proof: right, one bit off, short.
        let key = digest(Hash::Sha1, &[&h(S)]);
        let m1 = m1(g, b"sha1", [b"alice", &h(SALT), &h(A_PUB), &b, &key]).unwrap();
        let mut m2 = digest(Hash::Sha1, &[&h(A_PUB), &m1, &key]).to_vec();
        assert!(
            verify(b"sha1", &h(A_PUB), &m1, &key, &m2)
                .unwrap()
                .is_empty()
        );
        m2[19] ^= 1;
        assert!(verify(b"sha1", &h(A_PUB), &m1, &key, &m2).is_err());
        assert!(verify(b"sha1", &h(A_PUB), &m1, &key, &m2[..19]).is_err());
    }

    #[test]
    fn groups_are_safe_primes() {
        for (name, bits, generator) in [
            (&b"rfc5054_1024"[..], 1024, 2u8),
            (b"rfc5054_1536", 1536, 2),
            (b"rfc5054_2048", 2048, 2),
            (b"rfc5054_3072", 3072, 5),
            (b"rfc5054_4096", 4096, 5),
            (b"rfc5054_6144", 6144, 5),
            (b"rfc5054_8192", 8192, 19),
        ] {
            let ring = Ring::new(name).unwrap();
            assert_eq!(ring.bits, bits);
            assert_eq!(ring.generator, generator);
            assert!(ring.modulus[0] & 0x80 != 0, "full length");
            let n = BoxedUint::from_be_slice(&ring.modulus, ring.bits).unwrap();
            assert!(
                crypto_primes::is_prime(crypto_primes::Flavor::Safe, &n),
                "the {bits}-bit group is not a safe prime"
            );
        }
    }
}
