//! Known-answer tests of the cryptographic functions of the template language, against
//! published test vectors. Each test names its source. Where a scheme is randomized (RSA-PSS,
//! RSA encryption, ephemeral key agreement), the output is checked by an independent verifier
//! or decryptor, with a key taken from a published vector.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use zeroize::Zeroizing;

use crate::primitives;
use crate::template::{Budget, Bytes, Func};

fn unhex(text: &str) -> Vec<u8> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    clean
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn func(name: &str) -> Func {
    Func::ALL.iter().find(|(n, _)| *n == name).unwrap().1
}

fn call_in(budget: &Budget, name: &str, args: &[&[u8]]) -> crate::Result<Vec<u8>> {
    let args: Vec<Bytes> = args.iter().map(|a| Zeroizing::new(a.to_vec())).collect();
    primitives::call(func(name), &args, 0, budget).map(|v| v.to_vec())
}

fn call(name: &str, args: &[&[u8]]) -> Vec<u8> {
    call_in(&Budget::default(), name, args).unwrap()
}

fn hex_call(name: &str, args: &[&[u8]]) -> String {
    call(name, args)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// RFC 1320, appendix A.5 (the MD4 test suite).
#[test]
fn md4_rfc1320() {
    for (input, digest) in [
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
        ("message digest", "d9130a8164549fe818874806e1c7014b"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ] {
        assert_eq!(hex_call("md4", &[input.as_bytes()]), digest, "{input}");
    }
}

/// FIPS 180-2 appendix D.1 (SHA-384 of "abc") and the NIST example "SHA512_256.pdf" of
/// FIPS 180-4 (SHA-512/256 of "abc").
#[test]
fn sha384_and_sha512_256_fips180() {
    assert_eq!(
        hex_call("sha384", &[b"abc"]),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(
        hex_call("sha512_256", &[b"abc"]),
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    );
}

/// RFC 2202 section 2 (HMAC-MD5 test cases 1 to 3) and RFC 4231 section 4 (HMAC-SHA-384
/// test cases 1 and 2).
#[test]
fn hmac_rfc2202_rfc4231() {
    let key_0b16 = [0x0bu8; 16];
    let key_0b20 = [0x0bu8; 20];
    assert_eq!(
        hex_call("hmac_md5", &[&key_0b16, b"Hi There"]),
        "9294727a3638bb1c13f48ef8158bfc9d"
    );
    assert_eq!(
        hex_call("hmac_md5", &[b"Jefe", b"what do ya want for nothing?"]),
        "750c783e6ab0b503eaa86e310a5db738"
    );
    assert_eq!(
        hex_call("hmac_md5", &[&[0xaa; 16], &[0xdd; 50]]),
        "56be34521d144c88dbb8c733f0e8b3f6"
    );
    assert_eq!(
        hex_call("hmac_sha384", &[&key_0b20, b"Hi There"]),
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
    );
    assert_eq!(
        hex_call("hmac_sha384", &[b"Jefe", b"what do ya want for nothing?"]),
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
    );
}

/// RFC 6070 section 2 (PBKDF2-HMAC-SHA1; the test with 16,777,216 iterations is over the
/// limit of one call) and RFC 7914 section 11 (PBKDF2-HMAC-SHA256).
#[test]
fn pbkdf2_rfc6070_rfc7914() {
    for (password, salt, rounds, length, out) in [
        (
            "password",
            "salt",
            "1",
            "20",
            "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        ),
        (
            "password",
            "salt",
            "2",
            "20",
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        ),
        (
            "password",
            "salt",
            "4096",
            "20",
            "4b007901b765489abead49d926f721d065a429c1",
        ),
        (
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            "4096",
            "25",
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        ),
        (
            "pass\0word",
            "sa\0lt",
            "4096",
            "16",
            "56fa6aa75548099dcc37d7f03425e0c3",
        ),
    ] {
        let args: [&[u8]; 5] = [
            b"sha1",
            password.as_bytes(),
            salt.as_bytes(),
            rounds.as_bytes(),
            length.as_bytes(),
        ];
        assert_eq!(
            hex_call("pbkdf2", &args),
            out,
            "RFC 6070 vector, {rounds} rounds"
        );
    }
    let rfc7914 = [
        (
            "passwd",
            "salt",
            "1",
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ),
        (
            "Password",
            "NaCl",
            "80000",
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        ),
    ];
    for (password, salt, rounds, out) in rfc7914 {
        let args: [&[u8]; 5] = [
            b"sha256",
            password.as_bytes(),
            salt.as_bytes(),
            rounds.as_bytes(),
            b"64",
        ];
        assert_eq!(hex_call("pbkdf2", &args), out);
        // The older name gives the same bytes.
        assert_eq!(
            hex_call(
                "pbkdf2_sha256",
                &[
                    password.as_bytes(),
                    salt.as_bytes(),
                    rounds.as_bytes(),
                    b"64"
                ]
            ),
            out
        );
    }
    // The default length is the digest length.
    assert_eq!(
        call("pbkdf2", &[b"sha1", b"password", b"salt", b"1"]).len(),
        20
    );
}

/// No RFC lists PBKDF2 with SHA-384 or SHA-512. RFC 8018 section 5.2 defines the first block
/// with one iteration as `HMAC(P, S || INT(1))`; the HMACs are checked above (RFC 4231).
#[test]
fn pbkdf2_sha384_sha512_by_definition() {
    for (hash, mac) in [("sha384", "hmac_sha384"), ("sha512", "hmac_sha512")] {
        let block = call(mac, &[b"password", b"salt\x00\x00\x00\x01"]);
        assert_eq!(
            call("pbkdf2", &[hash.as_bytes(), b"password", b"salt", b"1"]),
            block,
            "{hash}"
        );
    }
}

/// "The Galois/Counter Mode of Operation (GCM)", McGrew and Viega, the specification NIST
/// SP 800-38D builds on: test cases 7 and 8 (AES-192, zero key and IV).
#[test]
fn aes192_gcm_spec_vectors() {
    let key = [0u8; 24];
    let nonce = [0u8; 12];
    assert_eq!(
        hex_call("aes_gcm_encrypt", &[&key, &nonce, b""]),
        "cd33b28ac773f74ba00ed1f312572435"
    );
    assert_eq!(
        hex_call("aes_gcm_encrypt", &[&key, &nonce, &[0u8; 16]]),
        "98e7247c07f0fe411c267e4384b0f6002ff58d80033927ab8ef4d4587514f0fb"
    );
}

/// RFC 8439 section 2.8.2.
#[test]
fn chacha20_poly1305_rfc8439() {
    let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = unhex("070000004041424344454647");
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b6116",
        "1ae10b594f09e26a7e902ecbd0600691",
    );
    assert_eq!(
        hex_call(
            "chacha20_poly1305_encrypt",
            &[&key, &nonce, plaintext, &aad]
        ),
        expected
    );
}

/// RFC 6979 appendix A.2.7: P-521, SHA-512, message "sample" (deterministic nonce).
#[test]
fn p521_rfc6979() {
    use p521::ecdsa::signature::Verifier as _;
    let key = unhex(
        "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
    );
    let signature = call("p521_sign", &[&key, b"sample"]);
    assert_eq!(
        signature,
        unhex(concat!(
            "00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
            "00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",
        ))
    );
    let signing = p521::ecdsa::SigningKey::from_slice(&key).unwrap();
    let verifying = p521::ecdsa::VerifyingKey::from(&signing);
    let parsed = p521::ecdsa::Signature::from_slice(&signature).unwrap();
    assert!(verifying.verify(b"sample", &parsed).is_ok());
}

/// RFC 7748 section 6.1 (X25519), static mode in both directions.
#[test]
fn x25519_rfc7748() {
    let alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_public = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_eq!(hex_call("ecdh", &[b"x25519", &bob_public, &alice]), shared);
    assert_eq!(hex_call("ecdh", &[b"x25519", &alice_public, &bob]), shared);
    // A low-order peer key gives an all-zero secret: refused.
    assert!(call_in(&Budget::default(), "ecdh", &[b"x25519", &[0u8; 32], &alice]).is_err());
}

/// NIST CAVP, KAS ECC CDH primitive test vectors (`KAS_ECC_CDH_PrimitiveTest.txt`), P-256
/// COUNT = 0: the peer key QCAVS, the private key dIUT and the shared x-coordinate ZIUT.
#[test]
fn p256_ecdh_cavp() {
    let peer = unhex(concat!(
        "04",
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
    ));
    let private = unhex("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    assert_eq!(
        hex_call("ecdh", &[b"p256", &peer, &private]),
        "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
    );
}

/// Ephemeral mode: one key pair per curve and operation. The peer computes the same secret
/// from the public key the node hands out (checked with the curve crates directly).
#[test]
fn ecdh_ephemeral_agrees_with_the_peer() {
    use p256::elliptic_curve::Generate as _;
    let budget = Budget::default();
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    macro_rules! check {
        ($krate:ident, $name:literal, $len:expr) => {{
            let peer = $krate::SecretKey::generate_from_rng(&mut rng);
            let peer_public = {
                use $krate::elliptic_curve::sec1::ToSec1Point as _;
                peer.public_key()
                    .as_affine()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec()
            };
            let node_public = call_in(&budget, "ecdh_public", &[$name]).unwrap();
            assert_eq!(node_public.len(), $len);
            // Asked twice, the same key.
            assert_eq!(
                call_in(&budget, "ecdh_public", &[$name]).unwrap(),
                node_public
            );
            let shared = call_in(&budget, "ecdh", &[$name, &peer_public]).unwrap();
            let node = $krate::PublicKey::from_sec1_bytes(&node_public).unwrap();
            let theirs = peer.diffie_hellman(&node);
            assert_eq!(shared.as_slice(), theirs.raw_secret_bytes().as_slice());
        }};
    }
    check!(p256, b"p256", 65);
    check!(p384, b"p384", 97);
    check!(p521, b"p521", 133);
    let peer = [7u8; 32];
    let peer_public = x25519_dalek::x25519(peer, x25519_dalek::X25519_BASEPOINT_BYTES);
    let node_public = call_in(&budget, "ecdh_public", &[b"x25519"]).unwrap();
    let shared = call_in(&budget, "ecdh", &[b"x25519", &peer_public]).unwrap();
    assert_eq!(
        shared,
        x25519_dalek::x25519(peer, node_public.try_into().unwrap())
    );
    // Another operation has another key.
    assert_ne!(
        call_in(&Budget::default(), "ecdh_public", &[b"p256"]).unwrap(),
        call_in(&budget, "ecdh_public", &[b"p256"]).unwrap()
    );
}

/// Example 10 (2048 bits) of `pss-vect.txt`, the RSASSA-PSS vectors of the PKCS #1 v2.1
/// test vector set (`pkcs-1v2-1-vec.zip`, RSA Laboratories) that accompanies RFC 8017, as
/// shipped in Go's `crypto/rsa/testdata/pss-vect.txt.bz2`.
mod pss_vect_10 {
    pub(crate) const N: &str = concat!(
        "a5dd867ac4cb02f90b9457d48c14a770ef991c56c39c0ec65fd11afa8937cea5",
        "7b9be7ac73b45c0017615b82d622e318753b6027c0fd157be12f8090fee2a7ad",
        "cd0eef759f88ba4997c7a42d58c9aa12cb99ae001fe521c13bb5431445a8d5ae",
        "4f5e4c7e948ac227d3604071f20e577e905fbeb15dfaf06d1de5ae6253d63a6a",
        "2120b31a5da5dabc9550600e20f27d3739e2627925fea3cc509f21dff04e6eea",
        "4549c540d6809ff9307eede91fff58733d8385a237d6d3705a33e39190099207",
        "0df7adf1357cf7e3700ce3667de83f17b8df1778db381dce09cb4ad058a51100",
        "1a738198ee27cf55a13b754539906582ec8b174bd58d5d1f3d767c613721ae05",
    );
    pub(crate) const E: &str = "010001";
    pub(crate) const D: &str = concat!(
        "2d2ff567b3fe74e06191b7fded6de112290c670692430d5969184047da234c96",
        "93deed1673ed429539c969d372c04d6b47e0f5b8cee0843e5c22835dbd3b05a0",
        "997984ae6058b11bc4907cbf67ed84fa9ae252dfb0d0cd49e618e35dfdfe59bc",
        "a3ddd66c33cebbc77ad441aa695e13e324b518f01c60f5a85c994ad179f2a6b5",
        "fbe93402b11767be01bf073444d6ba1dd2bca5bd074d4a5fae3531ad1303d84b",
        "30d897318cbbba04e03c2e66de6d91f82f96ea1d4bb54a5aae102d594657f5c9",
        "789553512b296dea29d8023196357e3e3a6e958f39e3c2344038ea604b31edc6",
        "f0f7ff6e7181a57c92826a268f86768e96f878562fc71d85d69e448612f7048f",
    );
    pub(crate) const P: &str = concat!(
        "cfd50283feeeb97f6f08d73cbc7b3836f82bbcd499479f5e6f76fdfcb8b38c4f",
        "71dc9e88bd6a6f76371afd65d2af1862b32afb34a95f71b8b132043ffebe3a95",
        "2baf7592448148c03f9c69b1d68e4ce5cf32c86baf46fed301ca1ab403069b32",
        "f456b91f71898ab081cd8c4252ef5271915c9794b8f295851da7510f99cb73eb",
    );
    pub(crate) const Q: &str = concat!(
        "cc4e90d2a1b3a065d3b2d1f5a8fce31b544475664eab561d2971b99fb7bef844",
        "e8ec1f360b8c2ac8359692971ea6a38f723fcc211f5dbcb177a0fdac5164a1d4",
        "ff7fbb4e829986353cb983659a148cdd420c7d31ba3822ea90a32be46c030e8c",
        "17e1fa0ad37859e06b0aa6fa3b216d9cbe6c0e22339769c0a615913e5da719cf",
    );
    pub(crate) const MESSAGE: &str = "883177e5126b9be2d9a9680327d5370c6f26861f5820c43da67a3ad609";
    pub(crate) const SIGNATURE: &str = concat!(
        "82c2b160093b8aa3c0f7522b19f87354066c77847abf2a9fce542d0e84e920c5",
        "afb49ffdfdace16560ee94a1369601148ebad7a0e151cf16331791a5727d05f2",
        "1e74e7eb811440206935d744765a15e79f015cb66c532c87a6a05961c8bfad74",
        "1a9a6657022894393e7223739796c02a77455d0f555b0ec01ddf259b6207fd0f",
        "d57614cef1a5573baaff4ec00069951659b85f24300a25160ca8522dc6e6727e",
        "57d019d7e63629b8fe5e89e25cc15beb3a647577559299280b9b28f79b040900",
        "0be25bbd96408ba3b43cc486184dd1c8e62553fa1af4040f60663de7f5e49c04",
        "388e257f1ce89c95dab48a315d9b66b1b7628233876ff2385230d070d07e1666",
    );
}

fn big(hex: &str) -> rsa::BoxedUint {
    let bytes = unhex(hex);
    let bits = u32::try_from(bytes.len() * 8).unwrap();
    rsa::BoxedUint::from_be_slice(&bytes, bits).unwrap()
}

/// The private key of `pss_vect_10`, and its public key as PKCS#1 DER (for ring).
fn rsa_key() -> (rsa::PrivateKey, Vec<u8>) {
    use pss_vect_10::{D, E, N, P, Q};
    use rsa::pkcs1::EncodeRsaPublicKey as _;
    let key =
        rsa::PrivateKey::from_components(big(N), big(E), big(D), vec![big(P), big(Q)]).unwrap();
    let public = key
        .to_public_key()
        .to_pkcs1_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    (key, public)
}

/// The key assembled from the vector verifies the vector's own signature (Example 10.1,
/// RSASSA-PSS with SHA-1), so the tests below sign and decrypt with the published key.
#[test]
fn rsa_vector_key_verifies_its_published_signature() {
    use rsa::signature::Verifier as _;
    let (key, _) = rsa_key();
    let verifying = rsa::pss::VerifyingKey::<sha1::Sha1>::new(key.to_public_key());
    let signature =
        rsa::pss::Signature::try_from(unhex(pss_vect_10::SIGNATURE).as_slice()).unwrap();
    assert!(
        verifying
            .verify(&unhex(pss_vect_10::MESSAGE), &signature)
            .is_ok()
    );
}

/// RSASSA-PKCS1-v1_5 is deterministic. No published vector with the private key's CRT
/// components was available offline, so each output is checked twice: by ring's verifier,
/// and against RustCrypto `rsa` signing the same message with the same key (independent
/// implementations must give the same bytes).
#[test]
fn rsa_sign_pkcs1_every_hash() {
    use ring::signature::{
        RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey,
    };
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::pkcs8::EncodePrivateKey as _;
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    let (key, public) = rsa_key();
    let pkcs1 = key.to_pkcs1_der().unwrap().as_bytes().to_vec();
    let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let message = unhex(pss_vect_10::MESSAGE);
    let reference = |hash: &str| -> Vec<u8> {
        let k = key.clone();
        match hash {
            "sha1" => rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(k)
                .sign(&message)
                .to_vec(),
            "sha256" => rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k)
                .sign(&message)
                .to_vec(),
            "sha384" => rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(k)
                .sign(&message)
                .to_vec(),
            _ => rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(k)
                .sign(&message)
                .to_vec(),
        }
    };
    for (hash, algorithm) in [
        ("sha1", &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        ("sha256", &RSA_PKCS1_2048_8192_SHA256),
        ("sha384", &RSA_PKCS1_2048_8192_SHA384),
        ("sha512", &RSA_PKCS1_2048_8192_SHA512),
    ] {
        for der in [&pkcs1, &pkcs8] {
            let signature = call("rsa_sign_pkcs1", &[hash.as_bytes(), der, &message]);
            assert!(
                UnparsedPublicKey::new(algorithm, &public)
                    .verify(&message, &signature)
                    .is_ok(),
                "{hash}"
            );
            assert_eq!(signature, reference(hash), "{hash}");
        }
    }
    // The older name is the SHA-256 form.
    assert_eq!(
        call("rsa_sign_pkcs1_sha256", &[&pkcs8, &message]),
        reference("sha256")
    );
}

/// RSASSA-PSS is randomized: each output is checked by ring's verifier.
#[test]
fn rsa_sign_pss_every_hash() {
    use ring::signature::{
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
        UnparsedPublicKey,
    };
    use rsa::pkcs8::EncodePrivateKey as _;
    let (key, public) = rsa_key();
    let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let message = unhex(pss_vect_10::MESSAGE);
    for (hash, algorithm) in [
        ("sha256", &RSA_PSS_2048_8192_SHA256),
        ("sha384", &RSA_PSS_2048_8192_SHA384),
        ("sha512", &RSA_PSS_2048_8192_SHA512),
    ] {
        let signature = call("rsa_sign_pss", &[hash.as_bytes(), &pkcs8, &message]);
        assert!(
            UnparsedPublicKey::new(algorithm, &public)
                .verify(&message, &signature)
                .is_ok(),
            "{hash}"
        );
    }
    assert!(
        call_in(
            &Budget::default(),
            "rsa_sign_pss",
            &[b"sha1", &pkcs8, &message]
        )
        .is_err()
    );
}

/// RSA encryption is randomized: each ciphertext, made under the public key of the vector
/// (SubjectPublicKeyInfo and PKCS#1 forms), is decrypted with its private key by RustCrypto
/// `rsa`.
#[test]
fn rsa_encrypt_decrypts_with_the_vector_key() {
    use rsa::pkcs8::EncodePublicKey as _;
    let (key, pkcs1_public) = rsa_key();
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let message = b"correct horse battery staple";
    for public in [&spki, &pkcs1_public] {
        let ct = call("rsa_encrypt_pkcs1", &[public, message]);
        assert_eq!(ct.len(), 256);
        assert_eq!(key.decrypt(rsa::Pkcs1v15Encrypt, &ct).unwrap(), message);
        for hash in ["sha1", "sha256", "sha384", "sha512"] {
            let ct = call("rsa_encrypt_oaep", &[hash.as_bytes(), public, message]);
            let plain = match hash {
                "sha1" => key.decrypt(rsa::Oaep::<sha1::Sha1>::new(), &ct),
                "sha256" => key.decrypt(rsa::Oaep::<sha2::Sha256>::new(), &ct),
                "sha384" => key.decrypt(rsa::Oaep::<sha2::Sha384>::new(), &ct),
                _ => key.decrypt(rsa::Oaep::<sha2::Sha512>::new(), &ct),
            };
            assert_eq!(plain.unwrap(), message, "{hash}");
        }
    }
    // Too long for the key: refused, not truncated.
    assert!(
        call_in(
            &Budget::default(),
            "rsa_encrypt_pkcs1",
            &[&spki, &[0u8; 250]]
        )
        .is_err()
    );
}
