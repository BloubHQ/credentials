//! Known-answer tests of the families of part 9 of the design: HPKE (RFC 9180), TurboSHAKE and
//! KangarooTwelve (RFC 9861). The vectors and their provenance are in
//! `tests/fixtures/vectors` (see its README).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;

use crate::primitives::hpke::{Context, Extras, Mode, Suite};
use crate::primitives::turbo::{Level, kt_into, turboshake_into};
use crate::template::Budget;
use crate::vectors::{call, call_in, unhex};

const HPKE: &str = include_str!("../tests/fixtures/vectors/hpke-rfc9180.json");
const TURBOSHAKE: &str = include_str!("../tests/fixtures/vectors/turboshake-rfc9861.json");

fn hex_of(v: &Value, key: &str) -> Vec<u8> {
    unhex(v[key].as_str().unwrap())
}

fn kem_name(id: u64) -> &'static str {
    match id {
        0x10 => "p256",
        0x11 => "p384",
        0x12 => "p521",
        0x20 => "x25519",
        0x21 => "x448",
        _ => unreachable!(),
    }
}

fn kdf_name(id: u64) -> &'static str {
    match id {
        1 => "sha256",
        2 => "sha384",
        3 => "sha512",
        _ => unreachable!(),
    }
}

fn aead_name(id: u64) -> &'static str {
    match id {
        1 => "aes128gcm",
        2 => "aes256gcm",
        3 => "chacha20poly1305",
        0xffff => "export",
        _ => unreachable!(),
    }
}

fn mode_name(id: u64) -> &'static str {
    ["base", "psk", "auth", "auth_psk"][usize::try_from(id).unwrap()]
}

/// RFC 9180 appendix A (the CFRG JSON vectors, subset): for every suite and mode, the derived
/// key pairs, `enc`, the key schedule, the encryptions at sequence 0, 1, 255 and 256 both
/// ways, and every export both ways.
#[test]
fn hpke_rfc9180() {
    let vectors: Vec<Value> = serde_json::from_str(HPKE).unwrap();
    let (mut suites, mut encryptions, mut exports) = (0, 0, 0);
    for v in &vectors {
        let (kem, kdf, aead, mode) = (
            v["kem_id"].as_u64().unwrap(),
            v["kdf_id"].as_u64().unwrap(),
            v["aead_id"].as_u64().unwrap(),
            v["mode"].as_u64().unwrap(),
        );
        let name = format!("{},{},{}", kem_name(kem), kdf_name(kdf), aead_name(aead));
        let what = format!("{name} {}", mode_name(mode));
        let suite = Suite::parse(name.as_bytes()).unwrap();
        let mode = Mode::parse(mode_name(mode).as_bytes()).unwrap();
        // DeriveKeyPair gives the private keys of the vector.
        let sk_r = suite.kem.derive_private(&hex_of(v, "ikmR")).unwrap();
        assert!(*sk_r == hex_of(v, "skRm"), "{what}: skR");
        let sk_e = suite.kem.derive_private(&hex_of(v, "ikmE")).unwrap();
        assert!(*sk_e == hex_of(v, "skEm"), "{what}: skE");
        let (pk_r, info) = (hex_of(v, "pkRm"), hex_of(v, "info"));
        let psk = v
            .get("psk")
            .map(|_| (hex_of(v, "psk"), hex_of(v, "psk_id")));
        let sk_s = v.get("skSm").map(|_| hex_of(v, "skSm"));
        let pk_s = v.get("pkSm").map(|_| hex_of(v, "pkSm"));
        if let Some(ikm) = v.get("ikmS") {
            let derived = suite
                .kem
                .derive_private(&unhex(ikm.as_str().unwrap()))
                .unwrap();
            assert!(Some(derived.to_vec()) == sk_s, "{what}: skS");
        }
        let psk_pair = psk.as_ref().map(|(p, i)| (p.as_slice(), i.as_slice()));
        let send_extras = Extras {
            psk: psk_pair,
            sender: sk_s.as_deref(),
        };
        let receive_extras = Extras {
            psk: psk_pair,
            sender: pk_s.as_deref(),
        };
        let (mut sender, enc) =
            Context::sender(suite, mode, &pk_r, &info, send_extras, &sk_e).unwrap();
        assert!(*enc == hex_of(v, "enc"), "{what}: enc");
        let mut receiver =
            Context::receiver(suite, mode, &hex_of(v, "skRm"), &enc, &info, receive_extras)
                .unwrap();
        let (key, nonce, exporter) = sender.secrets();
        assert!(key == hex_of(v, "key"), "{what}: key");
        assert!(nonce == hex_of(v, "base_nonce"), "{what}: base_nonce");
        assert!(
            exporter == hex_of(v, "exporter_secret"),
            "{what}: exporter_secret"
        );
        assert!(receiver.secrets() == sender.secrets(), "{what}: receiver");
        for e in v["encryptions"].as_array().unwrap() {
            let seq = e["seq"].as_u64().unwrap();
            sender.set_seq(seq);
            receiver.set_seq(seq);
            let (aad, pt, ct) = (hex_of(e, "aad"), hex_of(e, "pt"), hex_of(e, "ct"));
            let sealed = sender.seal(&aad, &pt).unwrap();
            assert!(*sealed == ct, "{what}: seal at {seq}");
            let opened = receiver.open(&aad, &ct).unwrap();
            assert!(*opened == pt, "{what}: open at {seq}");
            encryptions += 1;
        }
        for x in v["exports"].as_array().unwrap() {
            let length = usize::try_from(x["L"].as_u64().unwrap()).unwrap();
            let context = hex_of(x, "exporter_context");
            let expected = hex_of(x, "exported_value");
            assert!(
                *sender.export(&context, length).unwrap() == expected,
                "{what}: export"
            );
            assert!(
                *receiver.export(&context, length).unwrap() == expected,
                "{what}: receiver export"
            );
            exports += 1;
        }
        suites += 1;
    }
    println!("hpke: {suites} suites and modes, {encryptions} encryptions, {exports} exports");
    assert_eq!((suites, encryptions, exports), (128, 384, 384));
}

/// The template functions round trip on every KEM (P-384 and HKDF-SHA384 included, which the
/// CFRG vectors lack), every AEAD and every mode; a wrong key, info or AAD fails to open, and
/// the modes refuse arguments that do not match them.
#[test]
fn hpke_template_functions() {
    let psk = [0x42u8; 32];
    let mut checked = 0;
    for kem in ["p256", "p384", "p521", "x25519", "x448"] {
        let k = Suite::parse(format!("{kem},sha256,aes128gcm").as_bytes())
            .unwrap()
            .kem;
        let sk_r = k.derive_private(b"recipient key material").unwrap();
        let sk_s = k.derive_private(b"sender key material").unwrap();
        let pk_r = call_in(&Budget::default(), "hpke_public", &[kem.as_bytes(), &sk_r]).unwrap();
        let pk_s = call_in(&Budget::default(), "hpke_public", &[kem.as_bytes(), &sk_s]).unwrap();
        assert_eq!(pk_r.len(), k.public_len());
        for kdf in ["sha256", "sha384", "sha512"] {
            for aead in ["aes128gcm", "aes256gcm", "chacha20poly1305"] {
                let suite = format!("{kem},{kdf},{aead}");
                for mode in ["base", "psk", "auth", "auth_psk"] {
                    let mut send_extra: Vec<&[u8]> = Vec::new();
                    let mut open_extra: Vec<&[u8]> = Vec::new();
                    if mode.contains("psk") {
                        send_extra.extend([&psk[..], b"id"]);
                        open_extra.extend([&psk[..], b"id"]);
                    }
                    if mode.starts_with("auth") {
                        send_extra.push(&sk_s);
                        open_extra.push(&pk_s);
                    }
                    let mut seal: Vec<&[u8]> = vec![
                        suite.as_bytes(),
                        mode.as_bytes(),
                        &pk_r,
                        b"info",
                        b"aad",
                        b"hello",
                    ];
                    seal.extend(&send_extra);
                    let sealed = call("hpke_seal", &seal);
                    let (enc, ct) = sealed.split_at(k.public_len());
                    let mut open: Vec<&[u8]> = vec![
                        suite.as_bytes(),
                        mode.as_bytes(),
                        &sk_r,
                        enc,
                        b"info",
                        b"aad",
                        ct,
                    ];
                    open.extend(&open_extra);
                    assert_eq!(call("hpke_open", &open), b"hello", "{suite} {mode}");
                    // Another AAD or info does not open.
                    let mut wrong = open.clone();
                    wrong[5] = b"other";
                    assert!(call_in(&Budget::default(), "hpke_open", &wrong).is_err());
                    wrong = open.clone();
                    wrong[4] = b"other";
                    assert!(call_in(&Budget::default(), "hpke_open", &wrong).is_err());
                    // Exports agree on both sides.
                    let mut export: Vec<&[u8]> = vec![
                        suite.as_bytes(),
                        mode.as_bytes(),
                        &pk_r,
                        b"info",
                        b"ctx",
                        b"48",
                    ];
                    export.extend(&send_extra);
                    let exported = call("hpke_export", &export);
                    let (enc, secret) = exported.split_at(k.public_len());
                    assert_eq!(secret.len(), 48);
                    let mut receive: Vec<&[u8]> = vec![
                        suite.as_bytes(),
                        mode.as_bytes(),
                        &sk_r,
                        enc,
                        b"info",
                        b"ctx",
                        b"48",
                    ];
                    receive.extend(&open_extra);
                    assert_eq!(call("hpke_receiver_export", &receive), secret);
                    // Arguments that do not match the mode are refused.
                    let mut extra = seal.clone();
                    extra.push(b"x");
                    assert!(call_in(&Budget::default(), "hpke_seal", &extra).is_err());
                    checked += 1;
                }
            }
        }
    }
    println!("hpke round trips: {checked}");
    assert_eq!(checked, 5 * 3 * 3 * 4);
    // Fresh ephemeral keys: two seals of one message differ.
    let k = Suite::parse(b"x25519,sha256,chacha20poly1305").unwrap().kem;
    let sk = k.derive_private(b"k").unwrap();
    let pk = call("hpke_public", &[b"x25519", &sk]);
    let seal: [&[u8]; 6] = [
        b"x25519,sha256,chacha20poly1305",
        b"base",
        &pk,
        b"",
        b"",
        b"m",
    ];
    assert_ne!(call("hpke_seal", &seal), call("hpke_seal", &seal));
    for (seal, why) in [
        (
            vec![&b"x25519,sha256,export"[..], b"base", &pk, b"", b"", b"m"],
            "export-only suite",
        ),
        (
            vec![&b"x25519,sha1,aes128gcm"[..], b"base", &pk, b"", b"", b"m"],
            "kdf",
        ),
        (
            vec![&b"p256,sha256,aes128gcm"[..], b"base", &pk, b"", b"", b"m"],
            "key length",
        ),
        (
            vec![
                &b"x25519,sha256,aes128gcm"[..],
                b"psk",
                &pk,
                b"",
                b"",
                b"m",
                b"short",
                b"id",
            ],
            "short psk",
        ),
        (
            vec![
                &b"x25519,sha256,aes128gcm"[..],
                b"auth",
                &pk,
                b"",
                b"",
                b"m",
            ],
            "auth without key",
        ),
    ] {
        assert!(
            call_in(&Budget::default(), "hpke_seal", &seal).is_err(),
            "{why}"
        );
    }
    let export: [&[u8]; 6] = [b"x25519,sha256,export", b"base", &pk, b"", b"", b"8193"];
    assert!(call_in(&Budget::default(), "hpke_export", &export).is_err());
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|j| u8::try_from(j % 251).unwrap()).collect()
}

/// RFC 9861 section 5, TurboSHAKE128 and TurboSHAKE256 with domain bytes 0x06 and 0x07 (the
/// records of the `turboshake` crate), through the template function where the output fits
/// its limits and directly otherwise.
#[test]
fn turboshake_rfc9861() {
    let vectors: Vec<Value> = serde_json::from_str(TURBOSHAKE).unwrap();
    for v in &vectors {
        let level = match v["level"].as_u64().unwrap() {
            128 => Level::L128,
            _ => Level::L256,
        };
        let domain = u8::try_from(v["domain"].as_u64().unwrap()).unwrap();
        let skip = usize::try_from(v["skip"].as_u64().unwrap()).unwrap();
        let len = usize::try_from(v["pattern_len"].as_u64().unwrap()).unwrap();
        let message = if len > 0 {
            pattern(len)
        } else {
            hex_of(v, "message")
        };
        let expected = hex_of(v, "output");
        let mut out = vec![0u8; skip + expected.len()];
        turboshake_into(level, &message, domain, &mut out);
        assert_eq!(out[skip..], expected, "{v}");
        if skip == 0 && message.len() < 4096 {
            let name = if level == Level::L128 {
                "turboshake128"
            } else {
                "turboshake256"
            };
            let length = expected.len().to_string();
            let domain = domain.to_string();
            let via = call(name, &[&message, domain.as_bytes(), length.as_bytes()]);
            assert_eq!(via, expected, "{name}");
        }
    }
    println!("turboshake: {} vectors", vectors.len());
    assert_eq!(vectors.len(), 25);
    for (domain, length) in [
        ("0", "32"),
        ("128", "32"),
        ("x", "32"),
        ("1", "0"),
        ("1", "8193"),
    ] {
        let args: [&[u8]; 3] = [b"", domain.as_bytes(), length.as_bytes()];
        assert!(call_in(&Budget::default(), "turboshake128", &args).is_err());
    }
}

/// RFC 9861 section 3.2, written out over the TurboSHAKE above: the single node (domain byte
/// 0x07) and the tree (0x0B for chaining values, 0x06 for the final node). Checked against
/// the `k12` crate, so the TurboSHAKE of this module is checked with those domain bytes too.
fn kt_reference(level: Level, message: &[u8], custom: &[u8], len: usize) -> Vec<u8> {
    fn length_encode(x: usize) -> Vec<u8> {
        let bytes: Vec<u8> = x
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = bytes.clone();
        out.push(u8::try_from(bytes.len()).unwrap());
        out
    }
    let mut s = message.to_vec();
    s.extend_from_slice(custom);
    s.extend(length_encode(custom.len()));
    let chunk = 8192;
    let mut out = vec![0u8; len];
    if s.len() <= chunk {
        turboshake_into(level, &s, 0x07, &mut out);
        return out;
    }
    let cv = if level == Level::L128 { 32 } else { 64 };
    let mut node = s[..chunk].to_vec();
    node.extend_from_slice(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
    let mut n = 0;
    for part in s[chunk..].chunks(chunk) {
        let mut value = vec![0u8; cv];
        turboshake_into(level, part, 0x0b, &mut value);
        node.extend(value);
        n += 1;
    }
    node.extend(length_encode(n));
    node.extend_from_slice(&[0xff, 0xff]);
    turboshake_into(level, &node, 0x06, &mut out);
    out
}

/// RFC 9861 section 5, KT128 and KT256 (as listed in the tests of the `k12` crate), and the
/// written-out tree above against the crate for messages of one to four chunks.
#[test]
fn kangarootwelve_rfc9861() {
    let kt = |level, m: &[u8], c: &[u8], len: usize| {
        let mut out = vec![0u8; len];
        kt_into(level, m, c, &mut out);
        out
    };
    let hex = |s: &str| unhex(s);
    assert_eq!(
        kt(Level::L128, b"", b"", 32),
        hex("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")
    );
    assert_eq!(
        kt(Level::L128, b"", b"", 10032)[10000..],
        hex("e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d")
    );
    assert_eq!(
        kt(Level::L256, b"", b"", 64),
        hex(
            "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"
        )
    );
    let m128 = [
        "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f",
        "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888",
        "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c",
        "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0",
        "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe",
    ];
    for (i, expected) in m128.iter().enumerate() {
        let m = pattern(17usize.pow(u32::try_from(i).unwrap()));
        assert_eq!(
            kt(Level::L128, &m, b"", 32),
            hex(expected),
            "KT128 ptn(17^{i})"
        );
    }
    let m256 = [
        "0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0",
        "1ba3c02b1fc514474f06c8979978a9056c8483f4a1b63d0dccefe3a28a2f323e1cdcca40ebf006ac76ef0397152346837b1277d3e7faa9c9653b19075098527b",
        "de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba",
        "647efb49fe9d717500171b41e7f11bd491544443209997ce1c2530d15eb1ffbb598935ef954528ffc152b1e4d731ee2683680674365cd191d562bae753b84aa5",
        "b06275d284cd1cf205bcbe57dccd3ec1ff6686e3ed15776383e1f2fa3c6ac8f08bf8a162829db1a44b2a43ff83dd89c3cf1ceb61ede659766d5ccf817a62ba8d",
    ];
    for (i, expected) in m256.iter().enumerate() {
        let m = pattern(17usize.pow(u32::try_from(i).unwrap()));
        assert_eq!(
            kt(Level::L256, &m, b"", 64),
            hex(expected),
            "KT256 ptn(17^{i})"
        );
    }
    let c128 = [
        "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583",
        "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4",
        "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74",
        "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf",
    ];
    let c256 = [
        "9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b159811f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6",
        "47ef96dd616f200937aa7847e34ec2feae8087e3761dc0f8c1a154f51dc9ccf845d7adbce57ff64b639722c6a1672e3bf5372d87e00aff89be97240756998853",
        "3b48667a5051c5966c53c5d42b95de451e05584e7806e2fb765eda959074172cb438a9e91dde337c98e9c41bed94c4e0aef431d0b64ef2324f7932caa6f54969",
        "e0911cc00025e1540831e266d94add9b98712142b80d2629e643aac4efaf5a3a30a88cbf4ac2a91a2432743054fbcc9897670e86ba8cec2fc2ace9c966369724",
    ];
    for i in 0..4u32 {
        let m = vec![0xffu8; 2usize.pow(i) - 1];
        let c = pattern(41usize.pow(i));
        assert_eq!(
            kt(Level::L128, &m, &c, 32),
            hex(c128[i as usize]),
            "KT128 C {i}"
        );
        assert_eq!(
            kt(Level::L256, &m, &c, 64),
            hex(c256[i as usize]),
            "KT256 C {i}"
        );
        // Through the template functions.
        let via = call("kt128", &[&m, &c, b"32"]);
        assert_eq!(via, hex(c128[i as usize]));
        let via = call("kt256", &[&m, &c, b"64"]);
        assert_eq!(via, hex(c256[i as usize]));
    }
    // The tree written out over this module's TurboSHAKE agrees with the crate.
    for len in [0, 1, 8191, 8192, 8193, 16384, 16385, 3 * 8192 + 7] {
        let m = pattern(len);
        for (level, size) in [(Level::L128, 32), (Level::L256, 64)] {
            assert_eq!(
                kt_reference(level, &m, b"ctx", size),
                kt(level, &m, b"ctx", size),
                "tree of {len} bytes"
            );
        }
    }
}

/// The base64 body of a PEM block.
fn pem_body(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

/// ML-DSA (FIPS 204): the public keys of the seed `00 01 .. 1f` in the examples of the IETF
/// LAMPS ML-DSA certificate profile (as bundled with the `ml-dsa` crate), and signatures that
/// the crate's verifier accepts, with and without a context.
#[test]
fn mldsa_lamps_examples() {
    use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};
    macro_rules! level {
        ($level:literal, $params:ty, $private:literal, $public:literal, $len:literal) => {{
            let private = pem_body(include_str!(concat!(
                "../tests/fixtures/vectors/",
                $private
            )));
            let spki = pem_body(include_str!(concat!("../tests/fixtures/vectors/", $public)));
            let seed = &private[private.len() - 32..];
            assert_eq!(seed, (0u8..32).collect::<Vec<_>>().as_slice());
            let public = &spki[spki.len() - $len..];
            assert!(
                call("mldsa_public", &[$level, seed]) == public,
                concat!("ML-DSA-", stringify!($level), " public key")
            );
            let key = VerifyingKey::<$params>::decode(
                &EncodedVerifyingKey::<$params>::try_from(public).unwrap(),
            );
            for context in [&b""[..], b"context"] {
                let mut args: Vec<&[u8]> = vec![$level, seed, b"message"];
                if !context.is_empty() {
                    args.push(context);
                }
                let first = call("mldsa_sign", &args);
                let second = call("mldsa_sign", &args);
                // Hedged: a fresh `rnd` makes each signature new.
                assert_ne!(first, second);
                for bytes in [first, second] {
                    let signature =
                        Signature::<$params>::decode(&bytes.as_slice().try_into().unwrap())
                            .unwrap();
                    assert!(key.verify_with_context(b"message", context, &signature));
                    assert!(!key.verify_with_context(b"messagf", context, &signature));
                }
            }
        }};
    }
    level!(b"44", MlDsa44, "ML-DSA-44-seed.priv", "ML-DSA-44.pub", 1312);
    level!(b"65", MlDsa65, "ML-DSA-65-seed.priv", "ML-DSA-65.pub", 1952);
    level!(b"87", MlDsa87, "ML-DSA-87-seed.priv", "ML-DSA-87.pub", 2592);
    let seed = [7u8; 32];
    assert!(call_in(&Budget::default(), "mldsa_sign", &[b"99", &seed, b"m"]).is_err());
    assert!(
        call_in(
            &Budget::default(),
            "mldsa_sign",
            &[b"44", &seed[..31], b"m"]
        )
        .is_err()
    );
    assert!(
        call_in(
            &Budget::default(),
            "mldsa_sign",
            &[b"44", &seed, b"m", &[0u8; 256]]
        )
        .is_err()
    );
}

/// SM2 (GB/T 32918.2): the key and the OpenSSL signature bundled with the `sm2` crate
/// (`tests/sm2dsa.rs`); signatures by `sm2_sign` verify under that public key, with the
/// crate's identifier and with the default one.
#[test]
fn sm2_crate_vector() {
    use sm2::dsa::signature::Verifier as _;
    use sm2::dsa::{Signature, VerifyingKey};
    let public = unhex(
        "0408D77AE04C01CC4C1104360DD8AF6B6F7DF334283D7C1A6AFD5652407B87BEE5014E2A57C36C150D16324DC664E31E6432359609C4E79847A5B161C8C7364C8A",
    );
    let id = "example@rustcrypto.org";
    let openssl = unhex(
        "d1dcccedd9fb785e0f67c16b7c52901625c0b69de9bca2144acc7be713cad2fcf7d1eae6e3a157b36c65f672f738ca8b46298bf149a6510072c431b49cd88b1c",
    );
    let key = VerifyingKey::from_sec1_bytes(id, &public).unwrap();
    let signature = Signature::from_slice(&openssl).unwrap();
    assert!(key.verify(b"testing", &signature).is_ok());
    let private: &[u8] = include_bytes!("../tests/fixtures/vectors/sm2-pkcs8-private-key.der");
    let ours = call("sm2_sign", &[private, b"testing", id.as_bytes()]);
    assert!(
        key.verify(b"testing", &Signature::from_slice(&ours).unwrap())
            .is_ok()
    );
    assert!(
        key.verify(b"testinh", &Signature::from_slice(&ours).unwrap())
            .is_err()
    );
    // The default identifier.
    let default = VerifyingKey::from_sec1_bytes("1234567812345678", &public).unwrap();
    let ours = call("sm2_sign", &[private, b"testing"]);
    assert!(
        default
            .verify(b"testing", &Signature::from_slice(&ours).unwrap())
            .is_ok()
    );
    assert!(call_in(&Budget::default(), "sm2_sign", &[private, b"m", b""]).is_err());
}

/// Brainpool P256r1 and P384r1 (RFC 5639) through `ecdsa_sign_prehash`: the signature
/// verifies under the key's public key, and the nonce is deterministic (RFC 6979).
#[test]
fn brainpool_prehash_round_trip() {
    use ecdsa::signature::hazmat::PrehashVerifier as _;
    macro_rules! curve {
        ($name:literal, $curve:ty, $len:literal) => {{
            let secret = [0x11u8; $len];
            let digest = [0x5au8; $len];
            let bytes = call("ecdsa_sign_prehash", &[$name, &secret, &digest]);
            assert_eq!(
                bytes,
                call("ecdsa_sign_prehash", &[$name, &secret, &digest])
            );
            let key = ecdsa::SigningKey::<$curve>::from_slice(&secret).unwrap();
            let signature = ecdsa::Signature::<$curve>::from_slice(&bytes).unwrap();
            assert!(
                key.verifying_key()
                    .verify_prehash(&digest, &signature)
                    .is_ok()
            );
            assert!(
                key.verifying_key()
                    .verify_prehash(&[0x5bu8; $len], &signature)
                    .is_err()
            );
        }};
    }
    curve!(b"bp256", bp256::BrainpoolP256r1, 32);
    curve!(b"bp384", bp384::BrainpoolP384r1, 48);
}
