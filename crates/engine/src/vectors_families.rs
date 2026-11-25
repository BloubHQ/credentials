//! Known-answer tests of the second group of primitive families (KDFs, key wrapping, AES
//! modes and MACs, Ed448, prehashed ECDSA, DSA, X448, SHA-3 and SHAKE, CBOR, Kerberos
//! n-fold and DK), against published vectors. Each test names its source.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crate::template::Budget;
use crate::vectors::{call, call_in, hex_call, unhex};

/// FIPS 202 examples (NIST CSRC "Example Values"): SHA3-224/256/384/512 of the empty
/// message and of "abc"; SHAKE128 and SHAKE256 of the empty message.
#[test]
fn sha3_and_shake_fips202() {
    for (name, empty, abc) in [
        (
            "sha3_224",
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
        ),
        (
            "sha3_256",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        ),
        (
            "sha3_384",
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        ),
        (
            "sha3_512",
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        ),
    ] {
        assert_eq!(hex_call(name, &[b""]), empty, "{name}");
        assert_eq!(hex_call(name, &[b"abc"]), abc, "{name}");
    }
    assert_eq!(
        hex_call("shake128", &[b"", b"32"]),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
    assert_eq!(
        hex_call("shake256", &[b"", b"64"]),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    );
    // An extendable output: a shorter read is a prefix of a longer one.
    let long = call("shake256", &[b"abc", b"200"]);
    assert_eq!(call("shake256", &[b"abc", b"17"]), long[..17]);
    for len in [&b"0"[..], b"8193", b"x"] {
        assert!(call_in(&Budget::default(), "shake128", &[b"", len]).is_err());
    }
}

/// RFC 5869 appendix A.1 to A.3 (HKDF-SHA-256), and the first cases of Project Wycheproof's
/// `hkdf_sha384_test.json` and `hkdf_sha512_test.json` (no RFC lists SHA-384 or SHA-512).
#[test]
fn hkdf_rfc5869_wycheproof() {
    let cases: [(&str, &str, &str, &str, &str); 3] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ];
    for (ikm, salt, info, prk, okm) in cases {
        let (ikm, salt, info) = (unhex(ikm), unhex(salt), unhex(info));
        let len = (okm.len() / 2).to_string();
        assert_eq!(
            hex_call("hkdf", &[b"sha256", &ikm, &salt, &info, len.as_bytes()]),
            okm
        );
        // Extract is HMAC(salt, ikm) (a zero salt of the hash length when empty); expand
        // alone from the published PRK gives the same output.
        let zero = [0u8; 32];
        let salt = if salt.is_empty() { &zero[..] } else { &salt };
        assert_eq!(hex_call("hmac_sha256", &[salt, &ikm]), prk);
        assert_eq!(
            hex_call(
                "hkdf_expand",
                &[b"sha256", &unhex(prk), &info, len.as_bytes()]
            ),
            okm
        );
    }
    for (hash, okm) in [
        ("sha384", "3f8b0e4a7b2bff01a26a18f1e07c0218897a324e"),
        ("sha512", "2109bd244744acae2b8caa9e70f57596ad680212"),
    ] {
        let ikm = unhex("60ab7f45b0ad534683b3a6c020d4f775");
        assert_eq!(
            hex_call("hkdf", &[hash.as_bytes(), &ikm, b"", b"", b"20"]),
            okm
        );
    }
    // At most 255 blocks; SHA-1 and unknown names are refused.
    assert!(
        call_in(
            &Budget::default(),
            "hkdf",
            &[b"sha256", b"k", b"", b"", b"8161"]
        )
        .is_err()
    );
    assert!(
        call_in(
            &Budget::default(),
            "hkdf",
            &[b"sha1", b"k", b"", b"", b"16"]
        )
        .is_err()
    );
    assert_eq!(
        call("hkdf", &[b"sha256", b"k", b"", b"", b"8160"]).len(),
        8160
    );
}

/// RFC 7518 appendix C: the ECDH-ES key agreement of the JWE example, on P-256, with Concat
/// KDF (NIST SP 800-56A) over SHA-256. The shared secret Z comes from the published
/// ephemeral private key and the recipient's public key; the derived key is
/// `VqqN6vgjbSBcIijNcacQGg`.
#[test]
fn ecdh_es_concat_kdf_rfc7518() {
    let ephemeral = unhex("d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a");
    let recipient = unhex(concat!(
        "04",
        "c1e349cb61ec70248ce801034c3834e1b88ebe1161cb25af38741f785fcfc4c4",
        "7bc96708ef80952b53f8d2555fe72b841ed04588628b1d378a594939500ec9c9",
    ));
    let z = call("ecdh", &[b"p256", &recipient, &ephemeral]);
    assert_eq!(
        z,
        [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196
        ]
    );
    // AlgorithmID "A128GCM", PartyUInfo "Alice", PartyVInfo "Bob", SuppPubInfo 128.
    let other = unhex("000000074131323847434d00000005416c69636500000003426f6200000080");
    assert_eq!(
        hex_call("concat_kdf", &[b"sha256", &z, &other, b"16"]),
        "56aa8deaf8236d205c2228cd71a7101a"
    );
}

/// NIST CAVP, KBKDF (SP 800-108) counter mode, `KDFCTR_gen.txt`, [PRF=HMAC_SHA256]
/// [CTRLOCATION=BEFORE_FIXED] [RLEN=32_BITS], COUNT=15; and RFC 8009 appendix A, whose
/// KDF-HMAC-SHA2 is this KDF with the fixed input `label || 0x00 || [L]32`: Kc, Ke and Ki
/// of key usage 2 for aes128-cts-hmac-sha256-128 and aes256-cts-hmac-sha384-192.
#[test]
fn kbkdf_counter_cavp_rfc8009() {
    let key = unhex("43eef6d824fd820405626ab9b6d79f1fd04e126ab8e17729e3afc7cb5af794f8");
    let fixed = unhex(concat!(
        "5e269b5a7bdedcc3e875e2725693a257fc60011af7dcd68a3358507fe29b0659",
        "ca66951daa05a15032033650bc58a27840f8fbe9f4088b9030738f68",
    ));
    assert_eq!(
        hex_call("kbkdf_counter", &[b"sha256", &key, &fixed, b"32"]),
        "f0a339ecbcae6add1afb27da3ba40a1320c6427a58afb9dc366b219b7eb29ecf"
    );
    let fixed = |label: &str, bits: u32| {
        let mut f = unhex(label);
        f.push(0);
        f.extend_from_slice(&bits.to_be_bytes());
        f
    };
    let base = unhex("3705d96080c17728a0e800eab6e0d23c");
    for (label, out) in [
        ("0000000299", "b31a018a48f54776f403e9a396325dc3"),
        ("00000002aa", "9b197dd1e8c5609d6e67c3e37c62c72e"),
        ("0000000255", "9fda0e56ab2d85e1569a688696c26a6c"),
    ] {
        assert_eq!(
            hex_call(
                "kbkdf_counter",
                &[b"sha256", &base, &fixed(label, 128), b"16"]
            ),
            out,
            "{label}"
        );
    }
    let base = unhex("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52");
    for (label, bits, out) in [
        (
            "0000000299",
            192,
            "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d",
        ),
        (
            "00000002aa",
            256,
            "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
        ),
        (
            "0000000255",
            192,
            "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
        ),
    ] {
        let len = (bits / 8).to_string();
        assert_eq!(
            hex_call(
                "kbkdf_counter",
                &[b"sha384", &base, &fixed(label, bits), len.as_bytes()]
            ),
            out,
            "{label}"
        );
    }
}

/// RFC 3394 section 4 (all six key and KEK sizes) and RFC 5649 section 6 (both examples).
#[test]
fn aes_key_wrap_rfc3394_rfc5649() {
    let kek = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let data = unhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
    for (kek_len, data_len, out) in [
        (16, 16, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
        (24, 16, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"),
        (32, 16, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"),
        (
            24,
            24,
            "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2",
        ),
        (
            32,
            24,
            "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1",
        ),
        (
            32,
            32,
            "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
        ),
    ] {
        assert_eq!(
            hex_call("aes_kw_wrap", &[&kek[..kek_len], &data[..data_len]]),
            out
        );
    }
    let kek = unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    assert_eq!(
        hex_call(
            "aes_kwp_wrap",
            &[&kek, &unhex("c37b7e6492584340bed12207808941155068f738")]
        ),
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"
    );
    assert_eq!(
        hex_call("aes_kwp_wrap", &[&kek, &unhex("466f7250617369")]),
        "afbeb0f07dfbf5419200f2ccb50bb24f"
    );
    // RFC 3394 wraps at least two 64-bit blocks.
    assert!(call_in(&Budget::default(), "aes_kw_wrap", &[&kek, &[0u8; 8]]).is_err());
    assert!(call_in(&Budget::default(), "aes_kw_wrap", &[&kek, &[0u8; 20]]).is_err());
}

/// The input of RFC 7518 appendix B: the plaintext, IV and associated data shared by B.1,
/// B.2 and B.3, under the key `00 01 .. 3f` cut to each length.
fn cbc_hmac_case(key_len: usize) -> Vec<u8> {
    let key: Vec<u8> = (0u8..64).take(key_len).collect();
    let plaintext = b"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience";
    let iv = unhex("1af38c2dc2b96ffdd86694092341bc04");
    let aad = b"The second principle of Auguste Kerckhoffs";
    call("aes_cbc_hmac_encrypt", &[&key, &iv, plaintext, aad])
}

/// RFC 7518 appendix B.1 (AES_128_CBC_HMAC_SHA_256) in full; B.2 and B.3: the tags, which
/// cover the ciphertext.
#[test]
fn aes_cbc_hmac_rfc7518() {
    let out = cbc_hmac_case(32);
    let (ciphertext, tag) = out.split_at(out.len() - 16);
    assert_eq!(
        ciphertext,
        unhex(concat!(
            "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9",
            "a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336",
            "09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b",
            "384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5",
            "4b8851ffb598f7f80074b9473c82e2db",
        ))
    );
    assert_eq!(tag, unhex("652c3fa36b0a7c5b3219fab3a30bc1c4"));
    let out = cbc_hmac_case(48);
    assert_eq!(
        out[out.len() - 24..],
        unhex("8490ac0e58949bfe51875d733f93ac2075168039ccc733d7")
    );
    let out = cbc_hmac_case(64);
    assert_eq!(
        out[out.len() - 32..],
        unhex("4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5")
    );
    assert!(
        call_in(
            &Budget::default(),
            "aes_cbc_hmac_encrypt",
            &[&[0u8; 16], &[0u8; 16], b"x"]
        )
        .is_err()
    );
}

/// NIST SP 800-38C appendix C, examples 1 to 3; RFC 3610 section 8, packet vectors 1 to 3
/// (M = 8) and 7 to 8 (M = 10).
#[test]
fn aes_ccm_sp800_38c_rfc3610() {
    let key = unhex("404142434445464748494a4b4c4d4e4f");
    for (nonce, aad, msg, tag, out) in [
        (
            "10111213141516",
            "0001020304050607",
            "20212223",
            "4",
            "7162015b4dac255d",
        ),
        (
            "1011121314151617",
            "000102030405060708090a0b0c0d0e0f",
            "202122232425262728292a2b2c2d2e2f",
            "6",
            "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
        ),
        (
            "101112131415161718191a1b",
            "000102030405060708090a0b0c0d0e0f10111213",
            "202122232425262728292a2b2c2d2e2f3031323334353637",
            "8",
            "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
        ),
    ] {
        assert_eq!(
            hex_call(
                "aes_ccm_encrypt",
                &[
                    &key,
                    &unhex(nonce),
                    tag.as_bytes(),
                    &unhex(msg),
                    &unhex(aad)
                ]
            ),
            out
        );
    }
    let key = unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let aad = unhex("0001020304050607");
    for (nonce, msg, tag, out) in [
        (
            "00000003020100a0a1a2a3a4a5",
            "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            "8",
            "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
        ),
        (
            "00000004030201a0a1a2a3a4a5",
            "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8",
            "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916",
        ),
        (
            "00000005040302a0a1a2a3a4a5",
            "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "8",
            "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5",
        ),
        (
            "00000009080706a0a1a2a3a4a5",
            "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            "10",
            "0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490",
        ),
        (
            "0000000a090807a0a1a2a3a4a5",
            "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "10",
            "7b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24c17b4433f434963f34b4",
        ),
    ] {
        assert_eq!(
            hex_call(
                "aes_ccm_encrypt",
                &[&key, &unhex(nonce), tag.as_bytes(), &unhex(msg), &aad]
            ),
            out
        );
    }
}

/// CCM written here against the `ccm` crate on every tag and nonce size of SP 800-38C and
/// every key size, with and without associated data, across block boundaries.
#[test]
fn aes_ccm_matches_the_ccm_crate_on_every_size() {
    use ccm::aead::{Aead, KeyInit, Payload};
    use ccm::consts::{U4, U6, U7, U8, U9, U10, U11, U12, U13, U14, U16};
    let message: Vec<u8> = (0u8..=200).collect();
    let aad: Vec<u8> = (0u8..=40).rev().collect();
    let mut checked = 0;
    macro_rules! one {
        ($aes:ty, $key:expr, $tag:ty, $tag_len:literal, $nonce:ty, $nonce_len:literal) => {{
            let key = $key;
            let nonce: Vec<u8> = (100u8..).take($nonce_len).collect();
            let cipher = ccm::Ccm::<$aes, $tag, $nonce>::new_from_slice(&key).unwrap();
            for (m, a) in [(0, 0), (1, 0), (16, 3), (17, 40), (201, 41)] {
                let expected = cipher
                    .encrypt(
                        nonce.as_slice().try_into().unwrap(),
                        Payload {
                            msg: &message[..m],
                            aad: &aad[..a],
                        },
                    )
                    .unwrap();
                let tag = $tag_len.to_string();
                let ours = call(
                    "aes_ccm_encrypt",
                    &[&key, &nonce, tag.as_bytes(), &message[..m], &aad[..a]],
                );
                assert_eq!(
                    ours, expected,
                    "tag {} nonce {} m {m} a {a}",
                    $tag_len, $nonce_len
                );
                checked += 1;
            }
        }};
    }
    macro_rules! nonces {
        ($aes:ty, $key:expr, $tag:ty, $tag_len:literal) => {{
            one!($aes, $key, $tag, $tag_len, U7, 7);
            one!($aes, $key, $tag, $tag_len, U8, 8);
            one!($aes, $key, $tag, $tag_len, U9, 9);
            one!($aes, $key, $tag, $tag_len, U10, 10);
            one!($aes, $key, $tag, $tag_len, U11, 11);
            one!($aes, $key, $tag, $tag_len, U12, 12);
            one!($aes, $key, $tag, $tag_len, U13, 13);
        }};
    }
    macro_rules! tags {
        ($aes:ty, $key_len:literal) => {{
            let key: Vec<u8> = (7u8..).take($key_len).collect();
            nonces!($aes, key.clone(), U4, 4);
            nonces!($aes, key.clone(), U6, 6);
            nonces!($aes, key.clone(), U8, 8);
            nonces!($aes, key.clone(), U10, 10);
            nonces!($aes, key.clone(), U12, 12);
            nonces!($aes, key.clone(), U14, 14);
            nonces!($aes, key.clone(), U16, 16);
        }};
    }
    tags!(aes::Aes128, 16);
    tags!(aes::Aes192, 24);
    tags!(aes::Aes256, 32);
    assert_eq!(checked, 3 * 7 * 7 * 5);
    for (nonce, tag) in [(6, "8"), (14, "8"), (13, "5"), (13, "2"), (13, "18")] {
        assert!(
            call_in(
                &Budget::default(),
                "aes_ccm_encrypt",
                &[&[0u8; 16], &vec![0u8; nonce], tag.as_bytes(), b"m"]
            )
            .is_err()
        );
    }
}

/// The test vectors of the EAX paper (Bellare, Rogaway, Wagner, "The EAX Mode of Operation",
/// appendix), the first three.
#[test]
fn aes_eax_paper_vectors() {
    for (key, nonce, header, msg, out) in [
        (
            "233952dee4d5ed5f9b9c6d6ff80ff478",
            "62ec67f9c3a4a407fcb2a8c49031a8b3",
            "6bfb914fd07eae6b",
            "",
            "e037830e8389f27b025a2d6527e79d01",
        ),
        (
            "91945d3f4dcbee0bf45ef52255f095a4",
            "becaf043b0a23d843194ba972c66debd",
            "fa3bfd4806eb53fa",
            "f7fb",
            "19dd5c4c9331049d0bdab0277408f67967e5",
        ),
        (
            "01f74ad64077f2e704c0f60ada3dd523",
            "70c3db4f0d26368400a10ed05d2bff5e",
            "234a3463c1264ac6",
            "1a47cb4933",
            "d851d5bae03a59f238a23e39199dc9266626c40f80",
        ),
    ] {
        assert_eq!(
            hex_call(
                "aes_eax_encrypt",
                &[&unhex(key), &unhex(nonce), &unhex(msg), &unhex(header)]
            ),
            out
        );
    }
}

/// RFC 4493 section 4 (AES-128, messages of 0, 16, 40 and 64 bytes), and the examples of
/// NIST SP 800-38B for AES-128, -192 and -256 (messages of 0, 16, 20 and 64 bytes).
#[test]
fn aes_cmac_rfc4493_sp800_38b() {
    let full = unhex(concat!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    ));
    let rfc4493 = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    for (len, tag) in [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ] {
        assert_eq!(hex_call("aes_cmac", &[&rfc4493, &full[..len]]), tag);
    }
    for (key, tags) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            [
                "bb1d6929e95937287fa37d129b756746",
                "070a16b46b4d4144f79bdd9dd04a287c",
                "7d85449ea6ea19c823a7bf78837dfade",
                "51f0bebf7e3b9d92fc49741779363cfe",
            ],
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            [
                "d17ddf46adaacde531cac483de7a9367",
                "9e99a7bf31e710900662f65e617c5184",
                "3d75c194ed96070444a9fa7ec740ecf8",
                "a1d5df0eed790f794d77589659f39a11",
            ],
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            [
                "028962f61b7bf89efc6b551f4667d983",
                "28a7023f452e8f82bd4bf28d8c37c35c",
                "156727dc0878944a023c1fe03bad6d93",
                "e1992190549f6ed5696a2c056c315410",
            ],
        ),
    ] {
        for (len, tag) in [0, 16, 20, 64].into_iter().zip(tags) {
            assert_eq!(hex_call("aes_cmac", &[&unhex(key), &full[..len]]), tag);
        }
    }
}

/// CBC-MAC has no vectors of its own; it is the last block of CBC encryption with a zero IV.
/// FIPS 197 appendix C.1 (one block: the block encrypted), and NIST SP 800-38A F.2.1
/// (CBC-AES128): with the IV folded into the first block, the MAC is the last ciphertext
/// block. A partial block is padded with zero bytes.
#[test]
fn aes_cbc_mac_fips197_sp800_38a() {
    assert_eq!(
        hex_call(
            "aes_cbc_mac",
            &[
                &unhex("000102030405060708090a0b0c0d0e0f"),
                &unhex("00112233445566778899aabbccddeeff")
            ]
        ),
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    );
    let iv = unhex("000102030405060708090a0b0c0d0e0f");
    let mut message = unhex(concat!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    ));
    message.iter_mut().zip(&iv).for_each(|(m, v)| *m ^= v);
    let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    assert_eq!(
        hex_call("aes_cbc_mac", &[&key, &message]),
        "3ff1caa1681fac09120eca307586e1a7"
    );
    let mut padded = message[..40].to_vec();
    padded.resize(48, 0);
    assert_eq!(
        call("aes_cbc_mac", &[&key, &message[..40]]),
        call("aes_cbc_mac", &[&key, &padded])
    );
}

/// RFC 3962 appendix B: AES-128 CTS with a zero IV, all six messages.
#[test]
fn aes_cts_rfc3962() {
    let key = unhex("636869636b656e207465726979616b69");
    let iv = [0u8; 16];
    let plain = unhex(concat!(
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "6869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
    ));
    for (len, out) in [
        (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
        (
            31,
            "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
        ),
        (
            32,
            "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
        ),
        (
            47,
            "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
        ),
        (
            48,
            "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
        ),
        (
            64,
            "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
        ),
    ] {
        assert_eq!(
            hex_call("aes_cts_encrypt", &[&key, &iv, &plain[..len]]),
            out
        );
    }
    assert!(
        call_in(
            &Budget::default(),
            "aes_cts_encrypt",
            &[&key, &iv, &plain[..15]]
        )
        .is_err()
    );
}

/// RFC 3961 appendix A.1 (n-fold), and RFC 3962 appendix B: the AES keys of string-to-key,
/// which is DK(PBKDF2-HMAC-SHA1(password, salt, iterations), "kerberos").
#[test]
fn nfold_and_dk_rfc3961_rfc3962() {
    for (input, bits, out) in [
        ("012345", "64", "be072631276b1955"),
        ("password", "56", "78a07b6caf85fa"),
        (
            "Rough Consensus, and Running Code",
            "64",
            "bb6ed30870b7f0e0",
        ),
        (
            "password",
            "168",
            "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
        ),
        (
            "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            "192",
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        ),
        ("Q", "168", "518a54a215a8452a518a54a215a8452a518a54a215"),
        ("ba", "168", "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"),
        ("kerberos", "64", "6b65726265726f73"),
        ("kerberos", "128", "6b65726265726f737b9b5b2b93132b93"),
        (
            "kerberos",
            "168",
            "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4",
        ),
        (
            "kerberos",
            "256",
            "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
        ),
    ] {
        assert_eq!(
            hex_call("nfold", &[input.as_bytes(), bits.as_bytes()]),
            out,
            "{input} {bits}"
        );
    }
    let salt = b"ATHENA.MIT.EDUraeburn";
    for (rounds, key128, key256) in [
        (
            "1",
            "42263c6e89f4fc28b8df68ee09799f15",
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        ),
        (
            "2",
            "c651bf29e2300ac27fa469d693bdda13",
            "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
        ),
        (
            "1200",
            "4c01cd46d632d01e6dbe230a01ed642a",
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
        ),
    ] {
        for (len, expected) in [("16", key128), ("32", key256)] {
            let tkey = call(
                "pbkdf2",
                &[
                    b"sha1",
                    b"password",
                    salt,
                    rounds.as_bytes(),
                    len.as_bytes(),
                ],
            );
            assert_eq!(
                hex_call("kerberos_dk", &[&tkey, b"kerberos"]),
                expected,
                "{rounds} {len}"
            );
        }
    }
}

/// RFC 8032 section 7.4: Ed448, the blank, one-byte, one-byte-with-context and 256-byte
/// messages (the secret keys are the published ones).
#[test]
fn ed448_rfc8032() {
    for (secret, message, context, signature) in [
        (
            "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
            "",
            None,
            "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
        ),
        (
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            "03",
            None,
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
        ),
        (
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            "03",
            Some("666f6f"),
            "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00",
        ),
        (
            "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
            "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11",
            None,
            "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00",
        ),
    ] {
        let (secret, message) = (unhex(secret), unhex(message));
        let out = match context {
            None => hex_call("ed448_sign", &[&secret, &message]),
            Some(c) => hex_call("ed448_sign", &[&secret, &message, &unhex(c)]),
        };
        assert_eq!(out, signature);
    }
}

/// RFC 7748 section 6.2 (X448), both directions, and the public keys of both parties.
#[test]
fn x448_rfc7748() {
    let alice = unhex(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    );
    let alice_public = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
    let bob = unhex(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    );
    let bob_public = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
    let shared = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";
    assert_eq!(
        hex_call("ecdh", &[b"x448", &unhex(bob_public), &alice]),
        shared
    );
    assert_eq!(
        hex_call("ecdh", &[b"x448", &unhex(alice_public), &bob]),
        shared
    );
    // The ephemeral key of an operation: 56 bytes, and the peer computes the same secret.
    let budget = Budget::default();
    let node_public = call_in(&budget, "ecdh_public", &[b"x448"]).unwrap();
    assert_eq!(node_public.len(), 56);
    let from_node = call_in(&budget, "ecdh", &[b"x448", &unhex(bob_public)]).unwrap();
    assert_eq!(from_node, call("ecdh", &[b"x448", &node_public, &bob]));
    // A low-order peer key is refused.
    assert!(call_in(&Budget::default(), "ecdh", &[b"x448", &[0u8; 56], &alice]).is_err());
}

/// RFC 6979 appendix A.2.5 (P-256, SHA-256, "sample"), A.2.6 (P-384, SHA-384, "sample") and
/// A.2.7 (P-521, SHA-512, "sample"): signing the published digest gives the published
/// signature. secp256k1 has no RFC vector: the prehashed signature equals `k256_sign`.
#[test]
fn ecdsa_prehash_rfc6979() {
    use sha2::{Digest as _, Sha256, Sha384, Sha512};
    let p256 = unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    assert_eq!(
        hex_call(
            "ecdsa_sign_prehash",
            &[b"p256", &p256, &Sha256::digest(b"sample")]
        ),
        concat!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        )
    );
    let p384 = unhex(
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
    );
    assert_eq!(
        hex_call(
            "ecdsa_sign_prehash",
            &[b"p384", &p384, &Sha384::digest(b"sample")]
        ),
        concat!(
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
            "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8"
        )
    );
    let p521 = unhex(
        "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
    );
    assert_eq!(
        hex_call(
            "ecdsa_sign_prehash",
            &[b"p521", &p521, &Sha512::digest(b"sample")]
        ),
        concat!(
            "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa",
            "00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a"
        )
    );
    let k256 = [0x11u8; 32];
    assert_eq!(
        call(
            "ecdsa_sign_prehash",
            &[b"k256", &k256, &Sha256::digest(b"m")]
        ),
        call("k256_sign", &[&k256, b"m"])
    );
    assert!(
        call_in(
            &Budget::default(),
            "ecdsa_sign_prehash",
            &[b"p256", &p256, &[1u8; 8]]
        )
        .is_err()
    );
}

/// RFC 6979 appendix A.2.1: the DSA 1024-bit key, message "sample", with SHA-1 and SHA-256.
/// The key is made from the published p, q, g, x and y and encoded as PKCS#8.
#[test]
fn dsa_rfc6979() {
    use dsa::pkcs8::EncodePrivateKey as _;
    use dsa::{BoxedUint, Components, SigningKey, VerifyingKey};
    let number = |h: &str, bits: u32| BoxedUint::from_be_slice(&unhex(h), bits).unwrap();
    let p = number(
        "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        1024,
    );
    let q = number("996F967F6C8E388D9E28D01E205FBA957A5698B1", 160);
    let g = number(
        "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        1024,
    );
    let x = number("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7", 160);
    let y = number(
        "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F65392195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E682F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B",
        1024,
    );
    let components = Components::from_components(p, q, g).unwrap();
    let verifying = VerifyingKey::from_components(components, y).unwrap();
    let key = SigningKey::from_components(verifying, x)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let key = key.as_bytes();
    assert_eq!(
        hex_call("dsa_sign", &[b"sha1", key, b"sample"]),
        "2e1a0c2562b2912caaf89186fb0f42001585da5529efb6b0aff2d7a68eb70ca313022253b9a88df5"
    );
    assert_eq!(
        hex_call("dsa_sign", &[b"sha256", key, b"sample"]),
        "81f2f5850be5bc123c43f71a3033e9384611c5454cdd914b65eb6c66a8aaad27299bee6b035f5e89"
    );
    // The DER form: SEQUENCE { INTEGER r, INTEGER s }, both positive and 20 bytes here.
    assert_eq!(
        hex_call("dsa_sign_der", &[b"sha1", key, b"sample"]),
        "302c02142e1a0c2562b2912caaf89186fb0f42001585da55021429efb6b0aff2d7a68eb70ca313022253b9a88df5"
    );
}

/// RFC 8949 appendix A: the examples of encoded data items this encoder can produce.
#[test]
fn cbor_rfc8949_examples() {
    for (n, out) in [
        ("0", "00"),
        ("1", "01"),
        ("10", "0a"),
        ("23", "17"),
        ("24", "1818"),
        ("25", "1819"),
        ("100", "1864"),
        ("1000", "1903e8"),
        ("1000000", "1a000f4240"),
        ("1000000000000", "1b000000e8d4a51000"),
        ("18446744073709551615", "1bffffffffffffffff"),
        ("-18446744073709551616", "3bffffffffffffffff"),
        ("-1", "20"),
        ("-10", "29"),
        ("-100", "3863"),
        ("-1000", "3903e7"),
    ] {
        assert_eq!(hex_call("cbor_int", &[n.as_bytes()]), out, "{n}");
    }
    for n in ["18446744073709551616", "-18446744073709551617", "1.5", ""] {
        assert!(
            call_in(&Budget::default(), "cbor_int", &[n.as_bytes()]).is_err(),
            "{n}"
        );
    }
    assert_eq!(hex_call("cbor_bytes", &[b""]), "40");
    assert_eq!(hex_call("cbor_bytes", &[&[1, 2, 3, 4]]), "4401020304");
    for (text, out) in [
        ("", "60"),
        ("a", "6161"),
        ("IETF", "6449455446"),
        ("\"\\", "62225c"),
        ("\u{fc}", "62c3bc"),
        ("\u{6c34}", "63e6b0b4"),
    ] {
        assert_eq!(hex_call("cbor_text", &[text.as_bytes()]), out);
    }
    assert!(call_in(&Budget::default(), "cbor_text", &[&[0xff]]).is_err());
    let i = |n: &str| call("cbor_int", &[n.as_bytes()]);
    let t = |s: &str| call("cbor_text", &[s.as_bytes()]);
    assert_eq!(hex_call("cbor_array", &[]), "80");
    assert_eq!(
        hex_call("cbor_array", &[&i("1"), &i("2"), &i("3")]),
        "83010203"
    );
    let inner = |a: &str, b: &str| call("cbor_array", &[&i(a), &i(b)]);
    assert_eq!(
        hex_call("cbor_array", &[&i("1"), &inner("2", "3"), &inner("4", "5")]),
        "8301820203820405"
    );
    let numbers: Vec<Vec<u8>> = (1..=25).map(|n| i(&n.to_string())).collect();
    let refs: Vec<&[u8]> = numbers.iter().map(Vec::as_slice).collect();
    assert_eq!(
        hex_call("cbor_array", &refs),
        "98190102030405060708090a0b0c0d0e0f101112131415161718181819"
    );
    assert_eq!(hex_call("cbor_map", &[]), "a0");
    assert_eq!(
        hex_call("cbor_map", &[&i("3"), &i("4"), &i("1"), &i("2")]),
        "a201020304"
    );
    assert_eq!(
        hex_call("cbor_map", &[&t("b"), &inner("2", "3"), &t("a"), &i("1")]),
        "a26161016162820203"
    );
    let map_bc = call("cbor_map", &[&t("b"), &t("c")]);
    assert_eq!(
        hex_call("cbor_array", &[&t("a"), &map_bc]),
        "826161a161626163"
    );
    assert_eq!(
        hex_call("cbor_tag", &[b"1", &i("1363896240")]),
        "c11a514b67b0"
    );
    assert_eq!(
        hex_call("cbor_tag", &[b"23", &call("cbor_bytes", &[&[1, 2, 3, 4]])]),
        "d74401020304"
    );
    assert_eq!(
        hex_call("cbor_tag", &[b"32", &t("http://www.example.com")]),
        "d82076687474703a2f2f7777772e6578616d706c652e636f6d"
    );
    // Literal simple values pass through: false, true, null.
    assert_eq!(
        hex_call("cbor_array", &[&[0xf4], &[0xf5], &[0xf6]]),
        "83f4f5f6"
    );
    // Not one deterministic item: two items, a truncated one, a non-shortest head, an
    // indefinite length, a float, an unsorted map, a repeated key.
    for item in [
        "0101",
        "4401",
        "1817",
        "5f40ff",
        "f93c00",
        "a2030401",
        "a201020102",
    ] {
        assert!(
            call_in(&Budget::default(), "cbor_array", &[&unhex(item)]).is_err(),
            "{item}"
        );
    }
    assert!(
        call_in(
            &Budget::default(),
            "cbor_map",
            &[&i("1"), &i("2"), &i("1"), &i("3")]
        )
        .is_err()
    );
    assert!(call_in(&Budget::default(), "cbor_map", &[&i("1")]).is_err());
}

/// RFC 9052 appendix C.2.1: the `COSE_Sign1` of the single ECDSA signature example, up to
/// its signature (ECDSA signatures are randomized, so the 64 signature bytes are a
/// placeholder): protected `{1: -7}`, unprotected `{4: '11'}`, payload "This is the
/// content.", tag 18.
#[test]
fn cose_sign1_rfc9052_structure() {
    let i = |n: &str| call("cbor_int", &[n.as_bytes()]);
    let b = |v: &[u8]| call("cbor_bytes", &[v]);
    let protected = call("cbor_map", &[&i("1"), &i("-7")]);
    let unprotected = call("cbor_map", &[&i("4"), &b(b"11")]);
    let signature = [0u8; 64];
    let message = call(
        "cbor_array",
        &[
            &b(&protected),
            &unprotected,
            &b(b"This is the content."),
            &b(&signature),
        ],
    );
    let sign1 = hex_call("cbor_tag", &[b"18", &message]);
    assert_eq!(
        &sign1[..sign1.len() - 128],
        "d28443a10126a10442313154546869732069732074686520636f6e74656e742e5840"
    );
}
