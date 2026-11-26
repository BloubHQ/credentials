//! Tests of typed items: the reviewed kinds, every check, every mask, custom kinds, and the
//! shape a typed policy may not widen.

#![allow(clippy::type_complexity)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::keys::CallerKey;
use crate::policy::{
    Caller, Capture, Destination, FieldSpec, Injection, Method, Operation, Receive, Return, Send,
    Source, Store,
};

/// 2026-11-25T00:00:00Z.
const NOW: u64 = 1_795_564_800_000;
/// 2026-12-01T00:00:00Z.
const DECEMBER: u64 = 1_796_083_200_000;

/// Runs one check on a value, with the other fields given.
fn check(check: Check, value: &str, others: &[(&str, &str)], signoff: &[&str]) -> Rule {
    let signoff: Vec<String> = signoff.iter().map(|s| s.to_string()).collect();
    let other = |name: &str| {
        others
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_bytes().to_vec())
    };
    checks::run(&check, value.as_bytes(), &signoff, Some(NOW), &other)
}

type Rule = core::result::Result<(), &'static str>;

fn ok(check_: Check, value: &str) {
    assert_eq!(
        check(check_.clone(), value, &[], &[]),
        Ok(()),
        "{check_:?} {value:?}"
    );
}

fn bad(check_: Check, value: &str) {
    assert!(
        check(check_.clone(), value, &[], &[]).is_err(),
        "{check_:?} {value:?}"
    );
}

#[test]
fn the_reviewed_kinds_load_and_follow_their_own_rules() {
    let names: Vec<&str> = reviewed()
        .unwrap()
        .iter()
        .map(|k| k.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "card", "login", "oauth", "identity", "totp", "ssh", "database", "ftp", "mail",
            "queue", "vpn", "api"
        ]
    );
    for kind in reviewed().unwrap() {
        kind.validate().unwrap();
        // A secret field never has a mask, a masked one always has one.
        for f in &kind.fields {
            assert_eq!(
                f.mask.is_some(),
                f.disclosure == Disclosure::Masked,
                "{}",
                f.name
            );
        }
    }
    // Nothing in the catalog names a company or a site: every host is the owner's pin.
    let lower = ITEMS_JSON.to_ascii_lowercase();
    for word in [".com", ".net", ".org", "www."] {
        assert!(!lower.contains(word), "{word}");
    }
}

#[test]
fn luhn_accepts_card_numbers_and_refuses_the_rest() {
    for n in [
        "4242424242424242",
        "378282246310005",
        "5555555555554444",
        "6011111111111117",
    ] {
        ok(Check::Luhn {}, n);
    }
    for n in [
        "4242424242424241",
        "42424242424",
        "42424242424242424242",
        "4242 4242 4242 4242",
        "4242-4242-4242-4242",
        "",
    ] {
        bad(Check::Luhn {}, n);
    }
}

#[test]
fn brands_follow_the_iin_ranges() {
    for (number, brand, cvc) in [
        ("4242424242424242", Brand::Visa, 3),
        ("378282246310005", Brand::Amex, 4),
        ("341111111111111", Brand::Amex, 4),
        ("5555555555554444", Brand::Mastercard, 3),
        ("2223003122003222", Brand::Mastercard, 3),
        ("6011111111111117", Brand::Discover, 3),
        ("3566002020360505", Brand::Jcb, 3),
        ("30569309025904", Brand::Diners, 3),
        ("6200000000000005", Brand::Unionpay, 3),
        ("2200000000000004", Brand::Mir, 3),
        ("9999999999999995", Brand::Unknown, 3),
    ] {
        assert_eq!(brand_of(number.as_bytes()), brand, "{number}");
        let code = "1234".get(..cvc).unwrap();
        assert_eq!(
            check(
                Check::Cvc {
                    number: "number".into()
                },
                code,
                &[("number", number)],
                &[]
            ),
            Ok(()),
            "{number}"
        );
    }
}

#[test]
fn a_security_code_has_the_length_of_its_brand() {
    let cvc = || Check::Cvc {
        number: "number".into(),
    };
    let visa = [("number", "4242424242424242")];
    let amex = [("number", "378282246310005")];
    let unknown = [("number", "9999999999999995")];
    assert!(check(cvc(), "123", &visa, &[]).is_ok());
    assert!(check(cvc(), "1234", &visa, &[]).is_err());
    assert!(check(cvc(), "12", &visa, &[]).is_err());
    assert!(check(cvc(), "12a", &visa, &[]).is_err());
    assert!(check(cvc(), "1234", &amex, &[]).is_ok());
    assert!(check(cvc(), "123", &amex, &[]).is_err());
    assert!(check(cvc(), "123", &unknown, &[]).is_ok());
    assert!(check(cvc(), "1234", &unknown, &[]).is_ok());
    assert!(check(cvc(), "12345", &unknown, &[]).is_err());
    // Without its number a code is not checked as valid.
    assert!(check(cvc(), "123", &[], &[]).is_err());
}

#[test]
fn an_expiry_is_in_the_future_by_the_node_clock() {
    // On 2026-11-25 a card of 11/26 is valid through the end of November.
    for e in ["11/26", "12/26", "01/27", "11/2026", "12/2099"] {
        ok(Check::Expiry {}, e);
    }
    for e in [
        "10/26", "01/26", "11/25", "13/27", "00/27", "1/27", "11-27", "11/027", "ab/cd", "11/26 ",
    ] {
        bad(Check::Expiry {}, e);
    }
    // The month ends at midnight UTC on the first of the next.
    let at = |now: u64| checks::run(&Check::Expiry {}, b"11/26", &[], Some(now), &|_| None);
    assert_eq!(at(DECEMBER - 1), Ok(()));
    assert!(at(DECEMBER).is_err());
    // Without a clock only the form is checked.
    assert_eq!(
        checks::run(&Check::Expiry {}, b"01/20", &[], None, &|_| None),
        Ok(())
    );
}

#[test]
fn an_origin_is_an_exact_scheme_and_host() {
    for o in [
        "https://shop.example",
        "https://shop.example:8443",
        "https://a-b.c.example",
    ] {
        ok(Check::Origin {}, o);
    }
    for o in [
        "https://shop.example/",
        "https://shop.example/login",
        "https://shop.example?x=1",
        "https://shop.example#x",
        "https://user@shop.example",
        "https://Shop.example",
        "HTTPS://shop.example",
        "https://*.shop.example",
        "https://shop.example:0",
        "https://shop.example:080",
        "https://shop.example:65536",
        "https://shop.example:",
        "https://",
        "shop.example",
        "ftp://shop.example",
        "https://shop..example",
        "https://-shop.example",
        "http://shop.example",
    ] {
        bad(Check::Origin {}, o);
    }
    // Plain HTTP only with the owner's sign-off.
    assert!(
        check(
            Check::Origin {},
            "http://shop.example",
            &[],
            &["plain_http"]
        )
        .is_ok()
    );
    let origin = parse_origin("https://shop.example:8443").unwrap();
    assert_eq!(origin.destination, Destination::new("shop.example", 8443));
    assert_eq!(origin.text(), "https://shop.example:8443");
    assert_eq!(
        parse_origin("http://a.example").unwrap().destination.port,
        80
    );
}

#[test]
fn hosts_ports_lengths_patterns_and_lists() {
    ok(Check::Host {}, "db.internal.example");
    for h in [
        "DB.example",
        "db.example:5432",
        "*.example",
        "",
        "db_1.example",
    ] {
        bad(Check::Host {}, h);
    }
    let port = || Check::Integer { min: 1, max: 65535 };
    ok(port(), "5432");
    for p in ["0", "65536", "05432", "-1", "1.5", ""] {
        bad(port(), p);
    }
    ok(Check::Length { min: 1, max: 3 }, "abc");
    bad(Check::Length { min: 1, max: 3 }, "abcd");
    bad(Check::Length { min: 1, max: 3 }, "");
    let pattern = || Check::Pattern {
        regex: "[a-z]{2}".into(),
    };
    ok(pattern(), "ab");
    bad(pattern(), "abc");
    bad(pattern(), "xab");
    let one_of = || Check::OneOf {
        values: vec!["imap".into(), "smtp".into()],
    };
    ok(one_of(), "imap");
    bad(one_of(), "IMAP");
    bad(one_of(), "pop3");
}

#[test]
fn emails_dates_base32_and_keys() {
    ok(Check::Email {}, "j.doe+x@mail.example");
    for e in [
        "j.doe",
        "@mail.example",
        "j@localhost",
        "j@Mail.example",
        "j doe@mail.example",
        "j@mail.example.",
    ] {
        bad(Check::Email {}, e);
    }
    ok(Check::Date {}, "2024-02-29");
    ok(Check::Date {}, "1990-12-31");
    for d in [
        "2023-02-29",
        "1990-13-01",
        "1990-04-31",
        "90-01-01",
        "1990-1-01",
        "1990/01/01",
    ] {
        bad(Check::Date {}, d);
    }
    let seed = |bits| Check::Base32 { min_bits: bits };
    // 26 characters carry 130 bits, of which 128 fill bytes.
    ok(seed(128), "JBSWY3DPEHPK3PXPJBSWY3DPEH");
    ok(seed(128), "jbsw y3dp ehpk 3pxp jbsw y3dp eh");
    bad(seed(128), "JBSWY3DPEHPK3PXP");
    bad(seed(80), "JBSWY3DPEHPK3PX1");
    let key = STANDARD.encode([7u8; 32]);
    ok(Check::Base64Key { bytes: 32 }, &key);
    bad(Check::Base64Key { bytes: 32 }, &STANDARD.encode([7u8; 31]));
    bad(Check::Base64Key { bytes: 32 }, "not base64!");
}

fn ed25519_blob(kind: &str) -> String {
    let mut blob = Vec::new();
    blob.extend_from_slice(&u32::try_from(kind.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(kind.as_bytes());
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[9u8; 32]);
    STANDARD.encode(blob)
}

#[test]
fn an_ssh_host_key_names_its_algorithm_in_its_blob() {
    let blob = ed25519_blob("ssh-ed25519");
    ok(Check::SshHostKey {}, &format!("ssh-ed25519 {blob}"));
    ok(
        Check::SshHostKey {},
        &format!("ssh-ed25519 {blob} host comment"),
    );
    ok(
        Check::SshHostKey {},
        &format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode([1u8; 32])
        ),
    );
    let rsa = {
        let mut b = Vec::new();
        b.extend_from_slice(&7u32.to_be_bytes());
        b.extend_from_slice(b"ssh-rsa");
        b.extend_from_slice(&[0, 0, 0, 1, 3, 0, 0, 0, 1, 1]);
        STANDARD.encode(b)
    };
    ok(Check::SshHostKey {}, &format!("rsa-sha2-256 {rsa}"));
    for k in [
        format!("ecdsa-sha2-nistp256 {blob}"),
        format!("ssh-dss {blob}"),
        format!("ssh-ed25519 {}", ed25519_blob("ssh-rsa")),
        "ssh-ed25519 !!!".to_string(),
        "ssh-ed25519".to_string(),
        format!("ssh-ed25519 {}", STANDARD.encode([0, 0, 0, 11])),
        "SHA256:short".to_string(),
        String::new(),
    ] {
        bad(Check::SshHostKey {}, &k);
    }
    // An Ed25519 key is exactly 32 bytes.
    let mut long = Vec::new();
    long.extend_from_slice(&11u32.to_be_bytes());
    long.extend_from_slice(b"ssh-ed25519");
    long.extend_from_slice(&33u32.to_be_bytes());
    long.extend_from_slice(&[9u8; 33]);
    bad(
        Check::SshHostKey {},
        &format!("ssh-ed25519 {}", STANDARD.encode(long)),
    );
}

#[test]
fn a_signoff_value_needs_the_flag() {
    let rule = || Check::Signoff {
        values: vec!["disable".into()],
        flag: "plain".into(),
    };
    assert!(check(rule(), "require", &[], &[]).is_ok());
    assert!(check(rule(), "disable", &[], &[]).is_err());
    assert!(check(rule(), "disable", &[], &["other"]).is_err());
    assert!(check(rule(), "disable", &[], &["plain"]).is_ok());
}

#[test]
fn masks_show_a_small_fixed_part() {
    let m = |mask, v: &str| mask::apply(mask, v.as_bytes());
    assert_eq!(
        m(Mask::Card, "4242424242424242"),
        "visa \u{2022}\u{2022}\u{2022}\u{2022}4242"
    );
    assert_eq!(
        m(Mask::Card, "378282246310005"),
        "amex \u{2022}\u{2022}\u{2022}\u{2022}0005"
    );
    assert_eq!(
        m(Mask::Card, "4242"),
        "visa \u{2022}\u{2022}\u{2022}\u{2022}"
    );
    assert_eq!(m(Mask::Email, "jane.doe@mail.example"), "j***@mail.example");
    assert_eq!(m(Mask::Email, "j@mail.example"), "***@mail.example");
    assert_eq!(m(Mask::Email, "janedoe"), "j***");
    assert_eq!(m(Mask::Initial, "Jane Doe"), "J***");
    assert_eq!(m(Mask::Initial, "J"), "***");
    assert_eq!(m(Mask::Year, "11/27"), "2027");
    assert_eq!(m(Mask::Year, "11/2031"), "2031");
    assert_eq!(m(Mask::Year, "1990-05-01"), "1990");
    assert_eq!(
        m(Mask::Year, "May 1990"),
        "\u{2022}\u{2022}\u{2022}\u{2022}"
    );
    assert_eq!(
        m(Mask::Last2, "+82 10 1234 5678"),
        "\u{2022}\u{2022}\u{2022}\u{2022}78"
    );
    assert_eq!(m(Mask::Last2, "5678"), "\u{2022}\u{2022}\u{2022}\u{2022}");
    assert_eq!(
        m(Mask::Last4, "123456789012"),
        "\u{2022}\u{2022}\u{2022}\u{2022}9012"
    );
    assert_eq!(
        m(Mask::Last4, "12345678901"),
        "\u{2022}\u{2022}\u{2022}\u{2022}"
    );
    assert_eq!(m(Mask::Initial, "\u{c724}\u{c544}"), "\u{c724}***");
}

fn custom() -> KindSchema {
    serde_json::from_str(
        r#"{"name": "pin-pad", "description": "A door code.",
            "fields": [
              {"name": "site", "disclosure": "public", "pinned": true, "checks": [{"check": "origin"}]},
              {"name": "code", "disclosure": "secret", "guessable": true,
               "checks": [{"check": "pattern", "regex": "[0-9]{6}"}]},
              {"name": "label", "disclosure": "masked", "optional": true, "mask": "initial"}
            ],
            "shape": {"connections": ["https"], "destinations": {"from": "origin", "field": "site"},
                      "returns": "status"}}"#,
    )
    .unwrap()
}

fn kind_rule(kind: &KindSchema) -> Option<(String, &'static str)> {
    match kind.validate() {
        Ok(()) => None,
        Err(Error::KindInvalid { at, rule }) => Some((at, rule)),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn a_custom_kind_follows_the_rules_of_kinds() {
    assert_eq!(kind_rule(&custom()), None);
    let edits: Vec<(&str, Box<dyn Fn(&mut KindSchema)>)> = vec![
        (
            "name is not a token",
            Box::new(|k| k.name = "pin pad".into()),
        ),
        (
            "a description of 1 to 512 bytes",
            Box::new(|k| k.description.clear()),
        ),
        (
            "field names must be unique",
            Box::new(|k| k.fields[2].name = "code".into()),
        ),
        // A mask cannot open a secret field to describe.
        (
            "a masked field has a mask, and only a masked field",
            Box::new(|k| k.fields[1].mask = Some(Mask::Last4)),
        ),
        (
            "a masked field has a mask, and only a masked field",
            Box::new(|k| k.fields[2].mask = None),
        ),
        (
            "a pinned field is public and required",
            Box::new(|k| k.fields[0].optional = true),
        ),
        (
            "a pinned field is public and required",
            Box::new(|k| k.fields[1].pinned = true),
        ),
        (
            "only a secret or masked field can be guessable",
            Box::new(|k| k.fields[0].guessable = true),
        ),
        (
            "a regular expression of at most 256 bytes within the size limits",
            Box::new(|k| k.fields[1].checks = vec![Check::Pattern { regex: "(".into() }]),
        ),
        (
            "cvc names another field with a luhn check",
            Box::new(|k| {
                k.fields[1].checks = vec![Check::Cvc {
                    number: "site".into(),
                }]
            }),
        ),
        (
            "min is above max",
            Box::new(|k| k.fields[1].checks = vec![Check::Integer { min: 2, max: 1 }]),
        ),
        (
            "the origin is a pinned field with an origin check",
            Box::new(|k| {
                k.shape.destinations = DestinationRule::Origin {
                    field: "code".into(),
                }
            }),
        ),
        (
            "the host and port are pinned fields with host and port checks",
            Box::new(|k| {
                k.shape.destinations = DestinationRule::Host {
                    host: "site".into(),
                    port: "site".into(),
                }
            }),
        ),
        (
            "a capture fills a secret field of the kind (* for free fields only)",
            Box::new(|k| k.shape.captures = vec!["label".into()]),
        ),
        (
            "a capture fills a secret field of the kind (* for free fields only)",
            Box::new(|k| k.shape.captures = vec!["*".into()]),
        ),
        (
            "each connection once",
            Box::new(|k| {
                k.shape.connections = vec![ShapeConnection::Https, ShapeConnection::Https]
            }),
        ),
        (
            "a kind with free fields lists none",
            Box::new(|k| k.free_fields = true),
        ),
        (
            "a sign-off names 1 to 32 values and a token flag (plain_http belongs to origin)",
            Box::new(|k| {
                k.fields[1].checks = vec![Check::Signoff {
                    values: vec!["x".into()],
                    flag: "plain_http".into(),
                }]
            }),
        ),
    ];
    for (rule, edit) in edits {
        let mut k = custom();
        edit(&mut k);
        assert_eq!(kind_rule(&k).map(|(_, r)| r), Some(rule));
    }
    // Unknown members are refused, as in policies.
    let mut json = serde_json::to_value(custom()).unwrap();
    json["fields"][0]["junk"] = 1.into();
    assert!(serde_json::from_value::<KindSchema>(json).is_err());
    assert!(serde_json::from_str::<Check>(r#"{"check": "luhn", "junk": 1}"#).is_err());
    assert!(serde_json::from_str::<DestinationRule>(r#"{"from": "owner", "junk": 1}"#).is_err());
}

#[test]
fn a_custom_kind_is_signed_and_cannot_take_a_reviewed_name() {
    let device = DeviceKey::generate();
    let signed = device.sign_kind(custom()).unwrap();
    assert_eq!(signed.verify_any(&[device.public()]).unwrap(), &custom());
    let other = DeviceKey::generate();
    assert_eq!(
        signed.verify_any(&[other.public()]),
        Err(Error::KindSignature)
    );
    let mut changed = signed.clone();
    changed.kind.fields[1].disclosure = Disclosure::Public;
    assert_eq!(
        changed.verify_any(&[device.public()]),
        Err(Error::KindSignature)
    );
    let mut card = custom();
    card.name = "card".into();
    assert!(matches!(
        device.sign_kind(card),
        Err(Error::KindInvalid { .. })
    ));
}

fn caller() -> Caller {
    Caller::new("agent", CallerKey::generate().public(), ["pay"])
}

/// A card policy within its kind.
fn card() -> Policy {
    Policy::new()
        .with_item(ItemBinding::reviewed("card"))
        .with_field(FieldSpec::guessable("number"))
        .with_field(FieldSpec::guessable("expiry"))
        .with_field(FieldSpec::guessable("cvc"))
        .with_field(FieldSpec::public("holder").optional())
        .with_operation(
            Operation::https("pay", Destination::https("pay.example"))
                .then(
                    Send::fixed(Method::Post, "/v1/charges").inject(Injection::body(
                        "number={{number}}&exp={{expiry}}&cvc={{cvc}}&name={{holder}}",
                    )),
                )
                .then(Return::status().json("/id")),
        )
        .with_caller(caller())
}

/// A login policy within its kind.
fn login() -> Policy {
    Policy::new()
        .with_item(ItemBinding::reviewed("login").pin("origin", "https://shop.example"))
        .with_field(FieldSpec::public("origin"))
        .with_field(FieldSpec::secret("username"))
        .with_field(FieldSpec::guessable("password"))
        .with_field(FieldSpec::secret("session").optional())
        .with_operation(
            Operation::https("pay", Destination::https("shop.example"))
                .then(
                    Send::fixed(Method::Post, "/login")
                        .inject(Injection::body("u={{username}}&p={{password}}")),
                )
                .then(Receive::response().capture(Capture::new(
                    Source::Cookie { name: "sid".into() },
                    Store::field("session"),
                )))
                .then(Return::status().body()),
        )
        .with_caller(caller())
}

fn rule_of(policy: &Policy) -> Option<(String, &'static str)> {
    match policy.validate() {
        Ok(()) => None,
        Err(Error::PolicyInvalid { at, rule }) => Some((at, rule)),
        Err(Error::KindInvalid { at, rule }) => Some((at, rule)),
        Err(e) => panic!("{e}"),
    }
}

fn first_op(policy: &mut Policy) -> &mut Operation {
    policy.operations.first_mut().unwrap()
}

fn open_of(policy: &mut Policy) -> &mut crate::policy::Open {
    match first_op(policy).steps.first_mut().unwrap() {
        Step::Open(open) => open,
        _ => panic!("open"),
    }
}

#[test]
fn typed_policies_within_their_kind_validate() {
    assert_eq!(rule_of(&card()), None);
    assert_eq!(rule_of(&login()), None);
    // Narrower than the kind is fine: the status only, no optional field.
    let mut narrow = card();
    narrow.fields.retain(|f| f.name != "holder");
    narrow.operations = vec![
        Operation::https("pay", Destination::https("pay.example"))
            .then(
                Send::fixed(Method::Post, "/v1/charges")
                    .inject(Injection::body("n={{number}}&e={{expiry}}&c={{cvc}}")),
            )
            .then(Return::status()),
    ];
    assert_eq!(rule_of(&narrow), None);
}

#[test]
fn a_typed_policy_cannot_widen_its_kind() {
    type Edit = Box<dyn Fn(&mut Policy)>;
    let cases: Vec<(fn() -> Policy, &str, Edit)> = vec![
        // Where values may go.
        (
            card,
            "the kind does not allow a wildcard destination",
            Box::new(|p| {
                *first_op(p) = Operation::https("pay", Destination::https("pay.example"))
                    .destination(Destination::https("*.pay.example"))
                    .then(
                        Send::fixed_to(
                            Method::Post,
                            "/v1/charges",
                            Destination::https("pay.example"),
                        )
                        .inject(Injection::body("n={{number}}&e={{expiry}}&c={{cvc}}")),
                    )
                    .then(Return::status())
            }),
        ),
        (
            login,
            "a destination outside the item's pinned origin or host",
            Box::new(|p| open_of(p).destinations = vec![Destination::https("evil.example")]),
        ),
        (
            login,
            "a destination outside the item's pinned origin or host",
            Box::new(|p| open_of(p).destinations = vec![Destination::new("shop.example", 8443)]),
        ),
        (
            login,
            "a destination outside the item's pinned origin or host",
            Box::new(|p| {
                *first_op(p) = Operation::https("pay", Destination::https("shop.example"))
                    .destination(Destination::https("api.shop.example"))
                    .then(
                        Send::fixed_to(Method::Post, "/login", Destination::https("shop.example"))
                            .inject(Injection::body("u={{username}}&p={{password}}")),
                    )
                    .then(Return::status())
            }),
        ),
        (
            card,
            "the kind does not allow this connection",
            Box::new(|p| {
                *first_op(p) = Operation::tls("pay", Destination::https("pay.example"))
                    .then(Send::write("{{number}}\r\n"))
                    .then(Return::status())
            }),
        ),
        (
            login,
            "the kind does not allow this connection",
            Box::new(|p| *first_op(p) = Operation::derive("pay", "{{ len(password) }}")),
        ),
        (
            card,
            "the kind does not allow a client certificate",
            Box::new(|p| *first_op(p) = first_op(p).clone().identity("{{holder}}", "{{cvc}}")),
        ),
        // What comes back.
        (
            card,
            "the kind hands back less than this projection",
            Box::new(|p| {
                *first_op(p).steps.last_mut().unwrap() = Step::Return(Return::status().body())
            }),
        ),
        // What a response may fill.
        (
            login,
            "the kind does not let a response fill this field",
            Box::new(|p| {
                if let Step::Receive(r) = &mut first_op(p).steps[2] {
                    r.capture[0].into = Store::field("password");
                }
            }),
        ),
        // The fields themselves.
        (
            card,
            "the kind has no field of this name",
            Box::new(|p| p.fields.push(FieldSpec::secret("pin"))),
        ),
        (
            card,
            "a secret or masked field of the kind is secret in the policy",
            Box::new(|p| p.fields[0] = FieldSpec::public("number")),
        ),
        (
            login,
            "a secret or masked field of the kind is secret in the policy",
            Box::new(|p| p.fields[1] = FieldSpec::public("username")),
        ),
        (
            card,
            "a guessable field of the kind is guessable in the policy",
            Box::new(|p| p.fields[2] = FieldSpec::secret("cvc")),
        ),
        (
            card,
            "a required field of the kind is required in the policy",
            Box::new(|p| p.fields[2] = FieldSpec::guessable("cvc").optional()),
        ),
        (
            card,
            "the policy lacks a required field of the kind",
            Box::new(|p| {
                p.fields.remove(2);
                p.operations[0].steps[1] = Step::Send(
                    Send::fixed(Method::Post, "/v1/charges")
                        .inject(Injection::body("n={{number}}&e={{expiry}}")),
                );
            }),
        ),
        // Pins and sign-offs.
        (
            login,
            "a pinned field has no value",
            Box::new(|p| p.item.as_mut().unwrap().pins.clear()),
        ),
        (
            login,
            "a pinned value fails its checks",
            Box::new(|p| {
                p.item
                    .as_mut()
                    .unwrap()
                    .pins
                    .insert("origin".into(), "https://shop.example/x".into());
            }),
        ),
        (
            login,
            "a pinned value fails its checks",
            Box::new(|p| {
                p.item
                    .as_mut()
                    .unwrap()
                    .pins
                    .insert("origin".into(), "http://shop.example".into());
            }),
        ),
        (
            login,
            "only a pinned field of the policy has a pin",
            Box::new(|p| {
                p.item
                    .as_mut()
                    .unwrap()
                    .pins
                    .insert("username".into(), "x".into());
            }),
        ),
        (
            card,
            "each sign-off once, and only flags the checks of the kind name",
            Box::new(|p| p.item.as_mut().unwrap().signoff.push("plain".into())),
        ),
    ];
    for (base, rule, edit) in cases {
        let mut policy = base();
        edit(&mut policy);
        assert_eq!(rule_of(&policy).map(|(_, r)| r), Some(rule), "{rule}");
        // The device refuses to sign it too.
        assert!(DeviceKey::generate().sign_policy(policy).is_err());
    }
}

#[test]
fn plain_http_needs_the_owners_signoff() {
    let mut policy = login();
    let item = policy.item.as_mut().unwrap();
    item.pins
        .insert("origin".into(), "http://shop.example".into());
    item.signoff.push("plain_http".into());
    open_of(&mut policy).destinations = vec![Destination::new("shop.example", 80)];
    assert_eq!(rule_of(&policy), None);
}

#[test]
fn kinds_without_a_connection_yet_validate_no_policy() {
    let blob = ed25519_blob("ssh-ed25519");
    let host_key = format!("ssh-ed25519 {blob}");
    let ssh = Policy::new()
        .with_item(
            ItemBinding::reviewed("ssh")
                .pin("host", "git.example")
                .pin("port", "22")
                .pin("host_key", &host_key),
        )
        .with_field(FieldSpec::public("host"))
        .with_field(FieldSpec::public("port"))
        .with_field(FieldSpec::public("host_key"))
        .with_field(FieldSpec::public("user"))
        .with_field(FieldSpec::secret("private_key"))
        .with_operation(
            Operation::tls("pay", Destination::new("git.example", 22))
                .then(Send::write("{{private_key}}"))
                .then(Return::status()),
        )
        .with_caller(caller());
    assert_eq!(
        rule_of(&ssh).map(|(_, r)| r),
        Some("the kind does not allow this connection")
    );
    // The host key is a required pin: without it, or with a key of no algorithm, refused.
    let mut no_key = ssh.clone();
    no_key.fields.retain(|f| f.name != "host_key");
    no_key.item.as_mut().unwrap().pins.remove("host_key");
    assert_eq!(
        rule_of(&no_key).map(|(_, r)| r),
        Some("the policy lacks a required field of the kind")
    );
    let mut bad_key = ssh.clone();
    bad_key
        .item
        .as_mut()
        .unwrap()
        .pins
        .insert("host_key".into(), format!("ssh-dss {blob}"));
    assert_eq!(
        rule_of(&bad_key).map(|(_, r)| r),
        Some("a pinned value fails its checks")
    );
    let mut optional = ssh;
    optional.fields[2] = FieldSpec::public("host_key").optional();
    assert_eq!(
        rule_of(&optional).map(|(_, r)| r),
        Some("a required field of the kind is required in the policy")
    );
}

fn database(tls: &str, signoff: bool) -> Policy {
    let mut item = ItemBinding::reviewed("database")
        .pin("host", "db.example")
        .pin("port", "6380")
        .pin("tls", tls);
    if signoff {
        item = item.sign_off("plain");
    }
    Policy::new()
        .with_item(item)
        .with_field(FieldSpec::public("engine"))
        .with_field(FieldSpec::public("host"))
        .with_field(FieldSpec::public("port"))
        .with_field(FieldSpec::public("user"))
        .with_field(FieldSpec::guessable("password"))
        .with_field(FieldSpec::public("tls"))
        .with_operation(
            Operation::tls("pay", Destination::new("db.example", 6380))
                .then(Send::write("AUTH {{user}} {{password}}\r\n"))
                .then(Receive::until(["\r\n"]))
                .then(Return::relay(["GET [a-z]{1,16}\\r\\n"])),
        )
        .with_caller(caller())
}

#[test]
fn a_database_needs_tls_unless_the_owner_signs_it_off() {
    assert_eq!(rule_of(&database("verify-full", false)), None);
    assert_eq!(
        rule_of(&database("disable", false)).map(|(_, r)| r),
        Some("a pinned value fails its checks")
    );
    assert_eq!(rule_of(&database("disable", true)), None);
    assert_eq!(
        rule_of(&database("sometimes", true)).map(|(_, r)| r),
        Some("a pinned value fails its checks")
    );
}

#[test]
fn a_totp_seed_is_for_derivations_only() {
    let totp = || {
        Policy::new()
            .with_item(ItemBinding::reviewed("totp"))
            .with_field(FieldSpec::secret("seed"))
            .with_operation(Operation::derive("pay", "{{ totp(b32decode(seed)) }}"))
            .with_caller(caller())
    };
    assert_eq!(rule_of(&totp()), None);
    let mut sent = totp();
    sent.operations = vec![
        Operation::https("pay", Destination::https("pay.example"))
            .then(
                Send::fixed(Method::Post, "/")
                    .inject(Injection::body("{{ totp(b32decode(seed)) }}")),
            )
            .then(Return::status()),
    ];
    assert_eq!(
        rule_of(&sent).map(|(_, r)| r),
        Some("the kind does not allow this connection")
    );
}

#[test]
fn a_custom_kind_binds_like_a_reviewed_one() {
    let device = DeviceKey::generate();
    let signed = device.sign_kind(custom()).unwrap();
    let policy = || {
        Policy::new()
            .with_item(ItemBinding::custom(signed.clone()).pin("site", "https://door.example"))
            .with_field(FieldSpec::public("site"))
            .with_field(FieldSpec::guessable("code"))
            .with_operation(
                Operation::https("pay", Destination::https("door.example"))
                    .then(Send::fixed(Method::Post, "/open").inject(Injection::body("{{code}}")))
                    .then(Return::status()),
            )
            .with_caller(caller())
    };
    assert_eq!(rule_of(&policy()), None);
    let signed_policy = device.sign_policy(policy()).unwrap();
    signed_policy.verify_any(&[device.public()]).unwrap();
    // Signed by a device the node does not know for the owner: refused.
    let stranger = DeviceKey::generate();
    let foreign = ItemBinding::custom(stranger.sign_kind(custom()).unwrap())
        .pin("site", "https://door.example");
    let mut p = policy();
    p.item = Some(foreign);
    let signed_policy = device.sign_policy(p).unwrap();
    assert_eq!(
        signed_policy.verify_any(&[device.public()]),
        Err(Error::KindSignature)
    );
    // The binding names another kind than it carries, or a reviewed one.
    let mut p = policy();
    p.item.as_mut().unwrap().kind = "card".into();
    assert_eq!(
        rule_of(&p).map(|(_, r)| r),
        Some("a custom kind takes the name of a reviewed kind")
    );
    let mut p = policy();
    p.item.as_mut().unwrap().kind = "door".into();
    assert_eq!(
        rule_of(&p).map(|(_, r)| r),
        Some("the custom kind has another name than the binding")
    );
    // The destination outside the pinned site is refused for a custom kind too.
    let mut p = policy();
    open_of(&mut p).destinations = vec![Destination::https("elsewhere.example")];
    assert_eq!(
        rule_of(&p).map(|(_, r)| r),
        Some("a destination outside the item's pinned origin or host")
    );
    // An unknown reviewed kind.
    let mut p = card();
    p.item = Some(ItemBinding::reviewed("passport"));
    assert_eq!(
        rule_of(&p).map(|(_, r)| r),
        Some("no reviewed kind of this name, and no custom kind given")
    );
}

fn fields(values: &[(&str, &str)]) -> Fields {
    let mut f = Fields::new();
    for (n, v) in values {
        f.insert(n, v.as_bytes().to_vec()).unwrap();
    }
    f
}

fn card_values() -> Fields {
    fields(&[
        ("number", "4242424242424242"),
        ("expiry", "12/27"),
        ("cvc", "123"),
        ("holder", "Jane Doe"),
    ])
}

#[test]
fn values_are_checked_against_the_kind() {
    check_values(&card(), &card_values(), Some(NOW)).unwrap();
    let bad_number = fields(&[
        ("number", "4242424242424241"),
        ("expiry", "12/27"),
        ("cvc", "123"),
    ]);
    assert_eq!(
        check_values(&card(), &bad_number, Some(NOW)),
        Err(Error::FieldInvalid {
            field: "number".into(),
            rule: "the Luhn checksum does not hold"
        })
    );
    let expired = fields(&[
        ("number", "4242424242424242"),
        ("expiry", "10/26"),
        ("cvc", "123"),
    ]);
    assert_eq!(
        check_values(&card(), &expired, Some(NOW)),
        Err(Error::FieldInvalid {
            field: "expiry".into(),
            rule: "the card has expired"
        })
    );
    // Without a clock the expiry is not judged (the node judges it on every use).
    check_values(&card(), &expired, None).unwrap();
    let amex_code = fields(&[
        ("number", "378282246310005"),
        ("expiry", "12/27"),
        ("cvc", "123"),
    ]);
    assert!(check_values(&card(), &amex_code, Some(NOW)).is_err());
    // A pinned field holds its pin.
    let login_values = |origin: &str| {
        fields(&[
            ("origin", origin),
            ("username", "jane@mail.example"),
            ("password", "hunter22"),
        ])
    };
    check_values(&login(), &login_values("https://shop.example"), Some(NOW)).unwrap();
    assert_eq!(
        check_values(&login(), &login_values("https://evil.example"), Some(NOW)),
        Err(Error::FieldInvalid {
            field: "origin".into(),
            rule: "the value differs from its pin in the policy"
        })
    );
    // A public or masked value is text.
    let mut binary = fields(&[
        ("number", "4242424242424242"),
        ("expiry", "12/27"),
        ("cvc", "123"),
    ]);
    binary.insert("holder", vec![0xff, 0xfe]).unwrap();
    assert!(check_values(&card(), &binary, Some(NOW)).is_err());
}

#[test]
fn describe_returns_public_and_masked_fields_never_secret_ones() {
    let d = describe(&card(), &card_values()).unwrap();
    assert_eq!(d.kind, "card");
    let got: Vec<(&str, Disclosure, &str)> = d
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.disclosure, f.value.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "number",
                Disclosure::Masked,
                "visa \u{2022}\u{2022}\u{2022}\u{2022}4242"
            ),
            ("expiry", Disclosure::Masked, "2027"),
            ("holder", Disclosure::Public, "Jane Doe"),
        ]
    );
    let text = serde_json::to_string(&d).unwrap();
    for secret in ["4242424242424242", "12/27", "123\""] {
        assert!(
            !text.contains(secret),
            "a secret value is in the description"
        );
    }
    // A public field of the kind that the policy keeps secret is not described.
    let mut private = card();
    private.fields[3] = FieldSpec::secret("holder").optional();
    let d = describe(&private, &card_values()).unwrap();
    assert!(d.fields.iter().all(|f| f.name != "holder"));
    // A record without a kind has nothing to describe.
    let mut untyped = card();
    untyped.item = None;
    assert_eq!(describe(&untyped, &card_values()), Err(Error::NotAnItem));
    // The api kind has free fields: nothing of them is described.
    let mut api = untyped;
    api.item = Some(ItemBinding::reviewed("api"));
    assert_eq!(rule_of(&api), None);
    assert!(describe(&api, &card_values()).unwrap().fields.is_empty());
}

#[test]
fn the_node_refuses_a_widened_typed_policy_even_when_signed() {
    // A device that skipped the checks (or an attacker holding a device key) signs a card
    // policy that sends the number to a wildcard and hands back the whole body.
    let device = DeviceKey::generate();
    let mut wide = card();
    wide.operations = vec![
        Operation::https("pay", Destination::https("pay.example"))
            .destination(Destination::https("*.collect.example"))
            .then(
                Send::fixed_to(
                    Method::Post,
                    "/v1/charges",
                    Destination::https("pay.example"),
                )
                .inject(Injection::body("n={{number}}&e={{expiry}}&c={{cvc}}")),
            )
            .then(Return::status().body()),
    ];
    let message = crate::encoding::canonical(b"policy/v4\0", &wide).unwrap();
    let forged = crate::policy::SignedPolicy {
        signature: device.sign(&message),
        policy: wide,
    };
    assert!(matches!(
        forged.verify_any(&[device.public()]),
        Err(Error::PolicyInvalid { .. })
    ));
    // The same policy without the item binding is an ordinary policy: the binding is what
    // holds a typed record to its kind.
    let mut untyped = forged.policy.clone();
    untyped.item = None;
    let message = crate::encoding::canonical(b"policy/v4\0", &untyped).unwrap();
    let plain = crate::policy::SignedPolicy {
        signature: device.sign(&message),
        policy: untyped,
    };
    plain.verify_any(&[device.public()]).unwrap();
}

#[test]
fn every_check_and_mask_takes_any_bytes() {
    // The checks and masks of every reviewed kind on awkward values: empty, not UTF-8,
    // multi-byte characters at every cut, very long, digits only. None may panic; a masked
    // projection never holds more than a few characters of the value.
    let mut values: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0xff, 0xfe, 0x00],
        "\u{c724}\u{c544}@\u{c724}.example".as_bytes().to_vec(),
        "9".repeat(5000).into_bytes(),
        b"12/".to_vec(),
        b"/".to_vec(),
        b"SHA256:".to_vec(),
        b"ssh-ed25519 AAAA".to_vec(),
        b"https://".to_vec(),
        b"https://a:".to_vec(),
        b"@".to_vec(),
        b"9999-99-99".to_vec(),
    ];
    let multi = "\u{1f600}\u{c724}a\u{e9}".as_bytes().to_vec();
    for cut in 0..=multi.len() {
        values.push(multi.get(..cut).unwrap().to_vec());
    }
    for kind in reviewed().unwrap() {
        let flags: Vec<String> = kind.signoff_flags().iter().map(|s| s.to_string()).collect();
        for field in &kind.fields {
            for value in &values {
                let other = |_: &str| Some(value.clone());
                let _ = kind.check_value(&field.name, value, &flags, Some(NOW), &other);
                let _ = kind.check_value(&field.name, value, &[], None, &|_| None);
                if let Some(m) = field.mask {
                    let shown = mask::apply(m, value);
                    assert!(shown.chars().count() <= 12 + value.len().min(64), "{shown}");
                }
            }
        }
    }
    for m in [
        Mask::Card,
        Mask::Email,
        Mask::Initial,
        Mask::Year,
        Mask::Last2,
        Mask::Last4,
    ] {
        for value in &values {
            let _ = mask::apply(m, value);
        }
    }
}

/// An operation from JSON, for the protocol connections the builders do not cover.
fn op(value: serde_json::Value) -> Operation {
    serde_json::from_value(value).unwrap()
}

fn ssh_host_key() -> String {
    format!("ssh-ed25519 {}", ed25519_blob("ssh-ed25519"))
}

fn ssh_item(login: serde_json::Value, host_keys: Vec<String>) -> Policy {
    Policy::new()
        .with_item(
            ItemBinding::reviewed("ssh")
                .pin("host", "git.example")
                .pin("port", "22")
                .pin("host_key", &ssh_host_key()),
        )
        .with_field(FieldSpec::public("host"))
        .with_field(FieldSpec::public("port"))
        .with_field(FieldSpec::public("host_key"))
        .with_field(FieldSpec::public("user"))
        .with_field(FieldSpec::secret("private_key").optional())
        .with_field(FieldSpec::guessable("password").optional())
        .with_operation(op(serde_json::json!({"name": "pay", "steps": [
            {"do": "open", "connection": "ssh",
             "destinations": [{"host": "git.example", "port": 22}],
             "host_keys": host_keys, "login": login},
            {"do": "return", "relay": {"commands": [{"name": "id", "text": "id"}]}}
        ]})))
        .with_caller(caller())
}

#[test]
fn an_ssh_item_signs_in_with_its_own_fields_to_its_pinned_host_key() {
    let key_login = serde_json::json!({"user": "{{user}}", "key": "{{private_key}}"});
    assert_eq!(
        rule_of(&ssh_item(key_login.clone(), vec![ssh_host_key()])),
        None
    );
    let password_login = serde_json::json!({"user": "{{user}}", "password": "{{password}}"});
    assert_eq!(
        rule_of(&ssh_item(password_login, vec![ssh_host_key()])),
        None
    );
    let login_rule = "each login member is exactly {{field}} of the field the kind names for it";
    // A login member that is not exactly its field: a literal user, the key as a password,
    // the password wrapped in other text, an answer the kind does not name.
    for login in [
        serde_json::json!({"user": "root", "key": "{{private_key}}"}),
        serde_json::json!({"user": "{{user}}", "password": "{{private_key}}"}),
        serde_json::json!({"user": "{{user}}", "password": "x{{password}}"}),
        serde_json::json!({"user": "{{user}}",
                           "answers": [{"prompt": "P.*", "template": "{{password}}"}]}),
    ] {
        assert_eq!(
            rule_of(&ssh_item(login, vec![ssh_host_key()])).map(|(_, r)| r),
            Some(login_rule)
        );
    }
    // Another host key, or a second one besides it.
    let mut blob = 11u32.to_be_bytes().to_vec();
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[8u8; 32]);
    let other = format!("ssh-ed25519 {}", STANDARD.encode(blob));
    let key_rule = "an SSH operation of an item pins exactly the item's host key, a whole key";
    for keys in [vec![other.clone()], vec![ssh_host_key(), other]] {
        assert_eq!(
            rule_of(&ssh_item(key_login.clone(), keys)).map(|(_, r)| r),
            Some(key_rule)
        );
    }
    // A fingerprint in the pin: the node could not compare a key to it.
    let mut fingerprint = ssh_item(key_login.clone(), vec![ssh_host_key()]);
    fingerprint.item.as_mut().unwrap().pins.insert(
        "host_key".into(),
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".into(),
    );
    assert_eq!(rule_of(&fingerprint).map(|(_, r)| r), Some(key_rule));
    // Another destination than the pinned host and port.
    let mut elsewhere = ssh_item(key_login, vec![ssh_host_key()]);
    open_of(&mut elsewhere).destinations = vec![Destination::new("evil.example", 22)];
    assert_eq!(
        rule_of(&elsewhere).map(|(_, r)| r),
        Some("a destination outside the item's pinned origin or host")
    );
}

fn mail_item(steps: Vec<serde_json::Value>) -> Policy {
    Policy::new()
        .with_item(
            ItemBinding::reviewed("mail")
                .pin("smtp_host", "smtp.example")
                .pin("smtp_port", "465")
                .pin("imap_host", "imap.example")
                .pin("imap_port", "993"),
        )
        .with_field(FieldSpec::public("smtp_host"))
        .with_field(FieldSpec::public("smtp_port"))
        .with_field(FieldSpec::public("imap_host"))
        .with_field(FieldSpec::public("imap_port"))
        .with_field(FieldSpec::secret("user"))
        .with_field(FieldSpec::guessable("password").optional())
        .with_operation(op(serde_json::json!({"name": "pay", "steps": steps})))
        .with_caller(caller())
}

fn smtp_steps(host: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"do": "open", "connection": "smtp",
            "destinations": [{"host": host, "port": 465}],
            "login": {"user": "{{user}}", "password": "{{password}}"}}),
        serde_json::json!({"do": "return", "relay": {"mail": {
            "senders": ["me@example\\.com"], "recipients": [".*@example\\.com"]}}}),
    ]
}

#[test]
fn a_mailbox_sends_and_reads_only_on_its_pinned_servers() {
    assert_eq!(rule_of(&mail_item(smtp_steps("smtp.example"))), None);
    let imap = vec![
        serde_json::json!({"do": "open", "connection": "imap",
            "destinations": [{"host": "imap.example", "port": 993}],
            "login": {"user": "{{user}}", "password": "{{password}}"}}),
        serde_json::json!({"do": "return", "relay": {"commands": [
            {"name": "inbox", "text": "SELECT INBOX"}]}}),
    ];
    assert_eq!(rule_of(&mail_item(imap)), None);
    // SMTP to the IMAP server, or anywhere else.
    for host in ["imap.example", "evil.example"] {
        assert_eq!(
            rule_of(&mail_item(smtp_steps(host))).map(|(_, r)| r),
            Some("a destination outside the item's pinned origin or host")
        );
    }
    // A hand-written exchange over a TLS stream is not a mailbox operation.
    let tls = vec![
        serde_json::json!({"do": "open", "connection": "tls",
            "destinations": [{"host": "smtp.example", "port": 465}]}),
        serde_json::json!({"do": "send", "template": "AUTH PLAIN {{password}}\r\n"}),
        serde_json::json!({"do": "return"}),
    ];
    assert_eq!(
        rule_of(&mail_item(tls)).map(|(_, r)| r),
        Some("the kind does not allow this connection")
    );
}

#[test]
fn ssh_and_mail_items_describe_and_mask_their_public_fields() {
    let ssh = ssh_item(
        serde_json::json!({"user": "{{user}}", "key": "{{private_key}}"}),
        vec![ssh_host_key()],
    );
    let host_key = ssh_host_key();
    let values = fields(&[
        ("host", "git.example"),
        ("port", "22"),
        ("host_key", &host_key),
        ("user", "deploy"),
        ("private_key", "-----BEGIN PRIVATE KEY-----"),
    ]);
    check_values(&ssh, &values, Some(NOW)).unwrap();
    let d = describe(&ssh, &values).unwrap();
    let names: Vec<&str> = d.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["host", "port", "host_key", "user"]);
    assert!(!d.fields.iter().any(|f| f.value.contains("PRIVATE")));

    let mail = mail_item(smtp_steps("smtp.example"));
    let values = fields(&[
        ("smtp_host", "smtp.example"),
        ("smtp_port", "465"),
        ("user", "jane@example.com"),
        ("password", "app-password"),
    ]);
    check_values(&mail, &values, Some(NOW)).unwrap();
    let d = describe(&mail, &values).unwrap();
    let user = d.fields.iter().find(|f| f.name == "user").unwrap();
    assert_eq!(user.disclosure, Disclosure::Masked);
    assert_eq!(user.value, "j***@example.com");
    assert!(!d.fields.iter().any(|f| f.name == "password"));
    // A record whose server differs from the pin is refused when it is opened.
    let moved = fields(&[("smtp_host", "evil.example"), ("user", "jane@example.com")]);
    assert!(check_values(&mail, &moved, Some(NOW)).is_err());
}

#[test]
fn a_kind_with_a_protocol_connection_names_its_login_and_host_key() {
    let ssh = reviewed_kind("ssh").unwrap().clone();
    let mut no_login = ssh.clone();
    no_login.shape.login = None;
    assert!(no_login.validate().is_err());
    let mut no_host_key = ssh.clone();
    no_host_key.shape.host_key = None;
    assert!(no_host_key.validate().is_err());
    let mut public_secret = ssh.clone();
    if let Some(login) = public_secret.shape.login.as_mut() {
        login.password = Some("host".into());
    }
    assert!(public_secret.validate().is_err());
    let mut anywhere = ssh;
    anywhere.shape.destinations = DestinationRule::Owner {};
    assert!(anywhere.validate().is_err());
}
