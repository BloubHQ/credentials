//! Typed items: kinds of credentials as data.
//!
//! A [`KindSchema`] names the fields of a kind of item (a card, a login, an SSH account), the
//! [`Disclosure`] of each (what a caller may ever see of it), the [`Check`]s its values pass,
//! the [`Mask`] that makes a masked projection, and the [`Shape`] every policy of such an item
//! stays within: which connections, which destinations, what may go back, which fields a
//! response may fill.
//!
//! The reviewed kinds ship in `items.json`, compiled into the node ([`reviewed`]). An owner adds
//! a custom kind without a release: the device signs the schema ([`DeviceKey::sign_kind`]) and
//! the policy carries the [`SignedKind`]. A policy names its kind in [`ItemBinding`], with the
//! values of the pinned fields (the origin, the host and port, the host key) and the owner's
//! sign-offs; the node derives the shape from the kind and refuses a typed policy that is wider
//! ([`check_policy`]), and checks every value of the record against the kind when the record is
//! sealed and each time the node opens it ([`check_values`]).
//!
//! [`describe`] is what a caller may learn of an item: the public fields as they are and the
//! masked ones as their projection, never a secret field.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, canonical};
use crate::fields::Fields;
use crate::keys::{DeviceKey, DevicePublicKey};
use crate::policy::{
    BodyProjection, Connection, Destination, Open, Operation, Policy, Step, Store, is_false,
    is_token,
};
use crate::{Error, Result};

mod checks;
mod mask;

pub use checks::{Brand, Origin, brand_of, parse_origin};

const KIND_DOMAIN: &[u8] = b"kind/v1\0";

/// The reviewed kinds, as shipped: the text the node is built with.
pub const ITEMS_JSON: &str = include_str!("items.json");

/// Most fields of a kind.
pub const MAX_KIND_FIELDS: usize = 32;
/// Most checks of one field.
pub const MAX_CHECKS: usize = 8;
/// Longest description of a kind, in bytes.
pub const MAX_DESCRIPTION: usize = 512;
/// Longest pinned value, in bytes.
pub const MAX_PIN: usize = 4096;
/// Most sign-offs of a binding.
pub const MAX_SIGNOFFS: usize = 8;
/// Most values of a `one_of` check.
pub const MAX_ONE_OF: usize = 32;

/// What a caller may see of a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    /// Nothing: the value only goes where the signed policy sends it.
    Secret,
    /// Its [`Mask`] (a card's brand and last four, `j***@example.com`). In the policy it is a
    /// secret field, so the analysis tracks it like one.
    Masked,
    /// The value.
    Public,
}

/// The projection of a masked field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mask {
    /// The brand of a card number (from its IIN range) and its last four digits.
    Card,
    /// The first character of the local part and the domain: `j***@example.com`.
    Email,
    /// The first character: `J***`.
    Initial,
    /// The year of a date (`MM/YY`, `MM/YYYY`, `YYYY-MM-DD`).
    Year,
    /// The last two characters, of a value of at least eight.
    Last2,
    /// The last four characters, of a value of at least twelve.
    Last4,
}

/// A check a value of a field must pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// 12 to 19 decimal digits whose Luhn checksum holds (ISO/IEC 7812).
    Luhn {},
    /// `MM/YY` or `MM/YYYY`, whose month has not ended by the node's clock.
    Expiry {},
    /// Card security code: 4 digits for a number in an IIN range that uses four, else 3.
    Cvc {
        /// The field that holds the card number.
        number: String,
    },
    /// An exact origin: `https://host` or `https://host:port`, a lowercase host name, no path.
    /// `http://` needs the sign-off `plain_http`.
    Origin {},
    /// A lowercase host name.
    Host {},
    /// A decimal integer within bounds, without leading zeros.
    Integer {
        /// Least value.
        min: u64,
        /// Greatest value.
        max: u64,
    },
    /// A length in bytes.
    Length {
        /// Least length.
        min: usize,
        /// Greatest length.
        max: usize,
    },
    /// A regular expression the whole value matches (linear time, at most 256 bytes).
    Pattern {
        /// The expression.
        regex: String,
    },
    /// One of a list of values.
    OneOf {
        /// The values.
        values: Vec<String>,
    },
    /// An e-mail address: a local part, `@`, a lowercase host name.
    Email {},
    /// A calendar date, `YYYY-MM-DD`.
    Date {},
    /// Base32 (RFC 4648; case, spaces and padding ignored) of at least `min_bits` bits.
    Base32 {
        /// Fewest bits.
        min_bits: u32,
    },
    /// Standard base64 of exactly `bytes` bytes (a WireGuard key is 32).
    Base64Key {
        /// The length of the decoded key.
        bytes: usize,
    },
    /// An SSH host key: `<algorithm> <base64 key blob>` as in `known_hosts`, whose blob names
    /// the same algorithm, or a `SHA256:` fingerprint.
    SshHostKey {},
    /// A value in `values` needs the owner's sign-off `flag` in the binding.
    Signoff {
        /// The values that need it.
        values: Vec<String>,
        /// The sign-off, a token.
        flag: String,
    },
}

/// A field of a kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindField {
    /// The field name, a token.
    pub name: String,
    /// What a caller may see of it.
    pub disclosure: Disclosure,
    /// True when an item may lack it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    /// True for a value with few possibilities (a PIN, a card number, a password a person
    /// chose); the policy field must be guessable too.
    #[serde(default, skip_serializing_if = "is_false")]
    pub guessable: bool,
    /// True for a public value that fixes the shape of the policy (an origin, a host, a port, a
    /// host key): the binding repeats it, and the record must hold the same value.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    /// The projection of a masked field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<Mask>,
    /// What its value must pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,
}

/// A connection a kind allows its operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapeConnection {
    /// HTTPS.
    Https,
    /// A TLS byte stream.
    Tls,
    /// SSH: commands, a shell, SFTP and forwards, to a server whose host key is pinned.
    Ssh,
    /// SMTP: the caller's messages.
    Smtp,
    /// IMAP: commands.
    Imap,
    /// POP3: commands on message numbers.
    Pop3,
    /// FTP over TLS: file operations.
    Ftp,
    /// A browser over CDP: fills of the kind's [`BrowserShape`] roles, the agent's
    /// controller kept out by the endpoint's exclusive grant.
    Browser,
    /// No connection: a derivation.
    None,
}

impl ShapeConnection {
    fn name(self) -> &'static str {
        match self {
            ShapeConnection::Https => "https",
            ShapeConnection::Tls => "tls",
            ShapeConnection::Ssh => "ssh",
            ShapeConnection::Smtp => "smtp",
            ShapeConnection::Imap => "imap",
            ShapeConnection::Pop3 => "pop3",
            ShapeConnection::Ftp => "ftp",
            ShapeConnection::Browser => "browser",
            ShapeConnection::None => "none",
        }
    }

    /// True for a protocol connection, which signs in with the item's login.
    fn is_protocol(self) -> bool {
        matches!(
            self,
            ShapeConnection::Ssh
                | ShapeConnection::Smtp
                | ShapeConnection::Imap
                | ShapeConnection::Pop3
                | ShapeConnection::Ftp
        )
    }
}

/// Where operations of one connection of an item may connect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRoute {
    /// The connection.
    pub connection: ShapeConnection,
    /// The pinned host field.
    pub host: String,
    /// The pinned port field.
    pub port: String,
}

/// Which fields of the kind a protocol connection signs in with. Each member of the policy's
/// `login` must be exactly `{{field}}` of the field named here, and a member named nowhere
/// here must be absent: the item's secrets go to the sign-in and nowhere else on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginShape {
    /// The user name field.
    pub user: String,
    /// The password field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The private key field (SSH).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The OAuth token field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// A value a browser fill of the kind may put into a page: a name the owner picks fields by,
/// and the template that makes the value from the item's fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRole {
    /// The name, a token (`username`, `password`, `totp`, `number`, ...).
    pub role: String,
    /// The value: a template over the fields of the kind only (`{{password}}`,
    /// `{{ totp(b32decode(totp)) }}`).
    pub template: String,
}

/// The browser fills of a kind: where the page may be and which values go into it. A fill of
/// an item puts only these values into a page, each into the element the policy's selector
/// names, and only through a connection whose endpoint hands the browser to the node alone
/// and whose page is loaded again when it stays (`docs/policy.md`, Typed browser fills).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserShape {
    /// The pinned origin field every page of a fill must be at, exactly. Without it the page
    /// is the owner's choice (a card at a merchant), an `https` origin with no wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// True when a value may go into a direct child frame of another origin (a card form in
    /// a payment provider's frame; flagged `frame_origin`). Otherwise every element is in the
    /// top frame.
    #[serde(default, skip_serializing_if = "is_false")]
    pub frames: bool,
    /// The values, 1 to 16.
    pub roles: Vec<BrowserRole>,
}

impl BrowserShape {
    /// The role of this name.
    pub fn role(&self, name: &str) -> Option<&BrowserRole> {
        self.roles.iter().find(|r| r.role == name)
    }
}

/// Where the operations of an item may connect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum DestinationRule {
    /// Where the owner's policy says (a card goes to the merchant or payment provider the
    /// owner signs), without wildcards unless the shape allows them.
    Owner {},
    /// Exactly the host and port of the pinned origin field.
    Origin {
        /// The field.
        field: String,
    },
    /// Exactly the pinned host and port fields.
    Host {
        /// The host field.
        host: String,
        /// The port field.
        port: String,
    },
    /// Per connection, exactly its pinned host and port fields (a mailbox: SMTP to one
    /// server, IMAP to another).
    Hosts {
        /// One route per connection of the shape.
        hosts: Vec<HostRoute>,
    },
}

/// The most an HTTPS operation of an item may hand back to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Returns {
    /// The status only.
    Status,
    /// The status, listed headers and listed JSON members.
    Json,
    /// Anything the projection lists, the whole body included.
    All,
}

/// What every policy of a kind stays within.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shape {
    /// The connections its operations may open (`none` for derivations). Empty for a kind
    /// whose protocol the node does not speak yet: no policy of it validates.
    pub connections: Vec<ShapeConnection>,
    /// Where they may connect.
    pub destinations: DestinationRule,
    /// True when a destination may be a `*.` pattern.
    #[serde(default, skip_serializing_if = "is_false")]
    pub wildcards: bool,
    /// The most an HTTPS operation hands back.
    pub returns: Returns,
    /// True when a TLS operation may relay the caller's exchanges.
    #[serde(default, skip_serializing_if = "is_false")]
    pub relay: bool,
    /// True when an operation may present a client certificate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub identity: bool,
    /// The secret fields a response may fill (`*`: any, for free fields only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<String>,
    /// True when every use of an item of the kind waits for the owner's approval (a card:
    /// every payment), whatever the policy or the spending limits say.
    #[serde(default, skip_serializing_if = "is_false")]
    pub approval: bool,
    /// How a protocol connection signs in; required when the shape allows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginShape>,
    /// The pinned field holding the SSH host key; required when the shape allows SSH. The
    /// policy pins exactly that key, and it must be a whole key, not a fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// The pinned field that fixes how a protocol connection reaches TLS: `implicit` (TLS
    /// from the first byte), or `explicit` (`STARTTLS`, `STLS` or `AUTH TLS`). The policy's
    /// `tls` must agree; any other value (`plain`) allows no protocol operation, since the
    /// node sends no credential in the clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// The browser fills of the kind; required when the shape allows a browser connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserShape>,
}

/// A kind of item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindSchema {
    /// The name, a token.
    pub name: String,
    /// What it is, for the owner.
    pub description: String,
    /// True for a kind whose fields the policy names freely (`api`): none is described.
    #[serde(default, skip_serializing_if = "is_false")]
    pub free_fields: bool,
    /// The fields.
    pub fields: Vec<KindField>,
    /// The shape of its policies.
    pub shape: Shape,
}

/// A custom kind with the signature of a device of its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKind {
    /// The kind.
    pub kind: KindSchema,
    /// Ed25519 signature over the canonical bytes of the kind.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

/// What makes a policy the policy of a typed item: its kind and the owner's choices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemBinding {
    /// The name of the kind: a reviewed kind, or the custom kind carried in `custom`.
    pub kind: String,
    /// A custom kind, signed by a device of the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<SignedKind>,
    /// The values of the pinned fields the policy holds, by field name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pins: BTreeMap<String, String>,
    /// The owner's sign-offs (`plain`, `plain_http`): flags the `signoff` checks of the kind
    /// name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signoff: Vec<String>,
}

/// One field of a [`Description`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Described {
    /// The field name.
    pub name: String,
    /// `public` or `masked`.
    pub disclosure: Disclosure,
    /// The value, or its projection.
    pub value: String,
}

/// What a caller may learn of a typed item: public fields and masked projections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Description {
    /// The kind.
    pub kind: String,
    /// The public and masked fields the record holds, in the order of the kind.
    pub fields: Vec<Described>,
}

type Checked = core::result::Result<(), Error>;

fn kind_fail(at: impl Into<String>, rule: &'static str) -> Checked {
    Err(Error::KindInvalid {
        at: at.into(),
        rule,
    })
}

fn kind_ensure(ok: bool, at: impl FnOnce() -> String, rule: &'static str) -> Checked {
    if ok { Ok(()) } else { kind_fail(at(), rule) }
}

fn unique<'a>(names: impl Iterator<Item = &'a str>) -> bool {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    names.windows(2).all(|w| w.first() != w.get(1))
}

impl KindSchema {
    /// The field of this name.
    pub fn field(&self, name: &str) -> Option<&KindField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// The sign-off flags its checks name.
    pub fn signoff_flags(&self) -> Vec<&str> {
        self.fields
            .iter()
            .flat_map(|f| &f.checks)
            .filter_map(|c| match c {
                Check::Signoff { flag, .. } => Some(flag.as_str()),
                Check::Origin {} => Some(checks::PLAIN_HTTP),
                _ => None,
            })
            .collect()
    }

    fn check_check(&self, at: &str, field: &KindField, check: &Check) -> Checked {
        match check {
            Check::Cvc { number } => kind_ensure(
                number != &field.name
                    && self
                        .field(number)
                        .is_some_and(|n| n.checks.contains(&Check::Luhn {})),
                || at.to_string(),
                "cvc names another field with a luhn check",
            ),
            Check::Integer { min, max } => {
                kind_ensure(min <= max, || at.to_string(), "min is above max")
            }
            Check::Length { min, max } => kind_ensure(
                min <= max && *max <= crate::fields::MAX_TOTAL,
                || at.to_string(),
                "min is above max, or max above 16 MiB",
            ),
            Check::Pattern { regex } => kind_ensure(
                crate::extract::compile_whole(regex).is_some(),
                || at.to_string(),
                "a regular expression of at most 256 bytes within the size limits",
            ),
            Check::OneOf { values } => kind_ensure(
                !values.is_empty()
                    && values.len() <= MAX_ONE_OF
                    && values.iter().all(|v| !v.is_empty() && v.len() <= 256)
                    && unique(values.iter().map(String::as_str)),
                || at.to_string(),
                "1 to 32 distinct values of 1 to 256 bytes",
            ),
            Check::Base32 { min_bits } => kind_ensure(
                (1..=8192).contains(min_bits),
                || at.to_string(),
                "min_bits from 1 to 8192",
            ),
            Check::Base64Key { bytes } => kind_ensure(
                (1..=1024).contains(bytes),
                || at.to_string(),
                "bytes from 1 to 1024",
            ),
            Check::Signoff { values, flag } => kind_ensure(
                !values.is_empty()
                    && values.len() <= MAX_ONE_OF
                    && is_token(flag)
                    && flag != checks::PLAIN_HTTP,
                || at.to_string(),
                "a sign-off names 1 to 32 values and a token flag (plain_http belongs to origin)",
            ),
            Check::Luhn {}
            | Check::Expiry {}
            | Check::Origin {}
            | Check::Host {}
            | Check::Email {}
            | Check::Date {}
            | Check::SshHostKey {} => Ok(()),
        }
    }

    fn check_shape(&self) -> Checked {
        let shape = &self.shape;
        kind_ensure(
            unique(shape.connections.iter().map(|c| c.name())),
            || "shape.connections".into(),
            "each connection once",
        )?;
        let pinned_with = |name: &str, check: fn(&Check) -> bool| {
            self.field(name)
                .is_some_and(|f| f.pinned && f.checks.iter().any(check))
        };
        let is_host = |c: &Check| matches!(c, Check::Host {});
        let is_port =
            |c: &Check| matches!(c, Check::Integer { min, max } if *min >= 1 && *max <= 65535);
        let protocol = shape.connections.iter().any(|c| c.is_protocol());
        kind_ensure(
            !protocol
                || (!self.free_fields && !matches!(shape.destinations, DestinationRule::Owner {})),
            || "shape.destinations".into(),
            "a protocol connection goes to pinned hosts only",
        )?;
        match &shape.login {
            None => kind_ensure(
                !protocol,
                || "shape.login".into(),
                "a kind with a protocol connection names its login fields",
            )?,
            Some(login) => {
                let secret = |name: &Option<String>| {
                    name.as_deref().is_none_or(|n| {
                        self.field(n)
                            .is_some_and(|f| f.disclosure == Disclosure::Secret)
                    })
                };
                kind_ensure(
                    protocol
                        && self.field(&login.user).is_some()
                        && secret(&login.password)
                        && secret(&login.key)
                        && secret(&login.token),
                    || "shape.login".into(),
                    "login names a field of the kind for the user and secret fields for the rest, for a protocol connection",
                )?;
            }
        }
        let ssh = shape.connections.contains(&ShapeConnection::Ssh);
        kind_ensure(
            match &shape.host_key {
                None => !ssh,
                Some(name) => ssh && pinned_with(name, |c| matches!(c, Check::SshHostKey {})),
            },
            || "shape.host_key".into(),
            "an SSH connection pins its host key in a pinned field with an ssh_host_key check; other kinds name none",
        )?;
        kind_ensure(
            shape
                .tls
                .as_deref()
                .is_none_or(|name| protocol && self.field(name).is_some_and(|f| f.pinned)),
            || "shape.tls".into(),
            "tls names a pinned field, for a protocol connection",
        )?;
        match &shape.destinations {
            DestinationRule::Owner {} => {}
            DestinationRule::Origin { field } => kind_ensure(
                !self.free_fields && pinned_with(field, |c| matches!(c, Check::Origin {})),
                || "shape.destinations".into(),
                "the origin is a pinned field with an origin check",
            )?,
            DestinationRule::Host { host, port } => kind_ensure(
                !self.free_fields && pinned_with(host, is_host) && pinned_with(port, is_port),
                || "shape.destinations".into(),
                "the host and port are pinned fields with host and port checks",
            )?,
            DestinationRule::Hosts { hosts } => kind_ensure(
                !self.free_fields
                    && !hosts.is_empty()
                    && unique(hosts.iter().map(|r| r.connection.name()))
                    && shape
                        .connections
                        .iter()
                        .all(|c| hosts.iter().any(|r| r.connection == *c))
                    && hosts.iter().all(|r| {
                        shape.connections.contains(&r.connection)
                            && pinned_with(&r.host, is_host)
                            && pinned_with(&r.port, is_port)
                    }),
                || "shape.destinations".into(),
                "one route per connection of the shape, each to pinned fields with host and port checks",
            )?,
        }
        self.check_browser_shape()?;
        for (i, name) in shape.captures.iter().enumerate() {
            let ok = if name == "*" {
                self.free_fields
            } else {
                self.field(name)
                    .is_some_and(|f| f.disclosure == Disclosure::Secret)
            };
            kind_ensure(
                ok,
                || format!("shape.captures[{i}]"),
                "a capture fills a secret field of the kind (* for free fields only)",
            )?;
        }
        kind_ensure(
            unique(shape.captures.iter().map(String::as_str)),
            || "shape.captures".into(),
            "each capture once",
        )
    }

    /// Checks the browser fills of the shape: present exactly when a browser connection is
    /// allowed; the origin a pinned origin field (the one the kind's HTTPS goes to, when it
    /// fixes one); 1 to 16 roles of distinct names and templates, each a template over the
    /// fields of the kind only.
    fn check_browser_shape(&self) -> Checked {
        let shape = &self.shape;
        let allowed = shape.connections.contains(&ShapeConnection::Browser);
        let Some(browser) = &shape.browser else {
            return kind_ensure(
                !allowed,
                || "shape.browser".into(),
                "a kind with a browser connection names its browser roles",
            );
        };
        kind_ensure(
            allowed && !self.free_fields,
            || "shape.browser".into(),
            "browser roles are for a kind with named fields and a browser connection",
        )?;
        let wanted = match &shape.destinations {
            DestinationRule::Origin { field } => Some(field),
            _ => None,
        };
        match &browser.origin {
            Some(name) => kind_ensure(
                self.field(name)
                    .is_some_and(|f| f.pinned && f.checks.contains(&Check::Origin {}))
                    && wanted.is_none_or(|w| w == name),
                || "shape.browser.origin".into(),
                "the browser origin is a pinned field with an origin check, the one the kind's destinations name",
            )?,
            None => kind_ensure(
                wanted.is_none(),
                || "shape.browser.origin".into(),
                "a kind whose destinations are a pinned origin fills pages at that origin only",
            )?,
        }
        kind_ensure(
            !browser.roles.is_empty()
                && browser.roles.len() <= crate::policy::MAX_FILL_FIELDS
                && unique(browser.roles.iter().map(|r| r.role.as_str()))
                && unique(browser.roles.iter().map(|r| r.template.as_str())),
            || "shape.browser.roles".into(),
            "1 to 16 roles of distinct names and templates",
        )?;
        for (i, role) in browser.roles.iter().enumerate() {
            let at = || format!("shape.browser.roles[{i}]");
            kind_ensure(is_token(&role.role), at, "a role is a token")?;
            let names_fields = crate::template::Template::parse(&role.template).is_ok_and(|t| {
                let names = t.names();
                !names.is_empty() && names.iter().all(|n| self.field(n).is_some())
            });
            kind_ensure(
                names_fields,
                at,
                "a role's template parses and reads fields of the kind only",
            )?;
        }
        Ok(())
    }

    /// Checks the rules of the schema.
    pub fn validate(&self) -> Result<()> {
        kind_ensure(
            is_token(&self.name),
            || "name".into(),
            "name is not a token",
        )?;
        kind_ensure(
            !self.description.is_empty() && self.description.len() <= MAX_DESCRIPTION,
            || "description".into(),
            "a description of 1 to 512 bytes",
        )?;
        if self.free_fields {
            kind_ensure(
                self.fields.is_empty(),
                || "fields".into(),
                "a kind with free fields lists none",
            )?;
        } else {
            kind_ensure(
                !self.fields.is_empty() && self.fields.len() <= MAX_KIND_FIELDS,
                || "fields".into(),
                "1 to 32 fields",
            )?;
        }
        kind_ensure(
            unique(self.fields.iter().map(|f| f.name.as_str())),
            || "fields".into(),
            "field names must be unique",
        )?;
        for (i, field) in self.fields.iter().enumerate() {
            let at = format!("fields[{i}]");
            kind_ensure(
                is_token(&field.name),
                || format!("{at}.name"),
                "name is not a token",
            )?;
            kind_ensure(
                !field.guessable || field.disclosure != Disclosure::Public,
                || at.clone(),
                "only a secret or masked field can be guessable",
            )?;
            kind_ensure(
                field.mask.is_some() == (field.disclosure == Disclosure::Masked),
                || at.clone(),
                "a masked field has a mask, and only a masked field",
            )?;
            kind_ensure(
                !field.pinned || field.disclosure == Disclosure::Public,
                || at.clone(),
                "a pinned field is public",
            )?;
            kind_ensure(
                field.checks.len() <= MAX_CHECKS,
                || format!("{at}.checks"),
                "at most 8 checks",
            )?;
            for (j, check) in field.checks.iter().enumerate() {
                self.check_check(&format!("{at}.checks[{j}]"), field, check)?;
            }
        }
        self.check_shape()
    }

    /// Checks one value of the field `name`: UTF-8 text when it is public or masked, then
    /// each check. `signoff` holds the owner's sign-offs, `now_ms` the clock (time checks are
    /// skipped without it), `other` the values of the other fields.
    pub fn check_value(
        &self,
        name: &str,
        value: &[u8],
        signoff: &[String],
        now_ms: Option<u64>,
        other: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<()> {
        let fail = |rule: &'static str| Error::FieldInvalid {
            field: name.to_string(),
            rule,
        };
        if self.free_fields {
            return Ok(());
        }
        let field = self
            .field(name)
            .ok_or_else(|| fail("the kind has no such field"))?;
        let text = core::str::from_utf8(value).ok();
        if field.disclosure != Disclosure::Secret && text.is_none() {
            return Err(fail("a public or masked value is UTF-8 text"));
        }
        for check in &field.checks {
            checks::run(check, value, signoff, now_ms, other).map_err(fail)?;
        }
        Ok(())
    }

    /// The canonical bytes a device signs.
    fn message(&self) -> Result<Vec<u8>> {
        canonical(KIND_DOMAIN, self)
    }
}

impl SignedKind {
    /// Verifies the signature under one of `devices` and the rules of the schema.
    pub fn verify_any(&self, devices: &[DevicePublicKey]) -> Result<&KindSchema> {
        let message = self.kind.message()?;
        if !devices
            .iter()
            .any(|d| d.verify(&message, &self.signature).is_ok())
        {
            return Err(Error::KindSignature);
        }
        self.kind.validate()?;
        Ok(&self.kind)
    }
}

impl DeviceKey {
    /// Signs a custom kind after checking its rules. Runs on the device. A kind may not take
    /// the name of a reviewed kind.
    pub fn sign_kind(&self, kind: KindSchema) -> Result<SignedKind> {
        kind.validate()?;
        if reviewed_kind(&kind.name).is_ok() {
            return Err(Error::KindInvalid {
                at: "name".into(),
                rule: "a custom kind takes the name of a reviewed kind",
            });
        }
        let message = kind.message()?;
        Ok(SignedKind {
            signature: self.sign(&message),
            kind,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    kinds: Vec<KindSchema>,
}

fn load_reviewed() -> Result<Vec<KindSchema>> {
    let catalog: Catalog = serde_json::from_str(ITEMS_JSON).map_err(|_| Error::KindInvalid {
        at: "items.json".into(),
        rule: "the reviewed kinds do not parse",
    })?;
    for (i, kind) in catalog.kinds.iter().enumerate() {
        kind.validate().map_err(|e| match e {
            Error::KindInvalid { at, rule } => Error::KindInvalid {
                at: format!("items.json kinds[{i}].{at}"),
                rule,
            },
            other => other,
        })?;
    }
    if !unique(catalog.kinds.iter().map(|k| k.name.as_str())) {
        return Err(Error::KindInvalid {
            at: "items.json".into(),
            rule: "kind names must be unique",
        });
    }
    Ok(catalog.kinds)
}

/// The reviewed kinds compiled into the node.
pub fn reviewed() -> Result<&'static [KindSchema]> {
    static KINDS: OnceLock<Result<Vec<KindSchema>>> = OnceLock::new();
    KINDS
        .get_or_init(load_reviewed)
        .as_deref()
        .map_err(Clone::clone)
}

/// The reviewed kind of this name.
pub fn reviewed_kind(name: &str) -> Result<&'static KindSchema> {
    reviewed()?
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| Error::KindInvalid {
            at: "item.kind".into(),
            rule: "no reviewed kind of this name, and no custom kind given",
        })
}

impl ItemBinding {
    /// A binding to the reviewed kind `kind`.
    pub fn reviewed(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            custom: None,
            pins: BTreeMap::new(),
            signoff: Vec::new(),
        }
    }

    /// A binding to a custom kind.
    pub fn custom(kind: SignedKind) -> Self {
        Self {
            kind: kind.kind.name.clone(),
            custom: Some(kind),
            pins: BTreeMap::new(),
            signoff: Vec::new(),
        }
    }

    /// The same binding with the value of a pinned field.
    #[must_use]
    pub fn pin(mut self, field: &str, value: &str) -> Self {
        self.pins.insert(field.to_string(), value.to_string());
        self
    }

    /// The same binding with a sign-off.
    #[must_use]
    pub fn sign_off(mut self, flag: &str) -> Self {
        self.signoff.push(flag.to_string());
        self
    }

    /// The schema of the kind. A custom kind is checked against its own rules here; its
    /// signature is checked by [`crate::policy::SignedPolicy::verify_any`].
    pub fn schema(&self) -> Result<&KindSchema> {
        match &self.custom {
            Some(custom) => {
                if reviewed_kind(&self.kind).is_ok() || reviewed_kind(&custom.kind.name).is_ok() {
                    return Err(Error::policy(
                        "item.custom",
                        "a custom kind takes the name of a reviewed kind",
                    ));
                }
                if custom.kind.name != self.kind {
                    return Err(Error::policy(
                        "item.custom",
                        "the custom kind has another name than the binding",
                    ));
                }
                custom.kind.validate()?;
                Ok(&custom.kind)
            }
            None => reviewed_kind(&self.kind),
        }
    }

    /// The destination the shape fixes for operations of `connection`, if it fixes one.
    fn destination(
        &self,
        kind: &KindSchema,
        connection: ShapeConnection,
    ) -> Result<Option<Destination>> {
        let pin = |name: &str| {
            self.pins.get(name).ok_or_else(|| {
                Error::policy(format!("item.pins.{name}"), "a pinned field has no value")
            })
        };
        let host_port = |host: &str, port: &str| -> Result<Option<Destination>> {
            let port: u16 = pin(port)?
                .parse()
                .map_err(|_| Error::policy(format!("item.pins.{port}"), "not a port"))?;
            Ok(Some(Destination::new(pin(host)?, port)))
        };
        match &kind.shape.destinations {
            DestinationRule::Owner {} => Ok(None),
            DestinationRule::Origin { field } => parse_origin(pin(field)?)
                .map(|o| Some(o.destination))
                .ok_or_else(|| Error::policy(format!("item.pins.{field}"), "not an exact origin")),
            DestinationRule::Host { host, port } => host_port(host, port),
            DestinationRule::Hosts { hosts } => {
                let route = hosts
                    .iter()
                    .find(|r| r.connection == connection)
                    .ok_or_else(|| Error::policy("item", "the kind routes no such connection"))?;
                host_port(&route.host, &route.port)
            }
        }
    }

    /// The origin of the item, for summaries: the pinned origin field (any kind), or the
    /// destination the shape fixes.
    pub fn origin(&self) -> Option<Origin> {
        let kind = self.schema().ok()?;
        if let Some(origin) = kind
            .fields
            .iter()
            .filter(|f| f.pinned && f.checks.contains(&Check::Origin {}))
            .find_map(|f| self.pins.get(&f.name).and_then(|v| parse_origin(v)))
        {
            return Some(origin);
        }
        kind.shape
            .connections
            .iter()
            .copied()
            .chain([ShapeConnection::None])
            .find_map(|c| self.destination(kind, c).ok().flatten())
            .map(|d| Origin {
                https: true,
                destination: d,
            })
    }
}

fn shape_fail(at: impl Into<String>, rule: &'static str) -> Checked {
    Err(Error::policy(at, rule))
}

fn shape_ensure(ok: bool, at: impl FnOnce() -> String, rule: &'static str) -> Checked {
    if ok { Ok(()) } else { shape_fail(at(), rule) }
}

/// Checks the fields of a typed policy against its kind: the same names, a secret or masked
/// kind field secret in the policy, guessable when the kind says so, required when the kind
/// requires it.
fn check_fields(policy: &Policy, kind: &KindSchema) -> Checked {
    if kind.free_fields {
        return Ok(());
    }
    for (i, field) in policy.fields.iter().enumerate() {
        let at = || format!("fields[{i}]");
        let Some(spec) = kind.field(&field.name) else {
            return shape_fail(at(), "the kind has no field of this name");
        };
        shape_ensure(
            field.secret || spec.disclosure == Disclosure::Public,
            at,
            "a secret or masked field of the kind is secret in the policy",
        )?;
        shape_ensure(
            field.guessable || !spec.guessable,
            at,
            "a guessable field of the kind is guessable in the policy",
        )?;
        shape_ensure(
            !field.optional || spec.optional,
            at,
            "a required field of the kind is required in the policy",
        )?;
    }
    for spec in kind.fields.iter().filter(|f| !f.optional) {
        shape_ensure(
            policy.fields.iter().any(|f| f.name == spec.name),
            || "fields".into(),
            "the policy lacks a required field of the kind",
        )?;
    }
    Ok(())
}

fn check_pins(policy: &Policy, binding: &ItemBinding, kind: &KindSchema) -> Checked {
    let pinned: Vec<&KindField> = kind
        .fields
        .iter()
        .filter(|f| f.pinned && policy.fields.iter().any(|p| p.name == f.name))
        .collect();
    for (name, value) in &binding.pins {
        let at = || format!("item.pins.{name}");
        shape_ensure(
            pinned.iter().any(|f| &f.name == name),
            at,
            "only a pinned field of the policy has a pin",
        )?;
        shape_ensure(value.len() <= MAX_PIN, at, "a pin of at most 4096 bytes")?;
        kind.check_value(name, value.as_bytes(), &binding.signoff, None, &|other| {
            binding.pins.get(other).map(|v| v.as_bytes().to_vec())
        })
        .map_err(|_| Error::policy(at(), "a pinned value fails its checks"))?;
    }
    for field in &pinned {
        shape_ensure(
            binding.pins.contains_key(&field.name),
            || format!("item.pins.{}", field.name),
            "a pinned field has no value",
        )?;
    }
    let flags = kind.signoff_flags();
    shape_ensure(
        binding.signoff.len() <= MAX_SIGNOFFS
            && binding.signoff.iter().all(|s| flags.contains(&s.as_str()))
            && unique(binding.signoff.iter().map(String::as_str)),
        || "item.signoff".into(),
        "each sign-off once, and only flags the checks of the kind name",
    )
}

/// The connection of an operation as a shape names it.
fn shape_connection(at: &str, operation: &Operation) -> Result<ShapeConnection> {
    let refuse = |rule| Err(Error::policy(at, rule));
    match operation.connection() {
        Some(Connection::Https) => Ok(ShapeConnection::Https),
        Some(Connection::Tls) => Ok(ShapeConnection::Tls),
        Some(Connection::Ssh) => Ok(ShapeConnection::Ssh),
        Some(Connection::Smtp) => Ok(ShapeConnection::Smtp),
        Some(Connection::Imap) => Ok(ShapeConnection::Imap),
        Some(Connection::Pop3) => Ok(ShapeConnection::Pop3),
        Some(Connection::Ftp) => Ok(ShapeConnection::Ftp),
        Some(Connection::Websocket) => refuse("a typed item has no WebSocket operation"),
        Some(
            Connection::Postgres
            | Connection::Redis
            | Connection::Mysql
            | Connection::Mqtt
            | Connection::Amqp
            | Connection::Amqp1,
        ) => refuse("a typed item has no database or queue connection yet"),
        Some(Connection::Udp) => refuse("a typed item has no UDP operation"),
        Some(Connection::Browser) => Ok(ShapeConnection::Browser),
        None => Ok(ShapeConnection::None),
    }
}

/// Checks the sign-in of a protocol operation of a typed item: each login member exactly the
/// field the kind names for it, and for SSH exactly the pinned host key, whole.
fn check_login(
    at: &str,
    open: &Open,
    kind: &KindSchema,
    pins: &BTreeMap<String, String>,
) -> Checked {
    let shape = &kind.shape;
    let Some(rule) = &shape.login else {
        return shape_fail(at, "the kind names no login");
    };
    let Some(login) = &open.login else {
        return shape_fail(format!("{at}.login"), "a protocol connection needs login");
    };
    let exactly = |given: Option<&str>, field: Option<&str>| match (given, field) {
        (None, _) => true,
        (Some(text), Some(field)) => text == format!("{{{{{field}}}}}"),
        (Some(_), None) => false,
    };
    shape_ensure(
        exactly(Some(&login.user), Some(&rule.user))
            && exactly(login.password.as_deref(), rule.password.as_deref())
            && exactly(login.key.as_deref(), rule.key.as_deref())
            && exactly(login.token.as_deref(), rule.token.as_deref())
            && login.answers.is_empty()
            && login.database.is_none()
            && login.client_id.is_none()
            && login.vhost.is_none(),
        || format!("{at}.login"),
        "each login member is exactly {{field}} of the field the kind names for it",
    )?;
    if let Some(field) = &shape.tls {
        let wanted = match pins.get(field).map(String::as_str) {
            Some("implicit") => Some(crate::policy::TlsMode::Implicit),
            Some("explicit") => Some(crate::policy::TlsMode::Starttls),
            _ => None,
        };
        shape_ensure(
            wanted.is_some_and(|w| open.tls.unwrap_or_default() == w),
            || format!("{at}.tls"),
            "the operation reaches TLS as the item's pinned mode says (implicit or explicit); a plain mode allows none",
        )?;
    }
    if let Some(field) = &shape.host_key {
        let pinned = pins.get(field);
        shape_ensure(
            pinned.is_some_and(|key| {
                crate::proto::ssh::HostKey::parse(key).is_some()
                    && open.host_keys.len() == 1
                    && open.host_keys.first() == Some(key)
            }),
            || format!("{at}.host_keys"),
            "an SSH operation of an item pins exactly the item's host key, a whole key",
        )?;
    }
    Ok(())
}

/// Checks a browser operation of a typed item: the endpoint hands the browser to the node
/// alone and the page is loaded again when it stays; the handshake carries none of the
/// item's fields; each fill is at the kind's origin (the pinned one, when the kind names it),
/// in the top frame unless the kind allows frames, and puts only the kind's role values,
/// each at most once.
fn check_browser(
    at: &str,
    operation: &Operation,
    kind: &KindSchema,
    pins: &BTreeMap<String, String>,
) -> Checked {
    let Some(browser) = &kind.shape.browser else {
        return shape_fail(at, "the kind names no browser roles");
    };
    let control = operation.open().and_then(|o| o.browser.as_ref());
    shape_ensure(
        control.is_some_and(|c| c.is_exclusive() && c.leave == crate::policy::Leave::Reload),
        || format!("{at}.steps[0].browser"),
        "a browser operation of an item needs the endpoint's exclusive grant and leave reload",
    )?;
    let origin = match &browser.origin {
        Some(field) => Some(pins.get(field).ok_or_else(|| {
            Error::policy(format!("item.pins.{field}"), "a pinned field has no value")
        })?),
        None => None,
    };
    for (i, step) in crate::policy::flow::walk_indexed(&operation.steps) {
        let at = format!("{at}.steps[{i}]");
        let Step::Send(send) = step else {
            continue;
        };
        let Some(fill) = &send.fill else {
            // The handshake: the caller's own credential for its browser at most.
            shape_ensure(
                send.inject.is_empty(),
                || format!("{at}.inject"),
                "the browser handshake of an item carries none of its fields",
            )?;
            continue;
        };
        let at = format!("{at}.fill");
        if let Some(origin) = origin {
            shape_ensure(
                &fill.origin == origin,
                || format!("{at}.origin"),
                "a fill of the item is at its pinned origin exactly",
            )?;
        }
        let mut frames = fill
            .fields
            .iter()
            .map(|f| f.frame.as_ref())
            .chain([fill.submit.frame.as_ref()]);
        shape_ensure(
            browser.frames || frames.all(|f| f.is_none()),
            || at.clone(),
            "the kind fills the top frame only",
        )?;
        for (j, field) in fill.fields.iter().enumerate() {
            shape_ensure(
                browser.roles.iter().any(|r| r.template == field.template)
                    && !fill
                        .fields
                        .iter()
                        .take(j)
                        .any(|f| f.template == field.template),
                || format!("{at}.fields[{j}].template"),
                "a fill of the item puts one of the kind's role values, each at most once",
            )?;
        }
    }
    Ok(())
}

/// A field of a typed fill as the owner writes it: a role of the kind and the element its
/// value goes into.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleField {
    /// The role, one of the kind's [`BrowserShape::roles`].
    pub role: String,
    /// A CSS selector, as for [`crate::policy::Element::selector`].
    pub selector: String,
    /// The frame origin, as for [`crate::policy::Element::frame`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
}

/// A typed browser fill as the owner writes it: roles and selectors, no templates.
/// [`ItemBinding::browser_fill`] makes the [`crate::policy::Fill`] the policy carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemFill {
    /// The page's origin: only for a kind without a browser origin (a card at a merchant);
    /// a login fills at its pinned origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The fields.
    pub fields: Vec<RoleField>,
    /// What submits.
    pub submit: crate::policy::Element,
    /// As [`crate::policy::Fill::navigate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub navigate: Option<String>,
    /// As [`crate::policy::Fill::wait_ms`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
}

impl ItemBinding {
    /// The fill of `fill` for an item of this binding: the origin from the pin when the kind
    /// names one, each value the template of its role. The policy that carries it passes
    /// [`check_policy`] when its `open` asks for the exclusive grant and `leave: reload`.
    pub fn browser_fill(&self, fill: &ItemFill) -> Result<crate::policy::Fill> {
        let kind = self.schema()?;
        let Some(browser) = &kind.shape.browser else {
            return Err(Error::policy("item", "the kind names no browser roles"));
        };
        let origin = match (&browser.origin, &fill.origin) {
            (Some(field), given) => {
                let pin = self.pins.get(field).ok_or_else(|| {
                    Error::policy(format!("item.pins.{field}"), "a pinned field has no value")
                })?;
                if given.as_ref().is_some_and(|g| g != pin) {
                    return Err(Error::policy(
                        "fill.origin",
                        "a fill of the item is at its pinned origin exactly",
                    ));
                }
                pin.clone()
            }
            (None, Some(given)) => given.clone(),
            (None, None) => {
                return Err(Error::policy(
                    "fill.origin",
                    "the kind leaves the page's origin to the owner: name it",
                ));
            }
        };
        let fields = fill
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let role = browser.role(&f.role).ok_or_else(|| {
                    Error::policy(
                        format!("fill.fields[{i}].role"),
                        "the kind has no such role",
                    )
                })?;
                Ok(crate::policy::FillField {
                    selector: f.selector.clone(),
                    frame: f.frame.clone(),
                    template: role.template.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(crate::policy::Fill {
            origin,
            navigate: fill.navigate.clone(),
            fields,
            submit: fill.submit.clone(),
            wait_ms: fill.wait_ms,
        })
    }
}

fn check_operation(
    at: &str,
    operation: &Operation,
    kind: &KindSchema,
    fixed: Option<&Destination>,
    pins: &BTreeMap<String, String>,
) -> Checked {
    let shape = &kind.shape;
    let connection = shape_connection(at, operation)?;
    shape_ensure(
        shape.connections.contains(&connection),
        || at.to_string(),
        "the kind does not allow this connection",
    )?;
    if connection.is_protocol()
        && let Some(open) = operation.open()
    {
        check_login(&format!("{at}.steps[0]"), open, kind, pins)?;
    }
    if connection == ShapeConnection::Browser {
        check_browser(at, operation, kind, pins)?;
    }
    for (i, step) in crate::policy::flow::walk_indexed(&operation.steps) {
        let at = format!("{at}.steps[{i}]");
        match step {
            Step::Open(open) => {
                for (j, d) in open.destinations.iter().enumerate() {
                    let at = || format!("{at}.destinations[{j}]");
                    shape_ensure(
                        shape.wildcards || !d.is_wildcard(),
                        at,
                        "the kind does not allow a wildcard destination",
                    )?;
                    if let Some(fixed) = fixed {
                        shape_ensure(
                            d == fixed,
                            at,
                            "a destination outside the item's pinned origin or host",
                        )?;
                    }
                }
                shape_ensure(
                    shape.identity || open.identity.is_none(),
                    || at.clone(),
                    "the kind does not allow a client certificate",
                )?;
            }
            Step::Receive(receive) => {
                for (j, capture) in receive.capture.iter().enumerate() {
                    if let Store::Field { name } = &capture.into {
                        shape_ensure(
                            shape.captures.iter().any(|c| c == "*" || c == name),
                            || format!("{at}.capture[{j}]"),
                            "the kind does not let a response fill this field",
                        )?;
                    }
                }
            }
            Step::Return(ret) => {
                if let Some(projection) = &ret.response {
                    let needs = match &projection.body {
                        Some(BodyProjection::All | BodyProjection::Stream) => Returns::All,
                        Some(BodyProjection::Json(_)) => Returns::Json,
                        None if projection.headers.is_empty() && projection.trailers.is_empty() => {
                            Returns::Status
                        }
                        None => Returns::Json,
                    };
                    shape_ensure(
                        needs <= shape.returns,
                        || format!("{at}.response"),
                        "the kind hands back less than this projection",
                    )?;
                }
                shape_ensure(
                    shape.relay || ret.relay.is_none(),
                    || format!("{at}.relay"),
                    "the kind does not relay the caller's exchanges",
                )?;
            }
            // A run step's origin is one of the connection's destinations, checked above.
            Step::Send(_)
            | Step::Compute(_)
            | Step::Run(_)
            | Step::Repeat(_)
            | Step::If(_)
            | Step::Await(_) => {}
        }
    }
    Ok(())
}

/// Checks that a typed policy stays within the shape of its kind: its fields, pins and
/// sign-offs, and for each operation the connection, destinations, client certificate,
/// captures into fields and what goes back. The node runs it on every policy it verifies, so a
/// typed item cannot carry a wider policy than its kind.
pub fn check_policy(policy: &Policy, binding: &ItemBinding) -> Result<()> {
    let kind = binding.schema()?;
    check_fields(policy, kind)?;
    check_pins(policy, binding, kind)?;
    for (i, operation) in policy.operations.iter().enumerate() {
        let at = format!("operations[{i}]");
        let connection = shape_connection(&at, operation)?;
        // A connection the kind does not allow is refused below, whatever it would route to.
        // A browser connection goes to the CDP endpoint the owner signs; its pages are held
        // to the kind's browser origin by the fills.
        let fixed = if kind.shape.connections.contains(&connection)
            && connection != ShapeConnection::Browser
        {
            binding.destination(kind, connection)?
        } else {
            None
        };
        check_operation(&at, operation, kind, fixed.as_ref(), &binding.pins)?;
    }
    Ok(())
}

/// Checks the values of a record against the kind of its policy: each check, and each pinned
/// field equal to its pin. A policy without a kind passes. `now_ms` is the clock; without it
/// the checks that need one (a card's expiry) are skipped.
pub fn check_values(policy: &Policy, fields: &Fields, now_ms: Option<u64>) -> Result<()> {
    let Some(binding) = &policy.item else {
        return Ok(());
    };
    let kind = binding.schema()?;
    if kind.free_fields {
        return Ok(());
    }
    let other = |name: &str| fields.get(name).map(<[u8]>::to_vec);
    for (name, value) in fields.values() {
        kind.check_value(name, value, &binding.signoff, now_ms, &other)?;
        if let Some(pin) = binding.pins.get(name)
            && pin.as_bytes() != value
        {
            return Err(Error::FieldInvalid {
                field: name.to_string(),
                rule: "the value differs from its pin in the policy",
            });
        }
    }
    Ok(())
}

/// What a caller may learn of the record: its public fields (public in the kind and in the
/// policy) and the projections of its masked ones. Never a secret field.
pub fn describe(policy: &Policy, fields: &Fields) -> Result<Description> {
    let binding = policy.item.as_ref().ok_or(Error::NotAnItem)?;
    let kind = binding.schema()?;
    let mut out = Vec::new();
    for spec in &kind.fields {
        let Some(value) = fields.get(&spec.name) else {
            continue;
        };
        let secret_in_policy = policy.is_secret(&spec.name);
        let value = match (spec.disclosure, spec.mask) {
            (Disclosure::Public, _) if !secret_in_policy => {
                core::str::from_utf8(value).map(str::to_string).ok()
            }
            (Disclosure::Masked, Some(m)) => Some(mask::apply(m, value)),
            _ => None,
        };
        if let Some(value) = value {
            out.push(Described {
                name: spec.name.clone(),
                disclosure: spec.disclosure,
                value,
            });
        }
    }
    Ok(Description {
        kind: kind.name.clone(),
        fields: out,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests;
