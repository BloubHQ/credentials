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
//! does.
//!
//! Every value carries a taint: it is tainted when it holds a secret in a form that can be
//! turned back. Encodings keep the taint; one-way functions (hashes, MACs, signatures, TOTP)
//! drop it; an encryption drops it only when its key is itself secret. A request may carry
//! tainted values to the destinations of its operation; a value handed back to the caller must
//! be untainted, which [`Template::tainted`] decides before a policy is signed.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::fields::Fields;
use crate::{Error, Result, totp};

/// Longest template, in bytes.
pub const MAX_TEMPLATE: usize = 8192;
const MAX_DEPTH: usize = 24;
const MAX_NODES: usize = 512;
/// Most PBKDF2 iterations a template may ask for.
pub const MAX_PBKDF2_ROUNDS: u64 = 1_000_000;

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

    /// True when a derivation may read the variable.
    pub fn in_derive(self) -> bool {
        matches!(self, Var::Input | Var::Unix | Var::UnixMs | Var::Nonce)
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
    B64Decode = "b64decode"(1, 1): "Base64 decoding (any alphabet, padding optional).",
    B32Decode = "b32decode"(1, 1): "Base32 decoding (RFC 4648; case, spaces and padding ignored).",
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
    Xor = "xor"(2, 2): "`xor(a, b)` of two values of one length.",
    Md5 = "md5"(1, 1): "MD5 digest, for protocols that require it (one-way).",
    Sha1 = "sha1"(1, 1): "SHA-1 digest (one-way).",
    Sha256 = "sha256"(1, 1): "SHA-256 digest (one-way).",
    Sha512 = "sha512"(1, 1): "SHA-512 digest (one-way).",
    Keccak256 = "keccak256"(1, 1): "Keccak-256 digest as Ethereum uses it (one-way).",
    HmacSha1 = "hmac_sha1"(2, 2): "`hmac_sha1(key, message)` (one-way).",
    HmacSha256 = "hmac_sha256"(2, 2): "`hmac_sha256(key, message)` (one-way).",
    HmacSha512 = "hmac_sha512"(2, 2): "`hmac_sha512(key, message)` (one-way).",
    Pbkdf2Sha256 = "pbkdf2_sha256"(3, 4): "`pbkdf2_sha256(password, salt, rounds[, length])`, 32 bytes by default (one-way).",
    Totp = "totp"(1, 3): "`totp(seed[, digits[, period]])`, 6 digits and 30 s by default (one-way).",
    Ed25519Sign = "ed25519_sign"(2, 2): "`ed25519_sign(key, message)`; key raw 32 bytes or PKCS#8 DER (one-way).",
    P256Sign = "p256_sign"(2, 2): "ECDSA P-256 SHA-256, `r || s`; key raw 32 bytes or PKCS#8 DER (one-way).",
    P256SignDer = "p256_sign_der"(2, 2): "ECDSA P-256 SHA-256, DER (one-way).",
    P384Sign = "p384_sign"(2, 2): "ECDSA P-384 SHA-384, `r || s`; key PKCS#8 DER (one-way).",
    K256Sign = "k256_sign"(2, 2): "ECDSA secp256k1 SHA-256, `r || s` with low s; key raw 32 bytes or PKCS#8 DER (one-way).",
    K256SignRecoverable = "k256_sign_recoverable"(2, 2): "`k256_sign_recoverable(key, digest32)`: `r || s || v`, v = 27 + recovery id (one-way).",
    RsaSignPkcs1Sha256 = "rsa_sign_pkcs1_sha256"(2, 2): "RSASSA-PKCS1-v1_5 SHA-256 (RS256); key PKCS#8 or PKCS#1 DER (one-way).",
    RsaSignPssSha256 = "rsa_sign_pss_sha256"(2, 2): "RSASSA-PSS SHA-256 (PS256); key PKCS#8 or PKCS#1 DER (one-way).",
    AesGcmEncrypt = "aes_gcm_encrypt"(3, 4): "`aes_gcm_encrypt(key, nonce12, message[, aad])`: ciphertext and tag; key 16 or 32 bytes.",
    AesCbcEncrypt = "aes_cbc_encrypt"(3, 3): "`aes_cbc_encrypt(key, iv16, message)` with PKCS#7 padding; key 16, 24 or 32 bytes.",
}

impl Func {
    fn parse(name: &str) -> Option<Self> {
        Func::ALL.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
    }

    /// The taint of the output, from the taints of the arguments.
    pub fn taint(self, args: &[bool]) -> bool {
        let at = |i: usize| args.get(i).copied().unwrap_or(false);
        match self {
            Func::Len
            | Func::Md5
            | Func::Sha1
            | Func::Sha256
            | Func::Sha512
            | Func::Keccak256
            | Func::HmacSha1
            | Func::HmacSha256
            | Func::HmacSha512
            | Func::Pbkdf2Sha256
            | Func::Totp
            | Func::Ed25519Sign
            | Func::P256Sign
            | Func::P256SignDer
            | Func::P384Sign
            | Func::K256Sign
            | Func::K256SignRecoverable
            | Func::RsaSignPkcs1Sha256
            | Func::RsaSignPssSha256 => false,
            // Whoever knows the key reads the message back.
            Func::AesGcmEncrypt | Func::AesCbcEncrypt => at(2) && !at(0),
            _ => args.iter().any(|t| *t),
        }
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

fn lex(src: &str) -> Result<Vec<Tok>> {
    let mut toks = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {}
            '(' => toks.push(Tok::LParen),
            ')' => toks.push(Tok::RParen),
            ',' => toks.push(Tok::Comma),
            '+' => toks.push(Tok::Plus),
            '"' => {
                let mut s = String::new();
                loop {
                    match chars.next().ok_or(Error::TemplateInvalid)? {
                        '"' => break,
                        '\\' => s.push(match chars.next().ok_or(Error::TemplateInvalid)? {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '0' => '\0',
                            '"' => '"',
                            '\\' => '\\',
                            _ => return Err(Error::TemplateInvalid),
                        }),
                        other => s.push(other),
                    }
                }
                toks.push(Tok::Str(s.into_bytes()));
            }
            '$' | 'a'..='z' | 'A'..='Z' | '_' => {
                let mut name = String::new();
                if c != '$' {
                    name.push(c);
                }
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_alphanumeric() || n == '_' {
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
            _ => return Err(Error::TemplateInvalid),
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

    fn next(&mut self) -> Result<Tok> {
        let tok = self
            .toks
            .get(self.pos)
            .cloned()
            .ok_or(Error::TemplateInvalid)?;
        self.pos += 1;
        Ok(tok)
    }

    fn expr(&mut self, depth: usize) -> Result<Expr> {
        let mut parts = vec![self.term(depth)?];
        while self.peek() == Some(&Tok::Plus) {
            self.pos += 1;
            parts.push(self.term(depth)?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expr::Concat(parts)
        })
    }

    fn term(&mut self, depth: usize) -> Result<Expr> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(Error::TemplateInvalid);
        }
        match self.next()? {
            Tok::Str(s) => Ok(Expr::Lit(s)),
            Tok::Var(name) => Var::parse(&name)
                .map(Expr::Var)
                .ok_or(Error::TemplateInvalid),
            Tok::Ident(name) if self.peek() == Some(&Tok::LParen) => {
                let func = Func::parse(&name).ok_or(Error::TemplateInvalid)?;
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
                    return Err(Error::TemplateInvalid);
                }
                let (min, max) = func.arity();
                if args.len() < min || args.len() > max {
                    return Err(Error::TemplateInvalid);
                }
                Ok(Expr::Call(func, args))
            }
            Tok::Ident(name) if crate::policy::is_token(&name) => Ok(Expr::Name(name)),
            _ => Err(Error::TemplateInvalid),
        }
    }
}

fn walk<'e>(expr: &'e Expr, visit: &mut dyn FnMut(&'e Expr)) {
    visit(expr);
    if let Expr::Call(_, args) | Expr::Concat(args) = expr {
        args.iter().for_each(|a| walk(a, visit));
    }
}

fn expr_tainted(expr: &Expr, secret: &dyn Fn(&str) -> bool) -> bool {
    match expr {
        Expr::Lit(_) | Expr::Var(_) => false,
        Expr::Name(name) => secret(name),
        Expr::Call(func, args) => {
            let taints: Vec<bool> = args.iter().map(|a| expr_tainted(a, secret)).collect();
            func.taint(&taints)
        }
        Expr::Concat(parts) => parts.iter().any(|p| expr_tainted(p, secret)),
    }
}

impl Template {
    /// Parses a template. `}}` cannot appear inside a string literal of an expression.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_TEMPLATE {
            return Err(Error::TemplateInvalid);
        }
        let mut segments = Vec::new();
        let mut rest = text;
        let mut nodes = 0;
        while let Some(open) = rest.find("{{") {
            let (before, after) = rest.split_at(open);
            if !before.is_empty() {
                segments.push(Segment::Text(before.as_bytes().to_vec()));
            }
            let after = after.get(2..).ok_or(Error::TemplateInvalid)?;
            let close = after.find("}}").ok_or(Error::TemplateInvalid)?;
            let (inner, tail) = after.split_at(close);
            let mut parser = Parser {
                toks: lex(inner)?,
                pos: 0,
                nodes,
            };
            let expr = parser.expr(0)?;
            if parser.pos != parser.toks.len() {
                return Err(Error::TemplateInvalid);
            }
            nodes = parser.nodes;
            segments.push(Segment::Expr(expr));
            rest = tail.get(2..).ok_or(Error::TemplateInvalid)?;
        }
        if rest.contains("}}") {
            return Err(Error::TemplateInvalid);
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

    /// True when the output can give a secret back. `secret` says which names are secret.
    pub fn tainted(&self, secret: &dyn Fn(&str) -> bool) -> bool {
        self.exprs().any(|e| expr_tainted(e, secret))
    }

    pub(crate) fn render(&self, ctx: &Context<'_>) -> Result<Bytes> {
        let mut parts = Vec::with_capacity(self.segments.len());
        for segment in &self.segments {
            parts.push(match segment {
                Segment::Text(t) => Zeroizing::new(t.clone()),
                Segment::Expr(e) => eval(e, ctx)?,
            });
        }
        let mut out = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
        parts.iter().for_each(|p| out.extend_from_slice(p));
        Ok(out)
    }
}

/// Values captured by earlier steps of an operation.
pub(crate) type Temps = HashMap<String, Zeroizing<Vec<u8>>>;

/// What a rendering reads.
pub(crate) struct Context<'a> {
    pub fields: &'a Fields,
    pub temps: &'a Temps,
    pub vars: HashMap<Var, Vec<u8>>,
    pub unix: u64,
}

pub(crate) type Bytes = Zeroizing<Vec<u8>>;

fn eval(expr: &Expr, ctx: &Context<'_>) -> Result<Bytes> {
    Ok(match expr {
        Expr::Lit(b) => Zeroizing::new(b.clone()),
        Expr::Name(name) => {
            let value = ctx
                .fields
                .get(name)
                .or_else(|| ctx.temps.get(name).map(|v| v.as_slice()))
                .ok_or(Error::FieldMissing)?;
            Zeroizing::new(value.to_vec())
        }
        Expr::Var(v) => Zeroizing::new(ctx.vars.get(v).ok_or(Error::TemplateInvalid)?.clone()),
        Expr::Concat(parts) => {
            let values = parts
                .iter()
                .map(|p| eval(p, ctx))
                .collect::<Result<Vec<_>>>()?;
            let mut out = Zeroizing::new(Vec::with_capacity(values.iter().map(|v| v.len()).sum()));
            values.iter().for_each(|v| out.extend_from_slice(v));
            out
        }
        Expr::Call(func, args) => {
            let args = args
                .iter()
                .map(|a| eval(a, ctx))
                .collect::<Result<Vec<_>>>()?;
            call(*func, &args, ctx.unix)?
        }
    })
}

// ---- primitives ----

const HEX: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn b64<E: Engine>(engine: &E, input: &[u8]) -> Result<Bytes> {
    let len = base64::encoded_len(input.len(), true).ok_or(Error::Encoding)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let written = engine
        .encode_slice(input, out.as_mut_slice())
        .map_err(|_| Error::Encoding)?;
    out.truncate(written);
    Ok(out)
}

pub(crate) fn pct(input: &[u8]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 3));
    for &b in input {
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.extend(HEX_UPPER.get(usize::from(b >> 4)));
            out.extend(HEX_UPPER.get(usize::from(b & 0x0f)));
        }
    }
    out
}

fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Encoding),
    }
}

fn pct_decode(input: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut iter = input.iter();
    while let Some(&b) = iter.next() {
        if b == b'%' {
            let hi = hex_digit(*iter.next().ok_or(Error::Encoding)?)?;
            let lo = hex_digit(*iter.next().ok_or(Error::Encoding)?)?;
            out.push(hi * 16 + lo);
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

pub(crate) fn json_escape(input: &[u8]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() + 16));
    for &b in input {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.extend(HEX.get(usize::from(b >> 4)));
                out.extend(HEX.get(usize::from(b & 0x0f)));
            }
            _ => out.push(b),
        }
    }
    out
}

pub(crate) fn hex(input: &[u8]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 2));
    for &b in input {
        out.extend(HEX.get(usize::from(b >> 4)));
        out.extend(HEX.get(usize::from(b & 0x0f)));
    }
    out
}

fn hex_decode(input: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() / 2));
    for pair in input.chunks(2) {
        let [hi, lo] = pair else {
            return Err(Error::Encoding);
        };
        out.push(hex_digit(*hi)? * 16 + hex_digit(*lo)?);
    }
    Ok(out)
}

fn b32_decode(input: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u64, 0u32);
    for &c in input {
        let v = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            b'=' | b' ' | b'-' => continue,
            _ => return Err(Error::Encoding),
        };
        buffer = ((buffer << 5) | u64::from(v)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| Error::Encoding)?);
        }
    }
    Ok(out)
}

fn b64_decode(input: &[u8]) -> Result<Bytes> {
    let text: Bytes = Zeroizing::new(
        input
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect(),
    );
    let url = text.iter().any(|b| *b == b'-' || *b == b'_');
    let padded = text.ends_with(b"=");
    let result = match (url, padded) {
        (false, true) => STANDARD.decode(text.as_slice()),
        (false, false) => STANDARD_NO_PAD.decode(text.as_slice()),
        (true, true) => URL_SAFE.decode(text.as_slice()),
        (true, false) => URL_SAFE_NO_PAD.decode(text.as_slice()),
    };
    result.map(Zeroizing::new).map_err(|_| Error::Encoding)
}

/// The base64 body between the first `-----BEGIN ` line and its `-----END ` line, whatever
/// the label.
fn pem_body(input: &[u8]) -> Result<Bytes> {
    let text = core::str::from_utf8(input).map_err(|_| Error::Encoding)?;
    let mut lines = text.lines().map(str::trim);
    lines
        .by_ref()
        .find(|l| l.starts_with("-----BEGIN ") && l.ends_with("-----"))
        .ok_or(Error::Encoding)?;
    let mut body = Zeroizing::new(Vec::with_capacity(input.len()));
    for line in lines {
        if line.starts_with("-----END ") {
            return b64_decode(&body);
        }
        if !line.contains(':') {
            body.extend_from_slice(line.as_bytes());
        }
    }
    Err(Error::Encoding)
}

fn replace(text: &[u8], from: &[u8], to: &[u8]) -> Result<Bytes> {
    if from.is_empty() {
        return Err(Error::TemplateInvalid);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut rest = text;
    while !rest.is_empty() {
        if rest.starts_with(from) {
            out.extend_from_slice(to);
            rest = rest.get(from.len()..).unwrap_or_default();
        } else {
            out.extend(rest.first());
            rest = rest.get(1..).unwrap_or_default();
        }
    }
    Ok(out)
}

/// The JSON object `object` with the string member `key: value` added at its end. The object
/// must not have that member; an empty object text is `{}`.
pub(crate) fn json_set(object: &[u8], key: &[u8], value: &[u8]) -> Result<Bytes> {
    let parsed: serde_json::Map<String, serde_json::Value> = if object.trim_ascii().is_empty() {
        serde_json::Map::new()
    } else {
        serde_json::from_slice(object).map_err(|_| Error::RequestInvalid)?
    };
    let key_text = core::str::from_utf8(key).map_err(|_| Error::Encoding)?;
    if parsed.contains_key(key_text) {
        return Err(Error::RequestInvalid);
    }
    let trimmed = object.trim_ascii();
    let open: &[u8] = if trimmed.is_empty() {
        b"{"
    } else {
        trimmed.strip_suffix(b"}").ok_or(Error::RequestInvalid)?
    };
    let escaped_key = json_escape(key);
    let escaped = json_escape(value);
    let mut out = Zeroizing::new(Vec::with_capacity(
        open.len() + escaped_key.len() + escaped.len() + 8,
    ));
    out.extend_from_slice(open);
    if !parsed.is_empty() {
        out.push(b',');
    }
    out.push(b'"');
    out.extend_from_slice(&escaped_key);
    out.extend_from_slice(b"\":\"");
    out.extend_from_slice(&escaped);
    out.extend_from_slice(b"\"}");
    Ok(out)
}

fn canonical_query(query: &[u8]) -> Result<Bytes> {
    let mut pairs: Vec<(Bytes, Bytes)> = Vec::new();
    for part in query.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        let mut halves = part.splitn(2, |b| *b == b'=');
        let name = halves.next().unwrap_or_default();
        let value = halves.next().unwrap_or_default();
        pairs.push((pct(&pct_decode(name)?), pct(&pct_decode(value)?)));
    }
    pairs.sort_by(|a, b| (a.0.as_slice(), a.1.as_slice()).cmp(&(b.0.as_slice(), b.1.as_slice())));
    let mut out = Zeroizing::new(Vec::with_capacity(query.len() * 3));
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        out.extend_from_slice(name);
        out.push(b'=');
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Year, month and day of a count of days since 1970-01-01 (proleptic Gregorian).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn time_format(unix: &[u8], format: &[u8]) -> Result<Bytes> {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds: i64 = core::str::from_utf8(unix)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(Error::TemplateInvalid)?;
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil(days);
    let weekday = usize::try_from(days.rem_euclid(7)).map_err(|_| Error::Encoding)?;
    let month_index = usize::try_from(month - 1).map_err(|_| Error::Encoding)?;
    let mut out = String::new();
    let mut chars = core::str::from_utf8(format)
        .map_err(|_| Error::TemplateInvalid)?
        .chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next().ok_or(Error::TemplateInvalid)? {
            'Y' => out.push_str(&format!("{year:04}")),
            'm' => out.push_str(&format!("{month:02}")),
            'd' => out.push_str(&format!("{day:02}")),
            'H' => out.push_str(&format!("{:02}", of_day / 3600)),
            'M' => out.push_str(&format!("{:02}", of_day / 60 % 60)),
            'S' => out.push_str(&format!("{:02}", of_day % 60)),
            'a' => out.push_str(DAYS.get(weekday).ok_or(Error::Encoding)?),
            'b' => out.push_str(MONTHS.get(month_index).ok_or(Error::Encoding)?),
            's' => out.push_str(&seconds.to_string()),
            '%' => out.push('%'),
            _ => return Err(Error::TemplateInvalid),
        }
    }
    Ok(Zeroizing::new(out.into_bytes()))
}

fn arg(args: &[Bytes], i: usize) -> Result<&[u8]> {
    args.get(i)
        .map(|a| a.as_slice())
        .ok_or(Error::TemplateInvalid)
}

fn number(args: &[Bytes], i: usize, default: u64) -> Result<u64> {
    match args.get(i) {
        None => Ok(default),
        Some(a) => core::str::from_utf8(a)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::TemplateInvalid),
    }
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Result<Bytes> {
    let mut mac = <M as Mac>::new_from_slice(key).map_err(|_| Error::KeyInvalid)?;
    mac.update(message);
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

fn ed25519_key(bytes: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    if let Ok(seed) = <[u8; 32]>::try_from(bytes) {
        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
    }
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::KeyInvalid)
}

fn p256_key(bytes: &[u8]) -> Result<p256::ecdsa::SigningKey> {
    if bytes.len() == 32 {
        return p256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| Error::KeyInvalid);
    }
    use p256::pkcs8::DecodePrivateKey;
    p256::ecdsa::SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::KeyInvalid)
}

fn k256_key(bytes: &[u8]) -> Result<k256::ecdsa::SigningKey> {
    if bytes.len() == 32 {
        return k256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| Error::KeyInvalid);
    }
    use k256::pkcs8::DecodePrivateKey;
    k256::ecdsa::SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::KeyInvalid)
}

fn rsa_sign(key: &[u8], message: &[u8], pss: bool) -> Result<Bytes> {
    use ring::signature::{RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaKeyPair};
    let pair = RsaKeyPair::from_pkcs8(key)
        .or_else(|_| RsaKeyPair::from_der(key))
        .map_err(|_| Error::KeyInvalid)?;
    let mut out = Zeroizing::new(vec![0u8; pair.public().modulus_len()]);
    let rng = ring::rand::SystemRandom::new();
    let padding: &'static dyn ring::signature::RsaEncoding = if pss {
        &RSA_PSS_SHA256
    } else {
        &RSA_PKCS1_SHA256
    };
    pair.sign(padding, &rng, message, &mut out)
        .map_err(|_| Error::KeyInvalid)?;
    Ok(out)
}

fn p384_sign(key: &[u8], message: &[u8]) -> Result<Bytes> {
    use ring::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, key, &rng)
        .map_err(|_| Error::KeyInvalid)?;
    let signature = pair.sign(&rng, message).map_err(|_| Error::KeyInvalid)?;
    Ok(Zeroizing::new(signature.as_ref().to_vec()))
}

fn aes_gcm(key: &[u8], nonce: &[u8], message: &[u8], aad: &[u8]) -> Result<Bytes> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
    if nonce.len() != 12 {
        return Err(Error::KeyInvalid);
    }
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: message, aad };
    let out = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt(nonce, payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt(nonce, payload),
        _ => return Err(Error::KeyInvalid),
    };
    out.map(Zeroizing::new).map_err(|_| Error::Encoding)
}

fn aes_cbc(key: &[u8], iv: &[u8], message: &[u8]) -> Result<Bytes> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    let out = match key.len() {
        16 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt_padded_vec_mut::<Pkcs7>(message),
        24 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, iv)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt_padded_vec_mut::<Pkcs7>(message),
        32 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt_padded_vec_mut::<Pkcs7>(message),
        _ => return Err(Error::KeyInvalid),
    };
    Ok(Zeroizing::new(out))
}

fn big_endian(text: &[u8], bytes: usize) -> Result<Bytes> {
    let value: u64 = core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(Error::TemplateInvalid)?;
    let all = value.to_be_bytes();
    let (high, low) = all.split_at(8 - bytes);
    if high.iter().any(|b| *b != 0) {
        return Err(Error::TemplateInvalid);
    }
    Ok(Zeroizing::new(low.to_vec()))
}

fn call(func: Func, args: &[Bytes], unix: u64) -> Result<Bytes> {
    let a = arg(args, 0)?;
    Ok(match func {
        Func::B64 => b64(&STANDARD, a)?,
        Func::B64Raw => b64(&STANDARD_NO_PAD, a)?,
        Func::B64Url => b64(&URL_SAFE, a)?,
        Func::B64UrlRaw => b64(&URL_SAFE_NO_PAD, a)?,
        Func::B64Decode => b64_decode(a)?,
        Func::B32Decode => b32_decode(a)?,
        Func::Hex => hex(a),
        Func::HexDecode => hex_decode(a)?,
        Func::Pct => pct(a),
        Func::PctDecode => pct_decode(a)?,
        Func::Json => json_escape(a),
        Func::Upper => Zeroizing::new(a.to_ascii_uppercase()),
        Func::Lower => Zeroizing::new(a.to_ascii_lowercase()),
        Func::Trim => Zeroizing::new(a.trim_ascii().to_vec()),
        Func::Replace => replace(a, arg(args, 1)?, arg(args, 2)?)?,
        Func::Pem => pem_body(a)?,
        Func::JsonSet => json_set(a, arg(args, 1)?, arg(args, 2)?)?,
        Func::CanonicalQuery => canonical_query(a)?,
        Func::Time => time_format(a, arg(args, 1)?)?,
        Func::Len => Zeroizing::new(a.len().to_string().into_bytes()),
        Func::Be16 => big_endian(a, 2)?,
        Func::Be32 => big_endian(a, 4)?,
        Func::Xor => {
            let b = arg(args, 1)?;
            if a.len() != b.len() {
                return Err(Error::Encoding);
            }
            Zeroizing::new(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
        }
        Func::Md5 => Zeroizing::new(md5::Md5::digest(a).to_vec()),
        Func::Sha1 => Zeroizing::new(Sha1::digest(a).to_vec()),
        Func::Sha256 => Zeroizing::new(Sha256::digest(a).to_vec()),
        Func::Sha512 => Zeroizing::new(Sha512::digest(a).to_vec()),
        Func::Keccak256 => Zeroizing::new(sha3::Keccak256::digest(a).to_vec()),
        Func::HmacSha1 => mac::<Hmac<Sha1>>(a, arg(args, 1)?)?,
        Func::HmacSha256 => mac::<Hmac<Sha256>>(a, arg(args, 1)?)?,
        Func::HmacSha512 => mac::<Hmac<Sha512>>(a, arg(args, 1)?)?,
        Func::Pbkdf2Sha256 => {
            let rounds = number(args, 2, 0)?;
            let length =
                usize::try_from(number(args, 3, 32)?).map_err(|_| Error::TemplateInvalid)?;
            if rounds == 0 || rounds > MAX_PBKDF2_ROUNDS || !(1..=64).contains(&length) {
                return Err(Error::TemplateInvalid);
            }
            let mut out = Zeroizing::new(vec![0u8; length]);
            let rounds = u32::try_from(rounds).map_err(|_| Error::TemplateInvalid)?;
            pbkdf2::pbkdf2_hmac::<Sha256>(a, arg(args, 1)?, rounds, &mut out);
            out
        }
        Func::Totp => {
            let digits = u32::try_from(number(args, 1, 6)?).map_err(|_| Error::TemplateInvalid)?;
            let period = number(args, 2, 30)?;
            let code = totp::code(a, unix, digits, period)?;
            let width = usize::try_from(digits).map_err(|_| Error::TemplateInvalid)?;
            Zeroizing::new(format!("{code:0width$}").into_bytes())
        }
        Func::Ed25519Sign => {
            Zeroizing::new(ed25519_key(a)?.sign(arg(args, 1)?).to_bytes().to_vec())
        }
        Func::P256Sign | Func::P256SignDer => {
            use p256::ecdsa::signature::Signer as _;
            let signature: p256::ecdsa::Signature = p256_key(a)?.sign(arg(args, 1)?);
            Zeroizing::new(if func == Func::P256Sign {
                signature.to_bytes().to_vec()
            } else {
                signature.to_der().as_bytes().to_vec()
            })
        }
        Func::P384Sign => p384_sign(a, arg(args, 1)?)?,
        Func::K256Sign => {
            use k256::ecdsa::signature::Signer as _;
            let signature: k256::ecdsa::Signature = k256_key(a)?.sign(arg(args, 1)?);
            Zeroizing::new(signature.to_bytes().to_vec())
        }
        Func::K256SignRecoverable => {
            let digest = arg(args, 1)?;
            if digest.len() != 32 {
                return Err(Error::TemplateInvalid);
            }
            let (signature, id) = k256_key(a)?
                .sign_prehash_recoverable(digest)
                .map_err(|_| Error::KeyInvalid)?;
            let mut out = Zeroizing::new(signature.to_bytes().to_vec());
            out.push(27 + id.to_byte());
            out
        }
        Func::RsaSignPkcs1Sha256 => rsa_sign(a, arg(args, 1)?, false)?,
        Func::RsaSignPssSha256 => rsa_sign(a, arg(args, 1)?, true)?,
        Func::AesGcmEncrypt => {
            let aad = args.get(3).map_or(&[][..], |v| v.as_slice());
            aes_gcm(a, arg(args, 1)?, arg(args, 2)?, aad)?
        }
        Func::AesCbcEncrypt => aes_cbc(a, arg(args, 1)?, arg(args, 2)?)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn render(text: &str, fields: &Fields) -> Vec<u8> {
        let temps = Temps::new();
        let ctx = Context {
            fields,
            temps: &temps,
            vars: HashMap::new(),
            unix: 59,
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
        let cases: [(&str, &[u8]); 13] = [
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
            (
                r#"{{ time("784111777", "%a, %d %b %Y %H:%M:%S GMT") }}"#,
                b"Sun, 06 Nov 1994 08:49:37 GMT",
            ),
            (r#"{{ time("951782400", "%Y-%m-%d") }}"#, b"2000-02-29"),
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
            "a }} b",
            "{{ \"x }}",
        ] {
            assert!(Template::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn taint_follows_reversible_functions_only() {
        let secret = |n: &str| n == "key" || n == "msg";
        let tainted = |t: &str| Template::parse(t).unwrap().tainted(&secret);
        assert!(tainted("{{key}}"));
        assert!(tainted("{{ b64(hexdecode(hex(key))) }}"));
        assert!(tainted("x{{ \"a\" + key }}"));
        assert!(tainted("{{ xor(key, \"0123456789\") }}"));
        assert!(tainted(
            r#"{{ aes_gcm_encrypt("0123456789abcdef", "000000000000", msg) }}"#
        ));
        assert!(!tainted(
            r#"{{ aes_gcm_encrypt(key, "000000000000", msg) }}"#
        ));
        assert!(!tainted("{{ hex(hmac_sha256(key, $input)) }}"));
        assert!(!tainted("{{ b64(rsa_sign_pkcs1_sha256(key, $input)) }}"));
        assert!(!tainted("{{ len(key) }}"));
        assert!(!tainted("{{ user }}"));
    }
}
