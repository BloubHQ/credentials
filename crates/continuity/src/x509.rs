//! What a Fulcio signing certificate says about its signer: the URIs of its subject
//! alternative name and the Fulcio extensions (OIDs under 1.3.6.1.4.1.57264.1).
//!
//! The chain, the signature of each certificate, the validity times, the key usages and the
//! critical extensions are checked by `webpki` before any of this is read.

use crate::der::{self, Reader};
use crate::{Error, Result};

/// `2.5.29.17`, subject alternative name.
const SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// The arc of the Fulcio extensions, 1.3.6.1.4.1.57264.1.
const FULCIO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01];
/// A `uniformResourceIdentifier` of a GeneralName (`[6] IMPLICIT IA5String`).
const URI_TAG: u8 = 0x86;

/// Fulcio extension 1.3.6.1.4.1.57264.1.8: the OIDC issuer (a DER UTF8String).
pub(crate) const ISSUER_V2: u8 = 8;
/// Fulcio extension 1.3.6.1.4.1.57264.1.11: the runner environment (`github-hosted`).
pub(crate) const RUNNER_ENVIRONMENT: u8 = 11;
/// Fulcio extension 1.3.6.1.4.1.57264.1.12: the source repository URI.
pub(crate) const SOURCE_REPOSITORY: u8 = 12;
/// Fulcio extension 1.3.6.1.4.1.57264.1.14: the source repository ref.
pub(crate) const SOURCE_REF: u8 = 14;

fn malformed(what: &'static str) -> Error {
    Error::CertificateMalformed(what)
}

/// The signer of a Fulcio certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Signer {
    /// The URIs of the subject alternative name.
    pub uris: Vec<String>,
    /// The Fulcio extensions with a DER UTF8String value, by the last arc of their OID.
    pub fulcio: Vec<(u8, String)>,
}

impl Signer {
    /// The value of Fulcio extension `arc`, when the certificate has it once.
    pub(crate) fn fulcio(&self, arc: u8) -> Option<&str> {
        let mut found = self.fulcio.iter().filter(|(a, _)| *a == arc);
        match (found.next(), found.next()) {
            (Some((_, value)), None) => Some(value),
            _ => None,
        }
    }
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| malformed("text is not UTF-8"))
}

fn san_uris(value: &[u8], out: &mut Vec<String>) -> Result<()> {
    let mut names = Reader::new(der::single(value, der::SEQUENCE)?);
    while !names.is_empty() {
        let (tag, name) = names.read()?;
        if tag == URI_TAG {
            if !name.is_ascii() {
                return Err(malformed("a URI is not ASCII"));
            }
            out.push(utf8(name)?);
        }
    }
    Ok(())
}

/// Reads the signer from a certificate (DER).
pub(crate) fn signer(certificate: &[u8]) -> Result<Signer> {
    let mut cert = Reader::new(der::single(certificate, der::SEQUENCE)?);
    let mut tbs = Reader::new(cert.expect(der::SEQUENCE)?);
    tbs.optional(0xa0)?; // version
    tbs.expect(der::INTEGER)?; // serial number
    tbs.expect(der::SEQUENCE)?; // signature algorithm
    tbs.expect(der::SEQUENCE)?; // issuer
    tbs.expect(der::SEQUENCE)?; // validity
    tbs.expect(der::SEQUENCE)?; // subject
    tbs.expect(der::SEQUENCE)?; // subject public key info
    tbs.optional(0x81)?; // issuer unique id
    tbs.optional(0x82)?; // subject unique id
    let mut signer = Signer::default();
    if let Some(extensions) = tbs.optional(0xa3)? {
        let mut list = Reader::new(der::single(extensions, der::SEQUENCE)?);
        let mut seen: Vec<&[u8]> = Vec::new();
        while !list.is_empty() {
            let mut extension = Reader::new(list.expect(der::SEQUENCE)?);
            let oid = extension.expect(der::OID)?;
            extension.optional(der::BOOLEAN)?;
            let value = extension.expect(der::OCTET_STRING)?;
            extension.finish()?;
            if seen.contains(&oid) {
                return Err(malformed("an extension is given twice"));
            }
            seen.push(oid);
            if oid == SAN {
                san_uris(value, &mut signer.uris)?;
            } else if let Some((&arc, [])) =
                oid.strip_prefix(FULCIO).and_then(|rest| rest.split_first())
            {
                // Extensions 1 to 6 hold raw text, 8 and later DER UTF8Strings; only the
                // latter are read.
                if arc >= ISSUER_V2 {
                    signer
                        .fulcio
                        .push((arc, utf8(der::single(value, der::UTF8_STRING)?)?));
                }
            }
        }
    }
    tbs.finish()?;
    cert.expect(der::SEQUENCE)?;
    cert.expect(0x03)?;
    cert.finish()?;
    Ok(signer)
}
