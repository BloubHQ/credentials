//! The structure of an attestation document: a COSE_Sign1 (RFC 9052) whose payload is the CBOR
//! map the Nitro Secure Module writes.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;

use crate::{Error, PCR_LEN, Result};

/// The protected header of ES384: the map `{1: -35}`.
const PROTECTED_ES384: [u8; 4] = [0xa1, 0x01, 0x38, 0x22];
/// The CBOR tag of COSE_Sign1.
const COSE_SIGN1_TAG: u64 = 18;
/// The Nitro Secure Module has 32 PCRs.
const PCR_COUNT: u64 = 32;

/// The parts of a COSE_Sign1 that are signed or are the signature.
pub(crate) struct Sign1 {
    pub(crate) protected: Vec<u8>,
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// The payload of an attestation document.
pub(crate) struct Payload {
    pub(crate) module_id: String,
    pub(crate) timestamp_ms: u64,
    pub(crate) pcrs: BTreeMap<u8, [u8; PCR_LEN]>,
    pub(crate) certificate: Vec<u8>,
    pub(crate) cabundle: Vec<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) user_data: Option<Vec<u8>>,
    pub(crate) nonce: Option<Vec<u8>>,
}

/// One CBOR item that fills `bytes` exactly.
fn decode(bytes: &[u8]) -> Option<Value> {
    let mut reader = bytes;
    let value: Value = ciborium::de::from_reader(&mut reader).ok()?;
    reader.is_empty().then_some(value)
}

fn not_sign1(rule: &'static str) -> Error {
    Error::NotCoseSign1(rule)
}

fn payload_invalid(rule: &'static str) -> Error {
    Error::PayloadInvalid(rule)
}

/// Splits a COSE_Sign1, tagged (18) or not, and checks that its protected header names ES384
/// and nothing else.
pub(crate) fn parse_sign1(document: &[u8]) -> Result<Sign1> {
    let value = decode(document).ok_or(Error::NotCbor)?;
    let value = match value {
        Value::Tag(COSE_SIGN1_TAG, inner) => *inner,
        Value::Tag(..) => return Err(not_sign1("tagged, but not with 18")),
        other => other,
    };
    let Value::Array(items) = value else {
        return Err(not_sign1("not an array"));
    };
    let [protected, unprotected, payload, signature]: [Value; 4] = items
        .try_into()
        .map_err(|_| not_sign1("not an array of 4"))?;
    let Value::Bytes(protected) = protected else {
        return Err(not_sign1("the protected header is not a byte string"));
    };
    if !matches!(unprotected, Value::Map(_)) {
        return Err(not_sign1("the unprotected header is not a map"));
    }
    let Value::Bytes(payload) = payload else {
        return Err(not_sign1("the payload is not a byte string"));
    };
    let Value::Bytes(signature) = signature else {
        return Err(not_sign1("the signature is not a byte string"));
    };
    if protected != PROTECTED_ES384 {
        return Err(Error::UnsupportedAlgorithm);
    }
    Ok(Sign1 {
        protected,
        payload,
        signature,
    })
}

/// The bytes the signature covers: `["Signature1", protected, h'', payload]` (RFC 9052,
/// section 4.4).
pub(crate) fn sig_structure(sign1: &Sign1) -> Result<Vec<u8>> {
    let structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(sign1.protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(sign1.payload.clone()),
    ]);
    let mut out = Vec::with_capacity(sign1.payload.len().saturating_add(32));
    ciborium::ser::into_writer(&structure, &mut out)
        .map_err(|_| not_sign1("the signed structure cannot be encoded"))?;
    Ok(out)
}

fn bytes(value: Value, rule: &'static str) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(payload_invalid(rule)),
    }
}

/// A byte string, or null or absent (the module writes null for what it was not given).
fn optional_bytes(value: Value, rule: &'static str) -> Result<Option<Vec<u8>>> {
    match value {
        Value::Null => Ok(None),
        Value::Bytes(bytes) => Ok(Some(bytes)),
        _ => Err(payload_invalid(rule)),
    }
}

fn pcrs(value: Value) -> Result<BTreeMap<u8, [u8; PCR_LEN]>> {
    let Value::Map(entries) = value else {
        return Err(payload_invalid("pcrs is not a map"));
    };
    let mut out = BTreeMap::new();
    for (index, digest) in entries {
        let index = match index {
            Value::Integer(index) => u64::try_from(index)
                .ok()
                .filter(|index| *index < PCR_COUNT)
                .and_then(|index| u8::try_from(index).ok()),
            _ => None,
        }
        .ok_or_else(|| payload_invalid("a PCR index is not an integer from 0 to 31"))?;
        let digest: [u8; PCR_LEN] = bytes(digest, "a PCR is not a byte string")?
            .try_into()
            .map_err(|_| payload_invalid("a PCR is not 48 bytes"))?;
        if out.insert(index, digest).is_some() {
            return Err(payload_invalid("a PCR is given twice"));
        }
    }
    Ok(out)
}

/// Reads the payload map. `module_id`, `digest`, `timestamp`, `pcrs`, `certificate` and
/// `cabundle` are required; `public_key`, `user_data` and `nonce` may be null or absent.
/// Unknown keys are ignored; a key given twice is refused.
pub(crate) fn parse_payload(payload: &[u8]) -> Result<Payload> {
    let Value::Map(entries) = decode(payload).ok_or(Error::PayloadInvalid("not CBOR"))? else {
        return Err(payload_invalid("not a map"));
    };
    let mut seen = BTreeSet::new();
    let mut module_id = None;
    let mut digest = None;
    let mut timestamp_ms = None;
    let mut pcr_map = None;
    let mut certificate = None;
    let mut cabundle = None;
    let mut public_key = None;
    let mut user_data = None;
    let mut nonce = None;
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(payload_invalid("a key is not text"));
        };
        if !seen.insert(key.clone()) {
            return Err(payload_invalid("a key is given twice"));
        }
        match key.as_str() {
            "module_id" => match value {
                Value::Text(text) if !text.is_empty() => module_id = Some(text),
                _ => return Err(payload_invalid("module_id is not text")),
            },
            "digest" => match value {
                Value::Text(text) => digest = Some(text),
                _ => return Err(payload_invalid("digest is not text")),
            },
            "timestamp" => match value {
                Value::Integer(value) => {
                    timestamp_ms = Some(
                        u64::try_from(value)
                            .map_err(|_| payload_invalid("timestamp is not a u64"))?,
                    );
                }
                _ => return Err(payload_invalid("timestamp is not an integer")),
            },
            "pcrs" => pcr_map = Some(pcrs(value)?),
            "certificate" => {
                certificate = Some(bytes(value, "certificate is not a byte string")?);
            }
            "cabundle" => {
                let Value::Array(items) = value else {
                    return Err(payload_invalid("cabundle is not an array"));
                };
                cabundle = Some(
                    items
                        .into_iter()
                        .map(|item| bytes(item, "a cabundle entry is not a byte string"))
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            "public_key" => public_key = optional_bytes(value, "public_key is not bytes")?,
            "user_data" => user_data = optional_bytes(value, "user_data is not bytes")?,
            "nonce" => nonce = optional_bytes(value, "nonce is not bytes")?,
            _ => {}
        }
    }
    let digest = digest.ok_or_else(|| payload_invalid("digest is missing"))?;
    if digest != "SHA384" {
        return Err(Error::UnsupportedDigest(digest));
    }
    let cabundle = cabundle.ok_or_else(|| payload_invalid("cabundle is missing"))?;
    if cabundle.is_empty() {
        return Err(Error::EmptyCaBundle);
    }
    Ok(Payload {
        module_id: module_id.ok_or_else(|| payload_invalid("module_id is missing"))?,
        timestamp_ms: timestamp_ms.ok_or_else(|| payload_invalid("timestamp is missing"))?,
        pcrs: pcr_map.ok_or_else(|| payload_invalid("pcrs is missing"))?,
        certificate: certificate.ok_or_else(|| payload_invalid("certificate is missing"))?,
        cabundle,
        public_key,
        user_data,
        nonce,
    })
}
