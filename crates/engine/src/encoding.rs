//! Byte encodings of the protocol: unpadded URL-safe base64 for every byte field.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{Error, Result};

/// Encodes bytes as unpadded URL-safe base64.
pub fn to_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded URL-safe base64 into an array of exactly `N` bytes.
pub fn array_from_b64<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Encoding)?;
    bytes.try_into().map_err(|_| Error::Encoding)
}

/// The canonical bytes of a value: its JSON with fields in declaration order.
pub(crate) fn canonical<T: serde::Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let mut out = domain.to_vec();
    serde_json::to_writer(&mut out, value).map_err(|_| Error::Encoding)?;
    Ok(out)
}

/// Serde form of a fixed-size byte array as base64.
pub mod b64_array {
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serializes the array.
    pub fn serialize<S: Serializer, const N: usize>(
        value: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::to_b64(value))
    }

    /// Deserializes the array; any other length is an error.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        super::array_from_b64(&text).map_err(|_| de::Error::custom("invalid base64 array"))
    }
}

/// Serde form of a byte vector as base64.
pub mod b64_vec {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serializes the bytes.
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::to_b64(value))
    }

    /// Deserializes the bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| de::Error::custom("invalid base64"))
    }
}
