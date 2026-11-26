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

/// Serde form of an optional fixed-size byte array as base64 (as [`b64_array`]); use with
/// `skip_serializing_if = "Option::is_none"` and `default`.
pub mod b64_option_array {
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serializes the array, or null.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer, const N: usize>(
        value: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&super::to_b64(bytes)),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes the array; any other length is an error.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::array_from_b64(&text)
            .map(Some)
            .map_err(|_| de::Error::custom("invalid base64 array"))
    }
}

/// Serde form of a boxed fixed-size byte array as base64 (as [`b64_array`]; boxed to keep a
/// rare variant of a large enum small).
pub mod b64_box_array {
    use serde::{Deserializer, Serializer};

    /// Serializes the array.
    #[allow(clippy::borrowed_box)]
    pub fn serialize<S: Serializer, const N: usize>(
        value: &Box<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::b64_array::serialize(value, serializer)
    }

    /// Deserializes the array; any other length is an error.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Box<[u8; N]>, D::Error> {
        super::b64_array::deserialize(deserializer).map(Box::new)
    }
}

/// Serde form of a list of byte vectors as a list of base64 strings.
pub mod b64_list {
    use base64::Engine;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serializes the list.
    pub fn serialize<S: Serializer>(value: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for item in value {
            seq.serialize_element(&super::to_b64(item))?;
        }
        seq.end()
    }

    /// Deserializes the list.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|text| {
                super::URL_SAFE_NO_PAD
                    .decode(text)
                    .map_err(|_| de::Error::custom("invalid base64"))
            })
            .collect()
    }
}

/// Serde form of header pairs whose values are bytes: `[name, base64 value]`.
pub mod b64_pairs {
    use base64::Engine;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serializes the pairs.
    pub fn serialize<S: Serializer>(
        value: &[(String, Vec<u8>)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for (name, bytes) in value {
            seq.serialize_element(&(name, super::to_b64(bytes)))?;
        }
        seq.end()
    }

    /// Deserializes the pairs.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<(String, Vec<u8>)>, D::Error> {
        Vec::<(String, String)>::deserialize(deserializer)?
            .into_iter()
            .map(|(name, text)| {
                super::URL_SAFE_NO_PAD
                    .decode(text)
                    .map(|bytes| (name, bytes))
                    .map_err(|_| de::Error::custom("invalid base64"))
            })
            .collect()
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
