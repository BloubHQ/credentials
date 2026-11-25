//! The measurements of a release: PCR0, PCR1 and PCR2 of its enclave image file, as the
//! `measurements.json` of the release states them.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Error, PCR_LEN, Result};

/// The measurements of one release.
///
/// As JSON: `{"release": "...", "git_commit": "...", "pcr0": "<96 hex digits>", "pcr1": ...,
/// "pcr2": ...}`. Other keys (such as the table of the inputs of the build) are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    /// The name of the release, such as `v1.2.0`.
    pub release: String,
    /// The commit the release was built from, when the file names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// The hash of the enclave image file.
    #[serde(with = "pcr_hex")]
    pub pcr0: [u8; PCR_LEN],
    /// The hash of the kernel and boot ramfs.
    #[serde(with = "pcr_hex")]
    pub pcr1: [u8; PCR_LEN],
    /// The hash of the application.
    #[serde(with = "pcr_hex")]
    pub pcr2: [u8; PCR_LEN],
}

impl Measurement {
    /// Whether these are the PCR0, PCR1 and PCR2 given.
    pub fn matches(
        &self,
        pcr0: &[u8; PCR_LEN],
        pcr1: &[u8; PCR_LEN],
        pcr2: &[u8; PCR_LEN],
    ) -> bool {
        &self.pcr0 == pcr0 && &self.pcr1 == pcr1 && &self.pcr2 == pcr2
    }
}

/// The measurements an owner accepts: one release or several.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measurements(Vec<Measurement>);

impl Measurements {
    /// A list of measurements.
    pub fn new(list: Vec<Measurement>) -> Self {
        Self(list)
    }

    /// The measurements.
    pub fn as_slice(&self) -> &[Measurement] {
        &self.0
    }

    /// Reads a `measurements.json`: one object, or an array of them. An empty array is refused.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| Error::Measurements(e.to_string()))?;
        let list = if value.is_array() {
            serde_json::from_value::<Vec<Measurement>>(value)
        } else {
            serde_json::from_value::<Measurement>(value).map(|one| vec![one])
        }
        .map_err(|e| Error::Measurements(e.to_string()))?;
        if list.is_empty() {
            return Err(Error::Measurements("the list is empty".to_string()));
        }
        Ok(Self(list))
    }

    /// The measurements as pretty JSON: an array, with a final newline.
    pub fn to_json(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(&self.0)
            .map_err(|e| Error::Measurements(e.to_string()))?;
        text.push('\n');
        Ok(text)
    }

    /// Reads a `measurements.json` file (see [`Measurements::from_json`]).
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&bytes)
    }

    /// Writes the measurements to a file as a JSON array, replacing it.
    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_json()?).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

impl From<Vec<Measurement>> for Measurements {
    fn from(list: Vec<Measurement>) -> Self {
        Self(list)
    }
}

impl AsRef<[Measurement]> for Measurements {
    fn as_ref(&self) -> &[Measurement] {
        &self.0
    }
}

mod pcr_hex {
    use serde::{Deserialize, Deserializer, Serializer, de};

    use crate::{PCR_LEN, hex};

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; PCR_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; PCR_LEN], D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode_array(&text).ok_or_else(|| {
            de::Error::custom(format!("a PCR is {} hexadecimal digits", PCR_LEN * 2))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const ONE: &str = r#"{"release": "v1.0.0", "git_commit": "abc", "pcr0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "pcr1": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        "pcr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
        "inputs": {"file/Cargo.lock": "00"}}"#;

    #[test]
    fn one_object_or_an_array() {
        let one = Measurements::from_json(ONE.as_bytes()).unwrap();
        assert_eq!(one.as_slice().len(), 1);
        assert_eq!(one.as_slice()[0].release, "v1.0.0");
        assert_eq!(one.as_slice()[0].pcr2[47], 3);
        let many = Measurements::from_json(format!("[{ONE}, {ONE}]").as_bytes()).unwrap();
        assert_eq!(many.as_slice().len(), 2);
        let again = Measurements::from_json(many.to_json().unwrap().as_bytes()).unwrap();
        assert_eq!(again, many);
    }

    #[test]
    fn refuses_bad_lists() {
        assert!(matches!(
            Measurements::from_json(b"[]"),
            Err(Error::Measurements(_))
        ));
        let short = ONE.replacen("01\"", "1\"", 1);
        assert!(matches!(
            Measurements::from_json(short.as_bytes()),
            Err(Error::Measurements(_))
        ));
        let missing = r#"{"release": "v1", "pcr0": "00"}"#;
        assert!(Measurements::from_json(missing.as_bytes()).is_err());
    }
}
