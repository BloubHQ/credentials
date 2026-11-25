//! The type of a secret value.
//!
//! A [`Secret`] cannot be printed, cloned or serialized, and its bytes are overwritten with
//! zeros when it is dropped. Only this crate can read it.
//!
//! ```compile_fail
//! let secret = engine::secret::Secret::new(vec![1u8; 8]);
//! let _ = secret.expose(); // private to the engine
//! ```
//!
//! ```compile_fail
//! let secret = engine::secret::Secret::new(vec![1u8; 8]);
//! println!("{}", secret); // no Display
//! ```
//!
//! ```compile_fail
//! fn clone_it<T: Clone>(_: &T) {}
//! clone_it(&engine::secret::Secret::new(vec![1u8; 8])); // no Clone
//! ```
//!
//! ```compile_fail
//! fn serialize_it<T: serde::Serialize>(_: &T) {}
//! serialize_it(&engine::secret::Secret::new(vec![1u8; 8])); // no Serialize
//! ```

use core::fmt;

use zeroize::Zeroize;

/// A secret value. See the module documentation.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps a value. The caller should not keep another copy of it.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Reads the value. Only the engine can call this.
    pub(crate) fn expose(&self) -> &T {
        &self.0
    }

    /// Writes into the value. Only the engine can call this.
    pub(crate) fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new(b"hunter2-hunter2".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    }
}
