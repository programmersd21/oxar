//! Password handling. A secret is copied into zeroizing storage exactly once
//! and is never rendered by `Debug`, `Display` or error messages.

use std::fmt;

use zeroize::Zeroizing;

/// A password or key. Comparison is constant time only where the archive
/// format requires it; this type exists for hygiene, not for cryptography.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Copy bytes into zeroizing storage.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// Access the raw bytes. Callers must not log the result.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

impl From<&[u8]> for Secret {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_renders_the_value() {
        let secret = Secret::from("hunter2");
        assert!(!format!("{secret:?}").contains("hunter2"));
        assert_eq!(secret.expose(), b"hunter2");
    }
}
