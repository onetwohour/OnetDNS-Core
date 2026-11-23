use std::sync::Arc;

use zeroize::Zeroizing;

/// Wiped when dropped, for building a message that carries a secret. Reserve the full length up
/// front: growing the buffer leaves unwiped copies behind.
pub type SecretBytes = Zeroizing<Vec<u8>>;

#[derive(Clone, Default, Eq, PartialEq)]
/// Secret string whose clones share one buffer. The last owner wipes it, so config reloads and
/// worker threads leave no plaintext copies behind.
pub struct SecretString(Arc<Zeroizing<String>>);

impl SecretString {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(Arc::new(Zeroizing::new(value)))
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_shares_storage_and_debug_redacts() {
        let secret = SecretString::from("top-secret");
        let clone = secret.clone();

        assert_eq!(secret.as_ptr(), clone.as_ptr());
        assert_eq!(format!("{secret:?}"), "<redacted>");
    }
}
