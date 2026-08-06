use std::sync::Mutex;

/// Mirrors `Acmebot.Acme.Internal.AcmeNonceStore`.
///
/// ACME nonces are single-use and expire server-side, so only the most recently
/// received one is worth keeping: holding just the latest nonce guarantees a request
/// always uses the freshest one, and a `badNonce` retry naturally picks up the fresh
/// nonce returned by the error response.
#[derive(Debug, Default)]
pub struct AcmeNonceStore {
    nonce: Mutex<Option<String>>,
}

impl AcmeNonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, nonce: Option<&str>) {
        let Some(nonce) = nonce else { return };

        if nonce.trim().is_empty() || !is_base64url(nonce) {
            return;
        }

        let mut guard = self.nonce.lock().unwrap();
        *guard = Some(nonce.to_owned());
    }

    pub fn try_take(&self) -> Option<String> {
        let mut guard = self.nonce.lock().unwrap();
        guard.take()
    }
}

fn is_base64url(value: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_take_returns_the_nonce() {
        let store = AcmeNonceStore::new();
        store.add(Some("YWJjZA"));

        assert_eq!(store.try_take().as_deref(), Some("YWJjZA"));
        assert_eq!(store.try_take(), None);
    }

    #[test]
    fn add_ignores_invalid_nonces() {
        let store = AcmeNonceStore::new();
        store.add(Some(""));
        store.add(Some("not valid base64url!!"));

        assert_eq!(store.try_take(), None);
    }

    #[test]
    fn add_keeps_only_the_latest_nonce() {
        let store = AcmeNonceStore::new();
        store.add(Some("YWJjZA"));
        store.add(Some("ZGVmZw"));

        assert_eq!(store.try_take().as_deref(), Some("ZGVmZw"));
    }
}
