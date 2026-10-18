use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Short-lived credential bytes. No Clone, Debug, Display, or Serialize.
/// Request/library/browser buffers may contain other copies; not guaranteed erasure.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > 1024 || std::str::from_utf8(&bytes).is_err() {
            return None;
        }
        Some(Self(bytes))
    }

    /// Compare only, so synthetic transports can test delivery without exposing it.
    pub fn matches(&self, expected: &[u8]) -> bool {
        bool::from(self.0.as_slice().ct_eq(expected))
    }
}
