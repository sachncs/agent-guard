//! Chain secret decoding helpers shared across the CLI and any
//! embedder that consumes the `AGENTGUARD_CHAIN_SECRET` file.
//!
//! The chain secret on disk can be in one of three formats:
//!
//! 1. **Hex**: 64 ASCII hex characters (32 raw bytes).
//! 2. **Base64**: standard base64 (with padding) of 32+ bytes.
//! 3. **Raw bytes**: any other byte sequence is passed through as-is.
//!
//! The CLI, the server, the doctor command, and the delegate command
//! all used to inline this logic. The five copies drifted over time
//! (one called `base64::engine::general_purpose::URL_SAFE_NO_PAD`,
//! the others `STANDARD`); this module is the single source of truth.

use base64::Engine as _;

/// Decode a chain secret file. Tries hex (64 ASCII chars) and
/// base64 (standard alphabet) in turn; falls back to raw bytes.
///
/// # Errors
/// Returns `None` for an empty input — empty is never a valid
/// HMAC key. Returns `Some(Vec<u8>)` for any non-empty input,
/// decoded as best as possible.
pub fn decode(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(b) = hex::decode(s) {
                return Some(b);
            }
        }
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
            return Some(b);
        }
    }
    Some(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_none() {
        assert_eq!(decode(b""), None);
    }

    #[test]
    fn hex_64_chars() {
        let hex = "0".repeat(64);
        let out = decode(hex.as_bytes()).unwrap();
        assert_eq!(out.len(), 32);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn base64_padded() {
        let raw = [42u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let out = decode(b64.as_bytes()).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn raw_bytes_passthrough() {
        let raw = [1u8, 2, 3, 4];
        let out = decode(&raw).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn trims_whitespace() {
        let raw = [7u8; 32];
        let b64 = format!("  {}  ", base64::engine::general_purpose::STANDARD.encode(raw));
        let out = decode(b64.as_bytes()).unwrap();
        assert_eq!(out, raw);
    }
}
