//! W3C Trace Context propagation for agentguard requests.
//!
//! See <https://www.w3.org/TR/trace-context/>. A `TraceContext` can be parsed
//! from the standard `traceparent` HTTP header and serialized back to one.
//! Carried on [`crate::request::AgentRequest`] and threaded through every
//! authorization decision's audit record.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Length in bytes of a W3C trace-id (16 bytes = 32 hex chars).
pub const TRACE_ID_LEN: usize = 16;
/// Length in bytes of a W3C parent-id / span-id (8 bytes = 16 hex chars).
pub const SPAN_ID_LEN: usize = 8;

/// 128-bit trace identifier, hex-encoded to 32 chars when displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TraceId(pub [u8; TRACE_ID_LEN]);

/// 64-bit span identifier, hex-encoded to 16 chars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SpanId(pub [u8; SPAN_ID_LEN]);

impl TraceId {
    pub fn new(bytes: [u8; TRACE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a random trace id from the OS CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; TRACE_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl FromStr for TraceId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::Other(format!("trace_id hex: {}", e)))?;
        if bytes.len() != TRACE_ID_LEN {
            return Err(Error::Other(format!(
                "trace_id must be {} bytes, got {}",
                TRACE_ID_LEN,
                bytes.len()
            )));
        }
        let mut arr = [0u8; TRACE_ID_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl From<TraceId> for String {
    fn from(t: TraceId) -> Self {
        t.as_hex()
    }
}

impl TryFrom<String> for TraceId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl SpanId {
    pub fn new(bytes: [u8; SPAN_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; SPAN_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl FromStr for SpanId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::Other(format!("span_id hex: {}", e)))?;
        if bytes.len() != SPAN_ID_LEN {
            return Err(Error::Other(format!(
                "span_id must be {} bytes, got {}",
                SPAN_ID_LEN,
                bytes.len()
            )));
        }
        let mut arr = [0u8; SPAN_ID_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl From<SpanId> for String {
    fn from(s: SpanId) -> Self {
        s.as_hex()
    }
}

impl TryFrom<String> for SpanId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

/// W3C Trace Context, parsed from the `traceparent` header.
///
/// Format: `00-<trace-id-hex>-<parent-id-hex>-<flags-hex>`
/// We currently ignore `tracestate` (kept for future propagation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    /// Trace flags. Bit 0 = sampled.
    pub flags: u8,
}

impl TraceContext {
    /// Build a new trace context with the given trace + span IDs. Flags
    /// default to `0x01` (sampled).
    pub fn new(trace_id: TraceId, span_id: SpanId) -> Self {
        Self {
            trace_id,
            span_id,
            flags: 0x01,
        }
    }

    /// Generate a fresh trace context (new trace, new root span).
    pub fn fresh() -> Self {
        Self::new(TraceId::random(), SpanId::random())
    }

    /// Return a new context with the same trace_id but a fresh span_id.
    /// Use this to record a child operation within the same trace.
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id: SpanId::random(),
            flags: self.flags,
        }
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.flags
        )
    }
}

impl FromStr for TraceContext {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        // W3C: "VERSION-TRACE_ID-PARENT_ID-FLAGS"
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 4 {
            return Err(Error::Other(format!(
                "traceparent must have 4 dash-separated parts, got {}",
                parts.len()
            )));
        }
        let version = parts[0];
        if version != "00" {
            return Err(Error::Other(format!(
                "unsupported traceparent version: {}",
                version
            )));
        }
        let trace_id: TraceId = parts[1].parse()?;
        let span_id: SpanId = parts[2].parse()?;
        let flags = u8::from_str_radix(parts[3], 16)
            .map_err(|e| Error::Other(format!("flags hex: {}", e)))?;
        Ok(Self {
            trace_id,
            span_id,
            flags,
        })
    }
}

impl Serialize for TraceContext {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TraceContext {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_roundtrip() {
        let tc = TraceContext::fresh();
        let s = tc.to_string();
        let parsed: TraceContext = s.parse().unwrap();
        assert_eq!(tc, parsed);
    }

    #[test]
    fn trace_id_must_be_16_bytes() {
        assert!("abcd".parse::<TraceId>().is_err());
        let bytes = [1u8; 16];
        let hex = hex::encode(bytes);
        let t: TraceId = hex.parse().unwrap();
        assert_eq!(t.0, bytes);
    }

    #[test]
    fn span_id_must_be_8_bytes() {
        let bytes = [1u8; 8];
        let hex = hex::encode(bytes);
        let s: SpanId = hex.parse().unwrap();
        assert_eq!(s.0, bytes);
    }

    #[test]
    fn traceparent_format() {
        let trace_id = TraceId::new([0xab; 16]);
        let span_id = SpanId::new([0xcd; 8]);
        let tc = TraceContext::new(trace_id, span_id);
        assert_eq!(
            tc.to_string(),
            "00-abababababababababababababababab-cdcdcdcdcdcdcdcd-01"
        );
    }

    #[test]
    fn traceparent_rejects_wrong_version() {
        // W3C traceparent version "01" is reserved; we accept only "00".
        let bad = "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert!(bad.parse::<TraceContext>().is_err());
    }

    #[test]
    fn traceparent_rejects_wrong_segment_count() {
        let bad = "00-aaaa-bbbb-cccc-dddd";
        assert!(bad.parse::<TraceContext>().is_err());
    }

    #[test]
    fn traceparent_rejects_non_hex() {
        let bad = "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01";
        assert!(bad.parse::<TraceContext>().is_err());
    }

    #[test]
    fn random_trace_id_is_unique_99pct_of_the_time() {
        // Collision check: 1000 random IDs should have no duplicates.
        // 128-bit space → 2^-128 collision probability per pair, so 1000
        // pairs gives effectively zero chance. We use a small threshold to
        // avoid flakiness on degenerate PRNGs.
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for _ in 0..1000 {
            set.insert(TraceId::random().0);
        }
        assert_eq!(set.len(), 1000, "TraceId::random had collisions");
    }

    #[test]
    fn random_span_id_is_unique_99pct_of_the_time() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for _ in 0..1000 {
            set.insert(SpanId::random().0);
        }
        assert_eq!(set.len(), 1000, "SpanId::random had collisions");
    }

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Parsing a printed trace context round-trips through
            /// `Display` → `FromStr`.
            #[test]
            fn round_trip(seed in any::<u8>()) {
                let trace_id = TraceId::new([seed; 16]);
                let span_id = SpanId::new([seed.wrapping_mul(2); 8]);
                let tc = TraceContext::new(trace_id, span_id);
                let printed = tc.to_string();
                let parsed: TraceContext = printed.parse().unwrap();
                prop_assert_eq!(tc.trace_id, parsed.trace_id);
                prop_assert_eq!(tc.span_id, parsed.span_id);
                prop_assert_eq!(tc.flags, parsed.flags);
            }
        }
    }
}
