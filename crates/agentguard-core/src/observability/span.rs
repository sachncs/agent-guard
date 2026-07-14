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
}
