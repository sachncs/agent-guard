//! Shared Redis-compatible storage adapters for AgentGuard.
//!
//! This crate depends on the core storage ports and implements them without
//! adding a Redis dependency to the authorization engine. The initial adapter
//! targets Redis-compatible HTTPS command endpoints, including REST services.

use agentguard_core::{DelegationRevocationStore, Error, Result};
use reqwest::{Client, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_TIMEOUT_SECS: u64 = 3;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Redis-compatible REST adapter for shared delegation revocation state.
///
/// Revoked token ids are SHA-256 hashed before becoming Redis keys, so the
/// backing store does not receive raw delegation identifiers. The adapter
/// requires HTTPS except for loopback endpoints used by local development and
/// tests. Storage and protocol failures return errors; callers must fail
/// closed rather than accept the grant.
pub struct RedisDelegationRevocationStore {
    client: Client,
    endpoint: Url,
    bearer_token: String,
    prefix: String,
}

impl RedisDelegationRevocationStore {
    /// Create a store using the default `agentguard:delegation:revoked:`
    /// namespace.
    pub fn new(endpoint: &str, bearer_token: impl Into<String>) -> Result<Self> {
        Self::with_prefix(endpoint, bearer_token, "agentguard:delegation:revoked:")
    }

    /// Create a store with an explicit namespace. Use a distinct prefix for
    /// each environment sharing the same Redis database.
    pub fn with_prefix(
        endpoint: &str,
        bearer_token: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint)
            .map_err(|_| Error::Other("invalid Redis-compatible endpoint URL".into()))?;
        let local_http = endpoint.scheme() == "http"
            && endpoint.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        if endpoint.scheme() != "https" && !local_http {
            return Err(Error::Other(
                "Redis-compatible endpoint must use HTTPS (HTTP is allowed only on loopback)"
                    .into(),
            ));
        }
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::Other(
                "Redis-compatible endpoint must not contain credentials, query, or fragment".into(),
            ));
        }

        let bearer_token = bearer_token.into();
        if bearer_token.is_empty()
            || bearer_token.len() > 8192
            || bearer_token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(Error::Other("invalid Redis-compatible bearer token".into()));
        }

        let prefix = prefix.into();
        if prefix.is_empty()
            || prefix.len() > 128
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
        {
            return Err(Error::Other("invalid Redis key prefix".into()));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                Error::Other("could not initialize Redis-compatible HTTP client".into())
            })?;

        Ok(Self {
            client,
            endpoint,
            bearer_token,
            prefix,
        })
    }

    fn key(&self, token_id: &str) -> String {
        let digest = Sha256::digest(token_id.as_bytes());
        format!("{}{}", self.prefix, hex::encode(digest))
    }

    async fn command(&self, command: Value) -> Result<Value> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.bearer_token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .json(&command)
            .send()
            .await
            .map_err(|_| Error::Other("Redis-compatible store request failed".into()))?;
        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Redis-compatible store returned HTTP {}",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(Error::Other(
                "Redis-compatible store response exceeded size limit".into(),
            ));
        }

        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::Other("Redis-compatible store response read failed".into()))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(Error::Other(
                    "Redis-compatible store response exceeded size limit".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let payload: Value = serde_json::from_slice(&body)
            .map_err(|_| Error::Other("Redis-compatible store returned invalid JSON".into()))?;
        if payload.get("error").is_some() {
            return Err(Error::Other(
                "Redis-compatible store rejected the command".into(),
            ));
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| Error::Other("Redis-compatible store response is missing result".into()))
    }
}

#[async_trait::async_trait]
impl DelegationRevocationStore for RedisDelegationRevocationStore {
    async fn revoke(&self, token_id: &str, retain_until_unix: i64) -> Result<()> {
        if token_id.is_empty() {
            return Err(Error::Other("delegation token id must not be empty".into()));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Other("system clock is before Unix epoch".into()))?
            .as_secs() as i128;
        let remaining = retain_until_unix as i128 - now;
        if remaining <= 0 {
            return Ok(());
        }
        // Add one second so the key cannot expire during the final Unix-second
        // boundary while the verifier still considers that second valid.
        let ttl = remaining
            .checked_add(1)
            .and_then(|ttl| i64::try_from(ttl).ok())
            .ok_or_else(|| Error::Other("delegation retention interval is too large".into()))?;
        let key = self.key(token_id);
        let script = "local ttl=redis.call('TTL',KEYS[1]); local requested=tonumber(ARGV[1]); if ttl == -2 or ttl == -1 or ttl < requested then redis.call('SET',KEYS[1],'1','EX',ARGV[1]); end; return 1";
        let result = self
            .command(serde_json::json!([
                "EVAL",
                script,
                "1",
                key,
                ttl.to_string()
            ]))
            .await?;
        if result.as_i64() != Some(1) {
            return Err(Error::Other(
                "Redis-compatible store returned an invalid revoke result".into(),
            ));
        }
        Ok(())
    }

    async fn is_revoked(&self, token_id: &str, _now_unix: i64) -> Result<bool> {
        if token_id.is_empty() {
            return Err(Error::Other("delegation token id must not be empty".into()));
        }
        let result = self
            .command(serde_json::json!(["EXISTS", self.key(token_id)]))
            .await?;
        match result.as_i64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(Error::Other(
                "Redis-compatible store returned an invalid existence result".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::DelegationRevocationStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn mock_endpoint(
        response_body: &'static str,
    ) -> (String, tokio::task::JoinHandle<(String, Vec<u8>)>) {
        mock_endpoint_with_status(200, response_body).await
    }

    async fn mock_endpoint_with_status(
        status: u16,
        response_body: &'static str,
    ) -> (String, tokio::task::JoinHandle<(String, Vec<u8>)>) {
        mock_endpoint_body(status, true, response_body.to_owned()).await
    }

    async fn mock_endpoint_body(
        status: u16,
        include_content_length: bool,
        response_body: String,
    ) -> (String, tokio::task::JoinHandle<(String, Vec<u8>)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 4096];
            let body_offset = loop {
                let read = stream.read(&mut buf).await.unwrap();
                assert_ne!(read, 0, "client closed before sending headers");
                request.extend_from_slice(&buf[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..body_offset]).into_owned();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() - body_offset < content_length {
                let read = stream.read(&mut buf).await.unwrap();
                assert_ne!(read, 0, "client closed before sending body");
                request.extend_from_slice(&buf[..read]);
            }
            let response_content_length = if include_content_length {
                format!("Content-Length: {}\r\n", response_body.len())
            } else {
                String::new()
            };
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n{response_content_length}Connection: close\r\n\r\n{}",
                response_body
            );
            // The client deliberately cancels oversized bodies; a closed
            // socket is therefore an expected outcome in those tests.
            let _ = stream.write_all(response.as_bytes()).await;
            (
                headers,
                request[body_offset..body_offset + content_length].to_vec(),
            )
        });
        (format!("http://{address}/"), task)
    }

    #[test]
    fn endpoint_requires_https_except_loopback_and_rejects_url_credentials() {
        assert!(RedisDelegationRevocationStore::new("http://redis.example", "secret").is_err());
        assert!(
            RedisDelegationRevocationStore::new("https://user:pass@redis.example", "secret")
                .is_err()
        );
        assert!(RedisDelegationRevocationStore::new("https://redis.example", "secret").is_ok());
    }

    #[test]
    fn prefix_and_bearer_token_are_validated() {
        assert!(RedisDelegationRevocationStore::with_prefix(
            "https://redis.example",
            "secret",
            "bad/prefix"
        )
        .is_err());
        assert!(RedisDelegationRevocationStore::new("https://redis.example", "bad token").is_err());
        assert!(RedisDelegationRevocationStore::new("https://redis.example", "secret").is_ok());
    }

    #[tokio::test]
    async fn revocation_uses_an_atomic_ttl_that_never_shortens_existing_state() {
        let deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 60;
        let (endpoint, task) = mock_endpoint(r#"{"result":1}"#).await;
        let store =
            RedisDelegationRevocationStore::with_prefix(&endpoint, "unit-secret", "test:").unwrap();
        store.revoke("opaque-jti", deadline).await.unwrap();
        let (headers, body) = task.await.unwrap();
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer unit-secret"));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body[0], "EVAL");
        assert!(body[1].as_str().unwrap().contains("TTL"));
        assert!(body[1].as_str().unwrap().contains("ttl < requested"));
        assert!(body[1].as_str().unwrap().contains("ttl == -1"));
        assert_eq!(
            body[3],
            format!("test:{}", hex::encode(Sha256::digest(b"opaque-jti")))
        );
        assert!(!body[3].as_str().unwrap().contains("opaque-jti"));
        let ttl = body[4].as_str().unwrap().parse::<u64>().unwrap();
        assert!((1..=61).contains(&ttl));
    }

    #[tokio::test]
    async fn revocation_lookup_is_boolean_and_store_errors_fail_closed() {
        let (endpoint, task) = mock_endpoint(r#"{"result":1}"#).await;
        let store = RedisDelegationRevocationStore::new(&endpoint, "unit-secret").unwrap();
        assert!(store.is_revoked("jti", 0).await.unwrap());
        let (headers, body) = task.await.unwrap();
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer unit-secret"));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!([
                "EXISTS",
                format!(
                    "agentguard:delegation:revoked:{}",
                    hex::encode(Sha256::digest(b"jti"))
                )
            ])
        );

        for (status, payload) in [
            (200, r#"{"error":"command rejected"}"#),
            (200, r#"{"result":"not a boolean"}"#),
            (200, r#"{"result":2}"#),
            (200, "not json"),
            (503, r#"{"result":0}"#),
        ] {
            let (endpoint, task) = mock_endpoint_with_status(status, payload).await;
            let store = RedisDelegationRevocationStore::new(&endpoint, "unit-secret").unwrap();
            assert!(
                store.is_revoked("jti", 0).await.is_err(),
                "status={status}, payload={payload} must fail closed"
            );
            let _ = task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_declared_and_streamed_responses_fail_closed() {
        let oversized = format!("{{\"result\":\"{}\"}}", "x".repeat(MAX_RESPONSE_BYTES));
        for include_content_length in [true, false] {
            let (endpoint, task) =
                mock_endpoint_body(200, include_content_length, oversized.clone()).await;
            let store = RedisDelegationRevocationStore::new(&endpoint, "unit-secret").unwrap();
            assert!(store.is_revoked("jti", 0).await.is_err());
            let _ = task.await.unwrap();
        }
    }
}
