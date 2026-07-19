use agentguard_core::auth_keys::Algorithm;
use agentguard_core::{DelegationConfig, DelegationSigner, DelegationToken};
use anyhow::{anyhow, Result};
use base64::Engine as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[allow(clippy::too_many_arguments)]
pub fn run(
    from: &str,
    to: &str,
    actions: Vec<String>,
    resources: Vec<String>,
    ttl: i64,
    key_id: Option<&str>,
    key_file: Option<impl AsRef<Path>>,
    out_path: Option<impl AsRef<Path>>,
    output: &str,
) -> Result<()> {
    let signer = load_signer(key_id, key_file.as_ref().map(|p| p.as_ref()), output)?;
    let token = signer.mint(
        from,
        to,
        "agentguard://default", // v2: required audience (RFC 8707)
        actions,
        resources,
        DelegationConfig {
            ttl: Duration::from_secs(ttl.max(0) as u64),
        },
    )?;

    let jws = token.to_jws().to_string();
    if let Some(p) = out_path {
        std::fs::write(p.as_ref(), &jws)?;
        if output != "json" {
            println!("wrote token to {}", p.as_ref().display());
        }
    } else if output == "json" {
        println!("{}", serde_json::to_string_pretty(&token)?);
    } else {
        println!("{}", jws);
    }
    Ok(())
}

pub fn verify(token_str: &str, keys_path: impl AsRef<Path>, output: &str) -> Result<()> {
    let path = Path::new(token_str);
    let compact = if path.exists() && path.is_file() {
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        token_str.to_string()
    };
    let _token = DelegationToken::parse(&compact)?;

    let verifier = agentguard_core::DelegationVerifier::new();
    let text = std::fs::read_to_string(keys_path.as_ref())?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (id, key) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("expected `kid=base64pubkey` in keys file"))?;
        let bytes = base64_decode(key.trim())?;
        verifier
            .add_key(id.trim(), Algorithm::EdDSA, &bytes)
            .map_err(|e| anyhow!("add key {:?}: {}", id.trim(), e))?;
    }

    let verified = verifier
        .verify(
            &compact,
            "agentguard://default",
            chrono::Utc::now().timestamp(),
        )
        .map_err(|e| anyhow!("verify: {}", e))?;
    let claims = &verified.claims;

    if output == "json" {
        println!("{}", serde_json::to_string_pretty(claims)?);
    } else {
        println!("token valid");
        println!("  iss:       {}", claims.iss);
        println!("  sub:       {}", claims.sub);
        println!("  aud:       {}", claims.aud);
        println!("  exp:       {}", claims.exp);
        println!("  actions:   {}", claims.allowed_actions.join(", "));
        println!("  resources: {}", claims.resource_patterns.join(", "));
    }
    Ok(())
}

fn load_signer(
    key_id: Option<&str>,
    key_file: Option<&Path>,
    output: &str,
) -> Result<Arc<DelegationSigner>> {
    if let Some(p) = key_file {
        return Ok(Arc::new(load_signer_from_file(p, key_id)?));
    }
    if let Some(p) = key_id {
        if Path::new(p).exists() {
            return Ok(Arc::new(load_signer_from_file(Path::new(p), Some(p))?));
        }
        let bytes = decode_payload(p)?;
        let mut s = DelegationSigner::from_bytes(&bytes)?;
        if !p.is_empty() {
            s.set_key_id(p);
        }
        return Ok(Arc::new(s));
    }
    let s = DelegationSigner::generate();
    if output != "json" {
        eprintln!(
            "warning: ephemeral key — public key ({}): {}",
            s.key_id(),
            s.public_key_b64()
        );
    }
    Ok(Arc::new(s))
}

fn load_signer_from_file(path: &Path, kid_hint: Option<&str>) -> Result<DelegationSigner> {
    let text = std::fs::read_to_string(path)?;
    let payload = if let Some(idx) = text.find('=') {
        text[idx + 1..].trim().to_string()
    } else {
        text.trim().to_string()
    };
    let bytes = decode_payload(&payload)?;
    let mut s = DelegationSigner::from_bytes(&bytes)?;
    if let Some(k) = kid_hint {
        if !k.is_empty() && k != payload {
            s.set_key_id(k.to_string());
        }
    }
    Ok(s)
}

fn decode_payload(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(s).map_err(|e| anyhow!("hex: {}", e));
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("invalid key payload (need 64-char hex or base64): {}", e))
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("base64: {}", e))
}
