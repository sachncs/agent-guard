use agentguard_core::{DelegationConfig, DelegationSigner, DelegationToken, DelegationVerifier};
use anyhow::{anyhow, Result};
use std::path::Path;
use std::sync::Arc;

pub fn run(
    from: &str,
    to: &str,
    actions: Vec<String>,
    resources: Vec<String>,
    ttl: i64,
    key_id: Option<&str>,
    key_file: Option<&str>,
    out_path: Option<&str>,
    output: &str,
) -> Result<()> {
    let signer = load_signer(key_id, key_file, output)?;
    let token = signer.mint(
        from,
        to,
        "agentguard",
        actions,
        resources,
        DelegationConfig { ttl_seconds: ttl },
    )?;

    let compact = token.to_compact();
    if let Some(p) = out_path {
        std::fs::write(p, &compact)?;
        if output != "json" {
            println!("wrote token to {}", p);
        }
    } else if output == "json" {
        println!("{}", serde_json::to_string_pretty(&token)?);
    } else {
        println!("{}", compact);
    }
    Ok(())
}

pub fn verify(token_str: &str, keys_path: &str, output: &str) -> Result<()> {
    let path = Path::new(token_str);
    let compact = if path.exists() && path.is_file() {
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        token_str.to_string()
    };
    let token = DelegationToken::from_compact(&compact)?;

    let mut verifier = DelegationVerifier::new();
    let text = std::fs::read_to_string(keys_path)?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (id, key) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("expected `kid=base64pubkey` in keys file"))?;
        verifier.add_key(id.trim(), key.trim())?;
    }

    let claims = verifier.verify(&token, agentguard_core::DelegationClaims::now())?;

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
    key_file: Option<&str>,
    output: &str,
) -> Result<Arc<DelegationSigner>> {
    // Resolve source: either a path (`key_file`) or inline (`key_id`).
    if let Some(p) = key_file {
        return load_signer_from_file(p, key_id);
    }
    if let Some(p) = key_id {
        // If it's a file path that exists, treat as file.
        if Path::new(p).exists() {
            return load_signer_from_file(p, Some(p));
        }
        // Otherwise treat as inline payload, with key_id = "imported".
        let bytes = decode_payload(p)?;
        let s = DelegationSigner::from_bytes(&bytes)?;
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

fn load_signer_from_file(path: &str, kid_hint: Option<&str>) -> Result<Arc<DelegationSigner>> {
    let text = std::fs::read_to_string(path)?;
    // Format: `kid=<payload>` per line. If no `=`, the entire file body is the payload.
    let payload = if let Some(idx) = text.find('=') {
        // skip past first '='; everything after is payload
        text[idx + 1..].trim().to_string()
    } else {
        text.trim().to_string()
    };
    let bytes = decode_payload(&payload)?;
    let mut s = DelegationSigner::from_bytes(&bytes)?;
    if let Some(k) = kid_hint {
        if !k.is_empty() {
            s.set_key_id(k.to_string());
        }
    }
    Ok(Arc::new(s))
}

fn decode_payload(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex_decode(s);
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("invalid key payload (need 64-char hex or base64): {}", e))
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex string has odd length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("invalid hex: {}", e))?;
        out.push(byte);
    }
    Ok(out)
}
