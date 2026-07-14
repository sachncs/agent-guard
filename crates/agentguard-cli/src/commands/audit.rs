//! Audit log commands: verify, export, sar, erase.

use agentguard_core::decision::{
    CefFormatter, DecisionLog, EcsFormatter, JsonlFormatter, LeefFormatter,
};
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub fn verify(audit_path: &str, secret_file: &str, output: &str) -> Result<()> {
    let key = std::fs::read(secret_file)
        .map_err(|e| anyhow!("read secret file {}: {}", secret_file, e))?;
    let key_str = std::str::from_utf8(&key)
        .map_err(|e| anyhow!("secret must be utf-8: {}", e))?
        .trim();
    let key_bytes = if key_str.len() == 64 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(key_str).map_err(|e| anyhow!("hex: {}", e))?
    } else {
        key.to_vec()
    };
    let chain_id = DecisionLog::verify_chain(audit_path, &key_bytes)?;
    if output == "json" {
        println!(
            "{}",
            serde_json::json!({"status": "ok", "chain_id": chain_id.to_string()})
        );
    } else {
        println!("✓ audit log chain verified");
        println!("  chain_id: {}", chain_id);
        println!("  file:     {}", audit_path);
    }
    Ok(())
}

pub fn export(audit_path: &str, format: &str, out_path: Option<&str>, _output: &str) -> Result<()> {
    let records = DecisionLog::read_all(audit_path)?;
    let formatter: Box<dyn agentguard_core::decision::AuditFormatter> = match format {
        "jsonl" => Box::new(JsonlFormatter),
        "cef" => Box::new(CefFormatter),
        "leef" => Box::new(LeefFormatter),
        "ecs" => Box::new(EcsFormatter),
        _ => {
            return Err(anyhow!(
                "unknown format: {} (use jsonl|cef|leef|ecs)",
                format
            ))
        }
    };
    let lines: Vec<String> = records.iter().map(|r| formatter.format(r)).collect();
    if let Some(p) = out_path {
        std::fs::write(p, lines.join("\n") + "\n")?;
        println!("wrote {} records to {}", lines.len(), p);
    } else {
        for line in &lines {
            println!("{}", line);
        }
    }
    Ok(())
}

pub fn sar(audit_path: &str, subject_id: &str, output: &str) -> Result<()> {
    let records = DecisionLog::read_all(audit_path)?;
    let matching: Vec<_> = records
        .into_iter()
        .filter(|r| r.principal == subject_id || r.subject_id.as_deref() == Some(subject_id))
        .collect();
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&matching)?);
    } else {
        println!(
            "found {} record(s) for subject {}",
            matching.len(),
            subject_id
        );
        for r in &matching {
            println!(
                "  {} {} {} {} {}",
                r.timestamp.format("%Y-%m-%dT%H:%M:%S"),
                if r.effect == "allow" { "✓" } else { "✗" },
                r.effect.to_uppercase(),
                r.action,
                r.resource
            );
        }
    }
    Ok(())
}

pub fn erase(
    audit_path: &str,
    subject_id: &str,
    salt_file: &str,
    out_path: Option<&str>,
) -> Result<()> {
    let salt =
        std::fs::read(salt_file).map_err(|e| anyhow!("read salt file {}: {}", salt_file, e))?;
    let records = DecisionLog::read_all(audit_path)?;
    let mut out = Vec::new();
    let mut erased = 0;
    for mut r in records {
        let r_matches = r.principal == subject_id || r.subject_id.as_deref() == Some(subject_id);
        if r_matches {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&salt)
                .map_err(|e| anyhow!("hmac init: {}", e))?;
            mac.update(r.principal.as_bytes());
            let hash = mac.finalize().into_bytes();
            r.principal = format!("erased:{}", hex::encode(hash));
            r.subject_id = Some(format!("erased:{}", hex::encode(hash)));
            erased += 1;
        }
        out.push(r);
    }
    let target = out_path.unwrap_or(audit_path);
    let file = std::fs::File::create(target)?;
    let mut writer = std::io::BufWriter::new(file);
    for r in &out {
        serde_json::to_writer(&mut writer, r)?;
        use std::io::Write;
        writer.write_all(b"\n")?;
    }
    println!(
        "erased {} records; wrote {} records to {}",
        erased,
        out.len(),
        target
    );
    Ok(())
}

fn decode_secret(s: &str) -> Result<Vec<u8>> {
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(s).map_err(|e| anyhow!("hex: {}", e));
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("base64: {}", e))
}

#[allow(dead_code)]
fn _path_helper(_: &Path) {}
