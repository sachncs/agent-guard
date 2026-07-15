//! Audit log commands: verify, export, sar, erase.

use agentguard_core::decision::{AuditFormat, DecisionLog};
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::str::FromStr;

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
    let format = AuditFormat::from_str(format)
        .map_err(|e| anyhow!(e))?;
    let records = DecisionLog::read_all(audit_path)?;
    let lines: Vec<String> = records.iter().map(|r| format.format(r)).collect();
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
    let records = DecisionLog::read_all_chained(audit_path)?;
    let mut out = Vec::new();
    let mut erased = 0;
    for mut cr in records {
        let r_matches = cr.record.principal == subject_id
            || cr.record.subject_id.as_deref() == Some(subject_id);
        if r_matches {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&salt)
                .map_err(|e| anyhow!("hmac init: {}", e))?;
            mac.update(cr.record.principal.as_bytes());
            let hash = mac.finalize().into_bytes();
            let tag = format!("erased:{}", hex::encode(hash));
            cr.record.principal = tag.clone();
            cr.record.subject_id = Some(tag);
            erased += 1;
        }
        // Preserve chain metadata (prev_hash / record_hash / chain_id)
        // so each record's place in the chain is documented even though
        // the HMAC no longer recomputes for erased rows.
        out.push(cr);
    }
    let target = out_path.unwrap_or(audit_path);
    let file = std::fs::File::create(target)?;
    let mut writer = std::io::BufWriter::new(file);
    for cr in &out {
        serde_json::to_writer(&mut writer, cr)?;
        use std::io::Write;
        writer.write_all(b"\n")?;
    }
    println!(
        "erased {} records; wrote {} records to {}",
        erased,
        out.len(),
        target
    );
    if erased > 0 {
        println!(
            "WARNING: the rewritten audit log will fail `agentguard audit verify` \
             because the HMAC of each erased record no longer matches its stored \
             hash. This is expected for GDPR Art. 17 erasure — the audit trail \
             keeps its position markers but the canonical record body has been \
             modified. Operators MUST keep the pre-erasure file as evidence of \
             the original chain."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::decision::DecisionRecord;
    use tempfile::tempdir;

    #[test]
    fn erase_preserves_chain_metadata() {
        // The audit log is rewritten preserving prev_hash / record_hash /
        // chain_id fields (so downstream verifiers see *what was* there),
        // even though the record body has been mutated and the HMAC no
        // longer recomputes. The operator is warned to keep the original.
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = DecisionLog::open_with_chain(&path, b"root").unwrap();
        let rec = DecisionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            effect: "allow".into(),
            policies: vec![],
            request_id: None,
            principal: "alice".into(),
            action: "send".into(),
            resource: "doc".into(),
            reasons: vec![],
            session_id: None,
            agent_chain: None,
            trace_id: None,
            span_id: None,
            tenant_id: None,
            subject_id: Some("alice".into()),
        };
        log.append(&rec).unwrap();
        log.append(&rec).unwrap();
        drop(log);

        let salt_path = dir.path().join("salt");
        std::fs::write(&salt_path, b"random-salt-bytes").unwrap();
        erase(path.to_str().unwrap(), "alice", salt_path.to_str().unwrap(), None).unwrap();

        // Re-read as ChainedRecord and verify the chain metadata is intact.
        let records = DecisionLog::read_all_chained(&path).unwrap();
        assert_eq!(records.len(), 2);
        for cr in &records {
            // hex of 32 bytes
            assert_eq!(cr.prev_hash.len(), 64);
            assert_eq!(cr.record_hash.len(), 64);
            assert_ne!(cr.chain_id.0, uuid::Uuid::nil());
            // principal was rewritten to "erased:<hex>"
            assert!(cr.record.principal.starts_with("erased:"));
        }
    }
}
