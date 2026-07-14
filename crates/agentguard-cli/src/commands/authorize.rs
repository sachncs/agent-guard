use agentguard_core::{
    authorize::build_entities, AgentRequest, Authorizer, DecisionLog, PolicyStore,
};
use anyhow::{anyhow, Result};
use std::io::Read;

pub async fn run(
    store: &str,
    audit: &str,
    request: &str,
    entities_path: Option<&str>,
    no_audit: bool,
    output: &str,
) -> Result<()> {
    let req: AgentRequest = if request == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        serde_json::from_str(&buf)?
    } else {
        let text = std::fs::read_to_string(request)?;
        serde_json::from_str(&text)?
    };

    let entities = load_entities(entities_path)?;

    let store = PolicyStore::open(store)?;
    let engine = Authorizer::new(store)?;
    let decision = engine.authorize(&req, &entities)?;

    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        let color = match decision.effect {
            agentguard_core::authorize::Effect::Allow => "\x1b[32m",
            _ => "\x1b[31m",
        };
        println!(
            "{} {}\x1b[0m",
            color,
            format!("{:?}", decision.effect).to_uppercase()
        );
        println!("principal: {}", req.principal);
        println!("action:    {}", req.action.action_uid());
        println!("resource:  {}", req.resource);
        if !decision.policies.is_empty() {
            println!("policies:  {}", decision.policies.join(", "));
        }
        for r in &decision.reasons {
            println!("  - {}", r);
        }
    }

    if !no_audit {
        // Open hash-chained log if AGENTGUARD_CHAIN_SECRET points to a file.
        let log = if let Ok(secret_path) = std::env::var("AGENTGUARD_CHAIN_SECRET") {
            let key = std::fs::read(&secret_path).unwrap_or_default();
            if !key.is_empty() {
                let key = trim_key(&key);
                DecisionLog::open_with_chain(audit, &key)?
            } else {
                DecisionLog::open(audit)?
            }
        } else {
            DecisionLog::open(audit)?
        };
        log.append_decision(&decision)?;
    }

    if matches!(decision.effect, agentguard_core::authorize::Effect::Deny) {
        // Keep exit 0 so callers can still read the JSON; they can use output format if they want nonzero on deny.
        // To preserve original CLI behavior some tools want, we exit 2 here.
        std::process::exit(2);
    }
    Ok(())
}

fn load_entities(path: Option<&str>) -> Result<cedar_policy::Entities> {
    let path = path.unwrap_or(".agentguard/entities.json");
    if !std::path::Path::new(path).exists() {
        return Ok(cedar_policy::Entities::empty());
    }
    let text = std::fs::read_to_string(path)?;
    let arr: Vec<serde_json::Value> = serde_json::from_str(&text).map_err(|e| {
        anyhow!(
            "entities file must be a JSON array of entity objects: {}",
            e
        )
    })?;
    build_entities(arr).map_err(Into::into)
}

fn trim_key(bytes: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(bytes)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(&s).unwrap_or_else(|_| s.into_bytes());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .unwrap_or_else(|_| s.into_bytes())
}
