use agentguard_core::{
    authorize::build_entities, AgentRequest, Authorizer, DecisionLog, PolicyStore,
};
use anyhow::{anyhow, Result};
use base64::Engine as _;
use std::io::Read;
use std::path::Path;

/// A policy decision returned to the caller.
#[derive(Debug)]
pub struct AuthorizeOutcome {
    /// The decision effect.
    #[allow(dead_code)]
    pub effect: agentguard_core::authorize::Effect,
    /// Whether the decision was an Allow.
    pub decision_was_allow: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: impl AsRef<Path>,
    audit: impl AsRef<Path>,
    request: impl AsRef<Path>,
    entities_path: Option<impl AsRef<Path>>,
    no_audit: bool,
    output: &str,
) -> Result<AuthorizeOutcome> {
    let req: AgentRequest = if request.as_ref().as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        serde_json::from_str(&buf)?
    } else {
        let text = std::fs::read_to_string(request.as_ref())?;
        serde_json::from_str(&text)?
    };

    let entities = load_entities(entities_path.as_ref().map(|p| p.as_ref()))?;

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
                DecisionLog::open_with_chain(audit.as_ref(), &key)?
            } else {
                DecisionLog::open(audit.as_ref())?
            }
        } else {
            DecisionLog::open(audit.as_ref())?
        };
        log.append_decision(&decision)?;
    }

    let outcome = AuthorizeOutcome {
        effect: decision.effect,
        decision_was_allow: matches!(decision.effect, agentguard_core::authorize::Effect::Allow),
    };
    Ok(outcome)
}

fn load_entities(path: Option<&Path>) -> Result<cedar_policy::Entities> {
    let path = path.unwrap_or_else(|| Path::new(".agentguard/entities.json"));
    if !path.exists() {
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

/// Parse a chain secret: hex (64 chars) or base64. Falls back to raw bytes
/// on decode error.
fn trim_key(bytes: &[u8]) -> Vec<u8> {
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(b) = hex::decode(s) {
                return b;
            }
        }
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
            return b;
        }
    }
    bytes.to_vec()
}