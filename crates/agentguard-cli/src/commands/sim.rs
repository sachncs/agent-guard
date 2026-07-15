use agentguard_core::authorize::build_entities;
use agentguard_core::{AgentRequest, Authorizer, PolicyStore};
use anyhow::Result;
use std::path::Path;

pub fn run(
    store: impl AsRef<Path>,
    request: impl AsRef<Path>,
    entities_path: Option<impl AsRef<Path>>,
    output: &str,
) -> Result<()> {
    let text = if request.as_ref().as_os_str() == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    } else {
        std::fs::read_to_string(request)?
    };
    let req: AgentRequest = serde_json::from_str(&text)?;

    let entities = if let Some(p) = entities_path {
        let text = std::fs::read_to_string(p.as_ref())?;
        let arr: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        build_entities(arr)?
    } else {
        cedar_policy::Entities::empty()
    };

    let store = PolicyStore::open(store)?;
    let engine = Authorizer::new(store)?;
    let decision = engine.authorize(&req, &entities)?;

    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        let sym = match decision.effect {
            agentguard_core::authorize::Effect::Allow => "✓ ALLOW",
            _ => "✗ DENY ",
        };
        println!(
            "{}  {} → {} on {}",
            sym,
            req.principal,
            req.action.action_uid(),
            req.resource
        );
        if !decision.policies.is_empty() {
            println!("    policies: {}", decision.policies.join(", "));
        }
        for r in &decision.reasons {
            println!("    reason:   {}", r);
        }
    }
    Ok(())
}
