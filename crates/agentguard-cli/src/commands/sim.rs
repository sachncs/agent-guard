use agentguard_core::authorize::build_entities;
use agentguard_core::{AgentRequest, Authorizer, PolicyStore};
use anyhow::Result;
use std::path::Path;
use tokio::io::AsyncReadExt;

pub async fn run(
    store: impl AsRef<Path>,
    request: impl AsRef<Path>,
    entities_path: Option<impl AsRef<Path>>,
    output: &str,
) -> Result<()> {
    let text = if request.as_ref().as_os_str() == "-" {
        let mut buf = String::new();
        tokio::io::stdin().read_to_string(&mut buf).await?;
        buf
    } else {
        tokio::fs::read_to_string(request.as_ref()).await?
    };
    let req: AgentRequest = serde_json::from_str(&text)?;

    let entities = if let Some(p) = entities_path {
        let path = p.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<cedar_policy::Entities> {
            let text = std::fs::read_to_string(&path)?;
            let arr: Vec<serde_json::Value> = serde_json::from_str(&text)?;
            Ok(build_entities(arr)?)
        })
        .await
        .map_err(|e| anyhow::anyhow!("blocking task: {e}"))??
    } else {
        cedar_policy::Entities::empty()
    };

    let store_path = store.as_ref().to_path_buf();
    let req_for_blocking = req.clone();
    let entities_for_blocking = entities.clone();
    let decision = tokio::task::spawn_blocking(move || -> Result<agentguard_core::authorize::Decision> {
        let store = PolicyStore::open(&store_path)?;
        let engine = Authorizer::new(store)?;
        Ok(engine.authorize(&req_for_blocking, &entities_for_blocking)?)
    })
    .await
    .map_err(|e| anyhow::anyhow!("blocking task: {e}"))??;

    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        let sym = match decision.effect {
            agentguard_core::authorize::Effect::Allow => "✓ ALLOW",
            _ => "✗ DENY ",
        };
        println!(
            "{}  {} → {} on {}",
            sym, req.principal, req.action, req.resource
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
