use agentguard_core::{
    authorize::build_entities, decode_chain_secret, AgentRequest, Authorizer, DecisionLog,
    PolicyStore,
};
use anyhow::{anyhow, Result};
use std::path::Path;
use tokio::io::AsyncReadExt;

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
    secret_file: Option<&Path>,
) -> Result<AuthorizeOutcome> {
    let mut req: AgentRequest = if request.as_ref().as_os_str() == "-" {
        let mut buf = String::new();
        tokio::io::stdin().read_to_string(&mut buf).await?;
        serde_json::from_str(&buf)?
    } else {
        let text = tokio::fs::read_to_string(request.as_ref()).await?;
        serde_json::from_str(&text)?
    };

    // The TS SDK (and any other wrapper that spawns the CLI as a
    // subprocess) forwards W3C trace context via AGENTGUARD_TRACEPARENT
    // so distributed traces stitch across the process boundary.
    // Apply it on top of whatever the request file carried — the env
    // var wins when present because the wrapper knew its caller.
    if let Ok(tp) = std::env::var("AGENTGUARD_TRACEPARENT") {
        match tp.parse::<agentguard_core::observability::TraceContext>() {
            Ok(ctx) => req.trace = Some(ctx),
            Err(e) => tracing::warn!(
                tp = %tp,
                error = %e,
                "AGENTGUARD_TRACEPARENT is not a valid trace context; ignoring"
            ),
        }
    }

    // AGENTGUARD_BEARER has no in-process use today (the CLI does not
    // contact a remote PDP), but the TS SDK still forwards it. Warn
    // once at startup so a misconfigured deployment gets a hint
    // instead of a silent no-op.
    if std::env::var_os("AGENTGUARD_BEARER").is_some() {
        tracing::debug!(
            "AGENTGUARD_BEARER is set; the CLI evaluates in-process and does \
             not currently forward this token. Use it when running an \
             agentguard-server deployment instead."
        );
    }

    let entities = load_entities(entities_path.as_ref().map(|p| p.as_ref())).await?;

    // Cedar engine evaluation + filesystem reads are CPU/IO heavy —
    // offload to a blocking thread so the tokio runtime stays
    // responsive.
    let store_path = store.as_ref().to_path_buf();
    let audit_path = audit.as_ref().to_path_buf();
    let secret_path_buf = secret_file.map(|p| p.to_path_buf());
    let req_for_blocking = req.clone();
    let entities_for_blocking = entities.clone();
    let decision =
        tokio::task::spawn_blocking(move || -> Result<agentguard_core::authorize::Decision> {
            let store = PolicyStore::open(&store_path)?;
            let engine = Authorizer::new(store)?;
            let decision = engine.authorize(&req_for_blocking, &entities_for_blocking)?;
            Ok(decision)
        })
        .await
        .map_err(|e| anyhow!("blocking task: {e}"))??;

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
        println!("action:    {}", req.action);
        println!("resource:  {}", req.resource);
        if !decision.policies.is_empty() {
            println!("policies:  {}", decision.policies.join(", "));
        }
        for r in &decision.reasons {
            println!("  - {}", r);
        }
    }

    if !no_audit {
        // Open hash-chained log if a secret file is provided via
        // --secret-file / AGENTGUARD_CHAIN_SECRET. Read errors
        // surface (no silent plain-mode downgrade). Audit writes
        // are sync IO and stay on the blocking thread.
        let audit_path_for_blocking = audit_path.clone();
        let secret_path_for_blocking = secret_path_buf.clone();
        let decision_for_blocking = decision.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let log = match &secret_path_for_blocking {
                Some(path) => {
                    let key = std::fs::read(path)
                        .map_err(|e| anyhow!("read chain secret {:?}: {}", path, e))?;
                    let key = decode_chain_secret(&key)
                        .ok_or_else(|| anyhow!("chain secret file {:?} is empty", path))?;
                    DecisionLog::open_with_chain(&audit_path_for_blocking, &key)?
                }
                None => DecisionLog::open(&audit_path_for_blocking)?,
            };
            log.append_decision(&decision_for_blocking)?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("blocking task: {e}"))??;
    }

    let outcome = AuthorizeOutcome {
        effect: decision.effect,
        decision_was_allow: matches!(decision.effect, agentguard_core::authorize::Effect::Allow),
    };
    Ok(outcome)
}

async fn load_entities(path: Option<&Path>) -> Result<cedar_policy::Entities> {
    let path = path.unwrap_or_else(|| Path::new(".agentguard/entities.json"));
    if !path.exists() {
        return Ok(cedar_policy::Entities::empty());
    }
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<cedar_policy::Entities> {
        let text = std::fs::read_to_string(&path)?;
        let arr: Vec<serde_json::Value> = serde_json::from_str(&text).map_err(|e| {
            anyhow!(
                "entities file must be a JSON array of entity objects: {}",
                e
            )
        })?;
        build_entities(arr).map_err(Into::into)
    })
    .await
    .map_err(|e| anyhow!("blocking task: {e}"))?
}
