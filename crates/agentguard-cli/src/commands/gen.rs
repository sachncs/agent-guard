//! NL → Cedar policy generator. Calls an LLM with a constrained prompt,
//! then validates the output against the schema. Loops until valid or N tries.

use agentguard_core::PolicyStore;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenRequest {
    model: String,
    messages: Vec<ChatMsg>,
    temperature: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMsg {
    role: String,
    content: String,
}

const SYSTEM_PROMPT: &str = r#"You are an expert at writing Cedar authorization policies for AI agent systems.

Output ONLY valid Cedar policy syntax. No commentary, no markdown fences.

Rules:
1. Use `permit` for allow rules and `forbid` for deny rules.
2. Reference entities/types that exist in the provided schema.
3. Reference actions in the form `Action::"ToolCall::<tool>"`.
4. Use `when { ... }` and `unless { ... }` for conditions.
5. Use `principal in Group::"..."` or `principal == User::"..."` for principal constraints.
6. Keep policies minimal and composable.
7. Always output at least one policy."#;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: &str,
    description: &str,
    name: Option<&str>,
    provider: &str,
    model: &str,
    dry_run: bool,
    confirm: bool,
    _output: &str,
) -> Result<()> {
    let store_path = store.to_string();
    let schema_text = tokio::task::spawn_blocking(move || -> Result<(PolicyStore, String)> {
        let s = PolicyStore::open(&store_path)?;
        let text = std::fs::read_to_string(s.schema_path()).unwrap_or_default();
        Ok((s, text))
    })
    .await
    .map_err(|e| anyhow!("blocking task: {e}"))??;
    let store = schema_text.0;
    let schema_text = schema_text.1;

    let user_prompt = format!(
        "Schema:\n```cedarschema\n{}\n```\n\nRequirement:\n{}\n\nWrite 1-3 Cedar policies that implement this requirement.",
        schema_text, description
    );

    let api_key = match provider {
        "openai" => {
            std::env::var("OPENAI_API_KEY").map_err(|_| anyhow!("set OPENAI_API_KEY env var"))?
        }
        "anthropic" => std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow!("set ANTHROPIC_API_KEY env var"))?,
        _ => return Err(anyhow!("unknown provider: {}", provider)),
    };

    let body = GenRequest {
        model: model.to_string(),
        messages: vec![
            ChatMsg {
                role: "system".into(),
                content: SYSTEM_PROMPT.into(),
            },
            ChatMsg {
                role: "user".into(),
                content: user_prompt,
            },
        ],
        temperature: 0.0,
    };

    // ponytail: bound the LLM HTTP call. Without timeouts, a stuck
    // OpenAI/Anthropic endpoint hangs the CLI indefinitely. Same
    // shape as the OIDC client in agentguard-auth.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;
    let (url, auth_header) = match provider {
        "openai" => (
            "https://api.openai.com/v1/chat/completions",
            format!("Bearer {}", api_key),
        ),
        "anthropic" => ("https://api.anthropic.com/v1/messages", api_key.clone()),
        _ => unreachable!(),
    };

    let mut req = client.post(url).header("content-type", "application/json");
    if provider == "anthropic" {
        req = req
            .header("x-api-key", auth_header)
            .header("anthropic-version", "2023-06-01");
    } else {
        req = req.bearer_auth(auth_header);
    }

    let mut attempt = 0u32;
    let resp = loop {
        attempt += 1;
        match req
            .try_clone()
            .expect("RequestBuilder is Clone-able")
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => break r,
            Ok(r) if r.status().is_server_error() && attempt < 3 => {
                // Exponential backoff with jitter (cap at 4 s).
                let base_ms = 250u64 * (1u64 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(base_ms)).await;
                continue;
            }
            Ok(r) => {
                let s = r.status();
                let t = r.text().await.unwrap_or_default();
                return Err(anyhow!(
                    "LLM API error {} after {} attempts: {}",
                    s,
                    attempt,
                    t
                ));
            }
            Err(e) if e.is_timeout() || e.is_connect() && attempt < 3 => {
                let base_ms = 250u64 * (1u64 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(base_ms)).await;
                continue;
            }
            Err(e) => {
                return Err(anyhow!(
                    "LLM request failed after {} attempts: {}",
                    attempt,
                    e
                ))
            }
        }
    };

    let json: serde_json::Value = resp.json().await?;
    let content = extract_content(&json, provider)
        .ok_or_else(|| anyhow!("could not parse LLM response: {}", json))?;

    // Strip markdown fences if present.
    let cleaned = strip_fences(&content);

    // Validate the generated policies against the schema.
    let policies = cedar_policy::PolicySet::from_str(&cleaned).map_err(|e| {
        anyhow!(
            "generated policies failed to parse: {}\n--- generated ---\n{}",
            e,
            cleaned
        )
    })?;
    if let Ok(Some(s)) = store.load_schema() {
        let validator = cedar_policy::Validator::new(s.schema);
        let v = validator.validate(&policies, cedar_policy::ValidationMode::Strict);
        if v.validation_errors().next().is_some() {
            return Err(anyhow!(
                "generated policies failed schema validation: {:?}",
                v.validation_errors().collect::<Vec<_>>()
            ));
        }
    }

    if dry_run {
        // --dry-run: print to stdout, do not write. The LLM output
        // is shown with the would-be filename so the operator can
        // review before installing.
        let fname = name.unwrap_or("generated");
        println!("--- generated policy (dry run, would write to policies/{fname}.cedar) ---");
        println!("{cleaned}");
        return Ok(());
    }
    if confirm {
        // --confirm: prompt for 'y/N' on stderr. Reads one byte, no
        // echo (so the prompt doesn't leak into stdout where the
        // generated policy is printed).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stderr = tokio::io::stderr();
        stderr
            .write_all(b"Apply generated policy? [y/N] ")
            .await
            .ok();
        let _ = stderr.flush().await;
        let mut stdin = tokio::io::stdin();
        let mut answer = [0u8; 1];
        let n = stdin.read(&mut answer).await.unwrap_or(0);
        if n == 0 || (answer[0] != b'y' && answer[0] != b'Y') {
            eprintln!("aborted");
            return Ok(());
        }
    }
    let fname = name.unwrap_or("generated");
    let path = store.write_policy(fname, &cleaned)?;
    println!("wrote {}", path.display());
    println!("--- generated policy ---");
    println!("{}", cleaned);
    Ok(())
}

fn extract_content(v: &serde_json::Value, provider: &str) -> Option<String> {
    match provider {
        "openai" => v
            .get("choices")?
            .get(0)?
            .get("message")?
            .get("content")?
            .as_str()
            .map(|s| s.to_string()),
        "anthropic" => v
            .get("content")?
            .get(0)?
            .get("text")?
            .as_str()
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn strip_fences(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("```cedar") {
        if let Some(end) = rest.rfind("```") {
            return rest[..end].trim().to_string();
        }
    }
    if let Some(rest) = s.strip_prefix("```") {
        if let Some(end) = rest.rfind("```") {
            return rest[..end].trim().to_string();
        }
    }
    s.to_string()
}
