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

pub async fn run(
    store: &str,
    description: &str,
    name: Option<&str>,
    provider: &str,
    model: &str,
    _output: &str,
) -> Result<()> {
    let store = PolicyStore::open(store)?;
    let schema_text = std::fs::read_to_string(store.schema_path()).unwrap_or_default();

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

    let client = reqwest::Client::new();
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

    let resp = req.json(&body).send().await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let t = resp.text().await.unwrap_or_default();
        return Err(anyhow!("LLM API error {}: {}", s, t));
    }

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
