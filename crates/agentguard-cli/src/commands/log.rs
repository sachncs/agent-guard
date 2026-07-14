use agentguard_core::DecisionLog;
use anyhow::Result;

pub fn tail(
    audit: &str,
    n: usize,
    principal: Option<&str>,
    action: Option<&str>,
    output: &str,
) -> Result<()> {
    let records = DecisionLog::read_all(audit)?;
    let mut filtered: Vec<_> = records
        .into_iter()
        .filter(|r| principal.map(|p| r.principal.contains(p)).unwrap_or(true))
        .filter(|r| action.map(|a| r.action.contains(a)).unwrap_or(true))
        .collect();
    filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let slice = filtered.into_iter().take(n).collect::<Vec<_>>();

    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&slice)?);
    } else {
        for r in slice.iter().rev() {
            let sym = if r.effect == "allow" { "✓" } else { "✗" };
            println!(
                "{} {} {:>5} {} {} {}",
                r.timestamp.format("%H:%M:%S"),
                sym,
                r.effect.to_uppercase(),
                r.principal,
                r.action,
                r.resource
            );
        }
        if slice.is_empty() {
            println!("(no matching decisions)");
        }
    }
    Ok(())
}

pub fn dump(audit: &str, output: &str) -> Result<()> {
    let records = DecisionLog::read_all(audit)?;
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else {
        for r in &records {
            println!("{}", serde_json::to_string_pretty(r)?);
        }
    }
    Ok(())
}
