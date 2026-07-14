use agentguard_core::PolicyStore;
use anyhow::Result;

pub fn run(store: &str, _output: &str) -> Result<()> {
    let store = PolicyStore::open(store)?;
    let report = store.validate()?;
    println!("Loaded {} policies.", report.policy_count);
    if report.errors.is_empty() && report.warnings.is_empty() {
        println!("✓ no errors, no warnings");
    }
    let is_ok = report.is_ok();
    for w in &report.warnings {
        println!("  warn  {}: {}", w.policy, w.message);
    }
    for e in &report.errors {
        println!("  ERR   {}: {}", e.policy, e.message);
    }
    if !is_ok {
        std::process::exit(1);
    }
    Ok(())
}
