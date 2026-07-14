use agentguard_core::{describe, PolicyStore};
use anyhow::Result;

pub fn run(store: &str, output: &str) -> Result<()> {
    let store = PolicyStore::open(store)?;
    match store.load_schema()? {
        Some(schema) => {
            let summary = describe(&schema.source)?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("entity types:");
                for e in &summary.entities {
                    println!("  {}", e.name);
                    for a in &e.attributes {
                        let req = if a.required { "*" } else { "?" };
                        println!("    {}{}: {}", req, a.name, a.ty);
                    }
                }
                println!("actions:");
                for a in &summary.actions {
                    println!("  Action::\"{}\"", a.name);
                }
            }
        }
        None => {
            println!("no schema found at {}", store.schema_path().display());
        }
    }
    Ok(())
}
