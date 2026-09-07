//! Initialize a fresh agentguard store with the starter schema.

use crate::error::Result;
use crate::policy::store::PolicyStore;
use std::path::Path;

/// Initialize a new agentguard store at `root` with the starter schema.
pub fn init_store(root: impl AsRef<Path>) -> Result<()> {
    let store = PolicyStore::open(root.as_ref())?;
    let starter = include_str!("../../../../schemas/starter.cedarschema");
    store.write_schema(starter)?;
    Ok(())
}
