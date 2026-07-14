//! Hot-reload watcher for policy files.
//!
//! **Status:** scaffolding — the public surface exists so the crate
//! compiles with `--features watch`, but the actual `notify`-backed
//! implementation is left for v0.3.0. Until then, calling `watch()`
//! returns a watcher handle that never fires; callers should poll the
//! policy store directly via [`crate::PolicyStore::load_policies`] or
//! use an external supervisor (systemd, k8s ConfigMap) to trigger
//! reloads.

use std::path::Path;
use std::time::Duration;

/// A no-op watcher. Constructed by [`watch`]; never fires.
pub struct PolicyWatcher {
    _private: (),
}

impl PolicyWatcher {
    /// Stop watching. Idempotent. The v0.3.0 implementation will
    /// signal the background task to exit and join it.
    pub fn stop(self) {}
}

/// Begin watching `dir` for changes to policy files. The returned
/// watcher is a stub until v0.3.0.
pub fn watch<P: AsRef<Path>>(_dir: P, _debounce: Duration) -> std::io::Result<PolicyWatcher> {
    Ok(PolicyWatcher { _private: () })
}