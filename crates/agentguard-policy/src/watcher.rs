//! Hot-reload watcher for policy files.
//!
//! Wraps the `notify` crate to provide a debounced stream of
//! filesystem events under a watched directory. The caller drains
//! events via [`PolicyWatcher::events`] and decides what to do (typically
//! call `PolicyStore::load_policies` to re-read the disk state).
//!
//! # Debouncing
//!
//! A single editor save can produce 3-5 raw events
//! (modify → close-write → chmod → ...). The watcher coalesces events
//! that arrive within `debounce` of each other into a single batch.
//! The kind is collapsed to the dominant kind for the batch (Create
//! wins, then Write, then Remove, then Other).
//!
//! # Errors
//!
//! `watch()` returns an error if the underlying watcher cannot register the
//! store (for example, because it does not exist or is unreadable). Runtime
//! errors delivered by `notify` are available through
//! [`PolicyWatcher::take_errors`]; an empty `events()` result is normal and
//! does not indicate watcher failure.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, PollWatcher, RecursiveMode, Watcher};

/// A debounced filesystem event for a watched policy directory.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    /// A bounded diagnostic sample of paths changed in this debounce window.
    /// This is not a complete change set; consumers must reload the complete
    /// policy store rather than update state based only on these paths.
    pub paths: Vec<PathBuf>,
    /// What kind of change occurred. See [`WatchEventKind`].
    pub kind: WatchEventKind,
}

/// High-level event kind. Maps roughly to `notify::EventKind` but
/// collapses the noisy variants (e.g. `Modify::Metadata` vs
/// `Modify::Data`) into one actionable case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEventKind {
    /// A file was created.
    Create,
    /// A file was written to (data changed).
    Write,
    /// A file was removed.
    Remove,
    /// Any other change (metadata, rename, etc.).
    Other,
}

const MAX_PENDING_WATCH_PATHS: usize = 128;
const MAX_PENDING_WATCH_ERRORS: usize = 16;
const MAX_WATCH_ERROR_BYTES: usize = 512;

impl From<&EventKind> for WatchEventKind {
    fn from(k: &EventKind) -> Self {
        match k {
            EventKind::Create(_) => Self::Create,
            EventKind::Modify(_) => Self::Write,
            EventKind::Remove(_) => Self::Remove,
            _ => Self::Other,
        }
    }
}

/// A debounced filesystem watcher.
///
/// The watcher runs a background thread that calls `notify`'s
/// recommended backend. Event paths and errors are coalesced into bounded
/// shared state; drain with [`PolicyWatcher::events`].
pub struct PolicyWatcher {
    _inner: PollWatcher,
    pending: Arc<Mutex<PendingSignals>>,
    debounce: Duration,
    last_emit: Option<Instant>,
}

struct PendingSignals {
    changed: bool,
    paths: Vec<PathBuf>,
    kind: WatchEventKind,
    pending_errors: Vec<String>,
    last_error: Option<String>,
}

impl Default for PendingSignals {
    fn default() -> Self {
        Self {
            changed: false,
            paths: Vec::new(),
            kind: WatchEventKind::Other,
            pending_errors: Vec::new(),
            last_error: None,
        }
    }
}

fn queue_new_error(errors: &mut Vec<String>, last_error: &mut Option<String>, mut error: String) {
    if error.len() > MAX_WATCH_ERROR_BYTES {
        let mut end = MAX_WATCH_ERROR_BYTES;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    if last_error.as_ref() != Some(&error) {
        if errors.len() < MAX_PENDING_WATCH_ERRORS {
            errors.push(error.clone());
        }
        *last_error = Some(error);
    }
}

fn promote_kind(current: WatchEventKind, incoming: WatchEventKind) -> WatchEventKind {
    match (current, incoming) {
        (WatchEventKind::Create, _) | (_, WatchEventKind::Create) => WatchEventKind::Create,
        (WatchEventKind::Write, _) | (_, WatchEventKind::Write) => WatchEventKind::Write,
        (WatchEventKind::Remove, _) | (_, WatchEventKind::Remove) => WatchEventKind::Remove,
        _ => WatchEventKind::Other,
    }
}

impl PendingSignals {
    fn record_event(&mut self, paths: impl IntoIterator<Item = PathBuf>, kind: WatchEventKind) {
        self.changed = true;
        self.last_error = None;
        self.kind = promote_kind(self.kind, kind);
        for path in paths {
            if self.paths.len() == MAX_PENDING_WATCH_PATHS {
                break;
            }
            self.paths.push(path);
        }
    }

    fn record_error(&mut self, error: String) {
        queue_new_error(&mut self.pending_errors, &mut self.last_error, error);
    }
}

impl PolicyWatcher {
    /// Drain any pending events. Returns an empty vec if no events
    /// are ready (i.e. nothing changed since the last call or the
    /// debounce window hasn't elapsed).
    pub fn events(&mut self) -> Vec<WatchEvent> {
        let now = Instant::now();
        let ready = match self.last_emit {
            None => true,
            Some(t) => now.duration_since(t) >= self.debounce,
        };
        if !ready {
            return Vec::new();
        }
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if !pending.changed {
            return Vec::new();
        }
        self.last_emit = Some(now);
        pending.changed = false;
        let paths = std::mem::take(&mut pending.paths);
        let kind = std::mem::replace(&mut pending.kind, WatchEventKind::Other);
        vec![WatchEvent { paths, kind }]
    }

    /// Drain newly observed runtime watcher errors. Identical errors are
    /// reported once until a successful filesystem event is observed.
    pub fn take_errors(&mut self) -> Vec<String> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut pending.pending_errors)
    }

    /// Stop watching. Idempotent. Drops the background thread and
    /// any buffered events.
    pub fn stop(self) {
        // RecommendedWatcher::drop joins the background thread.
        drop(self);
    }
}

/// Watch a policy store for changes to Cedar files anywhere under `policies/`
/// and to `schema.cedarschema`. The returned watcher is debounced: events that
/// arrive within `debounce` of each other are coalesced into a single batch.
pub fn watch<P: AsRef<Path>>(dir: P, debounce: Duration) -> std::io::Result<PolicyWatcher> {
    let dir = std::fs::canonicalize(dir.as_ref())?;
    let policies_dir = dir.join("policies");
    let schema_path = dir.join("schema.cedarschema");
    let pending = Arc::new(Mutex::new(PendingSignals::default()));
    let callback_pending = Arc::clone(&pending);
    let mut inner = PollWatcher::new(
        move |res: notify::Result<Event>| {
            // Collapse each notify::Event into (paths, kind). The kind
            // is the dominant kind for the event — multiple kinds in one
            // batch are coalesced at the consumer via `pending_kind`.
            match res {
                Ok(ev) => {
                    let kind = WatchEventKind::from(&ev.kind);
                    // Keep file matching aligned with `PolicyStore`'s
                    // recursive Cedar load semantics.
                    let paths = ev.paths.into_iter().filter(|path| {
                        path == &schema_path
                            || (path
                                .parent()
                                .is_some_and(|parent| parent.starts_with(&policies_dir))
                                && path.extension().is_some_and(|ext| ext == "cedar"))
                    });
                    let mut bounded_paths = Vec::new();
                    for path in paths {
                        if bounded_paths.len() == MAX_PENDING_WATCH_PATHS {
                            break;
                        }
                        bounded_paths.push(path);
                    }
                    if !bounded_paths.is_empty() {
                        callback_pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .record_event(bounded_paths, kind);
                    }
                }
                Err(error) => {
                    callback_pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_error(error.to_string());
                }
            }
        },
        Config::default()
            .with_poll_interval(Duration::from_millis(100))
            .with_compare_contents(true),
    )
    .map_err(|e| std::io::Error::other(format!("notify watcher: {e}")))?;
    inner
        .watch(&dir, RecursiveMode::Recursive)
        .map_err(|e| std::io::Error::other(format!("notify watch: {e}")))?;
    Ok(PolicyWatcher {
        _inner: inner,
        pending,
        debounce,
        last_emit: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    /// Store policies are nested one level below the root. They must still
    /// trigger a reload event.
    #[test]
    fn watcher_emits_event_for_nested_policy_create() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("policies")).unwrap();
        let mut w = watch(dir.path(), Duration::from_millis(50)).unwrap();
        // Give the watcher a moment to register.
        std::thread::sleep(Duration::from_millis(50));
        let path = dir.path().join("policies/test.cedar");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"permit (principal, action, resource);\n")
                .unwrap();
        }
        // Filesystem notification delivery is asynchronous and varies by
        // backend. Poll for a bounded period instead of relying on a fixed
        // sleep that flakes under load or on slower CI runners.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let events = loop {
            let events = w.events();
            if !events.is_empty() || std::time::Instant::now() >= deadline {
                break events;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(!events.is_empty(), "expected at least one event");
        let paths: Vec<_> = events.iter().flat_map(|e| e.paths.iter()).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("policies/test.cedar")),
            "expected policies/test.cedar in events, got: {paths:?}"
        );
    }

    #[test]
    fn watcher_emits_event_for_policy_in_nested_subdirectory() {
        let dir = tempdir().unwrap();
        let policy_dir = dir.path().join("policies/team");
        fs::create_dir_all(&policy_dir).unwrap();
        let mut watcher = watch(dir.path(), Duration::from_millis(50)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let path = policy_dir.join("read.cedar");
        fs::write(&path, "permit(principal, action, resource);").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let events = loop {
            let events = watcher.events();
            if !events.is_empty() || std::time::Instant::now() >= deadline {
                break events;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(
            events
                .iter()
                .flat_map(|event| &event.paths)
                .any(|changed| changed.ends_with("policies/team/read.cedar")),
            "expected nested policy path {path:?} in events: {events:?}"
        );
    }

    #[test]
    fn watcher_emits_event_for_schema_change() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("policies")).unwrap();
        let mut watcher = watch(dir.path(), Duration::from_millis(50)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        fs::write(dir.path().join("schema.cedarschema"), "namespace test {}").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let events = loop {
            let events = watcher.events();
            if !events.is_empty() || std::time::Instant::now() >= deadline {
                break events;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(
            events
                .iter()
                .flat_map(|event| &event.paths)
                .any(|path| path.ends_with("schema.cedarschema")),
            "expected schema.cedarschema in events: {events:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn watcher_detects_atomic_projected_volume_update() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let first = dir.path().join("..data-1");
        let second = dir.path().join("..data-2");
        fs::create_dir_all(first.join("policies")).unwrap();
        fs::create_dir_all(second.join("policies")).unwrap();
        fs::write(
            first.join("policies/allow.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        fs::write(
            second.join("policies/allow.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap();
        fs::create_dir(dir.path().join("policies")).unwrap();
        symlink(&first, dir.path().join("..data")).unwrap();
        symlink(
            "../..data/policies/allow.cedar",
            dir.path().join("policies/allow.cedar"),
        )
        .unwrap();

        let mut watcher = watch(dir.path(), Duration::from_millis(50)).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let next_link = dir.path().join("..data-next");
        symlink(&second, &next_link).unwrap();
        fs::rename(&next_link, dir.path().join("..data")).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let events = loop {
            let events = watcher.events();
            if !events.is_empty() || std::time::Instant::now() >= deadline {
                break events;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(
            events
                .iter()
                .flat_map(|event| &event.paths)
                .any(|path| { path.ends_with("policies/allow.cedar") }),
            "expected atomic projection update to report policies/allow.cedar: {events:?}"
        );
    }

    #[test]
    fn repeated_runtime_watcher_errors_are_deduplicated_until_recovery() {
        let mut errors = Vec::new();
        let mut last_error = None;
        queue_new_error(&mut errors, &mut last_error, "watch failed".to_owned());
        queue_new_error(&mut errors, &mut last_error, "watch failed".to_owned());
        assert_eq!(errors, ["watch failed"]);

        last_error = None; // A valid filesystem event clears the error state.
        queue_new_error(&mut errors, &mut last_error, "watch failed".to_owned());
        assert_eq!(errors, ["watch failed", "watch failed"]);
    }

    #[test]
    fn pending_watcher_signals_coalesce_and_stay_bounded() {
        let mut pending = PendingSignals::default();
        let paths = (0..MAX_PENDING_WATCH_PATHS + 50)
            .map(|index| PathBuf::from(format!("policies/{index}.cedar")));
        pending.record_event(paths, WatchEventKind::Write);
        pending.record_event(
            [PathBuf::from("policies/important.cedar")],
            WatchEventKind::Create,
        );

        assert!(pending.changed);
        assert_eq!(pending.paths.len(), MAX_PENDING_WATCH_PATHS);
        assert_eq!(pending.kind, WatchEventKind::Create);

        for index in 0..MAX_PENDING_WATCH_ERRORS + 10 {
            pending.record_error(format!("watch error {index}: {}", "x".repeat(1024)));
        }
        assert_eq!(pending.pending_errors.len(), MAX_PENDING_WATCH_ERRORS);
        assert!(pending
            .pending_errors
            .iter()
            .all(|error| error.len() <= MAX_WATCH_ERROR_BYTES));
    }

    /// The watcher stops cleanly when dropped (no panics, no leaked
    /// thread).
    #[test]
    fn watcher_stop_is_idempotent() {
        let dir = tempdir().unwrap();
        let w = watch(dir.path(), Duration::from_millis(10)).unwrap();
        w.stop();
    }
}
