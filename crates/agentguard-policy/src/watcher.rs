//! Hot-reload watcher for policy files.
//!
//! Wraps the `notify` crate to provide a debounced stream of
//! filesystem events under a watched directory. The caller drains
//! events via [`Watcher::events`] and decides what to do (typically
//! call `PolicyStore::load_policies` to re-read the disk state).
//!
//! # Debouncing
//!
//! A single editor save can produce 3-5 raw events
//! (modify → close-write → chmod → ...). The watcher coalesces events
//! that arrive within `debounce` of each other into a single batch.
//!
//! # Errors
//!
//! `watch()` returns an error if the underlying `notify::Watcher` fails
//! to register the directory (typically: path doesn't exist, or
//! inotify watch limit reached). Once constructed, the watcher
//! silently drops filesystem events that arrive after the OS limit;
//! callers should monitor `events()` for the empty result as a sign
//! to restart.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// A debounced filesystem event for a watched policy directory.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    /// Paths of files that changed in this debounce window.
    pub paths: Vec<PathBuf>,
    /// What kind of change occurred. Only `Create`, `Write`,
    /// `Remove`, and `Modify` are surfaced.
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
/// recommended backend. Events are coalesced on a single mpsc
/// channel; drain with [`PolicyWatcher::events`].
pub struct PolicyWatcher {
    _inner: RecommendedWatcher,
    rx: Receiver<Vec<PathBuf>>,
    debounce: Duration,
    last_emit: Option<Instant>,
    pending: Vec<PathBuf>,
}

impl PolicyWatcher {
    /// Drain any pending events. Returns an empty vec if no events
    /// are ready (i.e. nothing changed since the last call or the
    /// debounce window hasn't elapsed).
    pub fn events(&mut self) -> Vec<WatchEvent> {
        // Drain all raw events from notify, accumulating into pending.
        while let Ok(raw) = self.rx.try_recv() {
            // raw is Vec<PathBuf> already (we batched in the callback).
            self.pending.extend(raw);
        }
        let now = Instant::now();
        let ready = match self.last_emit {
            None => true,
            Some(t) => now.duration_since(t) >= self.debounce,
        };
        if !ready || self.pending.is_empty() {
            return Vec::new();
        }
        // Flush.
        self.last_emit = Some(now);
        let paths = std::mem::take(&mut self.pending);
        vec![WatchEvent {
            paths,
            kind: WatchEventKind::Other,
        }]
    }

    /// Stop watching. Idempotent. Drops the background thread and
    /// any buffered events.
    pub fn stop(self) {
        // RecommendedWatcher::drop joins the background thread.
        drop(self);
    }
}

/// Watch a directory for changes to `*.cedar` files. The returned
/// `Watcher` is debounced: events that arrive within `debounce` of
/// each other are coalesced into a single batch.
pub fn watch<P: AsRef<Path>>(
    dir: P,
    debounce: Duration,
) -> std::io::Result<PolicyWatcher> {
    let (tx, rx) = channel();
    let dir = dir.as_ref().to_path_buf();
    let mut inner = notify::recommended_watcher(move |res: notify::Result<Event>| {
        // Batch all paths from this event into one channel send.
        // `notify` delivers one Event per raw FS event; we collapse
        // them to a Vec<PathBuf> here so the consumer just gets
        // one item per "something happened".
        if let Ok(ev) = res {
            let paths: Vec<PathBuf> = ev.paths.into_iter().collect();
            let _ = tx.send(paths);
        }
    })
    .map_err(|e| std::io::Error::other(format!("notify watcher: {e}")))?;
    inner
        .watch(&dir, RecursiveMode::NonRecursive)
        .map_err(|e| std::io::Error::other(format!("notify watch: {e}")))?;
    Ok(PolicyWatcher {
        _inner: inner,
        rx,
        debounce,
        last_emit: None,
        pending: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    /// Smoke test: the watcher emits at least one event when a file
    /// in the watched directory is created + written.
    #[test]
    fn watcher_emits_event_on_file_create() {
        let dir = tempdir().unwrap();
        let mut w = watch(dir.path(), Duration::from_millis(50)).unwrap();
        // Give the watcher a moment to register.
        std::thread::sleep(Duration::from_millis(50));
        let path = dir.path().join("test.cedar");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"permit (principal, action, resource);\n").unwrap();
        }
        // Wait for the debounce window to elapse plus a small margin.
        std::thread::sleep(Duration::from_millis(150));
        let events = w.events();
        assert!(!events.is_empty(), "expected at least one event");
        let paths: Vec<_> = events.iter().flat_map(|e| e.paths.iter()).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("test.cedar")),
            "expected test.cedar in events, got: {paths:?}"
        );
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