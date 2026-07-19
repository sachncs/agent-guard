//! In-memory metrics counters and histograms.
//!
//! Thread-safe via interior mutability. Renderable to Prometheus text format
//! for the `/metrics` endpoint (Stage 7).

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Default cap on the number of distinct label-tuples retained for
/// any one label-keyed metric. Prevents a misconfigured caller (or
/// an attacker-controlled `tenant_id`) from growing the map without
/// bound. When the cap is reached, new label-tuples are dropped and
/// a warning is logged ONCE per metric.
pub const DEFAULT_LABEL_CARDINALITY_CAP: usize = 4096;

fn warn_once(flag: &AtomicBool, msg: String) {
    if !flag.swap(true, Ordering::Relaxed) {
        tracing::warn!("{}", msg);
    }
}

/// Atomic-backed counter for cheap `inc()` from hot paths.
#[derive(Debug, Default)]
pub struct Counter {
    inner: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment and return the new value.
    pub fn inc(&self) -> u64 {
        self.inner.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Add `n` and return the new value.
    pub fn add(&self, n: u64) -> u64 {
        self.inner.fetch_add(n, Ordering::Relaxed) + n
    }

    pub fn get(&self) -> u64 {
        self.inner.load(Ordering::Relaxed)
    }
}

/// Snapshot of a gauge.
#[derive(Debug, Default)]
pub struct Gauge {
    inner: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, v: f64) {
        self.inner.store(v.to_bits(), Ordering::Relaxed);
    }

    pub fn get(&self) -> f64 {
        f64::from_bits(self.inner.load(Ordering::Relaxed))
    }
}

/// Histogram with exponential bucket boundaries.
///
/// Bucket boundaries are in seconds. Default: `[0.001, 0.01, 0.1, 1, 10]`.
#[derive(Debug)]
pub struct Histogram {
    name: String,
    buckets: Vec<f64>,
    /// Counts of observations ≤ the bucket boundary. Last bucket is +Inf.
    bucket_counts: Vec<Counter>,
    sum_micros: AtomicU64,
    count: Counter,
}

impl Histogram {
    pub fn new(name: impl Into<String>, buckets: &[f64]) -> Self {
        let mut sorted = buckets.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        sorted.dedup();
        let bucket_counts = (0..sorted.len() + 1).map(|_| Counter::new()).collect();
        Self {
            name: name.into(),
            buckets: sorted,
            bucket_counts,
            sum_micros: AtomicU64::new(0),
            count: Counter::new(),
        }
    }

    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        self.count.inc();
        self.sum_micros
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        for (i, b) in self.buckets.iter().enumerate() {
            if secs <= *b {
                self.bucket_counts[i].inc();
            }
        }
        // +Inf bucket always counts.
        self.bucket_counts[self.buckets.len()].inc();
    }

    pub fn count(&self) -> u64 {
        self.count.get()
    }

    pub fn sum_seconds(&self) -> f64 {
        self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn bucket_counts(&self) -> Vec<(f64, u64)> {
        self.buckets
            .iter()
            .zip(self.bucket_counts.iter())
            .map(|(b, c)| (*b, c.get()))
            .chain(std::iter::once((
                f64::INFINITY,
                self.bucket_counts.last().unwrap().get(),
            )))
            .collect()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Standard metrics for agentguard.
pub struct Metrics {
    /// `agentguard.decision.total{effect,policy_id,action,tenant_id}`
    decision_total: RwLock<HashMap<String, Arc<Counter>>>,
    /// `agentguard.decision.duration_seconds{action,tenant_id}`
    decision_duration: RwLock<HashMap<String, Arc<Histogram>>>,
    /// `agentguard.delegation.mint.total`
    delegation_mint_total: Counter,
    /// `agentguard.delegation.verify.total{outcome}`
    delegation_verify_total: RwLock<HashMap<String, Arc<Counter>>>,
    /// `agentguard.cache.hit.total` / `agentguard.cache.miss.total`
    cache_hit_total: Counter,
    cache_miss_total: Counter,
    /// `agentguard.policy.reload.total`
    policy_reload_total: Counter,
    /// `agentguard.pdp.error.total{fallback}`
    pdp_error_total: RwLock<HashMap<String, Arc<Counter>>>,
    /// Cardinality cap per label-keyed metric. New label-tuples beyond
    /// the cap are dropped to bound memory under untrusted label input.
    cardinality_cap: usize,
    /// One-shot warn flags so we don't flood the log when a metric
    /// saturates its cardinality cap.
    warn_decision_cap: AtomicBool,
    warn_duration_cap: AtomicBool,
    warn_pdp_error_cap: AtomicBool,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::with_cap(DEFAULT_LABEL_CARDINALITY_CAP)
    }
}

impl Metrics {
    /// Build a new metrics registry. Returns `Self`; wrap with
    /// `Arc::new(Metrics::new())` at the call site if shared
    /// ownership is needed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a registry with a custom cardinality cap. Used in tests
    /// that want to verify the cap is enforced.
    pub fn with_cap(cardinality_cap: usize) -> Self {
        Self {
            decision_total: RwLock::new(HashMap::new()),
            decision_duration: RwLock::new(HashMap::new()),
            delegation_mint_total: Counter::new(),
            delegation_verify_total: RwLock::new(HashMap::new()),
            cache_hit_total: Counter::new(),
            cache_miss_total: Counter::new(),
            policy_reload_total: Counter::new(),
            pdp_error_total: RwLock::new(HashMap::new()),
            cardinality_cap,
            warn_decision_cap: AtomicBool::new(false),
            warn_duration_cap: AtomicBool::new(false),
            warn_pdp_error_cap: AtomicBool::new(false),
        }
    }

    pub fn cardinality_cap(&self) -> usize {
        self.cardinality_cap
    }

    fn label_key(parts: &[&str]) -> String {
        parts.join("\x1f")
    }

    pub fn record_decision(
        &self,
        effect: &str,
        policy_id: &str,
        action: &str,
        tenant_id: &str,
        duration: Duration,
    ) {
        let key = Self::label_key(&[effect, policy_id, action, tenant_id]);
        {
            let mut totals = self.decision_total.write();
            if let Some(c) = totals.get(&key) {
                c.inc();
            } else if totals.len() < self.cardinality_cap {
                let c = Arc::new(Counter::new());
                c.inc();
                totals.insert(key.clone(), c);
            } else {
                warn_once(
                    &self.warn_decision_cap,
                    format!(
                        "agentguard.decision.total reached cardinality cap {}; \
                         dropping new label-tuples",
                        self.cardinality_cap
                    ),
                );
                return;
            }
        }
        let dur_key = Self::label_key(&[action, tenant_id]);
        let mut durations = self.decision_duration.write();
        if let Some(h) = durations.get(&dur_key) {
            h.observe(duration);
        } else if durations.len() < self.cardinality_cap {
            let h = Arc::new(Histogram::new(
                "agentguard.decision.duration_seconds",
                &[0.001, 0.01, 0.1, 1.0, 10.0],
            ));
            h.observe(duration);
            durations.insert(dur_key, h);
        } else {
            warn_once(
                &self.warn_duration_cap,
                format!(
                    "agentguard.decision.duration_seconds reached cardinality cap {}; \
                     dropping new label-tuples",
                    self.cardinality_cap
                ),
            );
        }
    }

    pub fn record_delegation_mint(&self) {
        self.delegation_mint_total.inc();
    }

    pub fn record_delegation_verify(&self, success: bool) {
        let key = if success { "success" } else { "failure" };
        self.delegation_verify_total
            .write()
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Counter::new()))
            .inc();
    }

    pub fn record_cache_hit(&self) {
        self.cache_hit_total.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_miss_total.inc();
    }

    pub fn record_policy_reload(&self) {
        self.policy_reload_total.inc();
    }

    pub fn record_pdp_error(&self, fallback: &str) {
        let key = fallback.to_string();
        let mut pdp_errors = self.pdp_error_total.write();
        if let Some(c) = pdp_errors.get(&key) {
            c.inc();
        } else if pdp_errors.len() < self.cardinality_cap {
            let c = Arc::new(Counter::new());
            c.inc();
            pdp_errors.insert(key, c);
        } else {
            warn_once(
                &self.warn_pdp_error_cap,
                format!(
                    "agentguard.pdp.error.total reached cardinality cap {}; \
                     dropping new label-tuples",
                    self.cardinality_cap
                ),
            );
        }
    }

    /// Render a snapshot of all counters in Prometheus text format.
    ///
    /// Uses `std::fmt::Write` to write directly into the output
    /// `String`, avoiding the dozens of `format!` temporaries the
    /// previous implementation allocated.
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write as _;

        // 4 KiB is enough for ~200 metrics with labels; the String
        // grows as needed.
        let mut out = String::with_capacity(4096);

        writeln!(
            out,
            "# HELP agentguard_decision_total Total authorization decisions"
        )
        .unwrap();
        writeln!(out, "# TYPE agentguard_decision_total counter").unwrap();
        let totals = self.decision_total.read();
        for (key, c) in totals.iter() {
            let parts: Vec<&str> = key.split('\x1f').collect();
            let effect = parts.first().copied().unwrap_or("");
            let policy_id = parts.get(1).copied().unwrap_or("");
            let action = parts.get(2).copied().unwrap_or("");
            let tenant_id = parts.get(3).copied().unwrap_or("");
            writeln!(
                out,
                "agentguard_decision_total{{effect=\"{}\",policy_id=\"{}\",action=\"{}\",tenant_id=\"{}\"}} {}",
                escape_label(effect),
                escape_label(policy_id),
                escape_label(action),
                escape_label(tenant_id),
                c.get(),
            )
            .unwrap();
        }
        drop(totals);

        writeln!(
            out,
            "# HELP agentguard_decision_duration_seconds Decision evaluation time"
        )
        .unwrap();
        writeln!(out, "# TYPE agentguard_decision_duration_seconds histogram").unwrap();
        let durations = self.decision_duration.read();
        for (key, h) in durations.iter() {
            let parts: Vec<&str> = key.split('\x1f').collect();
            let action = parts.first().copied().unwrap_or("");
            let tenant_id = parts.get(1).copied().unwrap_or("");
            for (b, count) in h.bucket_counts() {
                let le = if b.is_infinite() {
                    "+Inf".to_string()
                } else {
                    b.to_string()
                };
                writeln!(
                    out,
                    "agentguard_decision_duration_seconds_bucket{{action=\"{}\",tenant_id=\"{}\",le=\"{}\"}} {}",
                    escape_label(action),
                    escape_label(tenant_id),
                    le,
                    count,
                )
                .unwrap();
            }
            writeln!(
                out,
                "agentguard_decision_duration_seconds_count{{action=\"{}\",tenant_id=\"{}\"}} {}",
                escape_label(action),
                escape_label(tenant_id),
                h.count(),
            )
            .unwrap();
            writeln!(
                out,
                "agentguard_decision_duration_seconds_sum{{action=\"{}\",tenant_id=\"{}\"}} {}",
                escape_label(action),
                escape_label(tenant_id),
                h.sum_seconds(),
            )
            .unwrap();
        }
        drop(durations);

        writeln!(
            out,
            "# HELP agentguard_delegation_mint_total Total delegation tokens minted"
        )
        .unwrap();
        writeln!(out, "# TYPE agentguard_delegation_mint_total counter").unwrap();
        writeln!(
            out,
            "agentguard_delegation_mint_total {}",
            self.delegation_mint_total.get(),
        )
        .unwrap();

        writeln!(
            out,
            "# HELP agentguard_delegation_verify_total Total delegation verifications"
        )
        .unwrap();
        writeln!(out, "# TYPE agentguard_delegation_verify_total counter").unwrap();
        let verify = self.delegation_verify_total.read();
        for (outcome, c) in verify.iter() {
            writeln!(
                out,
                "agentguard_delegation_verify_total{{outcome=\"{}\"}} {}",
                escape_label(outcome),
                c.get(),
            )
            .unwrap();
        }
        drop(verify);

        writeln!(out, "# HELP agentguard_cache_hit_total Decision cache hits").unwrap();
        writeln!(out, "# TYPE agentguard_cache_hit_total counter").unwrap();
        writeln!(
            out,
            "agentguard_cache_hit_total {}",
            self.cache_hit_total.get()
        )
        .unwrap();
        writeln!(out, "# TYPE agentguard_cache_miss_total counter").unwrap();
        writeln!(
            out,
            "agentguard_cache_miss_total {}",
            self.cache_miss_total.get()
        )
        .unwrap();

        writeln!(out, "# TYPE agentguard_policy_reload_total counter").unwrap();
        writeln!(
            out,
            "agentguard_policy_reload_total {}",
            self.policy_reload_total.get()
        )
        .unwrap();

        writeln!(out, "# TYPE agentguard_pdp_error_total counter").unwrap();
        let pdp = self.pdp_error_total.read();
        for (fallback, c) in pdp.iter() {
            writeln!(
                out,
                "agentguard_pdp_error_total{{fallback=\"{}\"}} {}",
                escape_label(fallback),
                c.get(),
            )
            .unwrap();
        }

        out
    }

    /// Build a snapshot of all counters for programmatic access.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let decision_total: HashMap<String, u64> = self
            .decision_total
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.get()))
            .collect();
        let decision_duration: HashMap<String, (u64, f64)> = self
            .decision_duration
            .read()
            .iter()
            .map(|(k, h)| (k.clone(), (h.count(), h.sum_seconds())))
            .collect();
        MetricsSnapshot {
            decision_total,
            decision_duration,
            delegation_mint_total: self.delegation_mint_total.get(),
            delegation_verify_total: self
                .delegation_verify_total
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), v.get()))
                .collect(),
            cache_hit_total: self.cache_hit_total.get(),
            cache_miss_total: self.cache_miss_total.get(),
            policy_reload_total: self.policy_reload_total.get(),
            pdp_error_total: self
                .pdp_error_total
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), v.get()))
                .collect(),
        }
    }
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Snapshot of all metrics, suitable for JSON serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub decision_total: HashMap<String, u64>,
    pub decision_duration: HashMap<String, (u64, f64)>,
    pub delegation_mint_total: u64,
    pub delegation_verify_total: HashMap<String, u64>,
    pub cache_hit_total: u64,
    pub cache_miss_total: u64,
    pub policy_reload_total: u64,
    pub pdp_error_total: HashMap<String, u64>,
}

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let c = Counter::new();
        assert_eq!(c.inc(), 1);
        assert_eq!(c.inc(), 2);
        assert_eq!(c.add(5), 7);
    }

    #[test]
    fn histogram_observes_into_buckets() {
        let h = Histogram::new("test", &[0.1, 1.0, 10.0]);
        h.observe(Duration::from_millis(5));
        h.observe(Duration::from_millis(500));
        h.observe(Duration::from_secs(20));
        let counts = h.bucket_counts();
        // 5ms <= 0.1s and <= 1.0s and <= 10s and <= +Inf: all 4 buckets get +1
        // 500ms <= 1.0s and <= 10s and <= +Inf: 3 buckets
        // 20s only <= +Inf: 1 bucket
        let bucket_01 = counts.iter().find(|(b, _)| *b == 0.1).unwrap().1;
        let bucket_1 = counts.iter().find(|(b, _)| *b == 1.0).unwrap().1;
        let bucket_10 = counts.iter().find(|(b, _)| *b == 10.0).unwrap().1;
        let bucket_inf = counts.iter().find(|(b, _)| b.is_infinite()).unwrap().1;
        assert_eq!(bucket_01, 1);
        assert_eq!(bucket_1, 2);
        assert_eq!(bucket_10, 2);
        assert_eq!(bucket_inf, 3);
    }

    #[test]
    fn metrics_record_and_render() {
        let m = Metrics::new();
        m.record_decision(
            "allow",
            "policy0",
            "send_email",
            "tenant1",
            Duration::from_micros(500),
        );
        m.record_decision(
            "deny",
            "policy3",
            "shell_exec",
            "tenant1",
            Duration::from_micros(2000),
        );
        m.record_cache_hit();
        m.record_cache_hit();
        m.record_cache_miss();

        let text = m.render_prometheus();
        assert!(text.contains("agentguard_decision_total"));
        assert!(text.contains("effect=\"allow\""));
        assert!(text.contains("agentguard_cache_hit_total 2"));
        assert!(text.contains("agentguard_cache_miss_total 1"));
    }

    /// T4: render_prometheus on an empty registry returns the
    /// HELP/TYPE headers and no series lines for label-keyed metrics
    /// (Prometheus requires the headers to be emitted even with no
    /// data). Label-free counters are always emitted with their
    /// initial 0 value.
    #[test]
    fn render_prometheus_empty_registry() {
        let m = Metrics::new();
        let text = m.render_prometheus();
        // Label-keyed metric: headers but no series.
        assert!(text.contains("# HELP agentguard_decision_total"));
        assert!(text.contains("# TYPE agentguard_decision_total counter"));
        assert!(!text.contains("agentguard_decision_total{"));
        // Label-free counter: always present with value 0.
        assert!(text.contains("agentguard_cache_hit_total 0"));
    }

    /// Cardinality invariant: even if a caller records 10× more
    /// distinct label tuples than the cap, the underlying map never
    /// grows past `cardinality_cap`. (Older entries are silently
    /// dropped once the cap is reached.)
    #[test]
    fn cardinality_cap_is_enforced() {
        let m = Metrics::with_cap(8);
        for i in 0..100 {
            m.record_decision(
                "allow",
                "policy0",
                &format!("action-{i}"),
                "",
                std::time::Duration::from_micros(i as u64),
            );
        }
        let snap = m.snapshot();
        assert_eq!(
            snap.decision_total.len(),
            8,
            "cardinality cap must be enforced; got {} entries",
            snap.decision_total.len()
        );
    }
}
