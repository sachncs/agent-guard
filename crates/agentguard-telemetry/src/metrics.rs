//! In-memory metrics counters and histograms.
//!
//! Thread-safe via interior mutability. Renderable to Prometheus text format
//! for the `/metrics` endpoint (Stage 7).

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
        let bucket_counts = (0..sorted.len() + 1)
            .map(|_| Counter::new())
            .collect();
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
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            decision_total: RwLock::new(HashMap::new()),
            decision_duration: RwLock::new(HashMap::new()),
            delegation_mint_total: Counter::new(),
            delegation_verify_total: RwLock::new(HashMap::new()),
            cache_hit_total: Counter::new(),
            cache_miss_total: Counter::new(),
            policy_reload_total: Counter::new(),
            pdp_error_total: RwLock::new(HashMap::new()),
        }
    }
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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
        self.decision_total
            .write()
            .entry(key)
            .or_insert_with(|| Arc::new(Counter::new()))
            .inc();
        let dur_key = Self::label_key(&[action, tenant_id]);
        let mut durations = self.decision_duration.write();
        durations
            .entry(dur_key)
            .or_insert_with(|| {
                Arc::new(Histogram::new(
                    "agentguard.decision.duration_seconds",
                    &[0.001, 0.01, 0.1, 1.0, 10.0],
                ))
            })
            .observe(duration);
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
        self.pdp_error_total
            .write()
            .entry(fallback.to_string())
            .or_insert_with(|| Arc::new(Counter::new()))
            .inc();
    }

    /// Render a snapshot of all counters in Prometheus text format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP agentguard_decision_total Total authorization decisions\n");
        out.push_str("# TYPE agentguard_decision_total counter\n");
        let totals = self.decision_total.read();
        for (key, c) in totals.iter() {
            let parts: Vec<&str> = key.split('\x1f').collect();
            let effect = parts.first().copied().unwrap_or("");
            let policy_id = parts.get(1).copied().unwrap_or("");
            let action = parts.get(2).copied().unwrap_or("");
            let tenant_id = parts.get(3).copied().unwrap_or("");
            out.push_str(&format!(
                "agentguard_decision_total{{effect=\"{}\",policy_id=\"{}\",action=\"{}\",tenant_id=\"{}\"}} {}\n",
                escape_label(effect),
                escape_label(policy_id),
                escape_label(action),
                escape_label(tenant_id),
                c.get(),
            ));
        }
        drop(totals);

        out.push_str("# HELP agentguard_decision_duration_seconds Decision evaluation time\n");
        out.push_str("# TYPE agentguard_decision_duration_seconds histogram\n");
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
                out.push_str(&format!(
                    "agentguard_decision_duration_seconds_bucket{{action=\"{}\",tenant_id=\"{}\",le=\"{}\"}} {}\n",
                    escape_label(action),
                    escape_label(tenant_id),
                    le,
                    count,
                ));
            }
            out.push_str(&format!(
                "agentguard_decision_duration_seconds_count{{action=\"{}\",tenant_id=\"{}\"}} {}\n",
                escape_label(action),
                escape_label(tenant_id),
                h.count(),
            ));
            out.push_str(&format!(
                "agentguard_decision_duration_seconds_sum{{action=\"{}\",tenant_id=\"{}\"}} {}\n",
                escape_label(action),
                escape_label(tenant_id),
                h.sum_seconds(),
            ));
        }
        drop(durations);

        out.push_str("# HELP agentguard_delegation_mint_total Total delegation tokens minted\n");
        out.push_str("# TYPE agentguard_delegation_mint_total counter\n");
        out.push_str(&format!(
            "agentguard_delegation_mint_total {}\n",
            self.delegation_mint_total.get(),
        ));

        out.push_str("# HELP agentguard_delegation_verify_total Total delegation verifications\n");
        out.push_str("# TYPE agentguard_delegation_verify_total counter\n");
        let verify = self.delegation_verify_total.read();
        for (outcome, c) in verify.iter() {
            out.push_str(&format!(
                "agentguard_delegation_verify_total{{outcome=\"{}\"}} {}\n",
                escape_label(outcome),
                c.get(),
            ));
        }
        drop(verify);

        out.push_str("# HELP agentguard_cache_hit_total Decision cache hits\n");
        out.push_str("# TYPE agentguard_cache_hit_total counter\n");
        out.push_str(&format!(
            "agentguard_cache_hit_total {}\n",
            self.cache_hit_total.get()
        ));
        out.push_str(&format!(
            "agentguard_cache_miss_total {}\n",
            self.cache_miss_total.get()
        ));

        out.push_str(&format!(
            "agentguard_policy_reload_total {}\n",
            self.policy_reload_total.get()
        ));

        let pdp = self.pdp_error_total.read();
        for (fallback, c) in pdp.iter() {
            out.push_str(&format!(
                "agentguard_pdp_error_total{{fallback=\"{}\"}} {}\n",
                escape_label(fallback),
                c.get(),
            ));
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
}
