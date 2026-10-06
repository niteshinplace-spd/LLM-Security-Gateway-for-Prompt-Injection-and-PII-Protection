//! Atomic gateway-wide metrics counters.
//!
//! A single `GatewayMetrics` instance is created at startup and shared via `Arc`.
//! All updates use `Relaxed` ordering because we care about aggregate counts, not
//! happens-before relationships across threads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Shared, lock-free metrics counters for the LLM security gateway.
#[derive(Debug)]
pub struct GatewayMetrics {
    /// Total inbound requests received (all endpoints).
    pub requests_total: AtomicU64,
    /// Requests blocked by the injection scanner.
    pub injection_blocks_total: AtomicU64,
    /// Requests blocked by authentication or governance.
    pub policy_blocks_total: AtomicU64,
    /// PII / secret redactions applied to outbound responses.
    pub pii_redactions_total: AtomicU64,
    /// Streaming responses that were killed mid-stream by the security scanner.
    pub stream_kills_total: AtomicU64,
    /// RAG context retrievals performed.
    pub rag_retrievals_total: AtomicU64,
    /// Cumulative upstream request latency in microseconds (for mean calculation).
    pub upstream_latency_us_total: AtomicU64,
    /// Number of upstream latency samples (for mean calculation).
    pub upstream_latency_samples: AtomicU64,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayMetrics {
    /// Create a new zeroed metrics instance.
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            injection_blocks_total: AtomicU64::new(0),
            policy_blocks_total: AtomicU64::new(0),
            pii_redactions_total: AtomicU64::new(0),
            stream_kills_total: AtomicU64::new(0),
            rag_retrievals_total: AtomicU64::new(0),
            upstream_latency_us_total: AtomicU64::new(0),
            upstream_latency_samples: AtomicU64::new(0),
        }
    }

    // --- Increment helpers ---

    #[inline]
    pub fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_injection_block(&self) {
        self.injection_blocks_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_policy_block(&self) {
        self.policy_blocks_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_pii_redaction(&self) {
        self.pii_redactions_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_stream_kill(&self) {
        self.stream_kills_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rag_retrieval(&self) {
        self.rag_retrievals_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an upstream round-trip latency sample.
    pub fn record_upstream_latency(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.upstream_latency_us_total.fetch_add(us, Ordering::Relaxed);
        self.upstream_latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    // --- Snapshot helpers ---

    /// Mean upstream latency in microseconds (0 if no samples).
    pub fn mean_upstream_latency_us(&self) -> u64 {
        let samples = self.upstream_latency_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return 0;
        }
        self.upstream_latency_us_total.load(Ordering::Relaxed) / samples
    }

    /// Render a Prometheus text-format exposition of all metrics.
    pub fn prometheus_text(&self) -> String {
        let mut out = String::with_capacity(512);

        let requests = self.requests_total.load(Ordering::Relaxed);
        let inj_blocks = self.injection_blocks_total.load(Ordering::Relaxed);
        let pol_blocks = self.policy_blocks_total.load(Ordering::Relaxed);
        let pii = self.pii_redactions_total.load(Ordering::Relaxed);
        let stream_kills = self.stream_kills_total.load(Ordering::Relaxed);
        let rag = self.rag_retrievals_total.load(Ordering::Relaxed);
        let mean_lat = self.mean_upstream_latency_us();
        let lat_total = self.upstream_latency_us_total.load(Ordering::Relaxed);
        let lat_samples = self.upstream_latency_samples.load(Ordering::Relaxed);

        macro_rules! prom_counter {
            ($out:expr, $name:expr, $help:expr, $val:expr) => {
                $out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        macro_rules! prom_gauge {
            ($out:expr, $name:expr, $help:expr, $val:expr) => {
                $out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        prom_counter!(out, "gateway_requests_total", "Total inbound requests received.", requests);
        prom_counter!(out, "gateway_injection_blocks_total", "Requests blocked by prompt injection scanner.", inj_blocks);
        prom_counter!(out, "gateway_policy_blocks_total", "Requests blocked by auth or governance policy.", pol_blocks);
        prom_counter!(out, "gateway_pii_redactions_total", "PII/secret redactions applied to responses.", pii);
        prom_counter!(out, "gateway_stream_kills_total", "SSE streams killed mid-flight by security scanner.", stream_kills);
        prom_counter!(out, "gateway_rag_retrievals_total", "RAG context retrievals performed.", rag);
        prom_gauge!(out, "gateway_upstream_latency_mean_us", "Mean upstream round-trip latency in microseconds.", mean_lat);
        prom_counter!(out, "gateway_upstream_latency_us_total", "Cumulative upstream latency in microseconds.", lat_total);
        prom_counter!(out, "gateway_upstream_latency_samples_total", "Number of upstream latency samples recorded.", lat_samples);

        out
    }
}

/// Convenience type alias used throughout the codebase.
pub type SharedMetrics = Arc<GatewayMetrics>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_zero_on_init() {
        let m = GatewayMetrics::new();
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.mean_upstream_latency_us(), 0);
    }

    #[test]
    fn test_metrics_increment() {
        let m = GatewayMetrics::new();
        m.inc_requests();
        m.inc_requests();
        m.inc_injection_block();
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.injection_blocks_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_metrics_latency_mean() {
        let m = GatewayMetrics::new();
        m.record_upstream_latency(Duration::from_micros(200));
        m.record_upstream_latency(Duration::from_micros(400));
        assert_eq!(m.mean_upstream_latency_us(), 300);
    }

    #[test]
    fn test_prometheus_text_contains_all_metrics() {
        let m = GatewayMetrics::new();
        m.inc_requests();
        m.inc_pii_redaction();
        m.inc_stream_kill();
        let text = m.prometheus_text();
        assert!(text.contains("gateway_requests_total 1"));
        assert!(text.contains("gateway_pii_redactions_total 1"));
        assert!(text.contains("gateway_stream_kills_total 1"));
        assert!(text.contains("# TYPE gateway_requests_total counter"));
        assert!(text.contains("# TYPE gateway_upstream_latency_mean_us gauge"));
    }

    #[test]
    fn test_metrics_arc_shared_across_threads() {
        use std::sync::Arc;
        let m = Arc::new(GatewayMetrics::new());
        let m2 = Arc::clone(&m);
        let handle = std::thread::spawn(move || {
            m2.inc_requests();
            m2.inc_requests();
        });
        handle.join().unwrap();
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 2);
    }
}
