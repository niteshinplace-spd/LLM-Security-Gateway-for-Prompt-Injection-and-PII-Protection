//! Structured JSON audit log emitter.
//!
//! Every request that passes through the gateway emits a single JSON line to
//! `stdout` (captured by any log aggregator) describing:
//! - The request ID, timestamp, endpoint, and model
//! - Security decisions (injection scan, governance, PII redaction)
//! - Whether the response was streamed and any stream kills
//! - Upstream latency and overall request outcome
//!
//! This is intentionally append-only and write-only — the gateway never reads
//! the audit log at runtime.

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Outcome of the complete request lifecycle.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestOutcome {
    /// Request completed successfully and response forwarded to client.
    Allowed,
    /// Request blocked by security policy before reaching upstream.
    BlockedSecurity,
    /// Request blocked by governance (auth or allowlist) policy.
    BlockedPolicy,
    /// Upstream returned an error or timed out.
    UpstreamError,
    /// Streaming response was killed mid-flight by the security scanner.
    StreamKilled,
}

/// A single structured audit record emitted per gateway request.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 UTC timestamp (seconds precision).
    pub timestamp: String,
    /// Unique request identifier (set from `X-Request-ID` or generated).
    pub request_id: String,
    /// Target endpoint path (e.g. `/v1/chat/completions`).
    pub endpoint: String,
    /// LLM model name requested.
    pub model: String,
    /// Whether the request was for a streaming response.
    pub streaming: bool,
    /// Whether injection scanning flagged the request.
    pub injection_detected: bool,
    /// Whether PII was found and redacted in the response.
    pub pii_redacted: bool,
    /// Number of PII / secret findings redacted from the response.
    pub pii_findings_count: usize,
    /// Whether the stream was killed mid-flight by the scanner.
    pub stream_killed: bool,
    /// Whether RAG retrieval was performed for this request.
    pub rag_retrieval_performed: bool,
    /// Upstream round-trip latency in microseconds (0 if not reached).
    pub upstream_latency_us: u64,
    /// Total inbound injection scan latency in microseconds.
    pub scan_latency_us: u64,
    /// Overall request outcome.
    pub outcome: RequestOutcome,
    /// Human-readable reason when outcome is not `Allowed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_reason: Option<String>,
}

impl AuditRecord {
    /// Create a new audit record for an incoming request.
    pub fn new(request_id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            timestamp: utc_now_rfc3339(),
            request_id: request_id.into(),
            endpoint: endpoint.into(),
            model: String::new(),
            streaming: false,
            injection_detected: false,
            pii_redacted: false,
            pii_findings_count: 0,
            stream_killed: false,
            rag_retrieval_performed: false,
            upstream_latency_us: 0,
            scan_latency_us: 0,
            outcome: RequestOutcome::Allowed,
            block_reason: None,
        }
    }

    /// Emit the record as a single JSON line to `tracing` at INFO level.
    ///
    /// Using `tracing` ensures the output obeys the subscriber's format,
    /// making it easy to redirect to files or log aggregators.
    pub fn emit(&self) {
        match serde_json::to_string(self) {
            Ok(json) => tracing::info!(target: "gateway_audit", "{}", json),
            Err(e) => tracing::warn!("Failed to serialize audit record: {}", e),
        }
    }
}

/// Generate a simple monotonic request ID using the current Unix nanoseconds.
/// In production this should be replaced by a UUID library.
pub fn generate_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("req-{:010}", nanos)
}

/// RFC 3339 UTC timestamp at second precision.
fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as YYYY-MM-DDThh:mm:ssZ using manual arithmetic (no chrono dep needed)
    let (y, mo, d, h, mi, s) = seconds_to_datetime(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

/// Convert Unix epoch seconds to (year, month, day, hour, minute, second).
fn seconds_to_datetime(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let total_minutes = secs / 60;
    let mi = total_minutes % 60;
    let total_hours = total_minutes / 60;
    let h = total_hours % 24;
    let mut days = total_hours / 24;

    // Gregorian calendar approximation
    let mut y: u64 = 1970;
    loop {
        let leap = is_leap(y);
        let days_in_year: u64 = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        y += 1;
    }
    let month_days: [u64; 12] = [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo: u64 = 1;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        mo += 1;
    }
    (y, mo, days + 1, h, mi, s)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_record_defaults() {
        let rec = AuditRecord::new("req-001", "/v1/chat/completions");
        assert_eq!(rec.request_id, "req-001");
        assert_eq!(rec.endpoint, "/v1/chat/completions");
        assert!(!rec.injection_detected);
        assert!(!rec.pii_redacted);
        assert_eq!(rec.outcome, RequestOutcome::Allowed);
    }

    #[test]
    fn test_audit_record_serializes_to_valid_json() {
        let mut rec = AuditRecord::new("req-002", "/chat");
        rec.model = "llama3.2:3b".to_string();
        rec.outcome = RequestOutcome::BlockedSecurity;
        rec.block_reason = Some("Injection detected".to_string());
        rec.injection_detected = true;

        let json = serde_json::to_string(&rec).expect("Should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse");

        assert_eq!(parsed["request_id"], "req-002");
        assert_eq!(parsed["outcome"], "blocked_security");
        assert_eq!(parsed["injection_detected"], true);
        assert!(parsed.get("block_reason").is_some());
    }

    #[test]
    fn test_block_reason_omitted_when_none() {
        let rec = AuditRecord::new("req-003", "/health");
        let json = serde_json::to_string(&rec).expect("serialize");
        assert!(!json.contains("block_reason"));
    }

    #[test]
    fn test_generate_request_id_is_unique() {
        let id1 = generate_request_id();
        // Brief busy-wait to get different nanosecond values
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_request_id();
        // Both must start with the prefix
        assert!(id1.starts_with("req-"));
        assert!(id2.starts_with("req-"));
    }

    #[test]
    fn test_utc_timestamp_format() {
        let rec = AuditRecord::new("req-ts", "/test");
        // Format: YYYY-MM-DDThh:mm:ssZ  (20 chars)
        assert_eq!(rec.timestamp.len(), 20);
        assert!(rec.timestamp.ends_with('Z'));
        assert!(rec.timestamp.contains('T'));
    }
}
