//! Gateway Core - High-Performance Security Inspection Engine
//!
//! Provides sub-millisecond, memory-safe detection routines for prompt injections,
//! jailbreaks, sensitive data leaks (PII), and secret keys.

use serde::{Deserialize, Serialize};

/// Action verdict resulting from security inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "details")]
pub enum Verdict {
    /// Request/response is clean and permitted to proceed.
    Allow,
    /// Request/response violates security policy and is rejected.
    Block {
        reason: String,
        category: ViolationCategory,
    },
    /// Request/response contains sensitive data that was redacted in-place.
    Redact {
        redacted_text: String,
        redactions_count: usize,
    },
}

impl Verdict {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow | Verdict::Redact { .. })
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }
}

/// Category of security violation detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationCategory {
    PromptInjection,
    Jailbreak,
    PiiLeak,
    SecretLeak,
    MaliciousPayload,
}

/// Metadata describing a specific sensitive entity match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub category: ViolationCategory,
    pub rule_name: String,
    pub start_offset: usize,
    pub end_offset: usize,
}

/// Result summary of an inspection pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionReport {
    pub verdict: Verdict,
    pub latency_micros: u64,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_helpers() {
        let allow = Verdict::Allow;
        assert!(allow.is_allowed());
        assert!(!allow.is_blocked());

        let block = Verdict::Block {
            reason: "Injection detected".to_string(),
            category: ViolationCategory::PromptInjection,
        };
        assert!(!block.is_allowed());
        assert!(block.is_blocked());
    }
}
