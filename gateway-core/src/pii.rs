//! Personally Identifiable Information (PII) and secret leak detection and redaction.
//!
//! Provides microsecond regex pattern matching, Luhn algorithm verification for
//! credit cards, secret token identification, and in-place masking routines.

use crate::{Finding, Verdict, ViolationCategory};
use regex::Regex;
use std::time::Instant;

/// Supported categories of sensitive information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveKind {
    Email,
    Phone,
    Ssn,
    CreditCard,
    ApiKey,
    SecretKey,
}

impl SensitiveKind {
    pub fn mask(&self) -> &'static str {
        match self {
            SensitiveKind::Email => "[REDACTED_EMAIL]",
            SensitiveKind::Phone => "[REDACTED_PHONE]",
            SensitiveKind::Ssn => "[REDACTED_SSN]",
            SensitiveKind::CreditCard => "[REDACTED_CREDIT_CARD]",
            SensitiveKind::ApiKey => "[REDACTED_API_KEY]",
            SensitiveKind::SecretKey => "[REDACTED_SECRET]",
        }
    }

    pub fn to_violation_category(&self) -> ViolationCategory {
        match self {
            SensitiveKind::Email | SensitiveKind::Phone | SensitiveKind::Ssn | SensitiveKind::CreditCard => {
                ViolationCategory::PiiLeak
            }
            SensitiveKind::ApiKey | SensitiveKind::SecretKey => ViolationCategory::SecretLeak,
        }
    }
}

/// A detected sensitive item span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveMatch {
    pub kind: SensitiveKind,
    pub start: usize,
    pub end: usize,
}

/// Pre-compiled PII and secret scanner.
pub struct PiiScanner {
    email_regex: Regex,
    phone_regex: Regex,
    ssn_regex: Regex,
    credit_card_candidate_regex: Regex,
    openai_key_regex: Regex,
    aws_key_regex: Regex,
    github_pat_regex: Regex,
    private_key_regex: Regex,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    /// Compiles all regular expressions once upon instantiation.
    pub fn new() -> Self {
        let email_regex = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
            .expect("Failed to compile email regex");

        let phone_regex = Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
            .expect("Failed to compile phone regex");

        let ssn_regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
            .expect("Failed to compile SSN regex");

        // 13 to 19 digits potentially separated by hyphens or spaces
        let credit_card_candidate_regex = Regex::new(r"\b(?:\d[ -]*?){13,19}\b")
            .expect("Failed to compile credit card candidate regex");
        let openai_key_regex = Regex::new(r"\bsk(?:[-_](?:test|proj|live))?[-_][a-zA-Z0-9_-]{8,}\b")
            .expect("Failed to compile OpenAI key regex");

        let aws_key_regex = Regex::new(r"\bAKIA[0-9A-Z]{16}\b")
            .expect("Failed to compile AWS key regex");

        let github_pat_regex = Regex::new(r"\bghp_[a-zA-Z0-9]{36}\b")
            .expect("Failed to compile GitHub PAT regex");

        let private_key_regex = Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
            .expect("Failed to compile private key regex");

        Self {
            email_regex,
            phone_regex,
            ssn_regex,
            credit_card_candidate_regex,
            openai_key_regex,
            aws_key_regex,
            github_pat_regex,
            private_key_regex,
        }
    }

    /// Finds all sensitive data matches in the text.
    pub fn find_matches(&self, text: &str) -> Vec<SensitiveMatch> {
        let mut matches = Vec::new();

        // 1. Email matches
        for m in self.email_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::Email,
                start: m.start(),
                end: m.end(),
            });
        }

        // 2. Phone matches
        for m in self.phone_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::Phone,
                start: m.start(),
                end: m.end(),
            });
        }

        // 3. SSN matches
        for m in self.ssn_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::Ssn,
                start: m.start(),
                end: m.end(),
            });
        }

        // 4. Credit Card matches (Validated with Luhn Check)
        for m in self.credit_card_candidate_regex.find_iter(text) {
            let candidate_str = m.as_str();
            if luhn_check(candidate_str) {
                matches.push(SensitiveMatch {
                    kind: SensitiveKind::CreditCard,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        // 5. API Keys & Secrets
        for m in self.openai_key_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::ApiKey,
                start: m.start(),
                end: m.end(),
            });
        }

        for m in self.aws_key_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::ApiKey,
                start: m.start(),
                end: m.end(),
            });
        }

        for m in self.github_pat_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::ApiKey,
                start: m.start(),
                end: m.end(),
            });
        }

        for m in self.private_key_regex.find_iter(text) {
            matches.push(SensitiveMatch {
                kind: SensitiveKind::SecretKey,
                start: m.start(),
                end: m.end(),
            });
        }

        // Sort matches by start position
        matches.sort_by_key(|m| m.start);

        // Deduplicate / remove overlapping spans (e.g., if a CC pattern overlapped phone)
        deduplicate_matches(matches)
    }

    /// Redacts sensitive information in-place, returning the sanitized string,
    /// a list of findings, and execution duration in microseconds.
    pub fn redact(&self, text: &str) -> (String, Vec<Finding>, u64) {
        let start_time = Instant::now();
        let matches = self.find_matches(text);

        if matches.is_empty() {
            let elapsed = start_time.elapsed().as_micros() as u64;
            return (text.to_string(), Vec::new(), elapsed);
        }

        let mut result = String::with_capacity(text.len());
        let mut findings = Vec::with_capacity(matches.len());
        let mut last_idx = 0;

        for m in &matches {
            if m.start >= last_idx {
                result.push_str(&text[last_idx..m.start]);
                result.push_str(m.kind.mask());
                last_idx = m.end;

                findings.push(Finding {
                    category: m.kind.to_violation_category(),
                    rule_name: format!("{:?}", m.kind),
                    start_offset: m.start,
                    end_offset: m.end,
                });
            }
        }

        if last_idx < text.len() {
            result.push_str(&text[last_idx..]);
        }

        let elapsed = start_time.elapsed().as_micros() as u64;
        (result, findings, elapsed)
    }

    /// Evaluates text and returns a Verdict (Allow, Redact, or Block).
    pub fn scan_and_verdict(&self, text: &str, block_secrets: bool) -> (Verdict, u64) {
        let (redacted, findings, elapsed) = self.redact(text);

        if findings.is_empty() {
            return (Verdict::Allow, elapsed);
        }

        if block_secrets && findings.iter().any(|f| f.category == ViolationCategory::SecretLeak) {
            return (
                Verdict::Block {
                    reason: "Secret key or private credential detected in content".to_string(),
                    category: ViolationCategory::SecretLeak,
                },
                elapsed,
            );
        }

        (
            Verdict::Redact {
                redactions_count: findings.len(),
                redacted_text: redacted,
            },
            elapsed,
        )
    }
}

/// Deduplicate overlapping or nested match intervals.
fn deduplicate_matches(matches: Vec<SensitiveMatch>) -> Vec<SensitiveMatch> {
    let mut deduped: Vec<SensitiveMatch> = Vec::with_capacity(matches.len());

    for current in matches {
        if let Some(prev) = deduped.last_mut() {
            if current.start < prev.end {
                // Overlap: prioritize SecretKey/CreditCard over simple phone/numbers
                if current.end > prev.end {
                    prev.end = current.end;
                }
                continue;
            }
        }
        deduped.push(current);
    }

    deduped
}

/// Luhn algorithm (Modulo 10 checksum) for credit card number validation.
pub fn luhn_check(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();

    // Standard credit card lengths are between 13 and 19 digits
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        if double {
            let doubled = digit * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += digit;
        }
        double = !double;
    }

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let scanner = PiiScanner::new();
        let input = "Contact our lead at john.doe@company.org for details.";
        let (redacted, findings, elapsed) = scanner.redact(input);

        assert_eq!(redacted, "Contact our lead at [REDACTED_EMAIL] for details.");
        assert_eq!(findings.len(), 1);
        assert!(elapsed > 0);
    }
    #[test]
fn test_multiple_email_redaction() {
    let scanner = PiiScanner::new();

    let input = "Contact john@company.org or jane@company.org";

    let (redacted, findings, _) = scanner.redact(input);

    assert_eq!(
        redacted,
        "Contact [REDACTED_EMAIL] or [REDACTED_EMAIL]"
    );
    assert_eq!(findings.len(), 2);
    }
    
    #[test]
    fn test_phone_redaction() {
        let scanner = PiiScanner::new();
        let input = "Call support at 415-555-2671 or (800) 123-4567.";
        let (redacted, findings, _) = scanner.redact(input);

        assert!(!redacted.contains("415-555-2671"));
        assert!(!redacted.contains("(800) 123-4567"));
        assert_eq!(findings.len(), 2);
    }


    #[test]
    fn test_ssn_redaction() {
        let scanner = PiiScanner::new();
        let input = "The applicant SSN is 123-45-6789.";
        let (redacted, findings, _) = scanner.redact(input);

        assert_eq!(redacted, "The applicant SSN is [REDACTED_SSN].");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_luhn_credit_card_validation() {
        let scanner = PiiScanner::new();

        // Valid test Visa card
        let valid_card = "My card is 4532-0151-1283-0366.";
        let (redacted, findings, _) = scanner.redact(valid_card);
        assert_eq!(redacted, "My card is [REDACTED_CREDIT_CARD].");
        assert_eq!(findings.len(), 1);

        // Invalid checksum (last digit modified from 6 to 7)
        let invalid_card = "My card is 4532-0151-1283-0367.";
        let (unredacted, findings_invalid, _) = scanner.redact(invalid_card);
        assert_eq!(unredacted, invalid_card);
        assert_eq!(findings_invalid.len(), 0); // Must NOT match invalid card
    }

    #[test]
    fn test_api_key_redaction() {
        let scanner = PiiScanner::new();

        let openai_key = "Authorization: Bearer sk-abcdef1234567890abcdef1234567890";
        let (redacted_oa, findings_oa, _) = scanner.redact(openai_key);
        assert_eq!(redacted_oa, "Authorization: Bearer [REDACTED_API_KEY]");
        assert_eq!(findings_oa[0].category, ViolationCategory::SecretLeak);

        let aws_key = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE";
        let (redacted_aws, findings_aws, _) = scanner.redact(aws_key);
        assert_eq!(redacted_aws, "AWS_ACCESS_KEY_ID = [REDACTED_API_KEY]");
        assert_eq!(findings_aws[0].category, ViolationCategory::SecretLeak);
        
        let fake_test_key = "Here is a test key: sk_test_1234567890abcdef1234567890";
        let (redacted_test, findings_test, _) = scanner.redact(fake_test_key);

        assert_eq!(
        redacted_test,
        "Here is a test key: [REDACTED_API_KEY]"
        );
        assert_eq!(findings_test.len(), 1);
        let short_test_key = "Short key: sk_test_4eGcVq3P4y2lG";
        let (redacted_short, findings_short, _) = scanner.redact(short_test_key);

        assert_eq!(redacted_short, "Short key: [REDACTED_API_KEY]");
        assert_eq!(findings_short.len(), 1);
        }

    #[test]
    fn test_block_secrets_verdict() {
        let scanner = PiiScanner::new();
        let input = "Here is the key: sk-abcdef1234567890abcdef1234567890";
        let (verdict, _) = scanner.scan_and_verdict(input, true);

        assert!(verdict.is_blocked());
        if let Verdict::Block { category, .. } = verdict {
            assert_eq!(category, ViolationCategory::SecretLeak);
        } else {
            panic!("Expected Verdict::Block");
        }
    }

    #[test]
    fn test_clean_text_allowed() {
        let scanner = PiiScanner::new();
        let input = "This is a safe sentence discussing mathematics: 12 + 34 = 46. No secrets.";
        let (verdict, _elapsed) = scanner.scan_and_verdict(input, true);

        assert_eq!(verdict, Verdict::Allow);
    }
}
