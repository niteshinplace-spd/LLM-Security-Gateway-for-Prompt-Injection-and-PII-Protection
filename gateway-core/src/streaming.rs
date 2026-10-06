//! Streaming response inspection with sliding-window cross-chunk detection.
//!
//! Handles token-by-token or chunk-by-chunk LLM responses, maintaining an overlap
//! buffer across chunk boundaries so secrets and malicious tokens split across
//! adjacent packets are caught and killed mid-stream.

use crate::injection::InjectionScanner;
use crate::pii::PiiScanner;
use crate::ViolationCategory;

/// Decision for an incremental chunk during stream inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamDecision {
    /// Chunk is clean and safe to forward to the client.
    Pass,
    /// Violation detected mid-stream; stream must be terminated immediately.
    Kill {
        reason: String,
        category: ViolationCategory,
    },
}

/// Sliding-window state machine that buffers recent text across streaming chunk boundaries.
pub struct SlidingWindowScanner {
    injection_scanner: InjectionScanner,
    pii_scanner: PiiScanner,
    /// Overlap buffer holding the recent tail of processed tokens
    window_buffer: String,
    /// Maximum overlap history in characters (default: 200)
    window_size: usize,
    /// Whether the stream has already been aborted
    killed: bool,
}

impl Default for SlidingWindowScanner {
    fn default() -> Self {
        Self::new(200)
    }
}

impl SlidingWindowScanner {
    /// Create a new scanner with the given sliding window character capacity.
    pub fn new(window_size: usize) -> Self {
        Self {
            injection_scanner: InjectionScanner::new(),
            pii_scanner: PiiScanner::new(),
            window_buffer: String::with_capacity(window_size * 2),
            window_size,
            killed: false,
        }
    }

    /// Check if the stream has already been terminated.
    #[inline]
    pub fn is_killed(&self) -> bool {
        self.killed
    }

    /// Reset the sliding window buffer for a new stream.
    pub fn reset(&mut self) {
        self.window_buffer.clear();
        self.killed = false;
    }

    /// Inspect a new text delta and determine if the stream may continue.
    pub fn process_text(&mut self, text: &str) -> StreamDecision {
        if self.killed {
            return StreamDecision::Kill {
                reason: "Stream was previously terminated".to_string(),
                category: ViolationCategory::SecretLeak,
            };
        }

        if text.is_empty() {
            return StreamDecision::Pass;
        }

        // 1. Append incoming text to overlap buffer
        self.window_buffer.push_str(text);

        // 2. Scan the current window for PII or leaked secrets
        let (pii_verdict, _elapsed) = self.pii_scanner.scan_and_verdict(&self.window_buffer, true);
        if let crate::Verdict::Block { reason, category } = pii_verdict {
            self.killed = true;
            return StreamDecision::Kill { reason, category };
        }

        // 3. Scan the current window for prompt injection / jailbreak echoes
        let inj_report = self.injection_scanner.scan(&self.window_buffer);
        if let crate::Verdict::Block { reason, category } = inj_report.verdict {
            self.killed = true;
            return StreamDecision::Kill { reason, category };
        }

        // 4. Maintain sliding window size (keep only the last `window_size` characters)
        if self.window_buffer.chars().count() > self.window_size {
            let keep_idx = self
                .window_buffer
                .char_indices()
                .rev()
                .nth(self.window_size - 1)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.window_buffer = self.window_buffer[keep_idx..].to_string();
        }

        StreamDecision::Pass
    }

    /// Extract text content delta from a standard SSE data line:
    /// e.g. `data: {"choices":[{"delta":{"content":"hello"}}]}`
    pub fn parse_sse_delta(line: &str) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("data:") {
            return None;
        }
        let payload = trimmed["data:".len()..].trim();
        if payload == "[DONE]" || payload.is_empty() {
            return None;
        }

        let json: serde_json::Value = serde_json::from_str(payload).ok()?;
        json.get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c0| c0.get("delta"))
            .and_then(|d| d.get("content"))
            .and_then(|cnt| cnt.as_str())
            .map(|s| s.to_string())
    }

    /// Process a raw SSE chunk (which may contain one or multiple `data: ...` lines).
    pub fn process_sse_chunk(&mut self, chunk: &str) -> StreamDecision {
        for line in chunk.lines() {
            if let Some(delta) = Self::parse_sse_delta(line) {
                let decision = self.process_text(&delta);
                if matches!(decision, StreamDecision::Kill { .. }) {
                    return decision;
                }
            }
        }
        StreamDecision::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window_safe_stream_passes() {
        let mut scanner = SlidingWindowScanner::new(100);
        assert_eq!(scanner.process_text("Hello "), StreamDecision::Pass);
        assert_eq!(scanner.process_text("world! "), StreamDecision::Pass);
        assert_eq!(scanner.process_text("How can I "), StreamDecision::Pass);
        assert_eq!(scanner.process_text("help you today?"), StreamDecision::Pass);
        assert!(!scanner.is_killed());
    }

    #[test]
    fn test_sliding_window_detects_secret_midstream() {
        let mut scanner = SlidingWindowScanner::new(100);
        assert_eq!(scanner.process_text("Sure, here is your key: "), StreamDecision::Pass);
        
        let leak_chunk = "sk-live-51aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789";
        let decision = scanner.process_text(leak_chunk);
        assert!(matches!(decision, StreamDecision::Kill { .. }));
        assert!(scanner.is_killed());

        // Subsequent chunks are immediately blocked
        assert!(matches!(scanner.process_text("more text"), StreamDecision::Kill { .. }));
    }

    #[test]
    fn test_sliding_window_cross_chunk_secret_split() {
        let mut scanner = SlidingWindowScanner::new(100);
        // Secret split right across chunk boundary
        assert_eq!(scanner.process_text("Here is token: sk-"), StreamDecision::Pass);
        
        let second_half = "live-51aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789";
        let decision = scanner.process_text(second_half);
        assert!(
            matches!(decision, StreamDecision::Kill { .. }),
            "Cross-chunk split secret must be detected by sliding window buffer"
        );
        assert!(scanner.is_killed());
    }

    #[test]
    fn test_sliding_window_parses_sse_deltas() {
        let mut scanner = SlidingWindowScanner::new(100);
        let sse_safe = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n";
        assert_eq!(scanner.process_sse_chunk(sse_safe), StreamDecision::Pass);

        let sse_leak = "data: {\"choices\":[{\"delta\":{\"content\":\"sk-live-51aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789\"}}]}\n\n";
        let decision = scanner.process_sse_chunk(sse_leak);
        assert!(matches!(decision, StreamDecision::Kill { .. }));
        assert!(scanner.is_killed());
    }

    #[test]
    fn test_parse_sse_done_line() {
        assert_eq!(SlidingWindowScanner::parse_sse_delta("data: [DONE]"), None);
        assert_eq!(SlidingWindowScanner::parse_sse_delta(": ping"), None);
    }
}
