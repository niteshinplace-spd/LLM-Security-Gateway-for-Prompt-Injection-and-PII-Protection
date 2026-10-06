//! Phase 6 - Streaming Response Handling Tests
//!
//! Verifies that real-time token-by-token streaming responses through the gateway
//! pass through clean content, maintain an overlap sliding-window buffer, and
//! immediately abort the stream mid-flight if sensitive secrets or prompt injection
//! echoes emerge across token boundaries.

use axum::body::Bytes;
use futures_util::stream::{self, StreamExt};
use gateway_server::proxy::create_secure_sse_stream;

type StreamItem = Result<Bytes, std::io::Error>;

#[tokio::test]
async fn test_secure_stream_safe_tokens_flow_through() {
    let chunks: Vec<StreamItem> = vec![
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n")),
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\" world!\"}}]}\n\n")),
        Ok(Bytes::from("data: [DONE]\n\n")),
    ];

    let upstream = stream::iter(chunks);
    let mut secure_stream = create_secure_sse_stream(upstream);

    let mut collected = Vec::new();
    while let Some(item) = secure_stream.next().await {
        let bytes = item.expect("Safe stream chunk should not fail");
        collected.push(String::from_utf8_lossy(&bytes).to_string());
    }

    assert_eq!(collected.len(), 3);
    assert!(collected[0].contains("Hello"));
    assert!(collected[1].contains("world!"));
    assert!(collected[2].contains("[DONE]"));
}

#[tokio::test]
async fn test_secure_stream_midstream_secret_leak_kills_stream() {
    let chunks: Vec<StreamItem> = vec![
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"Sure, here is your key: \"}}]}\n\n")),
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"sk-live-51aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789\"}}]}\n\n")),
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\" This confidential token should never be seen!\"}}]}\n\n")),
        Ok(Bytes::from("data: [DONE]\n\n")),
    ];

    let upstream = stream::iter(chunks);
    let mut secure_stream = create_secure_sse_stream(upstream);

    let mut collected = Vec::new();
    while let Some(item) = secure_stream.next().await {
        let bytes = item.expect("Stream should yield error frame");
        collected.push(String::from_utf8_lossy(&bytes).to_string());
    }

    // Chunk 1 is safe, Chunk 2 triggers kill and replaces chunk with terminal error frame, Chunk 3 & 4 dropped!
    assert_eq!(collected.len(), 2, "Stream must terminate after the violation is detected");
    assert!(collected[0].contains("Sure, here is your key:"));
    assert!(collected[1].contains("event: error"));
    assert!(collected[1].contains("security_violation"));
    assert!(collected[1].contains("403"));

    // Verify confidential text after the leak was never yielded
    for chunk in &collected {
        assert!(!chunk.contains("This confidential token should never be seen!"));
    }
}

#[tokio::test]
async fn test_secure_stream_cross_chunk_split_secret() {
    // Secret split exactly across two consecutive SSE chunk deltas: "sk-" in chunk 1, "live-..." in chunk 2
    let chunks: Vec<StreamItem> = vec![
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"API token: sk-\"}}]}\n\n")),
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"live-51aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789\"}}]}\n\n")),
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\" post-leak text\"}}]}\n\n")),
    ];

    let upstream = stream::iter(chunks);
    let mut secure_stream = create_secure_sse_stream(upstream);

    let mut collected = Vec::new();
    while let Some(item) = secure_stream.next().await {
        let bytes = item.expect("Stream result");
        collected.push(String::from_utf8_lossy(&bytes).to_string());
    }

    // Chunk 1 yields, Chunk 2 completes the split secret -> sliding window detects and kills stream
    assert_eq!(collected.len(), 2);
    assert!(collected[0].contains("API token: sk-"));
    assert!(collected[1].contains("event: error"));
    assert!(collected[1].contains("Stream blocked by security policy"));

    for chunk in &collected {
        assert!(!chunk.contains("post-leak text"));
    }
}

#[tokio::test]
async fn test_secure_stream_upstream_transport_error() {
    let chunks: Vec<StreamItem> = vec![
        Ok(Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n")),
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Upstream connection dropped")),
    ];

    let upstream = stream::iter(chunks);
    let mut secure_stream = create_secure_sse_stream(upstream);

    let first = secure_stream.next().await.unwrap();
    assert!(first.is_ok());

    let second = secure_stream.next().await.unwrap();
    assert!(second.is_err());
}
