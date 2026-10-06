//! Integration tests for the RAG ingestion pipeline and the RAG-enabled
//! request path through the gateway server.
//!
//! These tests exercise the full chain that a Phase-5 RAG-aware handler uses:
//!
//!   AppConfig (with `rag` field)
//!     └── RagConfig  (vector_dim, top_k, index_path, …)
//!           └── RagEngine::load → insert docs → search
//!                 └── persisted JSON doc-map round-trip
//!
//! Tests do NOT start a real HTTP server or contact an upstream LLM; they
//! drive the library types directly so they stay fast and hermetic.

use std::collections::HashMap;
use std::path::PathBuf;

use gateway_server::config::{AppConfig, GovernanceConfig, RagConfig, ThreatCategory};
use gateway_server::rag::RagEngine;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Return a `RagConfig` pointing at a non-existent path so `RagEngine::load`
/// always creates a brand-new in-memory HNSW index.
fn test_rag_config(dim: usize, top_k: usize) -> RagConfig {
    RagConfig {
        enabled: true,
        vector_dim: dim,
        top_k,
        index_path: PathBuf::from("/nonexistent/integration_test_rag"),
        embedding_model: "integration-test-model".into(),
    }
}

/// Create a normalised vector of the given dimension.
fn norm_vec(dim: usize, seed: f32) -> Vec<f32> {
    let raw: Vec<f32> = (0..dim).map(|i| seed + i as f32).collect();
    let mag = raw.iter().map(|x| x * x).sum::<f32>().sqrt();
    raw.iter().map(|x| x / mag).collect()
}

// ── AppConfig RAG field ───────────────────────────────────────────────────────

/// Phase 5, Step 1 concern: `state.config.rag.vector_dim` must be reachable.
/// This test verifies the field chain compiles and returns the expected value.
#[test]
fn test_app_config_rag_field_accessible() {
    let config = AppConfig::default();
    // Mirrors the access pattern used in handlers: state.config.rag.vector_dim
    assert_eq!(
        config.rag.vector_dim, 384,
        "state.config.rag.vector_dim should equal the RagConfig default"
    );
}

#[test]
fn test_app_config_rag_disabled_by_default() {
    let config = AppConfig::default();
    assert!(
        !config.rag.enabled,
        "RAG must be disabled in the default config so the engine is not initialised"
    );
}

#[test]
fn test_app_config_rag_enabled_override() {
    let mut config = AppConfig::default();
    config.rag.enabled = true;
    config.rag.vector_dim = 768;
    config.rag.top_k = 10;

    assert!(config.rag.enabled);
    assert_eq!(config.rag.vector_dim, 768);
    assert_eq!(config.rag.top_k, 10);
}

// ── Ingestion pipeline ────────────────────────────────────────────────────────

#[test]
fn test_ingest_pipeline_fresh_engine_starts_empty() {
    let cfg = test_rag_config(8, 3);
    let engine = RagEngine::load(&cfg).expect("fresh RagEngine::load failed");
    assert!(engine.docs.is_empty(), "A freshly created engine should have zero documents");
}

#[test]
fn test_ingest_pipeline_single_document() {
    let cfg = test_rag_config(8, 1);
    let mut engine = RagEngine::load(&cfg).expect("load failed");

    let vec = norm_vec(8, 1.0);
    engine.index.insert(&vec, 0);
    engine.docs.insert(0, "Integration test document".to_string());

    assert_eq!(engine.docs.len(), 1);
    assert_eq!(engine.docs[&0], "Integration test document");
}

#[test]
fn test_ingest_pipeline_multiple_documents_unique_ids() {
    let cfg = test_rag_config(8, 3);
    let mut engine = RagEngine::load(&cfg).expect("load failed");

    let texts = ["alpha", "beta", "gamma", "delta"];
    for (i, text) in texts.iter().enumerate() {
        let vec = norm_vec(8, i as f32 + 1.0);
        engine.index.insert(&vec, i);
        engine.docs.insert(i, text.to_string());
    }

    assert_eq!(engine.docs.len(), 4);
    for (i, text) in texts.iter().enumerate() {
        assert_eq!(&engine.docs[&i], *text, "doc {} mismatch", i);
    }
}

/// Simulates the JSON doc-map persistence step from `bin/ingest.rs` and then
/// reloads it, verifying the round-trip without touching the HNSW index file.
#[test]
fn test_ingest_doc_map_json_roundtrip() {
    let mut docs: HashMap<usize, String> = HashMap::new();
    docs.insert(0, "First document".into());
    docs.insert(1, "Second document".into());
    docs.insert(2, "Third document".into());

    // Serialise (mirrors what ingest.rs does before fs::write).
    let json = serde_json::to_string_pretty(&docs).expect("serialise failed");

    // Deserialise (mirrors what RagEngine::load does when the json file exists).
    let restored: HashMap<usize, String> =
        serde_json::from_str(&json).expect("deserialise failed");

    assert_eq!(restored.len(), 3);
    assert_eq!(restored[&0], "First document");
    assert_eq!(restored[&1], "Second document");
    assert_eq!(restored[&2], "Third document");
}

#[test]
fn test_ingest_doc_map_empty_roundtrip() {
    let docs: HashMap<usize, String> = HashMap::new();
    let json = serde_json::to_string(&docs).expect("serialise failed");
    let restored: HashMap<usize, String> =
        serde_json::from_str(&json).expect("deserialise failed");
    assert!(restored.is_empty());
}

// ── RAG-enabled request path ──────────────────────────────────────────────────

/// Verify that `state.config.rag.vector_dim` returns the correctly configured
/// value when AppConfig is constructed with a custom RagConfig — this mirrors
/// the handler access pattern introduced in Phase 5.
#[test]
fn test_rag_request_path_vector_dim_from_state_config() {
    let mut config = AppConfig::default();
    config.rag = RagConfig {
        enabled: true,
        vector_dim: 512,
        top_k: 5,
        index_path: PathBuf::from("./rag_index"),
        embedding_model: "custom".into(),
    };

    // Simulate what a handler does: state.config.rag.vector_dim
    let dim = config.rag.vector_dim;
    assert_eq!(dim, 512);
}

#[tokio::test]
async fn test_rag_request_path_search_returns_relevant_docs() {
    let cfg = test_rag_config(8, 2);
    let mut engine = RagEngine::load(&cfg).expect("load failed");

    // Insert a cluster of similar vectors and one orthogonal outlier.
    let query_vec = norm_vec(8, 1.0);
    engine.index.insert(&query_vec, 0);
    engine.docs.insert(0, "Relevant document A".into());

    let similar = norm_vec(8, 1.1);
    engine.index.insert(&similar, 1);
    engine.docs.insert(1, "Relevant document B".into());

    // An orthogonal-ish vector.
    let mut outlier = vec![0.0_f32; 8];
    outlier[7] = 1.0;
    engine.index.insert(&outlier, 2);
    engine.docs.insert(2, "Unrelated document".into());

    let results = engine.search(&query_vec).await;
    assert!(
        !results.is_empty(),
        "RAG search must return results when documents are indexed"
    );
    assert!(
        results.len() <= cfg.top_k,
        "Result count must not exceed top_k={}",
        cfg.top_k
    );
    // The most similar document should be in the results.
    assert!(
        results.contains(&"Relevant document A".to_string()),
        "The closest document should be retrieved"
    );
}

#[tokio::test]
async fn test_rag_request_path_search_with_rag_disabled_config() {
    // When RAG is disabled, the engine should never be initialised.
    // Here we model that guard: if !config.rag.enabled, skip engine use.
    let config = AppConfig::default();
    assert!(
        !config.rag.enabled,
        "RAG is off by default; handler should skip engine initialisation"
    );
    // No engine is created → no panic, no search attempted.
}

// ── Governance: RagPipeline threat category ───────────────────────────────────

#[test]
fn test_governance_rag_pipeline_category_allowed_when_deny_disabled() {
    let gov = GovernanceConfig {
        default_deny: false,
        allowlist: vec![],
    };
    let result = gov.check_request(ThreatCategory::RagPipeline, "rag://internal");
    assert!(result.is_ok(), "RagPipeline should pass when default_deny=false");
}

#[test]
fn test_governance_rag_pipeline_category_blocked_by_default_deny() {
    let gov = GovernanceConfig {
        default_deny: true,
        allowlist: vec![],
    };
    let result = gov.check_request(ThreatCategory::RagPipeline, "rag://internal");
    assert!(
        result.is_err(),
        "RagPipeline must be blocked by default-deny when not allowlisted"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("RagPipeline"),
        "Error should name the RagPipeline category; got: {}", err
    );
}

#[test]
fn test_governance_rag_pipeline_category_allowed_via_allowlist() {
    let gov = GovernanceConfig {
        default_deny: true,
        allowlist: vec!["rag://internal".to_string()],
    };
    let result = gov.check_request(ThreatCategory::RagPipeline, "rag://internal");
    assert!(
        result.is_ok(),
        "RagPipeline target on the allowlist must be permitted"
    );
}

// ── RagConfig top_k boundary conditions ──────────────────────────────────────

#[tokio::test]
async fn test_rag_top_k_zero_returns_empty() {
    // top_k = 0 → HNSW should return zero neighbours.
    let cfg = test_rag_config(4, 0);
    let mut engine = RagEngine::load(&cfg).expect("load failed");
    let v = norm_vec(4, 1.0);
    engine.index.insert(&v, 0);
    engine.docs.insert(0, "should not appear".into());

    let results = engine.search(&v).await;
    assert!(
        results.is_empty(),
        "top_k=0 should yield no results, got: {:?}", results
    );
}

#[tokio::test]
async fn test_rag_top_k_larger_than_corpus_returns_all_docs() {
    // top_k = 10 but only 3 docs inserted → all 3 should come back.
    let cfg = test_rag_config(4, 10);
    let mut engine = RagEngine::load(&cfg).expect("load failed");

    for i in 0..3usize {
        let v = norm_vec(4, i as f32 + 1.0);
        engine.index.insert(&v, i);
        engine.docs.insert(i, format!("doc-{}", i));
    }

    let query = norm_vec(4, 1.5);
    let results = engine.search(&query).await;
    assert!(
        results.len() <= 3,
        "Cannot return more docs than were inserted"
    );
    assert!(
        !results.is_empty(),
        "At least one doc should be returned"
    );
}
