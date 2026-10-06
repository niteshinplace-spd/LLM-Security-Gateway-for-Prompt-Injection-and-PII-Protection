use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use hnsw_rs::prelude::*;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Configuration for Retrieval‑Augmented Generation (RAG).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RagConfig {
    /// Enable RAG functionality. When false, the engine is not initialised.
    pub enabled: bool,
    /// Dimension of the embedding vectors (must match the embedding model).
    pub vector_dim: usize,
    /// Number of nearest neighbours to retrieve per query.
    pub top_k: usize,
    /// Filesystem path where the HNSW index and document map are persisted.
    pub index_path: PathBuf,
    /// Identifier of the embedding model to use (e.g. "all-MiniLM-L6-v2").
    pub embedding_model: String,
}

impl Default for RagConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vector_dim: 384, // default for MiniLM-L6-v2
            top_k: 3,
            index_path: PathBuf::from("./rag_index"),
            embedding_model: "all-MiniLM-L6-v2".into(),
        }
    }
}

/// Result of an approximate nearest-neighbour similarity query.
#[derive(Debug, Clone)]
pub struct VectorSearchResult {
    pub id: usize,
    pub distance: f32,
}

/// Safe wrapper around an HNSW index supporting insertion, search, and persistence.
pub struct VectorIndex {
    pub(crate) hnsw: Hnsw<'static, f32, DistCosine>,
    pub dim: usize,
}

impl VectorIndex {
    /// Create a new empty index for vectors of dimensionality `dim`.
    pub fn new(dim: usize) -> Self {
        let hnsw = Hnsw::<f32, DistCosine>::new(
            16,
            100_000,
            16,
            200,
            DistCosine {},
        );
        Self { hnsw, dim }
    }

    /// Insert a vector with its external document identifier.
    pub fn insert(&self, vec: &[f32], id: usize) {
        self.hnsw.insert((vec, id));
    }

    /// Search for the `top_k` nearest neighbours to `vec`.
    pub fn search(&self, vec: &[f32], top_k: usize) -> Vec<VectorSearchResult> {
        if top_k == 0 {
            return Vec::new();
        }
        let ef_search = 32.max(top_k * 2);
        let neighbours = self.hnsw.search(vec, top_k, ef_search);
        neighbours
            .into_iter()
            .map(|n| VectorSearchResult {
                id: n.d_id,
                distance: n.distance,
            })
            .collect()
    }

    /// Persist the HNSW index to disk at the given path.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rag_index");
        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
        self.hnsw.file_dump(parent_dir, file_stem)?;
        Ok(())
    }

    /// Load a persisted HNSW index from disk.
    pub fn load<P: AsRef<Path>>(path: P, dim: usize) -> Result<Self> {
        let path = path.as_ref();
        let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rag_index");
        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let reloader = Box::leak(Box::new(HnswIo::new(parent_dir, file_stem)));
        let hnsw: Hnsw<'static, f32, DistCosine> = reloader.load_hnsw_with_dist(DistCosine {})?;
        Ok(Self { hnsw, dim })
    }
}

/// Compute a fast, deterministic pseudo-embedding from text into a normalised f32 vector.
pub fn embed_text(text: &str, dim: usize) -> Vec<f32> {
    if dim == 0 {
        return Vec::new();
    }
    let mut vec = vec![0.0f32; dim];
    for (i, &b) in text.as_bytes().iter().enumerate() {
        let idx = (i * 31 + b as usize) % dim;
        vec[idx] += ((b as f32) / 128.0) - 1.0;
    }
    let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-6 {
        for x in vec.iter_mut() {
            *x /= norm;
        }
    }
    vec
}

/// Simple RAG engine holding an ANN index and a map of document IDs to raw text.
pub struct RagEngine {
    /// HNSW index for fast vector similarity search.
    pub index: VectorIndex,
    /// Mapping from internal document IDs to their text content.
    pub docs: HashMap<usize, String>,
    /// Embedding model name – used when generating query embeddings.
    pub model_name: String,
    /// Number of neighbours to return.
    pub top_k: usize,
    /// Shared, async‑safe state wrapper for potential concurrent queries.
    state: Arc<RwLock<()>>,
}

impl RagEngine {
    /// Initialise a new engine, loading an existing index if present.
    pub fn load(config: &RagConfig) -> Result<Self> {
        // Load or create the HNSW index.
        let index = if config.index_path.exists() {
            VectorIndex::load(&config.index_path, config.vector_dim)
                .unwrap_or_else(|_| VectorIndex::new(config.vector_dim))
        } else {
            VectorIndex::new(config.vector_dim)
        };

        // Load document map – stored as JSON next to the index.
        let docs_path = config.index_path.with_extension("json");
        let docs: HashMap<usize, String> = if docs_path.exists() {
            let data = std::fs::read_to_string(&docs_path)?;
            serde_json::from_str(&data)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            index,
            docs,
            model_name: config.embedding_model.clone(),
            top_k: config.top_k,
            state: Arc::new(RwLock::new(())),
        })
    }

    /// Perform a similarity search with a raw embedding and return the top‑k document texts.
    pub async fn search(&self, query_vec: &[f32]) -> Vec<String> {
        let _guard = self.state.read().await;
        let neighbours = self.index.search(query_vec, self.top_k);
        neighbours
            .into_iter()
            .filter_map(|n| self.docs.get(&n.id).cloned())
            .collect()
    }

    /// Convenience search by text prompt: embeds the query and retrieves matching context.
    pub async fn search_text(&self, query_text: &str) -> Vec<String> {
        let query_vec = self.embed(query_text);
        self.search(&query_vec).await
    }

    /// Generate an embedding vector matching this engine's dimensionality.
    pub fn embed(&self, text: &str) -> Vec<f32> {
        embed_text(text, self.index.dim)
    }

    /// Insert a document with vector and text content.
    pub fn insert(&mut self, vec: &[f32], id: usize, text: String) {
        self.index.insert(vec, id);
        self.docs.insert(id, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a `RagConfig` that will never resolve to an existing path so
    /// `RagEngine::load` always creates a fresh in-memory HNSW index.
    fn fresh_config(dim: usize, top_k: usize) -> RagConfig {
        RagConfig {
            enabled: true,
            vector_dim: dim,
            top_k,
            index_path: PathBuf::from("/nonexistent/rag_test_index_xyz"),
            embedding_model: "test-model".into(),
        }
    }

    /// Create a unit vector of the requested dimension.
    fn unit_vec(dim: usize) -> Vec<f32> {
        let v = 1.0_f32 / (dim as f32).sqrt();
        vec![v; dim]
    }

    // ── RagConfig unit tests ─────────────────────────────────────────────────

    #[test]
    fn test_rag_config_defaults() {
        let cfg = RagConfig::default();
        assert!(!cfg.enabled, "RAG should be disabled by default");
        assert_eq!(cfg.vector_dim, 384, "Default vector_dim should match MiniLM-L6-v2");
        assert_eq!(cfg.top_k, 3);
        assert_eq!(cfg.index_path, PathBuf::from("./rag_index"));
        assert_eq!(cfg.embedding_model, "all-MiniLM-L6-v2");
    }

    #[test]
    fn test_rag_config_custom_fields() {
        let cfg = RagConfig {
            enabled: true,
            vector_dim: 768,
            top_k: 5,
            index_path: PathBuf::from("/tmp/my_index"),
            embedding_model: "custom-model".into(),
        };
        assert!(cfg.enabled);
        assert_eq!(cfg.vector_dim, 768);
        assert_eq!(cfg.top_k, 5);
        assert_eq!(cfg.embedding_model, "custom-model");
    }

    #[test]
    fn test_rag_config_clone() {
        let original = RagConfig::default();
        let cloned = original.clone();
        assert_eq!(original.vector_dim, cloned.vector_dim);
        assert_eq!(original.top_k, cloned.top_k);
        assert_eq!(original.index_path, cloned.index_path);
        assert_eq!(original.embedding_model, cloned.embedding_model);
    }

    #[test]
    fn test_rag_config_serde_roundtrip() {
        let cfg = RagConfig {
            enabled: true,
            vector_dim: 512,
            top_k: 10,
            index_path: PathBuf::from("./custom_index"),
            embedding_model: "sentence-transformers/all-mpnet-base-v2".into(),
        };
        let json = serde_json::to_string(&cfg).expect("serialization failed");
        let deserialized: RagConfig = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(deserialized.enabled, cfg.enabled);
        assert_eq!(deserialized.vector_dim, cfg.vector_dim);
        assert_eq!(deserialized.top_k, cfg.top_k);
        assert_eq!(deserialized.index_path, cfg.index_path);
        assert_eq!(deserialized.embedding_model, cfg.embedding_model);
    }

    // ── RagEngine unit tests ─────────────────────────────────────────────────

    #[test]
    fn test_rag_engine_load_fresh_index() {
        let cfg = fresh_config(4, 2);
        let engine = RagEngine::load(&cfg).expect("RagEngine::load should succeed for a fresh index");
        assert!(engine.docs.is_empty(), "Freshly loaded engine should have no docs");
    }

    #[test]
    fn test_rag_engine_model_name_and_top_k_stored() {
        let cfg = fresh_config(8, 5);
        let engine = RagEngine::load(&cfg).expect("load failed");
        assert_eq!(engine.model_name, "test-model");
        assert_eq!(engine.top_k, 5);
    }

    #[test]
    fn test_rag_engine_insert_doc() {
        let cfg = fresh_config(4, 1);
        let mut engine = RagEngine::load(&cfg).expect("load failed");

        let vec = unit_vec(4);
        engine.index.insert(&vec, 0);
        engine.docs.insert(0, "Hello, world!".to_string());

        assert_eq!(engine.docs.len(), 1);
        assert_eq!(engine.docs[&0], "Hello, world!");
    }

    #[test]
    fn test_rag_engine_multiple_docs_inserted() {
        let cfg = fresh_config(4, 2);
        let mut engine = RagEngine::load(&cfg).expect("load failed");

        for i in 0..5 {
            let mut vec = vec![0.0_f32; 4];
            vec[i % 4] = 1.0;
            engine.index.insert(&vec, i);
            engine.docs.insert(i, format!("Document #{}", i));
        }

        assert_eq!(engine.docs.len(), 5, "All 5 documents should be stored");
    }

    #[tokio::test]
    async fn test_rag_engine_search_empty_returns_nothing() {
        let cfg = fresh_config(4, 3);
        let engine = RagEngine::load(&cfg).expect("load failed");

        let query = unit_vec(4);
        let results = engine.search(&query).await;
        assert!(results.is_empty(), "Search on empty engine must return no results");
    }

    #[tokio::test]
    async fn test_rag_engine_search_finds_inserted_doc() {
        let cfg = fresh_config(4, 1);
        let mut engine = RagEngine::load(&cfg).expect("load failed");

        let vec = unit_vec(4);
        engine.index.insert(&vec, 0);
        engine.docs.insert(0, "Retrieval test document".to_string());

        let results = engine.search(&vec).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Retrieval test document");
    }

    #[tokio::test]
    async fn test_rag_engine_search_top_k_respected() {
        let cfg = fresh_config(4, 2);
        let mut engine = RagEngine::load(&cfg).expect("load failed");

        for i in 0..5usize {
            let mut vec = vec![0.0_f32; 4];
            vec[i % 4] += 1.0;
            let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
            let vec: Vec<f32> = vec.iter().map(|x| x / norm).collect();
            engine.index.insert(&vec, i);
            engine.docs.insert(i, format!("doc-{}", i));
        }

        let query = unit_vec(4);
        let results = engine.search(&query).await;
        assert!(
            results.len() <= 2,
            "search should return at most top_k={} results, got {}",
            cfg.top_k,
            results.len()
        );
    }

    #[tokio::test]
    async fn test_rag_engine_search_only_returns_known_docs() {
        let cfg = fresh_config(4, 5);
        let mut engine = RagEngine::load(&cfg).expect("load failed");

        for i in 0..3usize {
            let mut vec = vec![0.0_f32; 4];
            vec[i % 4] = 1.0;
            engine.index.insert(&vec, i);
        }
        engine.docs.insert(0, "doc-zero".to_string());
        engine.docs.insert(2, "doc-two".to_string());

        let query = unit_vec(4);
        let results = engine.search(&query).await;
        for r in &results {
            assert!(
                r == "doc-zero" || r == "doc-two",
                "Unexpected result: {}", r
            );
        }
    }
}
