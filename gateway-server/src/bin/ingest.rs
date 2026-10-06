// src/bin/ingest.rs – RAG ingestion utility

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

use gateway_server::config::AppConfig;
use gateway_server::rag::RagEngine;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise logger (configure via RUST_LOG).
    tracing_subscriber::fmt::init();

    // Load configuration – fall back to defaults if the file is missing.
    let config = match AppConfig::load("./config.toml") {
        Ok(c) => c,
        Err(_) => AppConfig::default(),
    };
    let rag_cfg = &config.rag;
    if !rag_cfg.enabled {
        info!("RAG disabled – exiting ingestion");
        return Ok(());
    }

    // Directory containing plain‑text documents (override with RAG_DOCS_DIR).
    let docs_dir = env::var("RAG_DOCS_DIR").unwrap_or_else(|_| "./documents".to_string());
    let docs_path = PathBuf::from(&docs_dir);
    if !docs_path.is_dir() {
        warn!("Documents directory does not exist or is not a directory: {}", docs_dir);
        return Ok(());
    }

    // Load (or create) the RagEngine – this loads any existing index.
    let mut rag_engine = RagEngine::load(rag_cfg).context("Failed to load/create RagEngine")?;

    // Keep track of the next document ID.
    let mut next_id = rag_engine.docs.len();

    // Walk through all *.txt files and ingest them.
    for entry in fs::read_dir(&docs_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read file {}", path.display()))?;

        // Generate embedding for the document.
        let vec = rag_engine.embed(&content);

        // Insert embedding and raw text into the engine.
        rag_engine.index.insert(&vec, next_id);
        rag_engine.docs.insert(next_id, content);
        info!(path = %path.display(), doc_id = next_id, "ingested");
        next_id += 1;
    }

    // Persist the HNSW index and the document map.
    rag_engine.index.save(&rag_cfg.index_path).context("Failed to save HNSW index")?;
    let docs_json_path = rag_cfg.index_path.with_extension("json");
    let json = serde_json::to_string_pretty(&rag_engine.docs).context("Failed to serialize docs map")?;
    fs::write(&docs_json_path, json).context("Failed to write document map file")?;

    info!("RAG ingestion complete – {} documents indexed", rag_engine.docs.len());
    Ok(())
}
