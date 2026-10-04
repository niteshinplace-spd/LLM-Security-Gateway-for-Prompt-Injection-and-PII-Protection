//! Gateway Server - Async HTTP Security Proxy for LLMs
//!
//! Provides the network-facing layer for the LLM Security Gateway, routing
//! requests through gateway-core inspection filters to an upstream LLM (e.g. Ollama).

use gateway_core::Verdict;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load .env environment variables if present
    if let Ok(path) = dotenvy::dotenv() {
        println!("[startup] Loaded environment configuration from {:?}", path);
    }

    // 2. Initialize structured tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to initialize tracing subscriber");

    info!("=== Rust-Native Sub-Millisecond LLM Security Gateway ===");
    info!("Target LLM Provider: Local Ollama (http://127.0.0.1:11434)");
    info!("Workspace setup verified: gateway-core and gateway-server connected.");

    let dummy_verdict = Verdict::Allow;
    info!("Security engine readiness: allowed={}", dummy_verdict.is_allowed());
    info!("Phase 0 setup complete. Ready to proceed to Phase 1 (Proxy Engine).");

    Ok(())
}
