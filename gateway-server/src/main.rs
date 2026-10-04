//! Gateway Server - Async HTTP Security Proxy for LLMs
//!
//! Provides the network-facing layer for the LLM Security Gateway, routing
//! requests through gateway-core inspection filters to an upstream LLM (e.g. Ollama).

use gateway_server::config::AppConfig;
use gateway_server::proxy::{create_router, AppState};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load environment variables from .env if present
    if let Ok(path) = dotenvy::dotenv() {
        println!("[startup] Loaded environment configuration from {:?}", path);
    }

    // 2. Initialize tracing logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!("=== Rust-Native Sub-Millisecond LLM Security Gateway ===");

    // 3. Load configuration (config.toml + env overrides + SSRF validation)
    let config = AppConfig::load("config.toml")?;
    info!(
        host = %config.server.host,
        port = %config.server.port,
        upstream_url = %config.upstream_chat_url(),
        default_model = %config.upstream.default_model,
        "Configuration loaded successfully"
    );

    // 4. Initialize shared application state & HTTP client
    let bind_addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| format!("Invalid socket address {}:{}: {}", config.server.host, config.server.port, e))?;

    let state = AppState::new(config)?;

    // 5. Construct Axum router with middleware
    let app = create_router(state).layer(TraceLayer::new_for_http());

    // 6. Bind listener and start server
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("🚀 Security Gateway listening on http://{}", bind_addr);
    info!("Endpoints available:");
    info!("  - GET  /health");
    info!("  - POST /v1/chat/completions (OpenAI compatible)");
    info!("  - POST /chat (Simplified prompt interface)");

    axum::serve(listener, app).await?;

    Ok(())
}
