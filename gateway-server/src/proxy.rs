//! HTTP routes, proxy forwarding logic, and upstream connection management.

use crate::config::AppConfig;
use crate::error::GatewayError;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Shared application state across Axum request handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.server.timeout_seconds))
            // Security: Disable automatic redirects to prevent token leakage
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            config: Arc::new(config),
            client,
        })
    }
}

/// Simple convenience request payload for `/chat`.
#[derive(Debug, Deserialize)]
pub struct SimpleChatRequest {
    pub prompt: String,
    pub model: Option<String>,
}

/// Simple convenience response payload for `/chat`.
#[derive(Debug, Serialize)]
pub struct SimpleChatResponse {
    pub model: String,
    pub response: String,
    pub raw: serde_json::Value,
}

/// Health check endpoint response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub upstream_url: String,
    pub default_model: String,
    pub version: &'static str,
}

/// Build the Axum router with all proxy routes.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/chat/completions", post(chat_completions_handler))
        .route("/chat", post(simple_chat_handler))
        .with_state(state)
}

/// GET /health
async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        upstream_url: state.config.upstream_chat_url(),
        default_model: state.config.upstream.default_model.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// POST /v1/chat/completions - Standard OpenAI-compatible proxy endpoint
async fn chat_completions_handler(
    State(state): State<AppState>,
    Json(mut payload): Json<serde_json::Value>,
) -> Result<Response, GatewayError> {
    // 1. Validate payload structure
    let model_name = {
        let obj = payload
            .as_object_mut()
            .ok_or_else(|| GatewayError::BadRequest("Request body must be a JSON object".to_string()))?;

        if !obj.contains_key("messages") {
            return Err(GatewayError::BadRequest(
                "Missing required field 'messages' in chat completion request".to_string(),
            ));
        }

        // Default to configured model if not specified
        if !obj.contains_key("model") || obj.get("model").and_then(|v| v.as_str()).map_or(false, str::is_empty) {
            obj.insert(
                "model".to_string(),
                serde_json::Value::String(state.config.upstream.default_model.clone()),
            );
        }

        obj.get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(&state.config.upstream.default_model)
            .to_string()
    };

    // 2. Prepare upstream request
    let upstream_url = state.config.upstream_chat_url();
    let mut req_builder = state.client.post(&upstream_url).json(&payload);

    if let Some(auth_header) = state.config.authorization_header() {
        req_builder = req_builder.header(header::AUTHORIZATION, auth_header);
    }

    info!(
        upstream = %upstream_url,
        model = %model_name,
        "Forwarding chat completion request to upstream"
    );

    // 3. Dispatch request to upstream LLM
    let upstream_res = match req_builder.send().await {
        Ok(res) => res,
        Err(err) => {
            if err.is_timeout() {
                warn!(error = %err, "Upstream request timed out");
                return Err(GatewayError::UpstreamTimeout(format!(
                    "Upstream LLM at '{}' timed out after {}s",
                    upstream_url, state.config.server.timeout_seconds
                )));
            } else {
                error!(error = %err, "Upstream connection failure");
                return Err(GatewayError::UpstreamConnectionFailed(format!(
                    "Failed to connect to upstream LLM at '{}': {}",
                    upstream_url, err
                )));
            }
        }
    };

    let status = StatusCode::from_u16(upstream_res.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let content_type = upstream_res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let body_bytes = upstream_res
        .bytes()
        .await
        .map_err(|err| GatewayError::UpstreamConnectionFailed(format!("Failed to read upstream body: {}", err)))?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        content_type.parse().unwrap_or(header::HeaderValue::from_static("application/json")),
    );

    Ok((status, response_headers, body_bytes).into_response())
}

/// POST /chat - Simplified endpoint accepting {"prompt": "..."}
async fn simple_chat_handler(
    State(state): State<AppState>,
    Json(payload): Json<SimpleChatRequest>,
) -> Result<Json<SimpleChatResponse>, GatewayError> {
    if payload.prompt.trim().is_empty() {
        return Err(GatewayError::BadRequest("Prompt cannot be empty".to_string()));
    }

    let model = payload
        .model
        .unwrap_or_else(|| state.config.upstream.default_model.clone());

    let openai_body = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": payload.prompt
            }
        ],
        "stream": false
    });

    let upstream_url = state.config.upstream_chat_url();
    let mut req_builder = state.client.post(&upstream_url).json(&openai_body);

    if let Some(auth_header) = state.config.authorization_header() {
        req_builder = req_builder.header(header::AUTHORIZATION, auth_header);
    }

    let upstream_res = match req_builder.send().await {
        Ok(res) => res,
        Err(err) => {
            if err.is_timeout() {
                return Err(GatewayError::UpstreamTimeout(format!(
                    "Upstream LLM timed out after {}s",
                    state.config.server.timeout_seconds
                )));
            } else {
                return Err(GatewayError::UpstreamConnectionFailed(format!(
                    "Failed to reach upstream LLM: {}",
                    err
                )));
            }
        }
    };

    if !upstream_res.status().is_success() {
        let err_text = upstream_res.text().await.unwrap_or_default();
        return Err(GatewayError::UpstreamConnectionFailed(format!(
            "Upstream returned error: {}",
            err_text
        )));
    }

    let json_val: serde_json::Value = upstream_res
        .json()
        .await
        .map_err(|e| GatewayError::Internal(format!("Failed to parse upstream response JSON: {}", e)))?;

    // Extract message content from standard choices[0].message.content
    let response_text = json_val
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c0| c0.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|cnt| cnt.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Json(SimpleChatResponse {
        model,
        response: response_text,
        raw: json_val,
    }))
}
