//! HTTP routes, proxy forwarding logic, and upstream connection management.

use crate::audit::{generate_request_id, AuditRecord, RequestOutcome};
use crate::config::{AppConfig, ThreatCategory};
use crate::rag::RagEngine;
use crate::error::GatewayError;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::StreamExt;
use gateway_core::{GatewayMetrics, InjectionScanner, PiiScanner, SharedMetrics, SlidingWindowScanner, StreamDecision};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Shared application state across Axum request handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub client: reqwest::Client,
    pub injection_scanner: Arc<InjectionScanner>,
    pub pii_scanner: Arc<PiiScanner>,
    pub rag_engine: Option<Arc<RagEngine>>,
    pub metrics: SharedMetrics,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.server.timeout_seconds))
            // Security: Disable automatic redirects to prevent token leakage
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let rag_engine = if config.rag.enabled {
            match RagEngine::load(&config.rag) {
                Ok(engine) => {
                    info!("RAG engine initialised successfully");
                    Some(Arc::new(engine))
                }
                Err(e) => {
                    warn!("Failed to initialise RAG engine: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(config),
            client,
            injection_scanner: Arc::new(InjectionScanner::new()),
            pii_scanner: Arc::new(PiiScanner::new()),
            rag_engine,
            metrics: Arc::new(GatewayMetrics::new()),
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
        .route("/metrics", get(metrics_handler))
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

/// GET /metrics — Prometheus text-format exposition of all gateway counters.
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.prometheus_text();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// Wraps an upstream byte stream in a real-time sliding-window security scanner.
///
/// Chunks passing through are inspected across token boundaries. If a PII or secret leak
/// or prompt injection echo is detected, the stream is aborted immediately, emitting a terminal
/// security error frame and dropping the remaining stream.
pub fn create_secure_sse_stream<S, E>(
    mut upstream_stream: S,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = Result<Bytes, E>> + Unpin + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let mut scanner = SlidingWindowScanner::default();
    let mut terminated = false;

    futures_util::stream::poll_fn(move |cx| {
        if terminated {
            return std::task::Poll::Ready(None);
        }

        match upstream_stream.poll_next_unpin(cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                let text = String::from_utf8_lossy(&bytes);
                match scanner.process_sse_chunk(&text) {
                    StreamDecision::Pass => std::task::Poll::Ready(Some(Ok(bytes))),
                    StreamDecision::Kill { reason, category } => {
                        warn!(
                            reason = %reason,
                            category = ?category,
                            "Mid-stream security policy violation: cutting off stream immediately"
                        );
                        terminated = true;
                        let err_sse = format!(
                            "event: error\ndata: {{\"error\":{{\"message\":\"Stream blocked by security policy: {}\",\"type\":\"security_violation\",\"code\":403}}}}\n\n",
                            reason
                        );
                        std::task::Poll::Ready(Some(Ok(Bytes::from(err_sse))))
                    }
                }
            }
            std::task::Poll::Ready(Some(Err(err))) => {
                terminated = true;
                std::task::Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err.to_string(),
                ))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
}

/// Metrics-aware variant of [`create_secure_sse_stream`].
///
/// Identical security semantics, but increments `stream_kills_total` on the shared
/// [`GatewayMetrics`] counter whenever a mid-stream violation terminates the stream.
fn create_secure_sse_stream_tracked<S, E>(
    mut upstream_stream: S,
    metrics: SharedMetrics,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = Result<Bytes, E>> + Unpin + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let mut scanner = SlidingWindowScanner::default();
    let mut terminated = false;

    futures_util::stream::poll_fn(move |cx| {
        if terminated {
            return std::task::Poll::Ready(None);
        }

        match upstream_stream.poll_next_unpin(cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                let text = String::from_utf8_lossy(&bytes);
                match scanner.process_sse_chunk(&text) {
                    StreamDecision::Pass => std::task::Poll::Ready(Some(Ok(bytes))),
                    StreamDecision::Kill { reason, category } => {
                        warn!(
                            reason = %reason,
                            category = ?category,
                            "Mid-stream security policy violation: cutting off stream (metrics tracked)"
                        );
                        metrics.inc_stream_kill();
                        terminated = true;
                        let err_sse = format!(
                            "event: error\ndata: {{\"error\":{{\"message\":\"Stream blocked by security policy: {}\",\"type\":\"security_violation\",\"code\":403}}}}\n\n",
                            reason
                        );
                        std::task::Poll::Ready(Some(Ok(Bytes::from(err_sse))))
                    }
                }
            }
            std::task::Poll::Ready(Some(Err(err))) => {
                terminated = true;
                std::task::Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err.to_string(),
                ))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
}

/// POST /v1/chat/completions - Standard OpenAI-compatible proxy endpoint
async fn chat_completions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut payload): Json<serde_json::Value>,
) -> Result<Response, GatewayError> {
    // --- Phase 7: Observability instrumentation ---
    state.metrics.inc_requests();
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(generate_request_id);
    let mut audit = AuditRecord::new(request_id.clone(), "/v1/chat/completions");

    // 1. Authentication enforcement
    if let Err(e) = state.config.security.enforce_auth(&headers) {
        state.metrics.inc_policy_block();
        audit.outcome = RequestOutcome::BlockedPolicy;
        audit.block_reason = Some(e.to_string());
        audit.emit();
        return Err(e);
    }

    // 2. Governance check (NetworkAccess) for upstream target URL
    if let Err(e) = state.config.governance.check_request(ThreatCategory::NetworkAccess, &state.config.upstream.base_url) {
        state.metrics.inc_policy_block();
        audit.outcome = RequestOutcome::BlockedPolicy;
        audit.block_reason = Some(e.to_string());
        audit.emit();
        return Err(e);
    }

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
    audit.model = model_name.clone();
    audit.streaming = payload.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

    // 3. Inbound Security Inspection (Sub-Millisecond Guardrails)
    if let Some(messages) = payload.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                let report = state.injection_scanner.scan(content);
                audit.scan_latency_us += report.latency_micros;
                if let gateway_core::Verdict::Block { reason, category } = report.verdict {
                    warn!(
                        reason = %reason,
                        category = ?category,
                        latency_us = report.latency_micros,
                        request_id = %request_id,
                        "Inbound prompt injection blocked"
                    );
                    state.metrics.inc_injection_block();
                    audit.injection_detected = true;
                    audit.outcome = RequestOutcome::BlockedSecurity;
                    audit.block_reason = Some(reason.clone());
                    audit.emit();
                    return Err(GatewayError::SecurityBlocked {
                        reason,
                        category: format!("{:?}", category),
                    });
                }
            }
        }
    }

    // 4. RAG Pipeline: Retrieve relevant context and enrich prompt if enabled
    if state.config.rag.enabled {
        if let Err(e) = state.config.governance.check_request(ThreatCategory::RagPipeline, "rag://internal") {
            state.metrics.inc_policy_block();
            audit.outcome = RequestOutcome::BlockedPolicy;
            audit.block_reason = Some(e.to_string());
            audit.emit();
            return Err(e);
        }

        if let Some(ref rag_engine) = state.rag_engine {
            if let Some(messages) = payload.get_mut("messages").and_then(|m| m.as_array_mut()) {
                let user_content = messages.iter().rev().find_map(|msg| {
                    if msg.get("role").and_then(|r| r.as_str()) == Some("user") {
                        msg.get("content").and_then(|c| c.as_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                });

                if let Some(user_prompt) = user_content {
                    let context_chunks = rag_engine.search_text(&user_prompt).await;
                    if !context_chunks.is_empty() {
                        state.metrics.inc_rag_retrieval();
                        audit.rag_retrieval_performed = true;
                        let context_block = format!("[Retrieved Context]:\n{}", context_chunks.join("\n---\n"));
                        messages.insert(
                            0,
                            serde_json::json!({
                                "role": "system",
                                "content": context_block
                            }),
                        );
                    }
                }
            }
        }
    }

    // 5. Prepare upstream request
    let upstream_url = state.config.upstream_chat_url();
    let mut req_builder = state.client.post(&upstream_url).json(&payload);

    if let Some(auth_header) = state.config.authorization_header() {
        req_builder = req_builder.header(header::AUTHORIZATION, auth_header);
    }

    info!(
        upstream = %upstream_url,
        model = %model_name,
        request_id = %request_id,
        "Forwarding chat completion request to upstream"
    );

    // 6. Dispatch request to upstream LLM — time the round trip
    let upstream_start = Instant::now();
    let upstream_res = match req_builder.send().await {
        Ok(res) => res,
        Err(err) => {
            let elapsed = upstream_start.elapsed();
            audit.upstream_latency_us = elapsed.as_micros() as u64;
            audit.outcome = RequestOutcome::UpstreamError;
            audit.block_reason = Some(err.to_string());
            audit.emit();
            if err.is_timeout() {
                warn!(error = %err, request_id = %request_id, "Upstream request timed out");
                return Err(GatewayError::UpstreamTimeout(format!(
                    "Upstream LLM at '{}' timed out after {}s",
                    upstream_url, state.config.server.timeout_seconds
                )));
            } else {
                error!(error = %err, request_id = %request_id, "Upstream connection failure");
                return Err(GatewayError::UpstreamConnectionFailed(format!(
                    "Failed to connect to upstream LLM at '{}': {}",
                    upstream_url, err
                )));
            }
        }
    };
    let upstream_elapsed = upstream_start.elapsed();
    state.metrics.record_upstream_latency(upstream_elapsed);
    audit.upstream_latency_us = upstream_elapsed.as_micros() as u64;

    let status = StatusCode::from_u16(upstream_res.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let content_type = upstream_res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let is_stream = payload
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if is_stream && status.is_success() {
        audit.streaming = true;
        // Note: stream_killed is updated asynchronously inside create_secure_sse_stream.
        // We emit the audit record here before streaming begins (best-effort).
        audit.emit();

        let metrics_clone = Arc::clone(&state.metrics);
        let stream = create_secure_sse_stream_tracked(upstream_res.bytes_stream(), metrics_clone);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/event-stream"),
        );
        response_headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-cache"),
        );
        response_headers.insert(
            header::CONNECTION,
            header::HeaderValue::from_static("keep-alive"),
        );
        response_headers.insert(
            "x-request-id",
            request_id.parse().unwrap_or(header::HeaderValue::from_static("unknown")),
        );

        return Ok((status, response_headers, Body::from_stream(stream)).into_response());
    }

    let mut body_bytes = upstream_res
        .bytes()
        .await
        .map_err(|err| GatewayError::UpstreamConnectionFailed(format!("Failed to read upstream body: {}", err)))?;

    // 7. Outbound Security Inspection (PII & Secret Redaction)
    if status.is_success() && content_type.contains("application/json") {
        if let Ok(mut json_body) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let mut modified = false;
            if let Some(choices) = json_body.get_mut("choices").and_then(|c| c.as_array_mut()) {
                for choice in choices {
                    if let Some(message) = choice.get_mut("message") {
                        if let Some(content) = message.get("content").and_then(|c| c.as_str()) {
                            let (redacted, findings, elapsed_us) = state.pii_scanner.redact(content);
                            if !findings.is_empty() {
                                warn!(
                                    findings_count = findings.len(),
                                    latency_us = elapsed_us,
                                    request_id = %request_id,
                                    "Redacted sensitive PII / secret leak in chat completion response"
                                );
                                state.metrics.inc_pii_redaction();
                                audit.pii_redacted = true;
                                audit.pii_findings_count += findings.len();
                                message["content"] = serde_json::Value::String(redacted);
                                modified = true;
                            }
                        }
                    }
                }
            }

            if modified {
                if let Ok(serialized) = serde_json::to_vec(&json_body) {
                    body_bytes = serialized.into();
                }
            }
        }
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        content_type.parse().unwrap_or(header::HeaderValue::from_static("application/json")),
    );
    response_headers.insert(
        "x-request-id",
        request_id.parse().unwrap_or(header::HeaderValue::from_static("unknown")),
    );

    audit.emit();
    Ok((status, response_headers, body_bytes).into_response())
}

/// POST /chat - Simplified endpoint accepting {"prompt": "..."}
async fn simple_chat_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SimpleChatRequest>,
) -> Result<Json<SimpleChatResponse>, GatewayError> {
    if payload.prompt.trim().is_empty() {
        return Err(GatewayError::BadRequest("Prompt cannot be empty".to_string()));
    }

    // 1. Authentication enforcement
    state.config.security.enforce_auth(&headers)?;

    // 2. Governance check (NetworkAccess)
    state.config.governance.check_request(ThreatCategory::NetworkAccess, &state.config.upstream.base_url)?;

    // 3. Inbound Security Inspection (Sub-Millisecond Guardrails)
    let report = state.injection_scanner.scan(&payload.prompt);
    if let gateway_core::Verdict::Block { reason, category } = report.verdict {
        warn!(
            reason = %reason,
            category = ?category,
            latency_us = report.latency_micros,
            "Inbound prompt injection blocked on /chat"
        );
        return Err(GatewayError::SecurityBlocked {
            reason,
            category: format!("{:?}", category),
        });
    }

    // 4. RAG Pipeline: Retrieve relevant context and enrich prompt if enabled
    let mut final_prompt = payload.prompt.clone();
    if state.config.rag.enabled {
        state.config.governance.check_request(ThreatCategory::RagPipeline, "rag://internal")?;

        if let Some(ref rag_engine) = state.rag_engine {
            let context_chunks = rag_engine.search_text(&payload.prompt).await;
            if !context_chunks.is_empty() {
                final_prompt = format!(
                    "Context:\n{}\n\nUser Question: {}",
                    context_chunks.join("\n---\n"),
                    payload.prompt
                );
            }
        }
    }

    let model = payload
        .model
        .unwrap_or_else(|| state.config.upstream.default_model.clone());

    let openai_body = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": final_prompt
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

    // Outbound PII / Secret Inspection
    let (sanitized_response, findings, elapsed_us) = state.pii_scanner.redact(&response_text);
    if !findings.is_empty() {
        warn!(
            findings_count = findings.len(),
            latency_us = elapsed_us,
            "Redacted sensitive PII / secret leak in /chat response"
        );
    }

    Ok(Json(SimpleChatResponse {
        model,
        response: sanitized_response,
        raw: json_val,
    }))
}
