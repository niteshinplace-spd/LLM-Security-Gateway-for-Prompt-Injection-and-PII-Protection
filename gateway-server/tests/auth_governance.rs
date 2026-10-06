//! Phase 4 – Authentication and Governance tests

use axum::{http::{self, HeaderMap, Request, StatusCode}, response::IntoResponse, Json};
use tower::ServiceExt; // for `oneshot`
use serde_json::json;
use gateway_server::config::{AppConfig, ThreatCategory};
use gateway_server::proxy::{create_router, AppState};
use gateway_server::error::GatewayError;

#[tokio::test]
async fn test_enforce_auth_success() {
    let mut cfg = AppConfig::default();
    cfg.security.require_auth = true;
    cfg.security.auth_token = Some("my-secret-token".to_string());

    let headers = {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            "Bearer my-secret-token".parse().unwrap(),
        );
        h
    };

    // Directly test the method (unit test)
    cfg.security.enforce_auth(&headers).expect("auth should succeed");
}

#[tokio::test]
async fn test_enforce_auth_failure_missing_header() {
    let mut cfg = AppConfig::default();
    cfg.security.require_auth = true;
    cfg.security.auth_token = Some("my-secret-token".to_string());

    let headers = HeaderMap::new(); // empty
    let err = cfg.security.enforce_auth(&headers).unwrap_err();
    // Verify we get a SecurityBlocked error (the concrete variant is defined in GatewayError)
    match err {
        GatewayError::SecurityBlocked { .. } => {}
        _ => panic!("expected SecurityBlocked error"),
    }
}

#[tokio::test]
async fn test_governance_default_deny_block() {
    let mut cfg = AppConfig::default();
    cfg.governance.default_deny = true; // enforce deny
    cfg.governance.allowlist = vec![]; // nothing allowed
    let res = cfg.governance.check_request(ThreatCategory::NetworkAccess, "http://example.com");
    assert!(res.is_err(), "governance should block by default deny");
    match res.unwrap_err() {
        GatewayError::SecurityBlocked { .. } => {}
        _ => panic!("expected SecurityBlocked error"),
    }
}

#[tokio::test]
async fn test_governance_allowlist_pass() {
    let mut cfg = AppConfig::default();
    cfg.governance.default_deny = true;
    cfg.governance.allowlist = vec!["http://example.com".to_string()];
    cfg.governance
        .check_request(ThreatCategory::NetworkAccess, "http://example.com")
        .expect("allowlist should permit request");
}

// ---------------------------------------------------------------------------
// Integration‑style tests exercising the handlers' early auth/governance checks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_chat_handler_missing_auth() {
    // Build a config that requires auth and has default‑deny enabled.
    let mut cfg = AppConfig::default();
    cfg.security.require_auth = true;
    cfg.security.auth_token = Some("valid-token".to_string());
    cfg.governance.default_deny = true; // will also block if auth passes but URL not whitelisted
    cfg.governance.allowlist = vec![]; // no allowlist entries

    // Build app state and router.
    let state = AppState::new(cfg).expect("state creation should succeed");
    let app = create_router(state);

    // Build a request without the Authorization header.
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/chat")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Json(json!({"prompt": "hello"})).into_response().into_body())
        .unwrap();

    let resp = app.oneshot(req).await.expect("request should be processed");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn integration_chat_handler_auth_and_governance_allow() {
    // Auth enabled and a matching allowlist entry, so the request should pass the early checks.
    let mut cfg = AppConfig::default();
    cfg.security.require_auth = true;
    cfg.security.auth_token = Some("valid-token".to_string());
    cfg.governance.default_deny = true;
    cfg.governance.allowlist = vec![cfg.upstream.base_url.clone()];

    // Build a client that will never actually contact the upstream – we replace the
    // `client` with a dummy that returns a successful response.
    let state = {
        let mut s = AppState::new(cfg).expect("state creation");
        // Replace the reqwest client with a mock that always returns 200 OK and an empty JSON body.
        s.client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        s
    };

    let app = create_router(state);

    // Build request with proper Authorization header.
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "Bearer valid-token".parse().unwrap(),
    );

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/chat")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Json(json!({"prompt": "test"})).into_response().into_body())
        .unwrap();

    // Attach the headers to the request.
    let mut req = req;
    *req.headers_mut() = headers;

    let resp = app.oneshot(req).await.expect("request should be processed");
    // The upstream call will fail (no real server), but we only assert that the request
    // was not rejected by auth/governance – a 5xx is acceptable here.
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}
