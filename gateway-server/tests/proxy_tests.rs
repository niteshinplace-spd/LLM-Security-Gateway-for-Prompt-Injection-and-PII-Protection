use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use gateway_server::config::AppConfig;
use gateway_server::proxy::{create_router, AppState};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn setup_test_app() -> axum::Router {
    let config = AppConfig::default();
    let state = AppState::new(config).expect("Failed to initialize AppState");
    create_router(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["default_model"], "llama3.2:3b");
}

#[tokio::test]
async fn test_chat_completions_missing_messages() {
    let app = setup_test_app();

    let payload = serde_json::json!({
        "model": "llama3.2:3b"
    });

    let request = Request::builder()
        .uri("/v1/chat/completions")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["error"]["type"], "invalid_request_error");
    assert!(json["error"]["message"].as_str().unwrap().contains("messages"));
}

#[tokio::test]
async fn test_simple_chat_empty_prompt() {
    let app = setup_test_app();

    let payload = serde_json::json!({
        "prompt": "   "
    });

    let request = Request::builder()
        .uri("/chat")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(json["error"]["type"], "invalid_request_error");
    assert!(json["error"]["message"].as_str().unwrap().contains("empty"));
}

#[tokio::test]
async fn test_malformed_json_returns_400() {
    let app = setup_test_app();

    let request = Request::builder()
        .uri("/v1/chat/completions")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{invalid-json"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
