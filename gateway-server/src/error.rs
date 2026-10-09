//! Error types and HTTP response mappings for the gateway server.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Too many requests")]
    RateLimited,

    #[error("Upstream gateway timeout: {0}")]
    UpstreamTimeout(String),

    #[error("Upstream connection failure: {0}")]
    UpstreamConnectionFailed(String),

    #[error("Security policy violation: {reason}")]
    SecurityBlocked {
        reason: String,
        category: String,
    },

    #[error("Internal gateway error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, error_type, message, category) = match self {
            GatewayError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error".to_string(),
                msg,
                None,
            ),
            GatewayError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error".to_string(),
                "Too many requests. Please try again later.".to_string(),
                None,
            ),
            GatewayError::UpstreamTimeout(msg) => (
                StatusCode::GATEWAY_TIMEOUT,
                "gateway_timeout".to_string(),
                msg,
                None,
            ),
            GatewayError::UpstreamConnectionFailed(msg) => (
                StatusCode::BAD_GATEWAY,
                "bad_gateway".to_string(),
                msg,
                None,
            ),
            GatewayError::SecurityBlocked { reason, category } => (
                StatusCode::FORBIDDEN,
                "security_violation".to_string(),
                reason,
                Some(category),
            ),
            GatewayError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_gateway_error".to_string(),
                msg,
                None,
            ),
        };

        let body = ErrorEnvelope {
            error: ErrorDetail {
                message,
                error_type,
                code: status.as_u16(),
                category,
            },
        };

        (status, Json(body)).into_response()
    }
}
