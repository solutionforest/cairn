//! The admin API error envelope: `{"error":{"code","message","request_id"}}`.

use axum::Json;
use axum::response::{IntoResponse, Response};
use cairn_auth::AuthError;
use http::StatusCode;

tokio::task_local! {
    /// Request id of the admin request being handled (set by the auth middleware).
    pub static REQUEST_ID: String;
}

/// Request id header on every admin response.
pub const REQUEST_ID_HEADER: &str = "x-cairn-request-id";

/// An admin API error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct AdminError {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine-readable code.
    pub code: String,
    /// Human message (never contains secrets).
    pub message: String,
}

impl AdminError {
    /// Error with an explicit status and code.
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.into(),
        }
    }
    /// 400 InvalidArgument.
    pub fn invalid(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidArgument", m)
    }
    /// 404 NotFound.
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NotFound", m)
    }
    /// 409 Conflict.
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "Conflict", m)
    }
    /// 403 AccessDenied.
    pub fn denied(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "AccessDenied", m)
    }
    /// 501 NotImplemented.
    pub fn not_implemented(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, "NotImplemented", m)
    }
    /// 500 InternalError (the cause is logged, not returned).
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "admin internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "internal error",
        )
    }
}

impl From<AuthError> for AdminError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::NotFound { .. } => Self::not_found(e.to_string()),
            AuthError::AlreadyExists { .. } => {
                Self::new(StatusCode::CONFLICT, "AlreadyExists", e.to_string())
            }
            AuthError::Invalid(m) => Self::invalid(m),
            AuthError::Policy(p) => {
                Self::new(StatusCode::BAD_REQUEST, "MalformedPolicy", p.to_string())
            }
            AuthError::AccessDenied(m) => Self::denied(m),
            AuthError::LimitExceeded(m) => Self::new(StatusCode::CONFLICT, "LimitExceeded", m),
            AuthError::Backend(_) | AuthError::Corrupt(_) | AuthError::Crypto => Self::internal(e),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let rid = REQUEST_ID.try_with(Clone::clone).unwrap_or_default();
        let body = serde_json::json!({
            "error": { "code": self.code, "message": self.message, "request_id": rid }
        });
        (self.status, Json(body)).into_response()
    }
}
