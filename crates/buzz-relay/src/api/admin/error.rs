use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: &'static str,
    message: String,
    request_id: uuid::Uuid,
}

impl ApiError {
    pub fn bad_request(code: &'static str, message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.to_owned(),
        }
    }

    pub fn conflict(message: &str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.to_owned(),
        }
    }

    pub fn unavailable(message: &str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "roster_unavailable",
            message: message.to_owned(),
        }
    }

    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "request is not authorized".to_owned(),
        }
    }

    pub fn forbidden_with_message(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.to_owned(),
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "a valid admin credential is required".to_owned(),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "record was not found".to_owned(),
        }
    }

    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "request failed".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                    request_id: uuid::Uuid::new_v4(),
                },
            }),
        )
            .into_response();
        // Every 401 carries a challenge naming the only scheme this API
        // accepts, so clients know what to present.
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Nostr"),
            );
        }
        response
    }
}

impl From<buzz_db::DbError> for ApiError {
    fn from(_: buzz_db::DbError) -> Self {
        Self::internal()
    }
}

impl From<super::roster::RosterError> for ApiError {
    fn from(error: super::roster::RosterError) -> Self {
        match error {
            // The roster migration has not landed: a deployment fact, not a
            // client error and never an auth decision.
            super::roster::RosterError::Unavailable(message) => Self::unavailable(message),
            super::roster::RosterError::Internal(_) => Self::internal(),
        }
    }
}
