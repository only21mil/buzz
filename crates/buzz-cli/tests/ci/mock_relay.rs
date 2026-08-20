use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedRequest {
    pub method: Method,
    pub path_and_query: String,
    pub response_status: StatusCode,
    pub response_body: Vec<u8>,
    pub response_content_type: &'static str,
}

impl ExpectedRequest {
    pub fn json(
        method: Method,
        path_and_query: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            method,
            path_and_query: path_and_query.into(),
            response_status: StatusCode::OK,
            response_body: body.into(),
            response_content_type: "application/json",
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.response_status = status;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    pub method: Method,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct RelayState {
    expected: VecDeque<ExpectedRequest>,
    recorded: Vec<RecordedRequest>,
    errors: Vec<String>,
}

pub struct MockRelay {
    base_url: String,
    state: Arc<Mutex<RelayState>>,
    task: JoinHandle<()>,
}

impl MockRelay {
    pub async fn start(expected: impl IntoIterator<Item = ExpectedRequest>) -> Self {
        let state = Arc::new(Mutex::new(RelayState {
            expected: expected.into_iter().collect(),
            ..RelayState::default()
        }));
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock relay");
        let addr: SocketAddr = listener.local_addr().expect("mock relay address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock relay server must run");
        });
        Self {
            base_url: format!("http://{addr}"),
            state,
            task,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn recorded(&self) -> Vec<RecordedRequest> {
        self.state
            .lock()
            .expect("mock relay state")
            .recorded
            .clone()
    }

    pub fn assert_finished(&self) {
        let state = self.state.lock().expect("mock relay state");
        assert!(
            state.errors.is_empty(),
            "mock relay request errors:\n{}",
            state.errors.join("\n")
        );
        assert!(
            state.expected.is_empty(),
            "mock relay still expected requests: {:#?}",
            state.expected
        );
    }
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(State(state): State<Arc<Mutex<RelayState>>>, request: Request) -> Response<Body> {
    let method = request.method().clone();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_else(|| request.uri().path().to_owned());
    let headers = copy_headers(request.headers());
    let body = match to_bytes(request.into_body(), 1_048_576).await {
        Ok(body) => body.to_vec(),
        Err(error) => {
            let mut state = state.lock().expect("mock relay state");
            state.errors.push(format!(
                "could not read {method} {path_and_query} body: {error}"
            ));
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "body read failed");
        }
    };

    let mut state = state.lock().expect("mock relay state");
    state.recorded.push(RecordedRequest {
        method: method.clone(),
        path_and_query: path_and_query.clone(),
        headers,
        body,
    });
    let Some(expected) = state.expected.pop_front() else {
        state
            .errors
            .push(format!("unexpected request: {method} {path_and_query}"));
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "unexpected request");
    };
    if method != expected.method || path_and_query != expected.path_and_query {
        state.errors.push(format!(
            "expected {} {}, received {method} {path_and_query}",
            expected.method, expected.path_and_query
        ));
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "request mismatch");
    }

    Response::builder()
        .status(expected.response_status)
        .header("content-type", expected.response_content_type)
        .body(Body::from(expected.response_body))
        .expect("mock relay response")
}

fn copy_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = if matches!(
                name.as_str(),
                "authorization" | "cookie" | "proxy-authorization" | "x-auth-tag"
            ) {
                "<redacted>".to_owned()
            } else {
                value.to_str().unwrap_or("<non-utf8>").to_owned()
            };
            (name.as_str().to_owned(), value)
        })
        .collect()
}

fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(format!("{{\"error\":\"{message}\"}}")))
        .expect("mock relay error response")
}

#[test]
fn recorded_headers_redact_auth_material() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Nostr private-event".parse().unwrap());
    headers.insert("x-auth-tag", "owner-attestation".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    let copied = copy_headers(&headers);
    assert!(copied.contains(&("authorization".to_owned(), "<redacted>".to_owned())));
    assert!(copied.contains(&("x-auth-tag".to_owned(), "<redacted>".to_owned())));
    assert!(copied.contains(&("content-type".to_owned(), "application/json".to_owned())));
}
