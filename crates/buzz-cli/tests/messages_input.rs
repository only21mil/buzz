use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use axum::{
    routing::{post, put},
    Json, Router,
};
use serde_json::{json, Value};

async fn run_send(
    relay: String,
    content: &str,
    stdin: Option<&str>,
    file: Option<PathBuf>,
) -> Output {
    let content = content.to_owned();
    let stdin = stdin.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_buzz"));
        command
            .env_clear()
            .env("BUZZ_PRIVATE_KEY", "11".repeat(32)) // Synthetic test identity.
            .args([
                "--relay",
                &relay,
                "messages",
                "send",
                "--channel",
                "11111111-1111-4111-8111-111111111111",
                "--content",
                &content,
            ]);
        if let Some(file) = file {
            command.arg("--file").arg(file);
        }
        let mut child = command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

async fn relay() -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let queries = requests.clone();
    let events = requests.clone();
    let app = Router::new()
        .route(
            "/query",
            post(move |Json(body): Json<Value>| async move {
                queries.lock().unwrap().push(body);
                Json(json!([]))
            }),
        )
        .route(
            "/upload",
            put(|| async {
                Json(json!({
                    "url": "https://example.invalid/image.png",
                    "sha256": "aa".repeat(32), "size": 8,
                    "type": "image/png", "uploaded": 1
                }))
            }),
        )
        .route(
            "/events",
            post(move |Json(body): Json<Value>| async move {
                events.lock().unwrap().push(body);
                Json(json!({"event_id": "accepted", "accepted": true, "message": ""}))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, requests, server)
}

#[tokio::test]
async fn blank_messages_fail_before_any_relay_request() {
    let (url, requests, server) = relay().await;
    for (content, stdin) in [
        ("-", None),
        ("-", Some("")),
        ("-", Some(" \t\r\n\u{2003}")),
        ("", None),
        (" \t\r\n\u{2003}", None),
    ] {
        let output = run_send(url.clone(), content, stdin, None).await;
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains("message content must not be empty"));
        assert!(
            requests.lock().unwrap().is_empty(),
            "blank input must not contact the relay"
        );
    }
    server.abort();
}

#[tokio::test]
async fn valid_literal_and_stdin_messages_preserve_content() {
    let (url, requests, server) = relay().await;
    let text = "  hello\nworld \t\n";
    for (content, stdin) in [(text, None), ("-", Some(text))] {
        requests.lock().unwrap().clear();
        let output = run_send(url.clone(), content, stdin, None).await;
        assert!(output.status.success(), "{output:?}");
        let requests = requests.lock().unwrap();
        let event = requests.iter().find(|body| body["kind"] == 9).unwrap();
        assert_eq!(event["content"], text);
    }
    server.abort();
}

#[tokio::test]
async fn attachment_only_message_remains_supported() {
    let (url, requests, server) = relay().await;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
    let output = run_send(url, "-", None, Some(file.path().to_path_buf())).await;
    assert!(output.status.success(), "{output:?}");
    let requests = requests.lock().unwrap();
    let event = requests.iter().find(|body| body["kind"] == 9).unwrap();
    assert_eq!(
        event["content"],
        "\n![image](https://example.invalid/image.png)"
    );
    assert!(event["tags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tag| tag[0] == "imeta"));
    server.abort();
}
