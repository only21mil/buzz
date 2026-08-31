//! Tests for `terminal_runtime`, kept separate to satisfy the source file-size cap.

use super::*;
use buzz_terminal::damage::{CursorFrame, RowFrame, Span};

#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tauri::ipc::InvokeResponseBody;
#[cfg(unix)]
use tauri::Manager;

fn publication(spans: Vec<Span>) -> Publication {
    Publication {
        subscription_id: SubscriptionId::new(),
        sequence: 7,
        frame: buzz_terminal::damage::Frame {
            rows: vec![RowFrame {
                line: 3,
                wrapped: true,
                spans,
            }],
            cursor: CursorFrame {
                line: 1,
                column: 2,
                visible: true,
            },
            cursor_changed: true,
            full: true,
            viewport: Viewport {
                generation: 4,
                columns: 80,
                screen_lines: 24,
            },
        },
    }
}

fn style() -> Style {
    Style {
        fg: 1,
        bg: 2,
        flags: 3,
    }
}

fn marker_frame(marker: usize, full: bool) -> Frame {
    Frame {
        rows: vec![RowFrame {
            line: marker,
            wrapped: false,
            spans: Vec::new(),
        }],
        cursor: CursorFrame {
            line: 0,
            column: 0,
            visible: true,
        },
        cursor_changed: true,
        full,
        viewport: Viewport {
            generation: 0,
            columns: 80,
            screen_lines: 24,
        },
    }
}

fn assert_post_snapshot_capture_survives_attach(mut publisher: FramePublisher) {
    assert!(!publisher.requires_snapshot());
    let bootstrap = marker_frame(1, true);
    let post_snapshot_incremental = marker_frame(42, false);
    let subscription = SubscriptionId::new();
    publisher.attach(subscription, bootstrap).unwrap();
    let publisher = Mutex::new(publisher);

    assert_eq!(
        offer_capture(&publisher, post_snapshot_incremental, || marker_frame(
            42, true
        )),
        None
    );

    let successor = publisher
        .lock()
        .unwrap()
        .acknowledge(subscription, 1)
        .expect("post-snapshot PTY output was lost");
    assert_eq!(successor.frame.rows[0].line, 42);
    assert!(successor.frame.full);
}

#[test]
fn reader_pumps_a_deferred_tail_without_an_external_event() {
    let (terminal, _actions) = Terminal::new(Size::default(), Fences::ALL);
    let terminal = SharedTerminal::new(terminal);
    let payload = "\u{1b}c".repeat(2_102_714);

    assert!(
        feed_and_drain(&terminal, payload.as_bytes()),
        "fixture must defer parser work before the runtime pumps it"
    );

    let terminal = terminal.lock();
    assert_eq!(terminal.pending_bytes(), 0);
    assert_eq!(terminal.stats().completed_units, 2_102_714);
}

#[test]
fn initial_attach_retains_output_captured_after_its_bootstrap_snapshot() {
    let viewport = marker_frame(0, true).viewport;
    let publisher = FramePublisher::new(viewport);
    assert_post_snapshot_capture_survives_attach(publisher);
}

#[test]
fn reattach_retains_output_captured_after_its_bootstrap_snapshot() {
    let viewport = marker_frame(0, true).viewport;
    let mut publisher = FramePublisher::new(viewport);
    let old = SubscriptionId::new();
    publisher.attach(old, marker_frame(0, true)).unwrap();
    assert!(publisher.acknowledge(old, 1).is_none());
    assert_post_snapshot_capture_survives_attach(publisher);
}

#[test]
fn mapper_preserves_soft_wrap_metadata() {
    let message = wire_publication(publication(Vec::new())).unwrap();
    assert!(message.rows[0].wrapped);
}

#[test]
fn mapper_expands_ascii_runs_without_unicode_classification() {
    let message = wire_publication(publication(vec![Span {
        column: 4,
        text: "abc".into(),
        width: 1,
        cluster_count: 3,
        style: style(),
    }]))
    .unwrap();
    let clusters = &message.rows[0].spans[0].clusters;
    assert_eq!(
        clusters
            .iter()
            .map(|cluster| (cluster.column, cluster.text.as_str()))
            .collect::<Vec<_>>(),
        vec![(4, "a"), (5, "b"), (6, "c")]
    );
}

#[test]
fn mapper_keeps_a_multi_char_cluster_atomic() {
    let message = wire_publication(publication(vec![Span {
        column: 9,
        text: "1\u{fe0f}\u{20e3}".into(),
        width: 2,
        cluster_count: 1,
        style: style(),
    }]))
    .unwrap();
    let clusters = &message.rows[0].spans[0].clusters;
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].column, 9);
    assert_eq!(clusters[0].text, "1\u{fe0f}\u{20e3}");
    assert_eq!(clusters[0].width, 2);
}

#[test]
fn mapper_rejects_an_inconsistent_engine_span() {
    let result = wire_publication(publication(vec![Span {
        column: 0,
        text: "ab".into(),
        width: 1,
        cluster_count: 3,
        style: style(),
    }]));
    assert!(result.is_err());
}

#[test]
fn dimensions_reject_zero_and_preserve_scrollback_default() {
    assert!(size(0, 24).is_err());
    assert!(size(80, 0).is_err());
    let size = size(100, 40).unwrap();
    assert_eq!(
        (size.columns, size.screen_lines, size.scrollback),
        (100, 40, 10_000)
    );
}

#[cfg(unix)]
#[test]
fn attached_natural_exit_allows_reentrant_close_callback() {
    let app = tauri::test::mock_app();
    assert!(app.manage(TerminalSessions::default()));
    let (exit_tx, exit_rx) = mpsc::channel();
    let callback_app = app.handle().clone();
    let callback_session = Arc::new(Mutex::new(None::<String>));
    let callback_session_id = Arc::clone(&callback_session);
    let channel = Channel::new(move |body| {
        if let InvokeResponseBody::Json(json) = body {
            let message: serde_json::Value = serde_json::from_str(&json)?;
            if message.get("type").and_then(|value| value.as_str()) == Some("exit") {
                let session_id = callback_session_id
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("the session id is installed before shell exit");
                terminal_close(session_id, callback_app.state()).unwrap();
                exit_tx
                    .send(())
                    .map_err(|error| tauri::Error::Anyhow(error.into()))?;
            }
        }
        Ok(())
    });
    let response = terminal_attach(
        AttachRequest {
            session_id: None,
            channel_id: "test-channel".into(),
            channel_name: "Test channel".into(),
            thread_id: None,
            npub: "test-npub".into(),
            relay_url: "ws://127.0.0.1:1".into(),
            columns: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        },
        channel,
        app.state(),
    )
    .unwrap();

    *callback_session.lock().unwrap() = Some(response.session_id.clone());
    terminal_input(response.session_id, "exit\n".into(), app.state()).unwrap();
    exit_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("an attached renderer must receive the natural exit event");
}

#[cfg(unix)]
#[test]
fn detached_natural_exit_reaps_session_and_releases_slot() {
    let app = tauri::test::mock_app();
    assert!(app.manage(TerminalSessions::default()));
    for _ in 0..=MAX_LIVE_SESSIONS {
        let channel = Channel::new(|_body| Ok(()));
        let response = terminal_attach(
            AttachRequest {
                session_id: None,
                channel_id: "test-channel".into(),
                channel_name: "Test channel".into(),
                thread_id: None,
                npub: "test-npub".into(),
                relay_url: "ws://127.0.0.1:1".into(),
                columns: 80,
                rows: 24,
                pixel_width: 0,
                pixel_height: 0,
            },
            channel,
            app.state(),
        )
        .expect("a released session slot must accept the next PTY");

        terminal_detach(
            response.session_id.clone(),
            response.subscription_id,
            app.state(),
        )
        .unwrap();
        terminal_input(response.session_id.clone(), "exit\n".into(), app.state()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while app
            .state::<TerminalSessions>()
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|session| session.id.to_string() == response.session_id)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "detached natural exit must reap its native session"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    assert!(app.state::<TerminalSessions>().0.lock().unwrap().is_empty());
}
