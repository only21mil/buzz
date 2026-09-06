use super::*;
use crate::huddle::{agent_tts_admission::SpeechAdmission, HuddlePhase, HuddleState};
use tokio_util::sync::CancellationToken;

fn pipeline() -> (Arc<TtsPipeline>, mpsc::Receiver<QueuedText>) {
    let (text_tx, text_rx) = mpsc::sync_channel(TEXT_QUEUE_DEPTH);
    (
        Arc::new(TtsPipeline {
            text_tx,
            tts_active: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            cancel: Arc::new(AtomicBool::new(false)),
            human_floor: HumanFloor::new(),
            voice_cancel: Arc::new(AtomicBool::new(false)),
            voice: Arc::new(Mutex::new(DEFAULT_VOICE.to_string())),
            voice_generation: Arc::new(AtomicU64::new(1)),
            speaker_generations: Arc::new(Mutex::new(HashMap::new())),
            active_speaker: Arc::new(Mutex::new(None)),
            speaker_cancel: Arc::new(Mutex::new(None)),
            playback_probe: PlaybackProbe::new(),
            voice_change_ack: Arc::new(Mutex::new(None)),
            broadcasters: TtsBroadcasters::default(),
            thread: None,
        }),
        text_rx,
    )
}

async fn delayed_setup(change: &str, setup_fails: bool) {
    let (pipeline, text_rx) = pipeline();
    let mut state = HuddleState {
        phase: HuddlePhase::Active,
        ephemeral_channel_id: Some("room".into()),
        ..HuddleState::default()
    };
    state.begin_huddle_lifetime();
    state
        .agent_pubkeys
        .lock()
        .expect("members")
        .push("speaker".into());
    state.tts_pipeline = Some(Arc::clone(&pipeline));
    let admission = SpeechAdmission::capture(&state, "speaker").expect("admitted");
    let state = Mutex::new(state);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let cancelled = CancellationToken::new();
    let (audio_tx, _audio_rx) = tokio::sync::mpsc::channel(1);
    let publisher = TtsAudioPublisher::new(audio_tx, cancelled.clone());
    let setup = async {
        entered_tx.send(()).expect("entered");
        release_rx.await.expect("release");
        if setup_fails {
            Err("membership lookup failed".to_string())
        } else {
            Ok(Some(publisher))
        }
    };
    let complete = async {
        let current = admission.finish_setup(&state, setup).await.unwrap_or(true);
        if current && admission.is_current(&state.lock().expect("state")) {
            admission
                .sender
                .send(
                    1,
                    "speaker".into(),
                    admission.speaker_generation,
                    "voice".into(),
                    "old speech".into(),
                )
                .expect("enqueue");
        }
        current
    };
    let invalidate = async {
        entered_rx.await.expect("setup started");
        let mut state = state.lock().expect("state");
        match change {
            "remove" => {
                state.agent_pubkeys.lock().expect("members").clear();
                pipeline.cancel_speaker("speaker");
            }
            "cancel" => pipeline.cancel_speaker("speaker"),
            "reconnect" => {
                state.begin_huddle_lifetime();
            }
            "replace_pipeline" => {
                state.tts_pipeline = Some(self::pipeline().0);
            }
            "shutdown" => pipeline.shutdown(),
            "voice" => {
                let _ = pipeline.select_voice("eve");
            }
            "none" => {}
            _ => panic!("unknown mutation"),
        }
        release_tx.send(()).expect("resume setup");
    };
    let (current, ()) = tokio::join!(complete, invalidate);
    if change == "none" {
        assert!(current);
        assert!(text_rx.try_recv().is_ok());
        assert_eq!(pipeline.has_audio_publisher("speaker"), !setup_fails);
    } else {
        assert!(
            !current && text_rx.try_recv().is_err() && !pipeline.has_audio_publisher("speaker"),
            "late setup must preserve admission: current={current}, registered={}",
            pipeline.has_audio_publisher("speaker")
        );
        assert!(
            text_rx.try_recv().is_err(),
            "stale speech must not enter the queue"
        );
        assert!(
            !pipeline.has_audio_publisher("speaker"),
            "late publisher must not register"
        );
        assert!(
            cancelled.is_cancelled(),
            "rejected publisher must close its socket"
        );
    }
}

macro_rules! delayed_setup_test {
    ($name:ident, $change:literal, $fails:literal) => {
        #[tokio::test]
        async fn $name() {
            delayed_setup($change, $fails).await;
        }
    };
}

delayed_setup_test!(delayed_remove_success, "remove", false);
delayed_setup_test!(delayed_remove_error, "remove", true);
delayed_setup_test!(delayed_cancel_success, "cancel", false);
delayed_setup_test!(delayed_cancel_error, "cancel", true);
delayed_setup_test!(delayed_reconnect_success, "reconnect", false);
delayed_setup_test!(delayed_reconnect_error, "reconnect", true);
delayed_setup_test!(delayed_replace_pipeline_success, "replace_pipeline", false);
delayed_setup_test!(delayed_replace_pipeline_error, "replace_pipeline", true);
delayed_setup_test!(delayed_shutdown_success, "shutdown", false);
delayed_setup_test!(delayed_shutdown_error, "shutdown", true);
delayed_setup_test!(delayed_voice_success, "voice", false);
delayed_setup_test!(delayed_voice_error, "voice", true);

#[tokio::test]
async fn delayed_publisher_current_admission_keeps_local_error_fallback() {
    for setup_fails in [false, true] {
        delayed_setup("none", setup_fails).await;
    }
}

#[test]
fn publisher_registration_rechecks_cancellation_and_shutdown() {
    for shutdown in [false, true] {
        let (pipeline, _rx) = pipeline();
        let sender = pipeline.text_sender();
        let generation = sender.speaker_generation("speaker");
        if shutdown {
            pipeline.shutdown();
        } else {
            pipeline.cancel_speaker("speaker");
        }
        let cancel = CancellationToken::new();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        assert!(!pipeline.register_audio_publisher(
            "speaker",
            generation,
            sender.voice_generation(),
            TtsAudioPublisher::new(tx, cancel.clone())
        ));
        assert!(cancel.is_cancelled());
        assert!(!pipeline.has_audio_publisher("speaker"));
    }
}
