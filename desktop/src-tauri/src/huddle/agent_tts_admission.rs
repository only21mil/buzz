//! Keeps publisher setup and speech tied to the Huddle that admitted them.
use std::sync::{Arc, Mutex};

use super::{state::HuddleState, tts, tts::TtsAudioPublisher};

pub(super) struct SpeechAdmission {
    pub(super) pipeline: Arc<tts::TtsPipeline>,
    pub(super) sender: tts::TtsTextSender,
    pub(super) speaker_generation: u64,
    pub(super) speaker_pubkey: String,
    pub(super) ephemeral_channel_id: String,
    pub(super) parent_channel_id: Option<String>,
    pub(super) local_tts_publishers: super::tts::LocalTtsPublishers,
    huddle_generation: u64,
}

impl SpeechAdmission {
    pub(super) fn capture(huddle: &HuddleState, speaker: &str) -> Option<Self> {
        let pipeline = Arc::clone(huddle.tts_pipeline.as_ref()?);
        let sender = pipeline.text_sender();
        let admission = Self {
            speaker_generation: sender.speaker_generation(speaker),
            sender,
            pipeline,
            speaker_pubkey: speaker.to_string(),
            ephemeral_channel_id: huddle.ephemeral_channel_id.clone()?,
            parent_channel_id: huddle.parent_channel_id.clone(),
            local_tts_publishers: Arc::clone(&huddle.local_tts_publishers),
            huddle_generation: huddle.huddle_generation,
        };
        admission.is_current(huddle).then_some(admission)
    }

    pub(super) fn is_current(&self, huddle: &HuddleState) -> bool {
        huddle.is_current_huddle(&self.ephemeral_channel_id, self.huddle_generation)
            && huddle
                .tts_pipeline
                .as_ref()
                .is_some_and(|pipeline| Arc::ptr_eq(pipeline, &self.pipeline))
            && huddle
                .agent_pubkeys
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .any(|speaker| speaker.eq_ignore_ascii_case(&self.speaker_pubkey))
            && self.pipeline.speech_is_current(
                &self.speaker_pubkey,
                self.speaker_generation,
                self.sender.voice_generation(),
            )
    }

    /// False means cancellation won, including when the awaited setup failed.
    /// An error permits local fallback only while this original admission remains current.
    pub(super) async fn finish_setup(
        &self,
        huddle: &Mutex<HuddleState>,
        setup: impl std::future::Future<Output = Result<Option<TtsAudioPublisher>, String>>,
    ) -> Result<bool, String> {
        let result = setup.await;
        let huddle = huddle.lock().map_err(|error| error.to_string())?;
        if !self.is_current(&huddle) {
            return Ok(false);
        }
        if let Some(publisher) = result? {
            return Ok(self.pipeline.register_audio_publisher(
                &self.speaker_pubkey,
                self.speaker_generation,
                self.sender.voice_generation(),
                publisher,
            ));
        }
        Ok(true)
    }
}
