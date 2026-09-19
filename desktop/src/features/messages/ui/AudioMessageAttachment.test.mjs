import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AudioMessageAttachment,
  renderAudioMessageAttachment,
} from "./AudioMessageAttachment.tsx";

test("audio attachments render without a native Tauri runtime", () => {
  assert.equal(globalThis.window?.__TAURI_INTERNALS__, undefined);
  const href = "https://relay.example/song.mp3";
  const attachment = renderAudioMessageAttachment(
    { m: "audio/mpeg", filename: "song.mp3", duration: 42 },
    href,
    "Song",
    href,
  );
  assert.equal(attachment.type, AudioMessageAttachment);
  assert.equal(attachment.props.href, href);
  assert.equal(attachment.props.filename, "song.mp3");
  assert.equal(attachment.props.downloadUrl, href);
  assert.equal(attachment.props.duration, 42);
});

test("web voice notes keep their audio player and non-audio uses the fallback", () => {
  const href = "https://relay.example/voice-note-test.wav";
  const attachment = renderAudioMessageAttachment(
    { m: "audio/wav", filename: "voice-note-test.wav" },
    href,
    "Voice note",
    href,
  );
  assert.equal(attachment.type, AudioMessageAttachment);
  assert.equal(attachment.props.downloadUrl, undefined);
  assert.equal(
    renderAudioMessageAttachment({ m: "image/png" }, href, "Image"),
    null,
  );
});
