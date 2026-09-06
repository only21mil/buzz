import { Buffer } from "node:buffer";
import { expect, type Page } from "@playwright/test";
import { installMockBridge } from "./bridge";

export async function installVoiceNote(
  page: Page,
  sendMessageErrors?: string[],
) {
  // Generate audio locally. Chromium's MediaRecorder, decodeAudioData, WAV
  // encoder and audio element remain real; no physical microphone is opened.
  await page.addInitScript(() => {
    Object.defineProperty(navigator.mediaDevices, "getUserMedia", {
      configurable: true,
      async value() {
        const context = new AudioContext();
        const oscillator = context.createOscillator();
        const destination = context.createMediaStreamDestination();
        oscillator.frequency.value = 220;
        oscillator.connect(destination);
        oscillator.start();
        const track = destination.stream.getAudioTracks()[0];
        const stop = track.stop.bind(track);
        track.stop = () => {
          stop();
          oscillator.stop();
          void context.close();
        };
        return destination.stream;
      },
    });
  });
  await installMockBridge(page, {
    deferredComposerUploads: true,
    sendMessageErrors,
    uploadDescriptors: [
      {
        duration: 9.4,
        filename: "voice-note-123.mp4",
        sha256: "a".repeat(64),
        size: 16424,
        type: "video/mp4",
        uploaded: 1,
        url: "http://localhost:3000/media/voice-note-123.mp4",
      },
    ],
  });
  // This valid fixture WAV represents the native upload result's audio bytes.
  // Its transport descriptor is mocked, so this asserts no native transcoding.
  const samples = 8000 * 10;
  const wav = Buffer.alloc(44 + samples * 2);
  wav.write("RIFF", 0);
  wav.writeUInt32LE(wav.length - 8, 4);
  wav.write("WAVEfmt ", 8);
  wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(1, 22);
  wav.writeUInt32LE(8000, 24);
  wav.writeUInt32LE(16000, 28);
  wav.writeUInt16LE(2, 32);
  wav.writeUInt16LE(16, 34);
  wav.write("data", 36);
  wav.writeUInt32LE(samples * 2, 40);
  for (let i = 0; i < samples; i++)
    wav.writeInt16LE(
      Math.round(Math.sin((i * 2 * Math.PI * 220) / 8000) * 8000),
      44 + i * 2,
    );
  await page.route("**/media/voice-note-123.mp4", (route) => {
    const range = route
      .request()
      .headers()
      .range?.match(/^bytes=(\d+)-(\d*)$/);
    if (!range)
      return route.fulfill({
        contentType: "audio/wav",
        body: wav,
        headers: { "Accept-Ranges": "bytes" },
      });
    const start = Number(range[1]);
    const end = range[2]
      ? Math.min(Number(range[2]), wav.length - 1)
      : wav.length - 1;
    return route.fulfill({
      status: 206,
      contentType: "audio/wav",
      body: wav.subarray(start, end + 1),
      headers: {
        "Accept-Ranges": "bytes",
        "Content-Range": `bytes ${start}-${end}/${wav.length}`,
      },
    });
  });
}

export async function startRecording(page: Page) {
  await page.getByRole("button", { name: "Record voice note" }).click();
  await expect(page.getByTestId("voice-note-recorder")).toBeVisible();
  await expect(
    page
      .getByTestId("voice-note-live-waveform")
      .locator('[data-waveform-sample="recorded-0"]'),
  ).toBeAttached();
}

export async function finishRecording(page: Page) {
  await page.getByRole("button", { name: "Finish voice note" }).click();
  await expect(page.getByTestId("composer-voice-note-card")).toBeVisible();
}

export async function uploadCalls(page: Page) {
  return page.evaluate(() =>
    (window.__BUZZ_E2E_COMMANDS__ ?? []).filter((command) =>
      command.startsWith("upload_media_bytes"),
    ),
  );
}
