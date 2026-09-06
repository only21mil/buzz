import { expect, test } from "@playwright/test";
import {
  finishRecording,
  installVoiceNote,
  startRecording,
  uploadCalls,
} from "../helpers/voiceNote";

test("recording blocks submission and attachments; preview and discard release the queued note", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  const input = page.getByTestId("message-input");
  await input.fill("keep this draft");
  await startRecording(page);
  await input.press("Enter");
  await expect(input).toHaveText("keep this draft");
  await expect(page.getByTestId("voice-note-recorder")).toBeVisible();
  await expect(page.getByRole("button", { name: "Attach file" })).toBeHidden();
  expect(await uploadCalls(page)).toEqual([]);
  const rejectConflictingDrop = async () => {
    const transfer = await page.evaluateHandle(() => {
      const data = new DataTransfer();
      data.items.add(
        new File(["unrelated attachment"], "conflicting.pdf", {
          type: "application/pdf",
        }),
      );
      return data;
    });
    await page
      .getByTestId("channel-drop-zone")
      .dispatchEvent("drop", { dataTransfer: transfer });
    await transfer.dispose();
    await expect(page.getByTestId("message-composer")).not.toContainText(
      "conflicting.pdf",
    );
    expect(await uploadCalls(page)).toEqual([]);
  };
  await rejectConflictingDrop();
  await finishRecording(page);
  const card = page.getByTestId("composer-voice-note-card");
  await rejectConflictingDrop();
  await card.getByRole("button", { name: "Play voice note" }).press("Enter");
  await expect(
    card.getByRole("button", { name: "Pause voice note" }),
  ).toBeVisible();
  await card.getByRole("button", { name: "Pause voice note" }).press("Enter");
  const audioSrc = await card.locator("audio").getAttribute("src");
  expect(audioSrc).toMatch(/^blob:/);
  await page.getByTestId("remove-composer-voice-note").focus();
  await page.getByTestId("remove-composer-voice-note").press("Enter");
  await expect(card).toHaveCount(0);
  await expect(input).toHaveText("keep this draft");
  await expect(page.getByRole("button", { name: "Attach file" })).toBeVisible();
  expect(await uploadCalls(page)).toEqual([]);
  await expect
    .poll(() =>
      page.evaluate(async (src) => {
        try {
          await fetch(src ?? "");
          return false;
        } catch {
          return true;
        }
      }, audioSrc),
    )
    .toBe(true);
});

test("discard during pending processing wins after the decoder resolves", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await page.evaluate(() => {
    const original = AudioContext.prototype.decodeAudioData;
    const pending: Array<() => void> = [];
    const state = window as Window & {
      __VOICE_PENDING__?: number;
      __VOICE_SETTLED__?: number;
      __VOICE_RELEASE__?: () => void;
    };
    state.__VOICE_PENDING__ = 0;
    state.__VOICE_SETTLED__ = 0;
    state.__VOICE_RELEASE__ = () => {
      for (const release of pending.splice(0)) release();
    };
    AudioContext.prototype.decodeAudioData = function (bytes) {
      state.__VOICE_PENDING__ = (state.__VOICE_PENDING__ ?? 0) + 1;
      return new Promise<AudioBuffer>((resolve, reject) =>
        pending.push(() => {
          original
            .call(this, bytes)
            .then(resolve, reject)
            .finally(() => {
              state.__VOICE_SETTLED__ = (state.__VOICE_SETTLED__ ?? 0) + 1;
            });
        }),
      );
    };
  });
  await startRecording(page);
  await page.getByRole("button", { name: "Finish voice note" }).click();
  await expect(page.getByText("Preparing voice note…")).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { __VOICE_PENDING__?: number }).__VOICE_PENDING__,
      ),
    )
    .toBe(1);
  await page.getByRole("button", { name: "Discard voice note" }).press("Enter");
  await expect(page.getByTestId("voice-note-recorder")).toHaveCount(0);
  await page.evaluate(() =>
    (
      window as Window & { __VOICE_RELEASE__?: () => void }
    ).__VOICE_RELEASE__?.(),
  );
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { __VOICE_SETTLED__?: number }).__VOICE_SETTLED__,
      ),
    )
    .toBe(1);
  await expect(page.getByTestId("composer-voice-note-card")).toHaveCount(0);
  expect(await uploadCalls(page)).toEqual([]);
  await startRecording(page);
  await page.getByRole("button", { name: "Discard voice note" }).click();
  await expect(page.getByTestId("voice-note-recorder")).toHaveCount(0);
});

test("failed send restores the same queued preview and permits discarding it", async ({
  page,
}) => {
  await installVoiceNote(page, ["relay rejected voice note"]);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await startRecording(page);
  await finishRecording(page);
  const card = page.getByTestId("composer-voice-note-card");
  const bytes = await card
    .locator("audio")
    .evaluate(async (audio: HTMLAudioElement) =>
      Array.from(new Uint8Array(await (await fetch(audio.src)).arrayBuffer())),
    );
  await page.getByTestId("send-message").click();
  await expect(
    page.getByText("Message failed to send: relay rejected voice note"),
  ).toBeVisible();
  await expect(card).toBeVisible();
  await expect(page.getByTestId("audio-message-attachment")).toHaveCount(0);
  expect(
    await card
      .locator("audio")
      .evaluate(async (audio: HTMLAudioElement) =>
        Array.from(
          new Uint8Array(await (await fetch(audio.src)).arrayBuffer()),
        ),
      ),
  ).toEqual(bytes);
  await expect.poll(async () => (await uploadCalls(page)).length).toBe(1);
  await card.getByRole("button", { name: "Play voice note" }).press("Enter");
  await expect(
    card.getByRole("button", { name: "Pause voice note" }),
  ).toBeVisible();
  await page.getByTestId("remove-composer-voice-note").press("Enter");
  await expect(card).toHaveCount(0);
});

test("sent waveform supports keyboard seeking and all playback rates without a download action", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await startRecording(page);
  await finishRecording(page);
  await page.getByTestId("send-message").click();
  await expect(page.getByTestId("composer-voice-note-card")).toHaveCount(0);
  const card = page.getByTestId("audio-message-attachment");
  await expect(card).toBeVisible();
  const audio = card.locator("audio");
  await card.getByRole("button", { name: "Play voice note" }).press("Enter");
  await expect(
    card.getByRole("button", { name: "Pause voice note" }),
  ).toBeVisible();
  await expect
    .poll(() =>
      audio.evaluate((element: HTMLAudioElement) => element.currentTime),
    )
    .toBeGreaterThan(0.3);
  await card.getByRole("button", { name: "Pause voice note" }).press("Enter");
  const slider = card.getByRole("slider", {
    name: "Voice note playback position",
  });
  await slider.focus();
  await slider.press("Home");
  await expect(audio).toHaveJSProperty("currentTime", 0);
  await slider.press("ArrowRight");
  await expect
    .poll(() =>
      audio.evaluate((element: HTMLAudioElement) => element.currentTime),
    )
    .toBeGreaterThan(0);
  await slider.press("End");
  await expect
    .poll(() =>
      audio.evaluate((element: HTMLAudioElement) =>
        Math.abs(element.duration - element.currentTime),
      ),
    )
    .toBeLessThan(0.1);
  await slider.press("Home");
  const rate = card.getByTestId("voice-note-playback-rate");
  for (const value of [1.5, 2, 0.5, 1]) {
    await rate.press("Enter");
    await expect(audio).toHaveJSProperty("playbackRate", value);
    await expect(card.getByTestId("voice-note-playback-rate-value")).toHaveText(
      `${value === 0.5 ? ".5" : value}×`,
    );
  }
  await expect(card.getByRole("button", { name: /download/i })).toHaveCount(0);
  await expect(card.getByRole("link", { name: /download/i })).toHaveCount(0);
});

test("duplicate players coordinate and navigation stops playback", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
          channelName: "general",
        }),
      ),
    )
    .toBe(true);
  await page.evaluate(() => {
    const emit = window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
    if (!emit) throw new Error("Mock emitter missing");
    const url = "http://localhost:3000/media/voice-note-123.mp4";
    const input = {
      channelName: "general",
      content: `[voice-note-123.mp4](${url})`,
      extraTags: [
        [
          "imeta",
          `url ${url}`,
          "m video/mp4",
          "duration 10",
          "filename voice-note-123.mp4",
        ],
      ],
    };
    emit(input);
    emit(input);
  });
  const cards = page.getByTestId("audio-message-attachment");
  await expect(cards).toHaveCount(2);
  const first = cards.nth(0).locator("audio");
  const second = cards.nth(1).locator("audio");
  await cards
    .nth(0)
    .getByRole("button", { name: "Play voice note" })
    .press("Enter");
  await expect(first).toHaveJSProperty("paused", false);
  await cards
    .nth(1)
    .getByRole("button", { name: "Play voice note" })
    .press("Enter");
  await expect(first).toHaveJSProperty("paused", true);
  await expect(second).toHaveJSProperty("paused", false);
  const playing = await second.elementHandle();
  if (!playing) throw new Error("Playing audio missing");
  await page.getByTestId("channel-engineering").click();
  await expect(cards).toHaveCount(0);
  await expect
    .poll(() => playing.evaluate((audio: HTMLAudioElement) => audio.paused))
    .toBe(true);
  await playing.dispose();
});
