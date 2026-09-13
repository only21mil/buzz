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

// ── Restored upstream regression coverage ─────────────────────────────
// Ports from block/buzz@4cd82f51 desktop/tests/e2e/voice-note.spec.ts (audit D3).
// Bodies are verbatim except for setup (fork installVoiceNote helper replaces the
// upstream beforeEach) and the two scheduler tests: the fork loads timeline audio
// through the fetch_audio_bytes mock command, so the hold lives on
// __BUZZ_E2E_HOLD_MEDIA_FETCHES__ instead of a page.route gate, and command
// assertions read fetch_audio_bytes. The emoji/GIF test is intentionally not
// ported — the fork has no GIF picker (composer-emoji-button is emoji-only).

const AUDIO_URL = "http://127.0.0.1:4173/sounds/ping.mp3";

async function openMoreActionsMenu(page: Page, messageId: string) {
  const row = page.locator(`[data-message-id="${messageId}"]`);
  await row.hover();
  await page.getByTestId(`more-actions-${messageId}`).click();
  await expect(page.locator('[role="menuitem"]').first()).toBeVisible();
}

async function waitForMockLiveSubscription(page: Page, channelName: string) {
  await expect
    .poll(() =>
      page.evaluate(
        (currentChannelName) =>
          window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
            channelName: currentChannelName,
          }) ?? false,
        channelName,
      ),
    )
    .toBe(true);
}

test("keeps pasted snapshots and channel drops out of an active voice note", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();

  await page.getByRole("button", { name: "Record voice note" }).click();
  await expect(page.getByTestId("voice-note-recorder")).toBeVisible();
  await page.waitForTimeout(100);

  await page.getByRole("button", { name: "Finish voice note" }).click();
  await expect(page.getByTestId("composer-voice-note-card")).toBeVisible();

  await page
    .getByTestId("message-composer")
    .locator(".ProseMirror")
    .evaluate((editor) => {
      const payload = encodeURIComponent(
        JSON.stringify({
          version: 1,
          displayName: "Snapshot",
          filename: "shared.agent.png",
          sha256: "b".repeat(64),
          size: 128,
          type: "image/png",
          url: "https://relay.example/media/shared.agent.png",
        }),
      );
      const clipboardData = new DataTransfer();
      clipboardData.setData(
        "text/html",
        `<a data-buzz-agent-snapshot="${payload}" href="https://relay.example/media/shared.agent.png">Snapshot</a>`,
      );
      editor.dispatchEvent(
        new ClipboardEvent("paste", {
          bubbles: true,
          cancelable: true,
          clipboardData,
        }),
      );
    });
  await expect(page.getByTestId("composer-agent-snapshot-card")).toHaveCount(0);

  const dataTransfer = await page.evaluateHandle(() => {
    const transfer = new DataTransfer();
    transfer.items.add(
      new File(["second attachment"], "second-attachment.pdf", {
        type: "application/pdf",
      }),
    );
    return transfer;
  });
  const dropZone = page.getByTestId("channel-drop-zone");
  await dropZone.dispatchEvent("dragenter", { dataTransfer });
  await expect(dropZone.getByTestId("drop-zone-overlay")).toHaveCount(0);
  await dropZone.dispatchEvent("drop", { dataTransfer });
  await expect(page.getByTestId("message-composer")).not.toContainText(
    "second-attachment.pdf",
  );
  await expect(page.getByTestId("composer-voice-note-card")).toBeVisible();
});

test("discards an active recording when entering edit mode", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();

  await page.getByRole("button", { name: "Record voice note" }).click();
  await expect(page.getByTestId("voice-note-recorder")).toBeVisible();

  await openMoreActionsMenu(page, "mock-general-welcome");
  await page.getByTestId("edit-message-mock-general-welcome").click();

  await expect(page.getByTestId("edit-target")).toBeVisible();
  await expect(page.getByTestId("voice-note-recorder")).toHaveCount(0);
  await expect(page.getByTestId("composer-voice-note-card")).toHaveCount(0);
});

test("editor Enter never saves an edit while a voice note is recording", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();

  // Enter edit mode first, then start recording — the mic is available in edit
  // mode, so this is the ordering the recorder submission gate must cover.
  await openMoreActionsMenu(page, "mock-general-welcome");
  await page.getByTestId("edit-message-mock-general-welcome").click();
  await expect(page.getByTestId("edit-target")).toBeVisible();
  const input = page.getByTestId("message-input");
  await expect(input).not.toBeEmpty();

  // Change the text so a save (if it wrongly happened) is observable, then
  // start recording.
  const editedContent = `Edited mid-recording ${Date.now()}`;
  await input.click();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type(editedContent);

  await page.getByRole("button", { name: "Record voice note" }).click();
  await expect(page.getByTestId("voice-note-recorder")).toBeVisible();
  await page.waitForTimeout(100);

  // The editor's Enter shortcut must not slip past the Finish/Discard flow: the
  // edit stays unsaved and the recording stays live until explicitly resolved.
  await input.press("Enter");

  await expect(page.getByTestId("edit-target")).toBeVisible();
  await expect(page.getByTestId("voice-note-recorder")).toBeVisible();
  await expect(page.getByTestId("message-timeline")).not.toContainText(
    editedContent,
  );

  // Finishing the recording still works, proving the note was never discarded.
  await page.getByRole("button", { name: "Finish voice note" }).click();
  await expect(page.getByTestId("composer-voice-note-card")).toBeVisible();
});

test("surfaces waveform and playback failures with retry", async ({ page }) => {
  await installVoiceNote(page);
  await page.addInitScript(() => {
    AudioContext.prototype.decodeAudioData = () =>
      Promise.reject(new DOMException("corrupt audio", "EncodingError"));
    HTMLMediaElement.prototype.play = () =>
      Promise.reject(new DOMException("playback denied", "NotAllowedError"));
  });
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await waitForMockLiveSubscription(page, "general");
  await page.evaluate(
    ({ audioUrl }) => {
      const emit = (
        window as Window & {
          __BUZZ_E2E_EMIT_MOCK_MESSAGE__?: (input: {
            channelName: string;
            content: string;
            extraTags: string[][];
          }) => unknown;
        }
      ).__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
      if (!emit) throw new Error("Mock message emitter is unavailable.");
      emit({
        channelName: "general",
        content: `[voice-note-123.mp4](${audioUrl})`,
        extraTags: [
          [
            "imeta",
            `url ${audioUrl}`,
            "m video/mp4",
            "duration 9.4",
            "filename voice-note-123.mp4",
          ],
        ],
      });
    },
    { audioUrl: AUDIO_URL },
  );

  const card = page.getByTestId("audio-message-attachment").last();
  const waveform = card.getByTestId("voice-note-playback-waveform");
  await expect(waveform).toHaveAttribute("data-waveform-state", "error");
  await expect(card.getByRole("status")).toContainText(
    "Waveform preview unavailable. Playback may still work.",
  );

  await card.getByRole("button", { name: "Play voice note" }).click();
  await expect(card.getByRole("alert")).toContainText("Audio unavailable");
  const retry = card.getByRole("button", { name: "Retry voice note" });
  await retry.click();
  await expect(
    card.getByRole("button", { name: "Play voice note" }),
  ).toBeVisible();
  await card.locator("audio").dispatchEvent("error");
  await expect(card.getByRole("alert")).toContainText("Audio unavailable");
});

test("generic audio retains the relay-native download action", async ({
  page,
}) => {
  await installVoiceNote(page);
  const audioUrl = `http://localhost:3000/media/${"d".repeat(64)}.mp3`;
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await waitForMockLiveSubscription(page, "general");
  await page.evaluate(
    ({ href }) => {
      const emit = window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
      if (!emit) throw new Error("Mock message emitter is unavailable.");
      emit({
        channelName: "general",
        content: `[meeting.mp3](${href})`,
        extraTags: [
          ["imeta", `url ${href}`, "m audio/mpeg", "filename meeting.mp3"],
        ],
      });
    },
    { href: audioUrl },
  );

  const card = page.getByTestId("audio-message-attachment").last();
  const download = card.getByRole("button", { name: "Download meeting.mp3" });
  await expect(download).toBeVisible();
  await download.click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          window.__BUZZ_E2E_COMMAND_LOG__?.find(
            ({ command }) => command === "download_file",
          ) ?? null,
      ),
    )
    .toEqual({
      command: "download_file",
      payload: { filename: "meeting.mp3", url: audioUrl },
    });
});

test("resumes a Play click that landed before the source finished loading", async ({
  page,
}) => {
  await installVoiceNote(page);
  await installVoiceNote(page);
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await waitForMockLiveSubscription(page, "general");
  // Hold the audio fetch so the received card has no playback source when the
  // user first clicks Play. (Upstream gated page.route; the fork loads audio
  // through the fetch_audio_bytes mock command, so the hold lives there.)
  await page.evaluate(() => {
    window.__BUZZ_E2E_HOLD_MEDIA_FETCHES__ = true;
  });
  await page.evaluate(
    ({ audioUrl }) => {
      const emit = window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
      if (!emit) throw new Error("Mock message emitter is unavailable.");
      emit({
        channelName: "general",
        content: `[voice-note-123.mp4](${audioUrl})`,
        extraTags: [
          [
            "imeta",
            `url ${audioUrl}`,
            "m video/mp4",
            "duration 9.4",
            "filename voice-note-123.mp4",
          ],
        ],
      });
    },
    { audioUrl: AUDIO_URL },
  );

  const card = page.getByTestId("audio-message-attachment").last();
  await expect(card).toBeVisible();
  // The scheduler holds exactly one fetch for this card — the card is waiting
  // on the source, not failed over to direct loading.
  await expect
    .poll(() =>
      page.evaluate(
        () => window.__BUZZ_E2E_MEDIA_FETCH_STATE__ ?? { active: 0, peak: 0 },
      ),
    )
    .toEqual({ active: 1, peak: 1 });

  // Click Play while the fetch is still held: the intent must be remembered and
  // surfaced as a loading state, not silently dropped.
  await card.getByRole("button", { name: "Play voice note" }).click();
  await expect(
    card.getByRole("button", { name: "Loading voice note" }),
  ).toBeVisible();

  // Releasing the fetch resolves the source; playback starts without a second
  // click.
  await page.evaluate(() => {
    window.__BUZZ_E2E_HOLD_MEDIA_FETCHES__ = false;
  });
  await expect(
    card.getByRole("button", { name: "Pause voice note" }),
  ).toBeVisible();
});

test("hard-caps audio work and cancels active and queued loads on unmount", async ({
  page,
}) => {
  await installVoiceNote(page);
  await page.addInitScript(() => {
    window.__BUZZ_E2E_HOLD_MEDIA_FETCHES__ = true;
    const originalCreate = URL.createObjectURL.bind(URL);
    const originalRevoke = URL.revokeObjectURL.bind(URL);
    const counters = { created: 0, revoked: 0 };
    (
      window as Window & {
        __BUZZ_E2E_AUDIO_OBJECT_URLS__?: typeof counters;
      }
    ).__BUZZ_E2E_AUDIO_OBJECT_URLS__ = counters;
    URL.createObjectURL = (object) => {
      counters.created += 1;
      return originalCreate(object);
    };
    URL.revokeObjectURL = (url) => {
      counters.revoked += 1;
      originalRevoke(url);
    };
  });
  await page.setViewportSize({ width: 1280, height: 400 });
  await page.goto("/");
  await page.getByTestId("channel-general").click();
  await waitForMockLiveSubscription(page, "general");
  await page.evaluate(
    ({ audioUrl }) => {
      const emit = (
        window as Window & {
          __BUZZ_E2E_EMIT_MOCK_MESSAGE__?: (input: {
            channelName: string;
            content: string;
            extraTags: string[][];
          }) => unknown;
        }
      ).__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
      if (!emit) throw new Error("Mock message emitter is unavailable.");
      for (let index = 0; index < 24; index += 1) {
        emit({
          channelName: "general",
          content: `[voice-note-${index}.mp4](${audioUrl})`,
          extraTags: [
            [
              "imeta",
              `url ${audioUrl}`,
              "m video/mp4",
              "duration 9.4",
              `filename voice-note-${index}.mp4`,
            ],
          ],
        });
      }
    },
    { audioUrl: AUDIO_URL },
  );

  const cards = page.getByTestId("audio-message-attachment");
  await expect(cards).toHaveCount(24);
  const readFetchCount = () =>
    page.evaluate(
      () =>
        window.__BUZZ_E2E_COMMANDS__?.filter(
          (command) => command === "fetch_audio_bytes",
        ).length ?? 0,
    );
  await expect
    .poll(() =>
      page.evaluate(
        () => window.__BUZZ_E2E_MEDIA_FETCH_STATE__ ?? { active: 0, peak: 0 },
      ),
    )
    .toEqual({ active: 3, peak: 3 });
  expect(await readFetchCount()).toBe(3);
  expect(
    await page.evaluate(
      () => window.__BUZZ_E2E_AUDIO_OBJECT_URLS__?.created ?? 0,
    ),
  ).toBe(0);

  await page.getByTestId("channel-random").click();
  await expect(cards).toHaveCount(0);
  await expect
    .poll(() =>
      page.evaluate(() => window.__BUZZ_E2E_MEDIA_FETCH_STATE__?.active ?? -1),
    )
    .toBe(0);
  const commandCounts = await page.evaluate(() => {
    const commands = window.__BUZZ_E2E_COMMANDS__ ?? [];
    return {
      cancelled: commands.filter((command) => command === "cancel_media_fetch")
        .length,
      fetched: commands.filter((command) => command === "fetch_audio_bytes")
        .length,
      released: commands.filter((command) => command === "release_media_fetch")
        .length,
    };
  });
  expect(commandCounts).toEqual({ cancelled: 3, fetched: 3, released: 3 });
  expect(
    await page.evaluate(() => window.__BUZZ_E2E_AUDIO_OBJECT_URLS__),
  ).toEqual({ created: 0, revoked: 0 });
});
