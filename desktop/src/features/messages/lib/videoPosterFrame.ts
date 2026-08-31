import { waitForVisiblePaint } from "./objectUrlLifecycle";
import { videoMimeForFile } from "./videoFileType";

function waitForMediaEvent(
  element: HTMLMediaElement,
  eventName: string,
  timeoutMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeoutId = window.setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for ${eventName}`));
    }, timeoutMs);

    function cleanup() {
      window.clearTimeout(timeoutId);
      element.removeEventListener(eventName, onEvent);
      element.removeEventListener("error", onError);
    }

    function onEvent() {
      cleanup();
      resolve();
    }

    function onError() {
      cleanup();
      reject(new Error(`Could not load media for ${eventName}`));
    }

    element.addEventListener(eventName, onEvent, { once: true });
    element.addEventListener("error", onError, { once: true });
  });
}

type CapturedVideoPoster = {
  dim: string;
  posterUrl: string;
};

export async function captureVideoPosterFrame(
  file: File,
): Promise<CapturedVideoPoster | null> {
  const videoMime = videoMimeForFile(file);
  if (!videoMime) return null;

  // A blob URL inherits the File's own MIME type, so a video whose type is
  // empty or `application/octet-stream` would be rejected by the <video>
  // element and yield no poster. Re-type the bytes with the MIME we derived
  // from the extension; `slice` wraps the same bytes without copying them.
  const objectUrl = URL.createObjectURL(
    file.type === videoMime ? file : file.slice(0, file.size, videoMime),
  );
  const video = document.createElement("video");
  video.muted = true;
  video.playsInline = true;
  video.preload = "metadata";

  try {
    video.src = objectUrl;
    await waitForMediaEvent(video, "loadedmetadata", 3_000);

    const duration = Number.isFinite(video.duration) ? video.duration : 0;
    const seekTime = duration > 0.2 ? 0.1 : 0;
    if (seekTime > 0) {
      const seeked = waitForMediaEvent(video, "seeked", 2_000);
      video.currentTime = seekTime;
      await seeked.catch(() => undefined);
    } else if (video.readyState < 2) {
      await waitForMediaEvent(video, "loadeddata", 2_000).catch(
        () => undefined,
      );
    }

    await waitForVisiblePaint(document.visibilityState, requestAnimationFrame);

    if (video.videoWidth === 0 || video.videoHeight === 0) return null;

    const maxWidth = 640;
    const scale = Math.min(1, maxWidth / video.videoWidth);
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
    canvas.height = Math.max(1, Math.round(video.videoHeight * scale));

    const context = canvas.getContext("2d");
    if (!context) return null;
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    return {
      dim: `${video.videoWidth}x${video.videoHeight}`,
      posterUrl: canvas.toDataURL("image/jpeg", 0.82),
    };
  } catch {
    return null;
  } finally {
    URL.revokeObjectURL(objectUrl);
    video.removeAttribute("src");
    video.load();
  }
}
