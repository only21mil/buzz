export type BackgroundLinkPreviewResult =
  | { status: "cancelled" }
  | { status: "ready"; tags: string[][] };

export type PreparedBackgroundLinkPreviews = {
  cancel: () => void;
  promise: Promise<BackgroundLinkPreviewResult>;
  signal: AbortSignal;
  release: () => void;
  skip: () => void;
};
