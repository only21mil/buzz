export enum UserAttentionType {
  Critical = 1,
  Informational = 2,
}

type UnlistenFn = () => void;

const currentWindow = {
  label: "main",
  async close(): Promise<void> {},
  async hide(): Promise<void> {},
  async isFullscreen(): Promise<boolean> {
    return Boolean(document.fullscreenElement);
  },
  async onResized(): Promise<UnlistenFn> {
    return () => undefined;
  },
  async onThemeChanged(): Promise<UnlistenFn> {
    return () => undefined;
  },
  async requestUserAttention(): Promise<void> {},
  async setBadgeCount(): Promise<void> {},
  async setBadgeLabel(): Promise<void> {},
  async setFocus(): Promise<void> {
    window.focus();
  },
  async show(): Promise<void> {},
  async startDragging(): Promise<void> {},
  async unminimize(): Promise<void> {},
};

export function getCurrentWindow(): typeof currentWindow {
  return currentWindow;
}

export const appWindow = currentWindow;
