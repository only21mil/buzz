const currentWebview = {
  label: "main",
  async setZoom(): Promise<void> {},
};

export function getCurrentWebview(): typeof currentWebview {
  return currentWebview;
}
