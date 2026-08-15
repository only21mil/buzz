export async function openUrl(url: string | URL): Promise<void> {
  window.open(String(url), "_blank", "noopener,noreferrer");
}

export async function openPath(): Promise<void> {}

export async function revealItemInDir(): Promise<void> {}
