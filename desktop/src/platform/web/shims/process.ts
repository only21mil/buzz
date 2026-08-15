export async function exit(): Promise<void> {}

export async function relaunch(): Promise<void> {
  window.location.reload();
}
