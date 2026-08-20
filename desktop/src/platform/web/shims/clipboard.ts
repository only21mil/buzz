export async function readText(): Promise<string> {
  return navigator.clipboard.readText();
}

export async function writeText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}
