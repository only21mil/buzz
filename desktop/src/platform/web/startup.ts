/** Paint immediately and keep protected content behind initialization. */
export async function startBrowserShell(
  renderShell: () => void,
  initialize: () => Promise<void>,
  renderApp: () => void,
): Promise<void> {
  renderShell();
  await initialize();
  renderApp();
}
