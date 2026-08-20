export type CommunityApplyQueue = {
  run<T>(task: () => Promise<T>): Promise<T>;
};

/**
 * Serialize workspace applies for the lifetime of the renderer process.
 *
 * React effect cleanup cannot cancel an apply after it crosses the Tauri IPC
 * boundary. Keeping one module-lived tail ensures a later community waits for
 * an in-flight apply and therefore becomes the final backend state. The stored
 * tail absorbs failures so one rejected apply cannot poison later switches;
 * callers still receive the original rejection.
 */
export function createCommunityApplyQueue(): CommunityApplyQueue {
  let tail = Promise.resolve();

  return {
    run<T>(task: () => Promise<T>): Promise<T> {
      const run = tail.then(task);
      tail = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
  };
}

export const communityApplyQueue = createCommunityApplyQueue();
