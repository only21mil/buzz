/** A single boot promise guards every PAL command, including signing. */
export class PalReadiness {
  private pending: Promise<void> = Promise.resolve();

  start(initialize: () => Promise<void>): Promise<void> {
    this.pending = initialize().catch((cause: unknown) => {
      throw new Error("Browser identity initialization failed", { cause });
    });
    // Boot can fail before a command arrives. Retain the rejection for callers
    // without creating an unhandled rejection in the meantime.
    void this.pending.catch(() => {});
    return this.pending;
  }

  wait(): Promise<void> {
    return this.pending;
  }
}
