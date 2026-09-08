import type { BrowserIdentityManager } from "./identity";

/** Register command closures synchronously; their calls are gated by registry readiness. */
export function deferredIdentity(pending: Promise<BrowserIdentityManager>) {
  let manager: BrowserIdentityManager | undefined;
  const ready = pending.then((value) => {
    manager = value;
  });
  const identity = new Proxy({} as BrowserIdentityManager, {
    get(_target, property) {
      if (!manager) throw new Error("Browser identity is not ready");
      const value: unknown = Reflect.get(manager, property);
      return typeof value === "function" ? value.bind(manager) : value;
    },
  });
  return { identity, ready };
}
