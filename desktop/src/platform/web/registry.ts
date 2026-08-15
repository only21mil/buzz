export type InvokeBody =
  | Record<string, unknown>
  | number[]
  | ArrayBuffer
  | Uint8Array
  | undefined;

export type InvokeOptions = {
  headers?: Record<string, string>;
};

export type CommandHandler<T = unknown> = (
  body: InvokeBody,
  options?: InvokeOptions,
) => T | Promise<T>;

const handlers = new Map<string, CommandHandler>();
let unregisteredCommandMisses = 0;

export class CapabilityUnavailableError extends Error {
  readonly capability: string;

  constructor(
    capability: string,
    message = `Capability unavailable: ${capability}`,
  ) {
    super(message);
    this.name = "CapabilityUnavailableError";
    this.capability = capability;
  }
}

export function register(command: string, handler: CommandHandler): () => void {
  handlers.set(command, handler);
  return () => {
    if (handlers.get(command) === handler) {
      handlers.delete(command);
    }
  };
}

export async function dispatch<T>(
  command: string,
  body?: InvokeBody,
  options?: InvokeOptions,
): Promise<T> {
  const handler = handlers.get(command);
  if (!handler) {
    unregisteredCommandMisses += 1;
    console.error(`[web PAL] unregistered command: ${command}`);
    throw new CapabilityUnavailableError(command);
  }
  return (await handler(body, options)) as T;
}

export function getUnregisteredCommandMissCount(): number {
  return unregisteredCommandMisses;
}

export function resetRegistryForTests(): void {
  handlers.clear();
  unregisteredCommandMisses = 0;
}
