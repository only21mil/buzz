import { dispatch, type InvokeBody, type InvokeOptions } from "../registry";

let nextCallbackId = 1;
const callbacks = new Map<
  number,
  { callback?: (response: unknown) => void; once: boolean }
>();

export function transformCallback<T = unknown>(
  callback?: (response: T) => void,
  once = false,
): number {
  const id = nextCallbackId++;
  callbacks.set(id, {
    callback: callback as ((response: unknown) => void) | undefined,
    once,
  });
  return id;
}

export class Channel<T = unknown> {
  readonly id: number;
  private handler: (response: T) => void;

  constructor(onmessage: (response: T) => void = () => undefined) {
    this.handler = onmessage;
    this.id = transformCallback((response: T) => this.handler(response));
  }

  set onmessage(handler: (response: T) => void) {
    this.handler = handler;
  }

  get onmessage(): (response: T) => void {
    return this.handler;
  }

  toJSON(): string {
    return `__CHANNEL__:${this.id}`;
  }
}

export function invoke<T>(
  command: string,
  body?: InvokeBody,
  options?: InvokeOptions,
): Promise<T> {
  return dispatch<T>(command, body, options);
}

export function isTauri(): boolean {
  return false;
}

export function convertFileSrc(filePath: string): string {
  return filePath;
}
