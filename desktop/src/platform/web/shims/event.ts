export type UnlistenFn = () => void;

export type Event<T> = {
  event: string;
  id: number;
  payload: T;
};

type Listener<T> = (event: Event<T>) => void;

const eventTarget = new EventTarget();
let nextEventId = 1;

function browserEvent(name: string, payload: unknown): globalThis.Event {
  const event = new globalThis.Event(name);
  Object.defineProperty(event, "detail", { value: payload });
  return event;
}

export async function listen<T>(
  eventName: string,
  handler: Listener<T>,
): Promise<UnlistenFn> {
  const listener = (event: globalThis.Event) => {
    handler({
      event: eventName,
      id: nextEventId++,
      payload: (event as globalThis.Event & { detail?: T }).detail as T,
    });
  };
  eventTarget.addEventListener(eventName, listener);
  return () => eventTarget.removeEventListener(eventName, listener);
}

export async function once<T>(
  eventName: string,
  handler: Listener<T>,
): Promise<UnlistenFn> {
  let unlisten: UnlistenFn = () => undefined;
  unlisten = await listen<T>(eventName, (event) => {
    unlisten();
    handler(event);
  });
  return unlisten;
}

export async function emit<T>(eventName: string, payload?: T): Promise<void> {
  eventTarget.dispatchEvent(browserEvent(eventName, payload));
}
