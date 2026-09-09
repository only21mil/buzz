export type ResizeSubscription = {
  observer: ResizeObserver;
  content: HTMLDivElement | null;
  container: HTMLDivElement | null;
};

/** Reconnect only when committed scroll nodes have changed. */
export function reconnectScrollResizeObserver(
  subscription: ResizeSubscription | null,
  content: HTMLDivElement | null,
  container: HTMLDivElement | null,
): void {
  if (!subscription) return;
  if (subscription.content === content && subscription.container === container)
    return;

  subscription.observer.disconnect();
  subscription.content = content;
  subscription.container = container;
  if (content) subscription.observer.observe(content);
  if (container && container !== content)
    subscription.observer.observe(container);
}
