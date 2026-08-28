export type MessageDeliveryState = "queued" | "failed" | "expired";

export function messageDeliveryLabel(
  state: MessageDeliveryState | undefined,
  pending: boolean | undefined,
): string | null {
  if (state === "queued") return "Queued offline";
  if (state === "failed") return "Delivery failed";
  if (state === "expired") return "Delivery expired";
  return pending ? "Sending…" : null;
}
