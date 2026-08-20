export type ActionNotification = {
  extra?: Record<string, unknown>;
};

export async function isPermissionGranted(): Promise<boolean> {
  return (
    typeof Notification !== "undefined" && Notification.permission === "granted"
  );
}

export async function requestPermission(): Promise<NotificationPermission> {
  if (typeof Notification === "undefined") return "denied";
  return Notification.requestPermission();
}

export async function sendNotification(
  options: string | (NotificationOptions & { title: string }),
): Promise<void> {
  if (!(await isPermissionGranted())) return;
  if (typeof options === "string") new Notification(options);
  else new Notification(options.title, options);
}

export async function onAction(): Promise<{ unregister(): Promise<void> }> {
  return { unregister: async () => undefined };
}
