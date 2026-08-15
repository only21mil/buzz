export type Update = {
  version: string;
  download(): Promise<void>;
  install(): Promise<void>;
  close(): Promise<void>;
};

export async function check(): Promise<Update | null> {
  return null;
}
