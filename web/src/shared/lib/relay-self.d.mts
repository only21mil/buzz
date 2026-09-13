export function isRelaySelfPubkey(value: unknown): value is string;

export function getRelaySelf(baseUrl: string): Promise<string | null>;

export function resetRelaySelfCache(): void;
