const configuredBase = import.meta.env?.BASE_URL ?? "/";
const normalizedBase = configuredBase.endsWith("/")
  ? configuredBase
  : `${configuredBase}/`;

/** Resolve a file from `public/` under the active Vite base path. */
export function publicAssetUrl(path: string): string {
  return `${normalizedBase}${path.replace(/^\/+/, "")}`;
}
