import packageJson from "../../../../package.json";

const BUILD_VERSION = packageJson.version;

export async function getVersion(): Promise<string> {
  return BUILD_VERSION;
}
