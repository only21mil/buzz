import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/web",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4174",
    reducedMotion: "reduce",
    screenshot: "only-on-failure",
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: [
    {
      command:
        "pnpm exec vite preview --mode web --port 4174 --strictPort --host 127.0.0.1",
      cwd: ".",
      reuseExistingServer: false,
      url: "http://127.0.0.1:4174/app/",
    },
    {
      command:
        "pnpm exec vite --mode e2e --base /app/ --port 4175 --strictPort --host 127.0.0.1",
      cwd: ".",
      reuseExistingServer: false,
      url: "http://127.0.0.1:4175/app/?e2e=mock",
    },
  ],
});
